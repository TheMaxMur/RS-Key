// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use rsk_fs::KeyFid;
use rsk_otp::seal::{seal_put, seal_read};

use super::*;

/// First OTP slot FID (`rsk_otp`'s crate-private `EF_OTP_SLOT1`; the four slots
/// are 0xBB00..=0xBB03) and the slot record's shape: a 52-byte config
/// (`CONFIG_SIZE`) whose 8-byte tail opens with the 16-bit big-endian use
/// counter. Named here as `fuzz/fuzz_targets/otp_ticket.rs` names them, for the
/// same reason — the applet keeps them to itself.
const SLOT1_FID: u16 = 0xBB00;
const SLOT_RECORD: usize = 60;
const USE_COUNTER: usize = 52;

/// The vendor applet's AID and its warm-reboot command (`rsk_vendor`'s
/// crate-private `INS_REBOOT`, P1 = 0 for "come back up, do not drop to
/// BOOTSEL"), as `tests/51_secure_reboot.py` sends them.
const VENDOR_AID: [u8; 5] = [0xF0, 0x00, 0x00, 0x00, 0x01];
const INS_REBOOT: u8 = 0x1F;
const SW_OK: [u8; 2] = [0x90, 0x00];

const SERIAL: [u8; 8] = *b"RSKEMUT1";

/// The two CTAPHID channels the cancel tests speak on: the one that owns the
/// ceremony, and a second process's.
const CID: u32 = 0x0102_0304;
const OTHER_CID: u32 = 0x0A0B_0C0D;

/// The sealing identity `serve` builds: the chip serial and its hash, no fused
/// key — an emulator has no OTP block.
fn sealed_as() -> ([u8; 8], [u8; 32]) {
    (SERIAL, rsk_crypto::sha256(&SERIAL))
}

fn mount(path: &Path) -> Fs<crate::store::EmuStore> {
    let mut fs = Fs::new(crate::store::open(Some(path.to_path_buf()), None).unwrap());
    fs.scan();
    fs
}

/// Slot 1's stored use counter, read off the flash image the device is running.
fn use_counter(path: &Path) -> Option<u16> {
    let (serial_id, serial_hash) = sealed_as();
    let dev = Device {
        serial_hash: &serial_hash,
        serial_id: &serial_id,
        otp_key: None,
    };
    let mut rec = [0u8; SLOT_RECORD];
    let n = seal_read(&dev, &mut mount(path), KeyFid::new(SLOT1_FID), &mut rec)?;
    (n == SLOT_RECORD).then(|| u16::from_be_bytes([rec[USE_COUNTER], rec[USE_COUNTER + 1]]))
}

/// A blank flash image holding one plain Yubico-OTP slot — every flag byte zero,
/// which is the kind `power_up_bump` advances (HOTP / short / static it skips) —
/// with the device thread running against it.
fn bench(name: &str) -> (PathBuf, Jobs, Arc<Signals>, JoinHandle<()>) {
    bench_with(name, PresenceMode::Instant)
}

/// …and the same bench with a presence backend that really waits, which is what a
/// cancel needs something to cancel.
fn bench_with(name: &str, presence: PresenceMode) -> (PathBuf, Jobs, Arc<Signals>, JoinHandle<()>) {
    let path = std::env::temp_dir().join(format!("rsk-emu-{name}-{}.img", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let (serial_id, serial_hash) = sealed_as();
    let dev = Device {
        serial_hash: &serial_hash,
        serial_id: &serial_id,
        otp_key: None,
    };
    let mut rng = EmuRng::from_seed(&[0xa7; 32]);
    assert!(
        seal_put(
            &dev,
            &mut mount(&path),
            &mut rng,
            KeyFid::new(SLOT1_FID),
            &[0u8; SLOT_RECORD],
        ),
        "seal a slot into the image"
    );
    assert_eq!(use_counter(&path), Some(0), "a freshly programmed slot");

    let (jobs, requests) = job_queue();
    let cfg = Config {
        store: Some(path.clone()),
        presence,
        display: false,
        usbip: None,
        seed: Some(vec![0x5e; 32]),
        serial: SERIAL,
        kv_total: crate::KV_TOTAL,
        flash_size: crate::FLASH_SIZE,
        trace: false,
        yubico: false,
        power_cut: None,
    };
    let signals = Arc::new(Signals::default());
    let device = {
        let signals = signals.clone();
        std::thread::spawn(move || run(cfg, requests, signals, None, None))
    };
    (path, jobs, signals, device)
}

/// Send one job and wait for its answer.
fn ask(jobs: &Jobs, job: Job) -> Vec<u8> {
    let (reply, answer) = mpsc::channel();
    jobs.send(job, reply).expect("the device thread");
    answer
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("the device answered")
        .expect("a body")
}

fn shut_down(path: PathBuf, jobs: Jobs, device: JoinHandle<()>) {
    drop(jobs);
    device.join().unwrap();
    let _ = std::fs::remove_file(path);
}

/// A power cycle advances the Yubico-OTP use counter, on the bench as on the
/// board.
///
/// `firmware/src/main.rs` runs `power_up_bump` at every cold boot and its own
/// comment says why: the RAM session counter restarts at 0 on each power-up, so
/// a persistent use counter that stood still would let the `(use, session)` pair
/// a Yubico validation server orders OTPs by repeat — which is the replay. The
/// emulator had zero references to it, so `OP_REPLUG` reset the session half and
/// left the persistent half alone: the one arrangement the defence exists to
/// prevent, reproduced on the bench built to test it.
///
/// Driven through `device::run`'s real job loop over the real store image, not by
/// calling `rsk_otp::power_up_bump` again — that function has its own tests in
/// its own crate, and exercising it here would leave both call sites unproven.
#[test]
fn a_power_cycle_advances_the_yubico_otp_use_counter() {
    let (path, jobs, _signals, device) = bench("power-cycle");

    // Answering anything proves the boot block is behind us.
    ask(&jobs, Job::OtpStatus);
    assert_eq!(
        use_counter(&path),
        Some(1),
        "process start is a power-up too"
    );

    ask(&jobs, Job::Replug);
    assert_eq!(
        use_counter(&path),
        Some(2),
        "the replug left the counter where the last power-up did"
    );

    shut_down(path, jobs, device);
}

/// The other half of the same rule: a host-requested warm reboot must NOT bump.
/// `INS_REBOOT` is ungated, so a bump on that path would hand any host a way to
/// walk the 15-bit counter to its ceiling, where it saturates while the session
/// counter keeps restarting — the same repeated pair, reached from the other
/// side. `main.rs` states the rule as `if !pin_lock::was_warm_boot()`.
#[test]
fn a_warm_reboot_is_not_a_power_cycle() {
    let (path, jobs, _signals, device) = bench("warm-reboot");
    ask(&jobs, Job::OtpStatus);
    assert_eq!(use_counter(&path), Some(1), "the boot bump");

    let mut select = vec![0x00, 0xA4, 0x04, 0x00, VENDOR_AID.len() as u8];
    select.extend_from_slice(&VENDOR_AID);
    let r = ask(&jobs, Job::Apdu(select));
    assert_eq!(r[r.len() - 2..], SW_OK, "the vendor applet is selected");
    let r = ask(&jobs, Job::Apdu(vec![0x00, INS_REBOOT, 0x00, 0x00]));
    assert_eq!(r[r.len() - 2..], SW_OK, "the reboot was accepted");

    // The reboot runs after the response is out, as it does on the device, so
    // one more round trip is what proves it has happened.
    ask(&jobs, Job::OtpStatus);
    assert_eq!(
        use_counter(&path),
        Some(1),
        "a warm reboot is not a power-up"
    );

    shut_down(path, jobs, device);
}

/// Every [`Job`] variant, and whether a queued one is a request the parked worker
/// is owed the executor for (`rsk_display::Hooks::host_request_pending`). The
/// membership is the `REQ` set of `firmware/src/worker.rs` — get it wrong in
/// either direction and the emulator's panel yields where a board would not, or
/// starves where a board would not.
fn every_job() -> Vec<(Job, bool, &'static str)> {
    vec![
        (
            Job::Cbor {
                cid: 1,
                data: vec![0x04],
            },
            true,
            "CTAPHID_CBOR",
        ),
        (
            Job::Msg {
                cid: CID,
                data: vec![0x00, 0x03, 0, 0],
            },
            true,
            "CTAPHID_MSG",
        ),
        (
            Job::Vendor {
                cmd: 0x01,
                data: Vec::new(),
            },
            true,
            "a CTAPHID vendor command",
        ),
        (Job::Apdu(vec![0x00, 0xA4, 0x04, 0x00]), true, "a CCID APDU"),
        (Job::ResetCard, true, "a card reset"),
        (
            Job::OtpHid {
                slot: 0x30,
                payload: vec![0; 64],
            },
            false,
            "an OTP frame — the board's own OTP_REQ",
        ),
        (
            Job::OtpStatus,
            false,
            "the OTP status read — inline in the board's worker",
        ),
        (
            Job::DeselectMsg,
            false,
            "the CTAPHID_INIT deselect — an atomic on the board",
        ),
        (
            Job::Replug,
            false,
            "a power cycle — no host request behind it",
        ),
    ]
}

/// The queue's own accounting, which is what an on-panel modal reads to decide
/// whether to hand the executor back. A count that never comes down closes every
/// modal 2.5 s after the last touch; one that never goes up starves the host for
/// the full `MENU_INACTIVITY_MS`.
#[test]
fn a_queued_host_request_is_pending_only_until_the_device_takes_it() {
    let (jobs, source) = job_queue();
    let queued = source.queued();
    let (reply, _answers) = mpsc::channel();

    for (job, counts, what) in every_job() {
        assert!(!queued.any(), "the queue is empty before {what}");
        jobs.send(job, reply.clone()).unwrap();
        assert_eq!(queued.any(), counts, "{what}");
        source.try_next().expect("the job is there");
        assert!(!queued.any(), "the pickup clears {what}");
    }

    // Two outstanding, one taken: a count, not a flag. The transports are separate
    // threads and nothing serialises them, so this is the ordinary case and not a
    // corner of it.
    jobs.send(Job::ResetCard, reply.clone()).unwrap();
    jobs.send(Job::ResetCard, reply.clone()).unwrap();
    source.try_next().expect("the first is there");
    assert!(queued.any(), "the second is still owed the executor");
    source.try_next().expect("the second is there");
    assert!(!queued.any());

    // A send that never reached the queue owes nothing either — otherwise a device
    // thread that exits mid-session leaves the panel yielding to a ghost.
    drop(source);
    assert!(
        jobs.send(
            Job::Cbor {
                cid: 1,
                data: vec![0x04]
            },
            reply
        )
        .is_err()
    );
    assert!(!queued.any(), "a refused send left its claim behind");
}

/// A wait raised once a dispatch is over belongs to nobody: it is an on-panel
/// ceremony, and no transport may report or cancel it. `firmware/src/worker.rs`
/// lowers the scope between dispatches for exactly this reason, and without it a
/// local PIN entry is advertised to whichever transport asked last.
#[test]
fn a_wait_raised_after_a_dispatch_is_no_transports() {
    let (path, jobs, signals, device) = bench("wait-scope");

    ask(
        &jobs,
        Job::Cbor {
            cid: 1,
            data: vec![0x04],
        },
    );

    // The panel, raising its own: `TouchPresence::ceremony_begin` through
    // `EmuDisplayHooks::set_up_pending`, which is this same call.
    signals.set_up_pending(true);
    // `up_pending_for` is `raised && scope == asked`, so the wait showing up under
    // SCOPE_NONE is the same fact as no transport being able to claim it.
    assert!(
        signals.up_pending_for(signals::SCOPE_NONE),
        "the panel's own wait is filed under the last command's transport"
    );
    assert!(
        !signals.up_pending_for(signals::SCOPE_FIDO),
        "a local ceremony would make the FIDO keepalive say UPNEEDED for a touch \
         the host never asked for"
    );

    shut_down(path, jobs, device);
}

// --- the U2F touch wait and its cancel ---------------------------------------

/// How long the scripted presence backend holds the touch. Long enough that a
/// cancel taking effect and a cancel being ignored cannot be confused, short
/// enough that the ignored case still finishes the test.
const TOUCH_HOLD_MS: u64 = 6_000;
/// What a cancel on the owning channel may take. The backend polls the flag every
/// 50 ms; one that cannot see it at all waits out [`TOUCH_HOLD_MS`].
const CANCEL_BOUND_MS: u64 = 2_000;
const _: () = assert!(2 * CANCEL_BOUND_MS < TOUCH_HOLD_MS);

fn touch_hold() -> Duration {
    Duration::from_millis(TOUCH_HOLD_MS)
}

fn cancel_bound() -> Duration {
    Duration::from_millis(CANCEL_BOUND_MS)
}

/// The Management applet's READ CONFIG over the FIDO transport
/// (`rsk_device::ccid`'s crate-private `CTAP_READ_CONFIG`), named here as the
/// other applet-private constants above are.
const CTAP_READ_CONFIG: u8 = 0x42;

/// A U2F REGISTER as `tests/13_u2f.py` sends it: the extended-length APDU whose
/// 64-byte body is challenge ‖ application. Registration is the U2F command that
/// is a touch and then some work, so the wait is what the cancel below meets.
fn u2f_register() -> Vec<u8> {
    let mut apdu = vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x40];
    apdu.extend_from_slice(&rsk_crypto::sha256(b"rs-key u2f challenge"));
    apdu.extend_from_slice(&rsk_crypto::sha256(b"https://example.com"));
    apdu.extend_from_slice(&[0x00, 0x00]);
    apdu
}

/// U2F's only "interact and try again" status, which `u2f_interaction` answers
/// for a declined, timed-out or cancelled touch alike.
const SW_CONDITIONS_NOT_SATISFIED: [u8; 2] = [0x69, 0x85];

/// Queue `job` on its own channel and hand back the receiver, without waiting.
fn queue(jobs: &Jobs, job: Job) -> mpsc::Receiver<Option<Vec<u8>>> {
    let (reply, answer) = mpsc::channel();
    jobs.send(job, reply).expect("the device thread");
    answer
}

/// Poll until the device is asking a transport for a touch, so the cancel below
/// meets a wait rather than racing the dispatch.
fn wait_for_touch(signals: &Signals) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if signals.up_pending_for(signals::SCOPE_FIDO) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

/// A `CTAPHID_CANCEL` ends a U2F touch wait, as it ends a CBOR one.
///
/// `Job::Msg` was dispatched under `signals.begin(0)`, and `Signals::cancelled()`
/// needs a non-zero channel — so the cancel the transport faithfully raised was
/// dropped and a cancelled U2F REGISTER ran the full presence timeout and then
/// **minted the credential anyway**. On a board U2F runs under `SCOPE_FIDO`
/// (`firmware/src/worker.rs`) and `Arbiter::request_cancel` ends it, with
/// `rsk_usb::ctaphid::run_with_keepalive` watching the reader for the frame.
#[test]
fn a_cancel_ends_a_u2f_touch_wait_on_its_own_channel() {
    let (path, jobs, signals, device) =
        bench_with("u2f-cancel", PresenceMode::Delayed(touch_hold()));

    let answer = queue(
        &jobs,
        Job::Msg {
            cid: CID,
            data: u2f_register(),
        },
    );
    assert!(
        wait_for_touch(&signals),
        "the register never asked for a touch"
    );

    // What `hid.rs` does with a CANCEL frame whose channel owns the command.
    signals.request_cancel(CID);
    let sent = Instant::now();
    let body = answer
        .recv_timeout(touch_hold() * 3)
        .expect("the device answered")
        .expect("a U2F response is always a body");
    let took = sent.elapsed();

    assert_eq!(
        body[body.len() - 2..],
        SW_CONDITIONS_NOT_SATISFIED,
        "a cancelled registration answered {:02x?} — the touch wait ran on and \
         minted the credential the host had already withdrawn",
        &body[body.len() - 2..]
    );
    assert!(
        took < cancel_bound(),
        "the wait took {took:?} to notice the cancel"
    );

    shut_down(path, jobs, device);
}

/// …and only its own channel's. A single global cancel flag is the defect audit
/// run-31 filed as HIGH, and giving `Job::Msg` a real channel is what keeps the
/// scoping the CBOR path already had.
#[test]
fn a_cancel_from_another_channel_leaves_a_u2f_ceremony_alone() {
    let (path, jobs, signals, device) =
        bench_with("u2f-cancel-scope", PresenceMode::Delayed(touch_hold()));

    let answer = queue(
        &jobs,
        Job::Msg {
            cid: CID,
            data: u2f_register(),
        },
    );
    assert!(
        wait_for_touch(&signals),
        "the register never asked for a touch"
    );

    signals.request_cancel(OTHER_CID);
    let body = answer
        .recv_timeout(touch_hold() * 3)
        .expect("the device answered")
        .expect("a U2F response is always a body");

    assert_eq!(
        body[body.len() - 2..],
        SW_OK,
        "a second process's cancel ended a ceremony it does not own"
    );

    shut_down(path, jobs, device);
}

/// Why `Job::Vendor` is deliberately *not* bracketed with `begin`/`end`: no
/// vendor command is presence-gated, so there is no wait to own, and
/// `rsk_usb::ctaphid::run_vendor` streams no keepalive and watches for no CANCEL
/// — a board cannot cancel one either. This is that assumption, pinned: a vendor
/// command that ever grows a touch gate reds this and has to be given a channel.
#[test]
fn a_vendor_command_asks_for_no_touch() {
    let (path, jobs, signals, device) =
        bench_with("vendor-no-touch", PresenceMode::Delayed(touch_hold()));

    let sent = Instant::now();
    ask(
        &jobs,
        Job::Vendor {
            cmd: CTAP_READ_CONFIG,
            data: Vec::new(),
        },
    );
    let took = sent.elapsed();

    assert!(
        took < cancel_bound(),
        "the vendor read waited {took:?} — something on that path asked for a touch"
    );
    assert!(
        !signals.up_pending_for(signals::SCOPE_FIDO),
        "a vendor command left a touch pending behind it"
    );

    shut_down(path, jobs, device);
}
