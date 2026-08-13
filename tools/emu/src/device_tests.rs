// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread::JoinHandle;

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
        presence: PresenceMode::Instant,
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
        (Job::Msg(vec![0x00, 0x03, 0, 0]), true, "CTAPHID_MSG"),
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
