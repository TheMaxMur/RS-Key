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
fn bench(name: &str) -> (PathBuf, mpsc::Sender<Req>, JoinHandle<()>) {
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

    let (jobs, requests) = mpsc::channel();
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
    let device =
        std::thread::spawn(move || run(cfg, requests, Arc::new(Signals::default()), None, None));
    (path, jobs, device)
}

/// Send one job and wait for its answer.
fn ask(jobs: &mpsc::Sender<Req>, job: Job) -> Vec<u8> {
    let (reply, answer) = mpsc::channel();
    jobs.send(Req { job, reply }).expect("the device thread");
    answer
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("the device answered")
        .expect("a body")
}

fn shut_down(path: PathBuf, jobs: mpsc::Sender<Req>, device: JoinHandle<()>) {
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
    let (path, jobs, device) = bench("power-cycle");

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
    let (path, jobs, device) = bench("warm-reboot");
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
