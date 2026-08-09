// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::ram::RamStorage;

/// A provisioned MKEK for the tests. The applet holds a way to READ the fuses, not
/// the key, so a test source has to be a plain `fn`.
fn test_mkek() -> Option<[u8; 32]> {
    Some([0x11; 32])
}

struct LcgRng(u64);
impl Rng for LcgRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (self.0 >> 33) as u8;
        }
    }
}

struct AlwaysConfirm;
impl UserPresence for AlwaysConfirm {
    fn request(&mut self, _c: Confirm<'_>) -> Presence {
        Presence::Confirmed
    }
}
struct DenyPresence;
impl UserPresence for DenyPresence {
    fn request(&mut self, _c: Confirm<'_>) -> Presence {
        Presence::Declined
    }
}

struct FakePlatform {
    time: Option<u32>,
    reboots: Vec<bool>,
    status: (bool, bool, u8),
    /// Simulated PAGE58_LOCK1 raw value; `None` models a read error.
    lock_raw: Option<u32>,
    lock_writes: u32,
    /// Simulated anti-rollback rows; `None` models a read error.
    rollback_raw: Option<rollback::RollbackRaw>,
    rollback_writes: u32,
}
impl Default for FakePlatform {
    fn default() -> Self {
        FakePlatform {
            time: None,
            reboots: Vec::new(),
            status: (false, false, 0xFF),
            lock_raw: Some(0),
            lock_writes: 0,
            rollback_raw: Some(rollback::RollbackRaw {
                flags0: [0; 3],
                version0: [0; 3],
                version1: [0; 3],
            }),
            rollback_writes: 0,
        }
    }
}
impl Platform for FakePlatform {
    fn secure_boot_status(&self) -> SecureBootStatus {
        SecureBootStatus {
            enabled: self.status.0,
            locked: self.status.1,
            bootkey: self.status.2,
        }
    }
    fn now(&self) -> Option<u32> {
        self.time
    }
    fn set_time(&mut self, epoch: u32) {
        self.time = Some(epoch);
    }
    fn request_reboot(&mut self, bootsel: bool) {
        self.reboots.push(bootsel);
    }
    fn read_page58_lock_raw(&self) -> Option<u32> {
        self.lock_raw
    }
    fn lock_page58(&mut self) -> bool {
        // OTP bits only go 0→1; model the fuse burning to our value.
        self.lock_writes += 1;
        self.lock_raw = Some(otp_lock::PAGE58_LOCK_VALUE);
        true
    }
    fn read_rollback_raw(&self) -> Option<rollback::RollbackRaw> {
        self.rollback_raw
    }
    fn set_rollback_required(&mut self) -> bool {
        // OR the bit into every copy, like the firmware burn does.
        self.rollback_writes += 1;
        if let Some(raw) = self.rollback_raw.as_mut() {
            for row in raw.flags0.iter_mut() {
                *row |= rollback::ROLLBACK_REQUIRED_BIT;
            }
        }
        true
    }
}

const SERIAL_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const SERIAL_HASH: [u8; 32] = [0xA5; 32];
const KV_TOTAL: u32 = 64 * 1024;
const FLASH_SIZE: u32 = 4 * 1024 * 1024;

fn apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut a = vec![cla, ins, p1, p2];
    if !data.is_empty() {
        a.push(data.len() as u8);
        a.extend_from_slice(data);
    }
    a.push(0); // Le
    a
}

fn run(app: &mut RescueApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) -> (Sw, Vec<u8>) {
    let mut buf = [0u8; 512];
    let parsed = Apdu::parse(raw).unwrap();
    let mut res = ResBuf::new(&mut buf);
    let sw = app.process(&parsed, fs, &mut res);
    (sw, res.as_slice().to_vec())
}

#[test]
fn select_reports_identity() {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform::default());
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = RescueApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        None,
        None,
        &rng,
        &platform,
        &presence,
        KV_TOTAL,
        FLASH_SIZE,
    );
    let mut fs = Fs::new(RamStorage::new());
    let mut buf = [0u8; 64];
    let mut res = ResBuf::new(&mut buf);
    let sw = Applet::<Fs<RamStorage>>::select(&mut app, false, &mut fs, &mut res);
    assert_eq!(sw, Sw::OK);
    let mut want = vec![1u8, 2, 8, 6]; // RP2350, FIDO product, SDK 8.6
    want.extend_from_slice(&SERIAL_ID);
    assert_eq!(res.as_slice(), &want[..]);
}

#[test]
fn cla_is_checked() {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform::default());
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = RescueApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        None,
        None,
        &rng,
        &platform,
        &presence,
        KV_TOTAL,
        FLASH_SIZE,
    );
    let mut fs = Fs::new(RamStorage::new());
    let (sw, _) = run(&mut app, &mut fs, &apdu(0x00, INS_READ, 0x03, 0, &[]));
    assert_eq!(sw, Sw::CLA_NOT_SUPPORTED);
}

fn lock_app<'a>(
    rng: &'a RefCell<LcgRng>,
    platform: &'a RefCell<FakePlatform>,
    presence: &'a RefCell<AlwaysConfirm>,
    mkek_source: Option<FusedKey>,
) -> RescueApplet<'a> {
    RescueApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        mkek_source,
        None,
        rng,
        platform,
        presence,
        KV_TOTAL,
        FLASH_SIZE,
    )
}

fn lock_apdu() -> Vec<u8> {
    apdu(0x80, INS_OTP_LOCK, 0x58, 0x00, OTP_LOCK_MAGIC)
}

#[test]
fn otp_lock_writes_once_then_idempotent() {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform::default()); // lock_raw = Some(0)
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = lock_app(&rng, &platform, &presence, Some(test_mkek as FusedKey));
    let mut fs = Fs::new(RamStorage::new());

    let (sw, _) = run(&mut app, &mut fs, &lock_apdu());
    assert_eq!(sw, Sw::OK);
    assert_eq!(platform.borrow().lock_writes, 1);
    assert_eq!(
        platform.borrow().lock_raw,
        Some(otp_lock::PAGE58_LOCK_VALUE)
    );

    // A second call finds the row already locked: OK, no further fuse write.
    let (sw, _) = run(&mut app, &mut fs, &lock_apdu());
    assert_eq!(sw, Sw::OK);
    assert_eq!(platform.borrow().lock_writes, 1, "must not re-burn");
}

#[test]
fn otp_lock_refused_without_provisioned_keys() {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform::default());
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = lock_app(&rng, &platform, &presence, None); // no MKEK
    let mut fs = Fs::new(RamStorage::new());
    let (sw, _) = run(&mut app, &mut fs, &lock_apdu());
    assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);
    assert_eq!(platform.borrow().lock_writes, 0);
}

#[test]
fn otp_lock_rejects_bad_guards() {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform::default());
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = lock_app(&rng, &platform, &presence, Some(test_mkek as FusedKey));
    let mut fs = Fs::new(RamStorage::new());

    // wrong P1 (not the page number)
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(0x80, INS_OTP_LOCK, 0x00, 0x00, OTP_LOCK_MAGIC),
    );
    assert_eq!(sw, Sw::INCORRECT_P1P2);
    // wrong magic payload
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(0x80, INS_OTP_LOCK, 0x58, 0x00, b"nope"),
    );
    assert_eq!(sw, Sw::DATA_INVALID);
    // wrong CLA never reaches the handler
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(0x00, INS_OTP_LOCK, 0x58, 0x00, OTP_LOCK_MAGIC),
    );
    assert_eq!(sw, Sw::CLA_NOT_SUPPORTED);

    assert_eq!(platform.borrow().lock_writes, 0, "no guard path may burn");
}

#[test]
fn otp_lock_refuses_foreign_lock_value() {
    let rng = RefCell::new(LcgRng(7));
    // a different, pre-existing lock config
    let platform = RefCell::new(FakePlatform {
        lock_raw: Some(0x14_14_14),
        ..Default::default()
    });
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = lock_app(&rng, &platform, &presence, Some(test_mkek as FusedKey));
    let mut fs = Fs::new(RamStorage::new());
    let (sw, _) = run(&mut app, &mut fs, &lock_apdu());
    assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);
    assert_eq!(
        platform.borrow().lock_writes,
        0,
        "never clobber a non-blank row"
    );
}

#[test]
fn otp_lock_read_error_is_exec_error() {
    let rng = RefCell::new(LcgRng(7));
    // model a read failure
    let platform = RefCell::new(FakePlatform {
        lock_raw: None,
        ..Default::default()
    });
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = lock_app(&rng, &platform, &presence, Some(test_mkek as FusedKey));
    let mut fs = Fs::new(RamStorage::new());
    let (sw, _) = run(&mut app, &mut fs, &lock_apdu());
    assert_eq!(sw, Sw::EXEC_ERROR);
    assert_eq!(platform.borrow().lock_writes, 0);
}

fn rollback_apdu() -> Vec<u8> {
    apdu(0x80, INS_OTP_LOCK, 0x48, 0x00, ROLLBACK_MAGIC)
}

/// A platform with secure boot enabled (the rollback-require gate).
fn secure_platform() -> FakePlatform {
    FakePlatform {
        status: (true, true, 0),
        ..Default::default()
    }
}

#[test]
fn rollback_require_burns_once_then_idempotent() {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(secure_platform());
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = lock_app(&rng, &platform, &presence, None); // no MKEK needed for this one
    let mut fs = Fs::new(RamStorage::new());

    let (sw, _) = run(&mut app, &mut fs, &rollback_apdu());
    assert_eq!(sw, Sw::OK);
    assert_eq!(platform.borrow().rollback_writes, 1);
    let flags0 = platform.borrow().rollback_raw.unwrap().flags0;
    assert!(
        flags0
            .iter()
            .all(|r| r & rollback::ROLLBACK_REQUIRED_BIT != 0)
    );

    // A second call finds the bit already fused: OK, no further write.
    let (sw, _) = run(&mut app, &mut fs, &rollback_apdu());
    assert_eq!(sw, Sw::OK);
    assert_eq!(platform.borrow().rollback_writes, 1, "must not re-burn");
}

#[test]
fn rollback_require_needs_secure_boot() {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform::default()); // secure boot off
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = lock_app(&rng, &platform, &presence, Some(test_mkek as FusedKey));
    let mut fs = Fs::new(RamStorage::new());
    let (sw, _) = run(&mut app, &mut fs, &rollback_apdu());
    assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);
    assert_eq!(platform.borrow().rollback_writes, 0);
}

#[test]
fn rollback_require_rejects_bad_guards() {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(secure_platform());
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = lock_app(&rng, &platform, &presence, Some(test_mkek as FusedKey));
    let mut fs = Fs::new(RamStorage::new());

    // wrong magic (including the *other* P1's magic)
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(0x80, INS_OTP_LOCK, 0x48, 0x00, b"nope"),
    );
    assert_eq!(sw, Sw::DATA_INVALID);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(0x80, INS_OTP_LOCK, 0x48, 0x00, OTP_LOCK_MAGIC),
    );
    assert_eq!(sw, Sw::DATA_INVALID);
    // magics must not cross over to the page-58 arm either
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(0x80, INS_OTP_LOCK, 0x58, 0x00, ROLLBACK_MAGIC),
    );
    assert_eq!(sw, Sw::DATA_INVALID);
    // nonzero P2
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(0x80, INS_OTP_LOCK, 0x48, 0x01, ROLLBACK_MAGIC),
    );
    assert_eq!(sw, Sw::INCORRECT_P1P2);

    assert_eq!(
        platform.borrow().rollback_writes,
        0,
        "no guard path may burn"
    );
    assert_eq!(platform.borrow().lock_writes, 0);
}

#[test]
fn rollback_require_read_error_is_exec_error() {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform {
        rollback_raw: None,
        ..secure_platform()
    });
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = lock_app(&rng, &platform, &presence, Some(test_mkek as FusedKey));
    let mut fs = Fs::new(RamStorage::new());
    let (sw, _) = run(&mut app, &mut fs, &rollback_apdu());
    assert_eq!(sw, Sw::EXEC_ERROR);
    assert_eq!(platform.borrow().rollback_writes, 0);
}

#[test]
fn rollback_state_read() {
    let rng = RefCell::new(LcgRng(7));
    // Two of three flags copies fused (majority: required), thermometer at
    // 3 + 1 across the two words — incl. one sparse single-copy bit that
    // must NOT count (majority zero).
    let platform = RefCell::new(FakePlatform {
        rollback_raw: Some(rollback::RollbackRaw {
            flags0: [
                rollback::ROLLBACK_REQUIRED_BIT,
                rollback::ROLLBACK_REQUIRED_BIT,
                0,
            ],
            version0: [0b111, 0b111, 0b011],
            version1: [0b11, 0b01, 0b01],
        }),
        ..Default::default()
    });
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = lock_app(&rng, &platform, &presence, None);
    let mut fs = Fs::new(RamStorage::new());
    let (sw, body) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x06, 0, &[]));
    assert_eq!(sw, Sw::OK);
    assert_eq!(body, vec![1, 4, rollback::VERSION_CAPACITY]);

    // Blank board: not required, version 0.
    platform.borrow_mut().rollback_raw = Some(rollback::RollbackRaw {
        flags0: [0; 3],
        version0: [0; 3],
        version1: [0; 3],
    });
    let (sw, body) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x06, 0, &[]));
    assert_eq!(sw, Sw::OK);
    assert_eq!(body, vec![0, 0, rollback::VERSION_CAPACITY]);

    // Read error.
    platform.borrow_mut().rollback_raw = None;
    let (sw, _) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x06, 0, &[]));
    assert_eq!(sw, Sw::EXEC_ERROR);
}

#[test]
fn keydev_sign_verifies_and_key_persists() {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform::default());
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = RescueApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        None,
        None,
        &rng,
        &platform,
        &presence,
        KV_TOTAL,
        FLASH_SIZE,
    );
    let mut fs = Fs::new(RamStorage::new());

    let (sw, pubkey) = run(
        &mut app,
        &mut fs,
        &apdu(0x80, INS_KEYDEV_SIGN, 0x02, 0, &[]),
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(pubkey.len(), 65);
    assert_eq!(pubkey[0], 0x04);

    let digest = [0x42u8; 32];
    let (sw, sig) = run(
        &mut app,
        &mut fs,
        &apdu(0x80, INS_KEYDEV_SIGN, 0x01, 0, &digest),
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(sig.len(), 64);

    let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey).unwrap();
    let sig = k256::ecdsa::Signature::from_slice(&sig).unwrap();
    vk.verify_prehash(&digest, &sig).unwrap();

    // Same key on re-load (sealed in EF_DEVCERT_KEY, not regenerated).
    let (_, pubkey2) = run(
        &mut app,
        &mut fs,
        &apdu(0x80, INS_KEYDEV_SIGN, 0x02, 0, &[]),
    );
    assert_eq!(pubkey, pubkey2);

    // Wrong digest length.
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(0x80, INS_KEYDEV_SIGN, 0x01, 0, &[0; 16]),
    );
    assert_eq!(sw, Sw::WRONG_LENGTH);
}

#[test]
fn keydev_cert_upload() {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform::default());
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = RescueApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        None,
        None,
        &rng,
        &platform,
        &presence,
        KV_TOTAL,
        FLASH_SIZE,
    );
    let mut fs = Fs::new(RamStorage::new());
    let cert = [0x30u8, 0x82, 0x01, 0x00, 0xAA, 0xBB];
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(0x80, INS_KEYDEV_SIGN, 0x03, 0, &cert),
    );
    assert_eq!(sw, Sw::OK);
    let mut buf = [0u8; 16];
    assert_eq!(fs.read(keydev::EF_DEVCERT, &mut buf), Some(cert.len()));
    assert_eq!(&buf[..cert.len()], &cert);
    // Empty upload is rejected.
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(0x80, INS_KEYDEV_SIGN, 0x03, 0, &[]),
    );
    assert_eq!(sw, Sw::WRONG_LENGTH);
}

#[test]
fn phy_write_read_roundtrip() {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform::default());
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = RescueApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        None,
        None,
        &rng,
        &platform,
        &presence,
        KV_TOTAL,
        FLASH_SIZE,
    );
    let mut fs = Fs::new(RamStorage::new());

    // Virgin device: READ phy returns just the zero OPTS TLV.
    let (sw, body) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x01, 0, &[]));
    assert_eq!(sw, Sw::OK);
    assert_eq!(body, vec![0x06, 0x02, 0x00, 0x00]);

    // Write VIDPID + brightness; read back includes the ITF_ALL default.
    let blob = [0x00, 4, 0x10, 0x50, 0x04, 0x07, 0x05, 1, 99];
    let (sw, _) = run(&mut app, &mut fs, &apdu(0x80, INS_WRITE, 0x01, 0, &blob));
    assert_eq!(sw, Sw::OK);
    let (sw, body) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x01, 0, &[]));
    assert_eq!(sw, Sw::OK);
    let phy = phy::PhyData::parse(&body);
    assert_eq!(phy.vid_pid, Some((0x1050, 0x0407)));
    assert_eq!(phy.led_brightness, Some(99));
    assert_eq!(phy.enabled_usb_itf, Some(phy::USB_ITF_ALL));
}

#[test]
fn flash_info_layout() {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform::default());
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = RescueApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        None,
        None,
        &rng,
        &platform,
        &presence,
        KV_TOTAL,
        FLASH_SIZE,
    );
    let mut fs = Fs::new(RamStorage::new());
    fs.put(0x1111, &[0u8; 10]).unwrap();
    fs.put(0x2222, &[0u8; 6]).unwrap();

    let (sw, body) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x02, 0, &[]));
    assert_eq!(sw, Sw::OK);
    assert_eq!(body.len(), 20);
    let w = |i: usize| u32::from_be_bytes(body[i * 4..i * 4 + 4].try_into().unwrap());
    assert_eq!(w(0), KV_TOTAL - 16); // free
    assert_eq!(w(1), 16); // used
    assert_eq!(w(2), KV_TOTAL);
    assert_eq!(w(3), 2); // nfiles
    assert_eq!(w(4), FLASH_SIZE);
}

#[test]
fn secure_boot_status() {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform {
        status: (true, false, 2),
        ..Default::default()
    });
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = RescueApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        None,
        None,
        &rng,
        &platform,
        &presence,
        KV_TOTAL,
        FLASH_SIZE,
    );
    let mut fs = Fs::new(RamStorage::new());
    let (sw, body) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x03, 0, &[]));
    assert_eq!(sw, Sw::OK);
    assert_eq!(body, vec![1, 0, 2]);
}

#[test]
fn time_set_and_get_both_forms() {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform::default());
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = RescueApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        None,
        None,
        &rng,
        &platform,
        &presence,
        KV_TOTAL,
        FLASH_SIZE,
    );
    let mut fs = Fs::new(RamStorage::new());

    // Before set: 6985.
    let (sw, _) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x04, 0x02, &[]));
    assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);

    // Set 2026-06-11 00:00:00 UTC as a unix stamp; read back both forms.
    let t: u32 = 1781136000;
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(0x80, INS_WRITE, 0x02, 0x02, &t.to_be_bytes()),
    );
    assert_eq!(sw, Sw::OK);
    let (sw, body) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x04, 0x02, &[]));
    assert_eq!(sw, Sw::OK);
    assert_eq!(body, t.to_be_bytes());
    let (sw, body) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x04, 0x01, &[]));
    assert_eq!(sw, Sw::OK);
    // year, mon0=5 (June), mday=11, wday=4 (Thursday), 00:00:00.
    assert_eq!(body, vec![0x07, 0xEA, 5, 11, 4, 0, 0, 0]);

    // Set via the calendar form; get the same stamp back.
    let cal = [0x07, 0xEA, 5, 11, 0 /* wday ignored */, 12, 34, 56];
    let (sw, _) = run(&mut app, &mut fs, &apdu(0x80, INS_WRITE, 0x02, 0x01, &cal));
    assert_eq!(sw, Sw::OK);
    let (_, body) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x04, 0x02, &[]));
    assert_eq!(body, (t + 12 * 3600 + 34 * 60 + 56).to_be_bytes());

    // Invalid month.
    let bad = [0x07, 0xEA, 12, 11, 0, 0, 0, 0];
    let (sw, _) = run(&mut app, &mut fs, &apdu(0x80, INS_WRITE, 0x02, 0x01, &bad));
    assert_eq!(sw, Sw::DATA_INVALID);
}

#[test]
fn reboot_requests() {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform::default());
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = RescueApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        None,
        None,
        &rng,
        &platform,
        &presence,
        KV_TOTAL,
        FLASH_SIZE,
    );
    let mut fs = Fs::new(RamStorage::new());

    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(0x80, INS_REBOOT_BOOTSEL, 0x01, 0, &[]),
    );
    assert_eq!(sw, Sw::OK);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(0x80, INS_REBOOT_BOOTSEL, 0x00, 0, &[]),
    );
    assert_eq!(sw, Sw::OK);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(0x80, INS_REBOOT_BOOTSEL, 0x07, 0, &[]),
    );
    assert_eq!(sw, Sw::INCORRECT_P1P2);
    assert_eq!(platform.borrow().reboots, vec![true, false]);
}

#[test]
fn secure_ins_is_not_supported() {
    // 0x1D (enable secure boot) is deliberately unimplemented.
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform::default());
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = RescueApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        None,
        None,
        &rng,
        &platform,
        &presence,
        KV_TOTAL,
        FLASH_SIZE,
    );
    let mut fs = Fs::new(RamStorage::new());
    let (sw, _) = run(&mut app, &mut fs, &apdu(0x80, 0x1D, 0x00, 0, &[]));
    assert_eq!(sw, Sw::INS_NOT_SUPPORTED);
    assert!(platform.borrow().reboots.is_empty());
}

#[test]
fn privileged_ops_require_user_presence() {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform::default());
    let presence = RefCell::new(DenyPresence);
    let mut app = RescueApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        None,
        None,
        &rng,
        &platform,
        &presence,
        KV_TOTAL,
        FLASH_SIZE,
    );
    let mut fs = Fs::new(RamStorage::new());

    // Attestation sign / cert write / phy write / reboot-to-BOOTSEL are all
    // refused without a confirmation, and none take effect.
    for raw in [
        apdu(0x80, INS_KEYDEV_SIGN, 0x01, 0, &[0x42; 32]),
        apdu(0x80, INS_KEYDEV_SIGN, 0x03, 0, &[0xAA; 4]),
        apdu(0x80, INS_WRITE, 0x01, 0, &[0x00, 0x00]),
        apdu(0x80, INS_REBOOT_BOOTSEL, 0x01, 0, &[]),
    ] {
        let (sw, _) = run(&mut app, &mut fs, &raw);
        assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);
    }
    assert!(platform.borrow().reboots.is_empty());
    assert!(
        !fs.has_data(keydev::EF_DEVCERT),
        "cert must not have been written"
    );

    // Read-only pubkey, a plain reboot, and status reads stay ungated.
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(0x80, INS_KEYDEV_SIGN, 0x02, 0, &[]),
    );
    assert_eq!(sw, Sw::OK);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(0x80, INS_REBOOT_BOOTSEL, 0x00, 0, &[]),
    );
    assert_eq!(sw, Sw::OK);
    let (sw, _) = run(&mut app, &mut fs, &apdu(0x80, INS_READ, 0x03, 0, &[]));
    assert_eq!(sw, Sw::OK);
    assert_eq!(platform.borrow().reboots, vec![false]);
}

#[test]
fn otp_fuse_writes_require_user_presence() {
    // Both irreversible OTP fuse burns must be refused without a physical
    // confirmation, even with the correct magic payload and device posture.
    let rng = RefCell::new(LcgRng(7));

    // page-58 lock: provisioned MKEK + blank row, presence denied.
    let platform = RefCell::new(FakePlatform::default());
    let presence = RefCell::new(DenyPresence);
    let mut app = RescueApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        Some(test_mkek as FusedKey),
        None,
        &rng,
        &platform,
        &presence,
        KV_TOTAL,
        FLASH_SIZE,
    );
    let mut fs = Fs::new(RamStorage::new());
    let (sw, _) = run(&mut app, &mut fs, &lock_apdu());
    assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);
    assert_eq!(platform.borrow().lock_writes, 0, "no burn without presence");

    // ROLLBACK_REQUIRED: secure boot on, not yet fused, presence denied.
    let platform = RefCell::new(secure_platform());
    let presence = RefCell::new(DenyPresence);
    let mut app = RescueApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        Some(test_mkek as FusedKey),
        None,
        &rng,
        &platform,
        &presence,
        KV_TOTAL,
        FLASH_SIZE,
    );
    let mut fs = Fs::new(RamStorage::new());
    let (sw, _) = run(&mut app, &mut fs, &rollback_apdu());
    assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);
    assert_eq!(
        platform.borrow().rollback_writes,
        0,
        "no burn without presence"
    );
}
