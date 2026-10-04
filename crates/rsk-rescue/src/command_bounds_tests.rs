// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::Sealed;
use rsk_fs::storage::faults::Cut;

#[test]
fn malformed_commands_do_not_write_or_request_a_reboot() {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform::default());
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = lock_app(&rng, &platform, &presence, None);
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let before = fs.write_gen();
    for (ins, p1, p2, data, want) in [
        (INS_KEYDEV_SIGN, 1, 0, &b"short"[..], Sw::WRONG_LENGTH),
        (INS_KEYDEV_SIGN, 2, 0, &b"body"[..], Sw::WRONG_LENGTH),
        (INS_KEYDEV_SIGN, 3, 0, &b""[..], Sw::WRONG_LENGTH),
        (INS_KEYDEV_SIGN, 0xff, 0, &b""[..], Sw::INCORRECT_P1P2),
        (INS_WRITE, 1, 0, &b"x"[..], Sw::WRONG_LENGTH),
        (INS_WRITE, 2, 1, &b"short"[..], Sw::WRONG_LENGTH),
        (INS_WRITE, 2, 2, &b"short"[..], Sw::WRONG_LENGTH),
        (INS_WRITE, 2, 3, &b"body"[..], Sw::INCORRECT_P1P2),
        (INS_READ, 3, 0, &b"body"[..], Sw::WRONG_LENGTH),
        (INS_READ, 4, 3, &b""[..], Sw::INCORRECT_P1P2),
        (INS_REBOOT_BOOTSEL, 0, 0, &b"body"[..], Sw::WRONG_LENGTH),
    ] {
        assert_eq!(
            run(&mut app, &mut fs, &apdu(0x80, ins, p1, p2, data)),
            (want, Vec::new()),
            "ins {ins:#04x}, p1 {p1}, p2 {p2}"
        );
    }
    assert_eq!(fs.write_gen(), before);
    let platform = platform.borrow();
    assert_eq!(platform.time, None);
    assert!(platform.reboots.is_empty());
}

#[test]
fn keydev_rejects_a_corrupt_key_for_both_public_read_and_sign() {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform::default());
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = lock_app(&rng, &platform, &presence, None);
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let bad = [0xff; 17];
    fs.put_key(keydev::EF_DEVCERT_KEY, Sealed::wrap(&bad))
        .unwrap();
    let before = fs.write_gen();
    for (p1, data) in [(1, &[0x42; 32][..]), (2, &[][..])] {
        assert_eq!(
            run(&mut app, &mut fs, &apdu(0x80, INS_KEYDEV_SIGN, p1, 0, data)),
            (Sw::EXEC_ERROR, Vec::new())
        );
    }
    assert_eq!(fs.write_gen(), before);
    let mut stored = [0; 17];
    assert_eq!(fs.read_key(keydev::EF_DEVCERT_KEY, &mut stored), Some(17));
    assert_eq!(stored, bad);
}

#[test]
fn refused_certificate_and_phy_writes_preserve_the_previous_records() {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform::default());
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = lock_app(&rng, &platform, &presence, None);
    let (backend, medium) = Cut::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    fs.put(keydev::EF_DEVCERT, b"certificate").unwrap();
    let owner = rsk_phy::PhyData {
        vid_pid: Some((0x1234, 0x5678)),
        ..Default::default()
    };
    rsk_phy::save(&mut fs, &owner).unwrap();
    let expected = rsk_phy::try_load(&mut fs).unwrap();
    let old_cert = medium.value(keydev::EF_DEVCERT);
    let old_phy = medium.value(rsk_phy::EF_PHY);
    medium.arm(0);
    for (ins, p1, data, want) in [
        (INS_KEYDEV_SIGN, 3, &b"replacement"[..], Sw::MEMORY_FAILURE),
        (INS_WRITE, 1, &[0, 0][..], Sw::EXEC_ERROR),
    ] {
        assert_eq!(
            run(&mut app, &mut fs, &apdu(0x80, ins, p1, 0, data)),
            (want, Vec::new())
        );
    }
    assert_eq!(medium.value(keydev::EF_DEVCERT), old_cert);
    assert_eq!(medium.value(rsk_phy::EF_PHY), old_phy);
    medium.arm(u32::MAX);
    assert_eq!(rsk_phy::try_load(&mut fs), Ok(expected));
}

struct FailedBurn {
    succeeds: bool,
    writes: u32,
    readback: bool,
}

impl Platform for FailedBurn {
    fn secure_boot_status(&self) -> SecureBootStatus {
        SecureBootStatus {
            enabled: true,
            locked: true,
            bootkey: 0,
        }
    }
    fn now(&self) -> Option<u32> {
        None
    }
    fn set_time(&mut self, _: u32) {}
    fn request_reboot(&mut self, _: bool) {}
    fn read_page58_lock_raw(&self) -> Option<u32> {
        self.readback.then_some(0)
    }
    fn pre_otp_left(&self) -> Option<u16> {
        Some(0)
    }
    fn lock_page58(&mut self) -> bool {
        self.writes += 1;
        self.readback = false;
        self.succeeds
    }
    fn read_rollback_raw(&self) -> Option<rollback::RollbackRaw> {
        self.readback.then_some(rollback::RollbackRaw {
            flags0: [0; 3],
            version0: [0; 3],
            version1: [0; 3],
        })
    }
    fn set_rollback_required(&mut self) -> bool {
        self.writes += 1;
        self.readback = false;
        self.succeeds
    }
}

#[test]
fn failed_burns_and_failed_readbacks_never_report_success() {
    for succeeds in [false, true] {
        for (p1, data) in [(0x58, OTP_LOCK_MAGIC), (0x48, ROLLBACK_MAGIC)] {
            let rng = RefCell::new(LcgRng(7));
            let platform = RefCell::new(FailedBurn {
                succeeds,
                writes: 0,
                readback: true,
            });
            let presence = RefCell::new(AlwaysConfirm);
            let mut app = RescueApplet::new(
                SERIAL_ID,
                SERIAL_HASH,
                Some(FusedKey::open(test_mkek)),
                None,
                &rng,
                &platform,
                &presence,
                KV_TOTAL,
                FLASH_SIZE,
            );
            let mut fs = Fs::new(RamStorage::new());
            assert_eq!(
                run(&mut app, &mut fs, &apdu(0x80, INS_OTP_LOCK, p1, 0, data)),
                (Sw::EXEC_ERROR, Vec::new()),
                "p1 {p1:#04x}, write succeeded {succeeds}"
            );
            assert_eq!(platform.borrow().writes, 1);
        }
    }
}

#[test]
fn unreadable_rollback_state_has_no_response_body() {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform {
        rollback_raw: None,
        ..Default::default()
    });
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = lock_app(&rng, &platform, &presence, None);
    let mut fs = Fs::new(RamStorage::new());
    assert_eq!(
        run(&mut app, &mut fs, &apdu(0x80, INS_READ, 6, 0, &[])),
        (Sw::EXEC_ERROR, Vec::new())
    );
    assert_eq!(platform.borrow().rollback_writes, 0);
}
