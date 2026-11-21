// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn all_slot_migrations_preserve_counter_tails_when_both_migration_boots_are_cut() {
    let otp = [0x55; 32];
    let current = Device {
        otp_key: Some(&otp),
        ..device()
    };
    for plaintext in [false, true] {
        let (mut baseline, _) = empty();
        let mut expected = Vec::new();
        for (i, fid) in (EF_OTP_SLOT1..=EF_OTP_SLOT_LAST).enumerate() {
            plant(&mut baseline, fid, u8::try_from(i + 3).unwrap());
            expected.push(plain(&mut baseline, fid).unwrap());
        }
        assert!(sweep_restarts(
            || {
                let (mut fs, medium) = empty();
                for (fid, raw) in (EF_OTP_SLOT1..=EF_OTP_SLOT_LAST).zip(&expected) {
                    if plaintext {
                        fs.put_key(KeyFid::new(fid), rsk_fs::Sealed::wrap(raw))
                            .unwrap();
                    } else {
                        assert!(seal::seal_put(
                            &device(),
                            &mut fs,
                            &mut CountRng(7),
                            KeyFid::new(fid),
                            &SlotRecord::from_bytes(raw).unwrap()
                        ));
                    }
                }
                fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
                (fs, medium)
            },
            |fs| !migrate_seal(&current, fs, &mut CountRng(7)),
            |fs| {
                migrate_seal(&current, fs, &mut CountRng(91));
            },
            |fs, _, _, _, medium| {
                for (fid, wanted) in (EF_OTP_SLOT1..=EF_OTP_SLOT_LAST).zip(&expected) {
                    let mut rec = SlotRecord::vacant();
                    assert_eq!(rec.try_read(&current, fs, fid).unwrap(), Some(wanted.len()));
                    assert_eq!(rec.stored(), wanted);
                }
                assert!(!fs.has_data(rsk_fs::EF_HARDENED));
                let generation = fs.write_gen();
                assert!(!migrate_seal(&current, fs, &mut CountRng(200)));
                assert_eq!(fs.write_gen(), generation);
                retained(fs, medium);
            }
        ));
    }
}

#[test]
fn an_in_cycle_session_wrap_persists_before_issuing_its_ticket() {
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let app = RefCell::new(None);
    let typed = std::cell::Cell::new(None);
    let provision = || {
        let (mut fs, medium) = empty();
        let cfg = build_config(b"public", &[1; 6], &[0xA1; 16], &CODE, 0, 0, 0);
        assert_eq!(send(&mut fs, &otp_apdu(P1_CONFIG_SLOT1, 0, &cfg)), Sw::OK);
        let mut session = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &touch);
        for _ in 0..255 {
            assert!(press_position(&mut session, &mut fs, 1, &[0xA1; 16]).is_some());
        }
        *app.borrow_mut() = Some(session);
        (fs, medium)
    };
    let (mut reference, _) = provision();
    let before = plain(&mut reference, EF_OTP_SLOT1).unwrap();
    assert_eq!(
        press_position(
            app.borrow_mut().as_mut().unwrap(),
            &mut reference,
            1,
            &[0xA1; 16]
        ),
        Some((*b"public", 1, 255))
    );
    let after = plain(&mut reference, EF_OTP_SLOT1).unwrap();
    assert!(!sweep_restarts(
        provision,
        |fs| {
            let out = press_position(app.borrow_mut().as_mut().unwrap(), fs, 1, &[0xA1; 16]);
            typed.set(out);
            out.is_some()
        },
        boot,
        |fs, _, _, completed, medium| {
            let stored = plain(fs, EF_OTP_SLOT1).unwrap();
            assert!(stored == before || stored == after);
            if completed {
                assert_eq!(typed.get(), Some((*b"public", 1, 255)));
                assert_eq!(stored, after);
            } else {
                assert!(typed.get().is_none());
            }
            retained(fs, medium);
        }
    ));
}

#[test]
#[cfg(not(feature = "strict-config"))]
fn the_otp_device_info_command_persists_its_whole_configuration_through_both_boots() {
    let before = [0x03, 0x02, 0x00, 0x10];
    let after = [0x04, 0x03, 0x02, 0x00, 0x02];
    let raw = otp_apdu(P1_SET_DEVICE_INFO, 0, &after);
    let (mut reference, medium) = empty();
    reference
        .put(rsk_devconf::raw::EF_DEV_CONF, &before)
        .unwrap();
    assert_eq!(send(&mut reference, &raw), Sw::OK);
    let expected = medium.value(rsk_devconf::raw::EF_DEV_CONF).unwrap();
    assert_ne!(expected, before);
    assert!(!sweep_restarts(
        || {
            let (mut fs, medium) = empty();
            fs.put(rsk_devconf::raw::EF_DEV_CONF, &before).unwrap();
            (fs, medium)
        },
        |fs| send(fs, &raw) == Sw::OK,
        boot,
        |fs, _, _, completed, medium| {
            let actual = medium.value(rsk_devconf::raw::EF_DEV_CONF).unwrap();
            assert!(actual == before || actual == expected);
            if completed {
                assert_eq!(actual, expected);
            }
            retained(fs, medium);
        }
    ));
}
