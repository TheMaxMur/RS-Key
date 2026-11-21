// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;

#[test]
fn an_otp_rooted_pin_wrap_moves_without_rearming_the_completed_scrub() {
    let migrate = |fs: &mut Fs<Cut>| migrate_keydev_pin(&otp_dev(), fs, &[0x99; 16]).is_ok();
    assert!(sweep_restarts(
        || {
            let (storage, medium) = Cut::new();
            let mut fs = Fs::new(storage);
            fs.scan();
            wrap_keydev_legacy(&otp_dev(), &mut fs, &[0x11; 32], &[0x99; 16]);
            fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
            (fs, medium)
        },
        migrate,
        |fs| {
            let _ = migrate(fs);
        },
        |fs, _, _, _, medium| {
            assert_eq!(load_keydev(&otp_dev(), fs).unwrap().expose(), &[0x11; 32]);
            assert_eq!(medium.value(EF_KEY_DEV.get()).unwrap()[0], FORMAT_G1_OTP);
            assert!(fs.has_data(rsk_fs::EF_HARDENED));
            let generation = fs.write_gen();
            assert!(migrate(fs));
            assert_eq!(generation, fs.write_gen());
        }
    ));
}

#[test]
fn all_boot_migrated_seed_slots_and_pin_wrapped_seed_keep_identity_after_two_cuts() {
    for legacy in [false, true] {
        for pin_wrapped in [false, true] {
            let repair = |fs: &mut Fs<Cut>| -> bool {
                if pin_wrapped {
                    migrate_keydev_pin(&otp_dev(), fs, &[0x99; 16]).is_ok()
                } else {
                    migrate_keydev_boot(&otp_dev(), fs).is_ok()
                }
            };
            assert!(sweep_restarts(
                || {
                    let (storage, medium) = Cut::new();
                    let mut fs = Fs::new(storage);
                    fs.scan();
                    for (fid, value) in [
                        (EF_KEY_DEV, [0x11; 32]),
                        (EF_ATT_KEY, [0x33; 32]),
                        (EF_PAUTHTOKEN, [0x55; 32]),
                    ] {
                        if fid == EF_KEY_DEV && pin_wrapped {
                            wrap_keydev_legacy(&dev(), &mut fs, &value, &[0x99; 16]);
                        } else if legacy {
                            write_legacy_cbc(&dev(), &mut fs, fid, &value);
                        } else {
                            put_sealed32(&dev(), &mut fs, fid, &value, None).unwrap();
                        }
                    }
                    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
                    fs.put(0xB000, b"another applet").unwrap();
                    (fs, medium)
                },
                repair,
                |fs| {
                    let _ = repair(fs);
                    let _ = migrate_keydev_boot(&otp_dev(), fs);
                },
                |fs, _, _, _, medium| {
                    assert_eq!(load_keydev(&otp_dev(), fs).unwrap().expose(), &[0x11; 32]);
                    assert_eq!(load_att_key(&otp_dev(), fs).unwrap().expose(), &[0x33; 32]);
                    assert_eq!(load_ppuat(&otp_dev(), fs).unwrap().expose(), &[0x55; 32]);
                    for fid in [EF_KEY_DEV, EF_ATT_KEY, EF_PAUTHTOKEN] {
                        assert_eq!(medium.value(fid.get()).unwrap()[0], FORMAT_G1_OTP);
                    }
                    assert!(!fs.has_data(rsk_fs::EF_HARDENED));
                    let generation = fs.write_gen();
                    assert_eq!(migrate_keydev_boot(&otp_dev(), fs), Ok(false));
                    migrate_keydev_pin(&otp_dev(), fs, &[0x99; 16]).unwrap();
                    assert_eq!(generation, fs.write_gen());
                    assert_eq!(
                        medium.value(0xB000).as_deref(),
                        Some(&b"another applet"[..])
                    );
                }
            ));
        }
    }
}
