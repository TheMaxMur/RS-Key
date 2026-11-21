// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;

#[test]
fn legacy_and_pre_otp_device_keys_keep_their_scalar_across_interrupted_migration() {
    for legacy in [false, true] {
        for old_root in [false, true] {
            if !legacy && !old_root {
                continue;
            }
            assert!(sweep_restarts(
                || {
                    let (storage, medium) = Cut::new();
                    let mut fs = Fs::new(storage);
                    fs.scan();
                    let arm = if old_root { dev() } else { otp_dev() };
                    if legacy {
                        let mut cipher = [0x11; 32];
                        let mut iv = [0; 16];
                        iv.copy_from_slice(&arm.serial_hash[..16]);
                        let key = arm.derive_kbase();
                        aes_encrypt(key.expose(), &iv, Mode::Cbc, &mut cipher).unwrap();
                        let record = if old_root {
                            cipher.to_vec()
                        } else {
                            [&[TAG_OTP][..], &cipher].concat()
                        };
                        fs.put_key(EF_DEVCERT_KEY, Sealed::wrap(&record)).unwrap();
                    } else {
                        fs.put_key(
                            EF_DEVCERT_KEY,
                            Sealed::wrap(&seal_gcm(&arm, &mut LcgRng(7), &[0x11; 32])),
                        )
                        .unwrap();
                    }
                    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
                    fs.put(0xB000, b"another applet").unwrap();
                    (fs, medium)
                },
                |fs| !migrate_kbase(&otp_dev(), fs, &mut LcgRng(91)),
                |fs| {
                    let _ = migrate_kbase(&otp_dev(), fs, &mut LcgRng(91));
                },
                |fs, _, _, _, medium| {
                    assert_eq!(
                        load_or_generate(&otp_dev(), None, fs, &mut LcgRng(7))
                            .unwrap()
                            .to_bytes()
                            .as_slice(),
                        &[0x11; 32]
                    );
                    assert_eq!(fs.size(EF_DEVCERT_KEY.get()), Some(GCM_LEN));
                    if old_root {
                        assert!(!fs.has_data(rsk_fs::EF_HARDENED));
                    }
                    let generation = fs.write_gen();
                    assert!(!migrate_kbase(&otp_dev(), fs, &mut LcgRng(7)));
                    assert_eq!(fs.write_gen(), generation);
                    assert_eq!(
                        medium.value(0xB000).as_deref(),
                        Some(&b"another applet"[..])
                    );
                }
            ));
        }
    }
}
