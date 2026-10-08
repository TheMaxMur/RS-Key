// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn legacy_credentials_retain_their_plaintext_when_migration_and_its_next_boot_are_cut() {
    let otp = [0x55; 32];
    let current = Device {
        otp_key: Some(&otp),
        ..device()
    };
    let (mut baseline, _) = fixture(0x11);
    let expected = plain(&mut baseline, EF_OATH_CRED).unwrap();
    for plaintext in [false, true] {
        assert!(sweep_restarts(
            || {
                let (mut fs, medium) = new_cut_fs();
                fs.put(NEIGHBOR, b"another applet").unwrap();
                if plaintext {
                    fs.put_key(KeyFid::new(EF_OATH_CRED), rsk_fs::Sealed::wrap(&expected))
                        .unwrap();
                } else {
                    assert!(seal::seal_put(
                        &device(),
                        &mut fs,
                        &mut CountRng(7),
                        KeyFid::new(EF_OATH_CRED),
                        &expected
                    ));
                }
                fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
                (fs, medium)
            },
            |fs| !migrate_seal(&current, fs, &mut CountRng(7)),
            |fs| {
                migrate_seal(&current, fs, &mut CountRng(91));
            },
            |fs, _, _, _, medium| {
                let mut decoded = Secret::<[u8; CRED_MAX]>::zeroed();
                let n =
                    seal::seal_read(&current, fs, KeyFid::new(EF_OATH_CRED), &mut decoded).unwrap();
                assert_eq!(&decoded.expose()[..n], expected);
                assert!(!fs.has_data(rsk_fs::EF_HARDENED));
                let generation = fs.write_gen();
                assert!(!migrate_seal(&current, fs, &mut CountRng(200)));
                assert_eq!(fs.write_gen(), generation);
                assert_eq!(
                    medium.value(NEIGHBOR).as_deref(),
                    Some(&b"another applet"[..])
                );
            }
        ));
    }
}

#[test]
fn creating_a_credential_leaves_absence_or_the_entire_new_secret_after_two_boots() {
    let raw = apdu(
        INS_PUT,
        0,
        0,
        &put_data(b"created", 0x11, 6, SECRET_SHA1, false, Some(73)),
    );
    let provision = || {
        let (mut fs, medium) = new_cut_fs();
        fs.put(NEIGHBOR, b"another applet").unwrap();
        (fs, medium)
    };
    let (mut reference, _) = provision();
    assert_eq!(send(&mut reference, &raw).0, Sw::OK);
    let after = plain(&mut reference, EF_OATH_CRED).unwrap();
    assert!(!sweep_restarts(
        provision,
        |fs| send(fs, &raw).0 == Sw::OK,
        boot,
        |fs, _, _, completed, medium| {
            let actual = plain(fs, EF_OATH_CRED);
            assert!(actual.is_none() || actual.as_ref() == Some(&after));
            if completed {
                assert_eq!(actual.as_ref(), Some(&after));
            }
            assert_eq!(
                medium.value(NEIGHBOR).as_deref(),
                Some(&b"another applet"[..])
            );
        }
    ));
}

#[test]
fn bulk_increasing_updates_keep_a_committed_prefix_across_both_boots() {
    for p2 in [0, 1] {
        let provision = || {
            let (mut fs, medium) = new_cut_fs();
            let rng = RefCell::new(CountRng(7));
            let touch = RefCell::new(AlwaysConfirm);
            let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
            select(&mut app, &mut fs);
            for name in [b"a", b"b", b"c"] {
                let mut body = put_data(name, 0x21, 6, SECRET_SHA1, false, None);
                body.extend([TAG_PROPERTY, PROP_INCREASING]);
                assert_eq!(put(&mut app, &mut fs, &body), Sw::OK);
            }
            assert_eq!(
                put(
                    &mut app,
                    &mut fs,
                    &put_data(b"hotp", 0x11, 6, SECRET_SHA1, false, Some(73))
                ),
                Sw::OK
            );
            assert_eq!(
                put(
                    &mut app,
                    &mut fs,
                    &put_data(b"touch", 0x21, 6, SECRET_SHA1, true, None)
                ),
                Sw::OK
            );
            (fs, medium)
        };
        let raw = apdu(
            INS_CALC_ALL,
            0,
            p2,
            &tlv(TAG_CHALLENGE, &1u64.to_be_bytes()),
        );
        let (mut reference, _) = provision();
        let before: Vec<_> = (0..5)
            .map(|i| plain(&mut reference, EF_OATH_CRED + i).unwrap())
            .collect();
        assert_eq!(send(&mut reference, &raw).0, Sw::OK);
        let after: Vec<_> = (0..5)
            .map(|i| plain(&mut reference, EF_OATH_CRED + i).unwrap())
            .collect();
        assert_eq!(&after[3..], &before[3..]);
        assert!(!sweep_restarts(
            provision,
            |fs| send(fs, &raw).0 == Sw::OK,
            boot,
            |fs, _, _, completed, _| {
                let mut stopped = false;
                for i in 0..3 {
                    let actual = plain(fs, EF_OATH_CRED + u16::try_from(i).unwrap()).unwrap();
                    assert!(actual == before[i] || actual == after[i]);
                    if actual == before[i] {
                        stopped = true;
                    } else {
                        assert!(!stopped, "a later mark landed beyond the torn prefix");
                    }
                    if completed {
                        assert_eq!(actual, after[i]);
                    }
                }
                for (i, wanted) in before.iter().enumerate().skip(3) {
                    assert_eq!(
                        plain(fs, EF_OATH_CRED + u16::try_from(i).unwrap()).as_ref(),
                        Some(wanted)
                    );
                }
            }
        ));
    }
}

#[test]
fn legacy_pin_upgrade_and_wrong_attempts_preserve_verifier_identity_without_boot_retries() {
    let current = Device {
        otp_key: Some(&TEST_MKEK),
        ..device()
    };
    for legacy in [false, true] {
        for correct in [false, true] {
            let old = if legacy {
                [
                    &[MAX_OTP_COUNTER][..],
                    device().double_hash_pin(b"1234").expose(),
                ]
                .concat()
            } else {
                OathApplet::otp_pin_record_v1(&device(), b"1234").to_vec()
            };
            let new = OathApplet::otp_pin_record_v1(&current, b"1234");
            let request = apdu(
                INS_VERIFY_PIN,
                0,
                0,
                &tlv(TAG_PASSWORD, if correct { b"1234" } else { b"9999" }),
            );
            assert!(!sweep_restarts(
                || {
                    let (mut fs, medium) = new_cut_fs();
                    fs.put(EF_OTP_PIN, &old).unwrap();
                    fs.put(NEIGHBOR, b"another applet").unwrap();
                    (fs, medium)
                },
                |fs| {
                    let rng = RefCell::new(CountRng(7));
                    let touch = RefCell::new(AlwaysConfirm);
                    let mut app = OathApplet::new(
                        SERIAL,
                        [0x22; 32],
                        Some(rsk_crypto::FusedKey::open(test_mkek)),
                        &rng,
                        &touch,
                    );
                    select(&mut app, fs);
                    run(&mut app, fs, &request).0
                        == if correct {
                            Sw::OK
                        } else {
                            Sw::SECURITY_STATUS_NOT_SATISFIED
                        }
                },
                |fs| {
                    migrate_seal(&current, fs, &mut CountRng(91));
                },
                |fs, _, _, _, medium| {
                    let actual = medium.value(EF_OTP_PIN).unwrap();
                    assert!(actual[1..] == old[1..] || actual[1..] == new[1..]);
                    assert!((MAX_OTP_COUNTER - 1..=MAX_OTP_COUNTER).contains(&actual[0]));
                    assert!(OathApplet::otp_pin_matches(&current, &actual, b"1234"));
                    assert!(!OathApplet::otp_pin_matches(&current, &actual, b"9999"));
                    assert_eq!(
                        medium.value(NEIGHBOR).as_deref(),
                        Some(&b"another applet"[..])
                    );
                    assert!(fs.has_data(EF_OTP_PIN));
                }
            ));
        }
    }
}
