// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn all_initial_piv_records_finish_after_two_interrupted_select_passes() {
    assert!(sweep_restarts(
        || {
            let (mut fs, medium) = new_cut_fs();
            fs.put(NEIGHBOR, b"another applet").unwrap();
            fs.meta_add(NEIGHBOR, b"metadata").unwrap();
            (fs, medium)
        },
        |fs| files::scan_files(&device(), fs, &mut TestRng(7)).is_ok_and(|landed| landed),
        boot,
        |fs, _, _, _, medium| {
            let mut retry = [0; 4];
            assert_eq!(fs.read(EF_RETRIES, &mut retry), Some(4));
            assert_eq!(retry, [DEFAULT_RETRIES; 4]);
            let mut puk = [0; PIN_REC_LEN];
            assert_eq!(fs.read(EF_PUK, &mut puk), Some(PIN_REC_LEN));
            assert_eq!(
                &puk[2..],
                device().pin_derive_verifier(&DEFAULT_PUK).expose()
            );
            let rng = RefCell::new(TestRng(9));
            let touch = RefCell::new(AlwaysConfirm);
            let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &touch);
            select(&mut app, fs);
            auth_mgm(&mut app, fs);
            verify_pin(&mut app, fs);
            let key = seal::load_ec_key(&device(), fs, key_fid(SLOT_ATTESTATION)).unwrap();
            let mut public = [0; MAX_EC_POINT];
            let n = key.public_point(&mut public).unwrap();
            let cert = medium.value(EF_ATTESTATION_CERT).unwrap();
            assert_eq!(x509::attestation_point(&cert), Some(&public[..n]));
            let generation = fs.write_gen();
            assert_eq!(files::scan_files(&device(), fs, &mut TestRng(91)), Ok(true));
            assert_eq!(fs.write_gen(), generation);
            retained(fs, medium);
        }
    ));
}

#[test]
fn legacy_management_key_heads_are_repaired_after_both_boots_are_cut() {
    assert!(sweep_restarts(
        || {
            let (mut fs, medium) = fixture();
            seal::seal_put(
                &device(),
                &mut fs,
                &mut TestRng(7),
                key_fid(SLOT_CARDMGM),
                &DEFAULT_MGM,
            )
            .unwrap();
            fs.meta_delete(key_fid(SLOT_CARDMGM).get()).unwrap();
            (fs, medium)
        },
        |fs| files::scan_files(&device(), fs, &mut TestRng(7)).is_ok_and(|landed| landed),
        boot,
        |fs, _, _, _, medium| {
            let key = files::mgm_read(&device(), fs).unwrap();
            assert_eq!(key.key(), &DEFAULT_MGM);
            let mut head = [0; 3];
            assert_eq!(
                fs.meta_find(key_fid(SLOT_CARDMGM).get(), &mut head),
                Some(3)
            );
            assert_eq!(head, [ALGO_AES192, MGM_PIN_POLICY, TOUCHPOLICY_NEVER]);
            let rng = RefCell::new(TestRng(9));
            let touch = RefCell::new(AlwaysConfirm);
            let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &touch);
            select(&mut app, fs);
            auth_mgm(&mut app, fs);
            retained(fs, medium);
        }
    ));
}

#[test]
fn owner_replay_of_pin_protection_keeps_its_touch_policy_and_admin_data() {
    let before = [0x80, 0x09, 0x81, 1, 0x40, 0x83, 4, 1, 2, 3, 4];
    assert!(sweep_restarts(
        || {
            let (mut fs, medium) = fixture();
            files::mgm_put(
                &device(),
                &mut fs,
                &mut TestRng(7),
                ALGO_AES192,
                TOUCHPOLICY_ALWAYS,
                &DEFAULT_MGM,
            )
            .unwrap();
            fs.put(EF_PIVMAN_DATA, &before).unwrap();
            (fs, medium)
        },
        |fs| protect_mgm_key(&device(), fs, &mut TestRng(7)) == Sw::OK,
        |fs| {
            boot(fs);
            if mgm_is_protected(fs) {
                assert_eq!(
                    files::mgm_read(&device(), fs).unwrap().policy,
                    Some((ALGO_AES256, TOUCHPOLICY_ALWAYS)),
                    "the protection flag preceded its key"
                );
            }
            let _ = protect_mgm_key(&device(), fs, &mut TestRng(91));
        },
        |fs, _, _, _, medium| {
            assert!(mgm_is_protected(fs));
            let key = files::mgm_read(&device(), fs).unwrap();
            assert_eq!(key.policy, Some((ALGO_AES256, TOUCHPOLICY_ALWAYS)));
            let record = medium.value(EF_PIVMAN_DATA).unwrap();
            let fields = pivman_inner(&record);
            assert_eq!(find_tag(fields, 0x83), Some(&[1, 2, 3, 4][..]));
            assert_eq!(
                find_tag(fields, PIVMAN_FLAGS_TAG.into()).unwrap()[0] & 0x40,
                0x40
            );
            retained(fs, medium);
        }
    ));
}

#[test]
fn a_reset_and_its_owner_retry_cannot_expose_surviving_keys_under_factory_gates() {
    const OWNER_PIN: &[u8] = b"87654321";
    const OWNER_PUK: &[u8] = b"ABCDEFGH";
    const OWNER_MGM: &[u8; 32] = &[0x5A; 32];
    let inspect = |fs: &mut Fs<Cut>| {
        if fs.has_key(key_fid(SLOT_AUTHENTICATION)) {
            let mut pin = [0; PIN_REC_LEN];
            fs.read(EF_PIN, &mut pin).unwrap();
            assert_eq!(&pin[2..], device().pin_derive_verifier(OWNER_PIN).expose());
            let mut puk = [0; PIN_REC_LEN];
            fs.read(EF_PUK, &mut puk).unwrap();
            assert_eq!(&puk[2..], device().pin_derive_verifier(OWNER_PUK).expose());
            assert_eq!(files::mgm_read(&device(), fs).unwrap().key(), OWNER_MGM);
            assert_eq!(retries_left(fs, RETRY_PIN), Ok(0));
            assert_eq!(retries_left(fs, RETRY_PUK), Ok(0));
        }
    };
    assert!(sweep_restarts(
        || {
            let (mut fs, medium) = fixture();
            files::put_pin_verifier(&device(), &mut fs, EF_PIN, OWNER_PIN, None).unwrap();
            files::put_pin_verifier(&device(), &mut fs, EF_PUK, OWNER_PUK, None).unwrap();
            files::mgm_put(
                &device(),
                &mut fs,
                &mut TestRng(7),
                ALGO_AES256,
                TOUCHPOLICY_ALWAYS,
                OWNER_MGM,
            )
            .unwrap();
            let key = PrivKey::from_scalar(Curve::P256, &[0x33; 32]).unwrap();
            seal::store_ec_key(
                &device(),
                &mut fs,
                &mut TestRng(7),
                key_fid(SLOT_AUTHENTICATION),
                &key,
            )
            .unwrap();
            fs.put(EF_RETRIES, &[3, 0, 3, 0]).unwrap();
            fs.put(
                cert_fid_for_slot(SLOT_AUTHENTICATION).unwrap(),
                b"owner certificate",
            )
            .unwrap();
            (fs, medium)
        },
        |fs| send(fs, INS_RESET, 0, 0, &[], false) == Sw::OK,
        |fs| {
            if files::scan_files(&device(), fs, &mut TestRng(91)).is_err() {
                return;
            }
            inspect(fs);
            let rng = RefCell::new(TestRng(9));
            let touch = RefCell::new(AlwaysConfirm);
            let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &touch);
            select(&mut app, fs);
            for reference in [REF_PIN, REF_PUK] {
                let retry = if reference == REF_PIN {
                    RETRY_PIN
                } else {
                    RETRY_PUK
                };
                for _ in 0..3 {
                    if retries_left(fs, retry) == Ok(0) {
                        break;
                    }
                    let sw = if reference == REF_PIN {
                        run(&mut app, fs, INS_VERIFY, 0, reference, b"00000000").0
                    } else {
                        run(
                            &mut app,
                            fs,
                            INS_CHANGE_PIN,
                            0,
                            reference,
                            &[b"00000000".as_slice(), OWNER_PUK].concat(),
                        )
                        .0
                    };
                    if sw == Sw::MEMORY_FAILURE {
                        return;
                    }
                }
            }
            let _ = run(&mut app, fs, INS_RESET, 0, 0, &[]);
        },
        |fs, _, _, _, medium| {
            assert!(!fs.has_key(key_fid(SLOT_AUTHENTICATION)));
            assert!(!fs.has_data(cert_fid_for_slot(SLOT_AUTHENTICATION).unwrap()));
            let rng = RefCell::new(TestRng(9));
            let touch = RefCell::new(AlwaysConfirm);
            let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &touch);
            select(&mut app, fs);
            auth_mgm(&mut app, fs);
            verify_pin(&mut app, fs);
            retained(fs, medium);
        }
    ));
}

#[test]
fn rsa_persistence_and_import_keep_headless_survivors_blocked_through_two_boots() {
    let (p, q, expected) = if cfg!(feature = "fips-profile") {
        (
            rsk_rsa::vectors::hex(rsk_rsa::vectors::P_HEX),
            rsk_rsa::vectors::hex(rsk_rsa::vectors::Q_HEX),
            rsk_rsa::vectors::hex(rsk_rsa::vectors::N_HEX),
        )
    } else {
        (
            rsk_rsa::vectors::hex(rsk_rsa::vectors::P1024_HEX),
            rsk_rsa::vectors::hex(rsk_rsa::vectors::Q1024_HEX),
            rsk_rsa::vectors::hex(rsk_rsa::vectors::N1024_HEX),
        )
    };
    let key = rsk_rsa::rsa_from_pqe(rsk_rsa::RSA_PUB_EXP_BE, &p, &q).unwrap();
    let mut import = Vec::new();
    for (tag, bytes) in [(1, &p[..]), (2, &q[..])] {
        import.push(tag);
        let mut length = [0; 3];
        let n = format_len(u16::try_from(bytes.len()).unwrap(), &mut length);
        import.extend_from_slice(&length[..n]);
        import.extend(bytes);
    }
    for imported in [false, true] {
        let provision = || {
            let (mut fs, medium) = fixture();
            let old = PrivKey::from_scalar(Curve::P256, &[0x11; 32]).unwrap();
            seal::store_ec_key(
                &device(),
                &mut fs,
                &mut TestRng(7),
                key_fid(SLOT_AUTHENTICATION),
                &old,
            )
            .unwrap();
            fs.meta_add(
                key_fid(SLOT_AUTHENTICATION).get(),
                &[
                    ALGO_ECCP256,
                    PINPOLICY_ALWAYS,
                    TOUCHPOLICY_ALWAYS,
                    ORIGIN_GENERATED,
                ],
            )
            .unwrap();
            let mut point = [0; MAX_EC_POINT];
            let n = old.public_point(&mut point).unwrap();
            fs.put(pubkey_fid(SLOT_AUTHENTICATION), &point[..n])
                .unwrap();
            fs.put(
                cert_fid_for_slot(SLOT_AUTHENTICATION).unwrap(),
                b"owner certificate",
            )
            .unwrap();
            (fs, medium)
        };
        let (_, baseline) = provision();
        let old = baseline.value(key_fid(SLOT_AUTHENTICATION).get()).unwrap();
        assert!(!sweep_restarts(
            provision,
            |fs| {
                if imported {
                    send(
                        fs,
                        INS_IMPORT_ASYM,
                        ALGO_RSA_FIXTURE,
                        SLOT_AUTHENTICATION,
                        &import,
                        true,
                    ) == Sw::OK
                } else {
                    let rng = RefCell::new(TestRng(7));
                    let touch = RefCell::new(AlwaysConfirm);
                    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &touch);
                    app.rsa_generate_finish(
                        fs,
                        &mut TestRng(7),
                        SLOT_AUTHENTICATION,
                        [PINPOLICY_ONCE, TOUCHPOLICY_NEVER],
                        &key,
                        &mut [0; rsk_rsa::MAX_RSA_PUBDO],
                    )
                    .1 == Sw::OK
                }
            },
            boot,
            |fs, _, _, completed, medium| {
                let actual = medium.value(key_fid(SLOT_AUTHENTICATION).get()).unwrap();
                let mut head = [0; 4];
                let headed = fs
                    .meta_find(key_fid(SLOT_AUTHENTICATION).get(), &mut head)
                    .is_some();
                if actual != old {
                    let mut modulus = [0; rsk_rsa::MAX_RSA_BYTES];
                    let n = seal::load_rsa_modulus(
                        &device(),
                        fs,
                        key_fid(SLOT_AUTHENTICATION),
                        &mut modulus,
                    )
                    .unwrap();
                    assert_eq!(&modulus[..n], expected);
                    assert!(medium.value(pubkey_fid(SLOT_AUTHENTICATION)).is_none());
                    if headed {
                        assert_eq!(head[0], ALGO_RSA_FIXTURE);
                        assert_eq!(head[1], PINPOLICY_ONCE);
                        assert_eq!(head[2], TOUCHPOLICY_NEVER);
                        assert_eq!(
                            head[3],
                            if imported {
                                ORIGIN_IMPORTED
                            } else {
                                ORIGIN_GENERATED
                            }
                        );
                    }
                }
                if !headed {
                    let request = [&[0x7C, 0x24, 0x82, 0, 0x81, 0x20][..], &[0x42; 32]].concat();
                    assert_eq!(
                        send(
                            fs,
                            INS_AUTHENTICATE,
                            ALGO_RSA_FIXTURE,
                            SLOT_AUTHENTICATION,
                            &request,
                            false
                        ),
                        Sw::REFERENCE_NOT_FOUND
                    );
                }
                if completed {
                    assert_ne!(actual, old);
                    assert!(headed);
                }
                assert_eq!(
                    medium
                        .value(cert_fid_for_slot(SLOT_AUTHENTICATION).unwrap())
                        .as_deref(),
                    Some(&b"owner certificate"[..])
                );
                retained(fs, medium);
            }
        ));
    }
}

#[test]
fn a_piv_root_migration_and_its_retry_preserve_existing_slot_identities() {
    let otp = [0x55; 32];
    let current = Device {
        otp_key: Some(&otp),
        ..device()
    };
    let key = PrivKey::from_scalar(Curve::P256, &[0x33; 32]).unwrap();
    let mut expected = [0; MAX_EC_POINT];
    let n = key.public_point(&mut expected).unwrap();
    assert!(sweep_restarts(
        || {
            let (mut fs, medium) = fixture();
            seal::store_ec_key(
                &device(),
                &mut fs,
                &mut TestRng(7),
                key_fid(SLOT_AUTHENTICATION),
                &key,
            )
            .unwrap();
            fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
            (fs, medium)
        },
        |fs| !migrate_kbase(&current, fs, &mut TestRng(7)),
        |fs| {
            migrate_kbase(&current, fs, &mut TestRng(91));
        },
        |fs, _, _, _, medium| {
            let got = seal::load_ec_key(&current, fs, key_fid(SLOT_AUTHENTICATION)).unwrap();
            let mut point = [0; MAX_EC_POINT];
            let len = got.public_point(&mut point).unwrap();
            assert_eq!(&point[..len], &expected[..n]);
            assert_eq!(files::mgm_read(&current, fs).unwrap().key(), &DEFAULT_MGM);
            assert!(!fs.has_data(rsk_fs::EF_HARDENED));
            let generation = fs.write_gen();
            assert!(!migrate_kbase(&current, fs, &mut TestRng(200)));
            assert_eq!(fs.write_gen(), generation);
            retained(fs, medium);
        }
    ));
}
