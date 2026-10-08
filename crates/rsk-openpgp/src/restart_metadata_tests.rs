// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn deleting_sex_and_nonpermanent_touch_dos_reseeds_defaults_after_two_cuts() {
    const DEFAULT_UIF: &[u8] = &[0, 0x20];
    for (tag, old, default) in [
        (consts::EF_SEX, &b"1"[..], &b"9"[..]),
        (consts::EF_UIF_SIG, &[1, 0x20][..], DEFAULT_UIF),
        (consts::EF_UIF_DEC, &[1, 0x20][..], DEFAULT_UIF),
        (consts::EF_UIF_AUT, &[1, 0x20][..], DEFAULT_UIF),
        (consts::EF_UIF_ATT, &[1, 0x20][..], DEFAULT_UIF),
    ] {
        let provision = || {
            let (mut fs, medium) = fixture();
            fs.put(tag, old).unwrap();
            (fs, medium)
        };
        let raw = apdu(consts::INS_PUT_DATA, (tag >> 8) as u8, tag as u8, &[]);
        let (mut reference, medium) = provision();
        medium.clear_ops();
        assert_eq!(execute(&mut reference, &raw, consts::PW3_MODE83).1, Sw::OK);
        assert!(medium.value(tag).is_none());
        let cost = u32::try_from(medium.ops().len()).unwrap();
        assert!(sweep_restarts(
            provision,
            |fs| execute(fs, &raw, consts::PW3_MODE83).1 == Sw::OK,
            boot,
            |fs, first, _, _, medium| {
                let actual = medium.value(tag).unwrap();
                assert!(actual == old || actual == default);
                if first >= cost {
                    assert_eq!(actual, default);
                }
                retained(fs, medium);
            }
        ));
    }
}

#[test]
fn rsa_generation_finish_preserves_public_order_and_each_best_effort_tail() {
    let key = rsk_rsa::rsa_from_pqe(&[1, 0, 1], &hx(RSA_P), &hx(RSA_Q)).unwrap();
    for (crt, fid) in [
        (0xB6, consts::EF_PK_SIG),
        (0xB8, consts::EF_PK_DEC),
        (0xA4, consts::EF_PK_AUT),
    ] {
        let provision = || {
            let (mut fs, medium) = fixture();
            fs.put(consts::EF_SIG_COUNT, &[0, 0, 73]).unwrap();
            (fs, medium)
        };
        let finish = |fs: &mut Fs<Cut>| {
            let mut session = crate::pin::Session::new();
            let mut rng = LcgRng(71);
            if crate::pin::verify(
                &dev(),
                fs,
                &mut session,
                &mut rng,
                0,
                consts::PW3_MODE83,
                consts::PW3_DEFAULT,
            ) != Sw::OK
            {
                return false;
            }
            assert_eq!(
                crate::keypairgen::rsa_generate_params(fs, &session, 0x80, 0, &[crt, 0]),
                Ok(Some((fid, 2048)))
            );
            crate::keypairgen::rsa_generate_finish(
                &dev(),
                fs,
                &session,
                &mut rng,
                fid,
                &key,
                &mut [0; 600],
            )
            .1 == Sw::OK
        };
        let (mut reference, medium) = provision();
        medium.clear_ops();
        assert!(finish(&mut reference));
        let healthy_cost = u32::try_from(medium.ops().len()).unwrap();
        let private = medium.value(fid.get());
        let public = medium.value(consts::slot_pub_fid(fid));
        let aes = medium.value(consts::EF_AES_KEY.get());
        assert!(!sweep_restarts(
            provision,
            finish,
            boot,
            |fs, first, _, completed, medium| {
                let actual = medium.value(fid.get());
                let published = medium.value(consts::slot_pub_fid(fid));
                assert!(actual.is_none() || actual == private);
                assert!(published.is_none() || published == public);
                if published.is_some() {
                    assert_eq!(actual, private);
                }
                if crate::origin::of(fs, fid) == crate::origin::ORIGIN_GENERATED {
                    assert_eq!(actual, private);
                }
                let count = medium.value(consts::EF_SIG_COUNT).unwrap();
                if fid == consts::EF_PK_SIG {
                    assert!([vec![0, 0, 73], vec![0, 0, 0]].contains(&count));
                    if count == [0, 0, 0] {
                        assert_eq!(published, public);
                    }
                    if completed {
                        assert_eq!(count, [0, 0, 0]);
                    }
                } else {
                    assert_eq!(count, [0, 0, 73]);
                }
                let actual_aes = medium.value(consts::EF_AES_KEY.get());
                assert!(actual_aes.is_none() || actual_aes == aes);
                if actual_aes.is_some() {
                    assert_eq!(published, public);
                }
                if completed {
                    assert_eq!(actual, private);
                    assert_eq!(published, public);
                }
                if first >= healthy_cost {
                    assert_eq!(crate::origin::of(fs, fid), crate::origin::ORIGIN_GENERATED);
                    assert_eq!(actual_aes, aes);
                }
                retained(fs, medium);
            }
        ));
    }
}

#[test]
fn attribute_invalidation_never_leaves_a_key_under_its_new_algorithm() {
    for (crt, fid, tag) in [
        (0xB6, consts::EF_PK_SIG, consts::EF_ALGO_SIG),
        (0xB8, consts::EF_PK_DEC, consts::EF_ALGO_DEC),
        (0xA4, consts::EF_PK_AUT, consts::EF_ALGO_AUT),
    ] {
        for clear in [false, true] {
            let old = if fid == consts::EF_PK_DEC {
                ATTR_P256_ECDH
            } else {
                ATTR_P256
            };
            let new = if clear { &[][..] } else { consts::DEFAULT_ALGO };
            let provision = || {
                let (mut fs, medium) = fixture();
                assert_eq!(
                    execute(
                        &mut fs,
                        &apdu(consts::INS_PUT_DATA, 0, tag as u8, old),
                        consts::PW3_MODE83
                    )
                    .1,
                    Sw::OK
                );
                assert_eq!(
                    execute(&mut fs, &ec_import(crt, &[0x11; 32]), consts::PW3_MODE83).1,
                    Sw::OK
                );
                (fs, medium)
            };
            let raw = apdu(consts::INS_PUT_DATA, 0, tag as u8, new);
            assert!(!sweep_restarts(
                provision,
                |fs| execute(fs, &raw, consts::PW3_MODE83).1 == Sw::OK,
                boot,
                |fs, _, _, completed, medium| {
                    let attribute = medium.value(consts::algo_tag_to_priv(tag));
                    assert!(
                        attribute.as_deref() == Some(old)
                            || attribute.as_deref() == if clear { None } else { Some(new) }
                    );
                    if attribute.as_deref() != Some(old) || completed {
                        assert!(!fs.has_key(fid));
                        assert!(!fs.has_data(consts::slot_pub_fid(fid)));
                    }
                    retained(fs, medium);
                }
            ));
        }
    }
}

#[test]
fn every_certificate_occurrence_keeps_a_complete_create_replace_or_delete() {
    for occurrence in 0..consts::CERT_OCCURRENCES {
        for operation in 0..3 {
            let fid = consts::EF_CH_1 + u16::from(occurrence);
            let command = |fs: &mut Fs<Cut>, value: &[u8]| {
                let rng = RefCell::new(LcgRng(71));
                let presence = RefCell::new(crate::AlwaysConfirm);
                let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
                let verified = run(
                    &mut app,
                    fs,
                    &apdu(
                        consts::INS_VERIFY,
                        0,
                        consts::PW3_MODE83,
                        consts::PW3_DEFAULT,
                    ),
                );
                if verified.1 != Sw::OK {
                    return verified.1;
                }
                assert_eq!(run(&mut app, fs, &select_cert(occurrence)).1, Sw::OK);
                run(&mut app, fs, &apdu(consts::INS_PUT_DATA, 0x7F, 0x21, value)).1
            };
            let provision = || {
                let (mut fs, medium) = fixture();
                for i in 0..consts::CERT_OCCURRENCES {
                    if operation != 0 || i != occurrence {
                        fs.put(consts::EF_CH_1 + u16::from(i), &[i, 0x11]).unwrap();
                    }
                }
                (fs, medium)
            };
            let (_, baseline) = provision();
            let before = baseline.value(fid);
            let neighbors: Vec<_> = (0..consts::CERT_OCCURRENCES as u16)
                .filter(|i| consts::EF_CH_1 + i != fid)
                .map(|i| (consts::EF_CH_1 + i, baseline.value(consts::EF_CH_1 + i)))
                .collect();
            let new = if operation == 2 {
                &[][..]
            } else {
                &b"new certificate"[..]
            };
            let (mut reference, medium) = provision();
            assert_eq!(command(&mut reference, new), Sw::OK);
            let after = medium.value(fid);
            assert_ne!(before, after);
            assert!(!sweep_restarts(
                provision,
                |fs| command(fs, new) == Sw::OK,
                boot,
                |fs, _, _, completed, medium| {
                    let value = medium.value(fid);
                    assert!(value == before || value == after);
                    if completed && operation != 2 {
                        assert_eq!(value, after);
                    }
                    for (fid, value) in &neighbors {
                        assert_eq!(medium.value(*fid), *value);
                    }
                    retained(fs, medium);
                }
            ));
        }
    }
}

#[test]
fn retry_maxima_and_current_budgets_keep_the_declared_two_record_prefix() {
    for wanted in [[2, 2, 2], [5, 5, 5], [0, 0, 2]] {
        let raw = apdu(consts::INS_SET_RETRIES, 0, 0, &wanted);
        let (mut reference, medium) = fixture();
        let before_left = medium.value(consts::EF_PW_PRIV).unwrap();
        let before_max = medium.value(consts::EF_PW_RETRIES).unwrap();
        assert_eq!(execute(&mut reference, &raw, consts::PW3_MODE83).1, Sw::OK);
        let after_left = medium.value(consts::EF_PW_PRIV).unwrap();
        let after_max = medium.value(consts::EF_PW_RETRIES).unwrap();
        assert!(!sweep_restarts(
            fixture,
            |fs| execute(fs, &raw, consts::PW3_MODE83).1 == Sw::OK,
            boot,
            |fs, _, _, completed, medium| {
                let left = medium.value(consts::EF_PW_PRIV).unwrap();
                let max = medium.value(consts::EF_PW_RETRIES).unwrap();
                assert!(max == before_max || max == after_max);
                assert_eq!(&left[..4], &before_left[..4]);
                assert_eq!(left[5], 0);
                for index in [4, 6] {
                    assert!(
                        left[index] == before_left[index]
                            || left[index] == before_left[index] - 1
                            || left[index] == after_left[index]
                    );
                }
                if max == after_max || completed {
                    assert_eq!(left, after_left);
                }
                if completed {
                    assert_eq!(max, after_max);
                }
                retained(fs, medium);
            }
        ));
    }
}

#[test]
fn a_signature_is_released_only_after_its_counter_commits() {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let response = RefCell::new(Vec::new());
    assert!(!sweep_restarts(
        || {
            let (mut fs, medium) = fixture();
            assert_eq!(
                execute(
                    &mut fs,
                    &apdu(consts::INS_PUT_DATA, 0, 0xC1, ATTR_P256),
                    consts::PW3_MODE83
                )
                .1,
                Sw::OK
            );
            assert_eq!(
                execute(&mut fs, &ec_import(0xB6, &[0x11; 32]), consts::PW3_MODE83).1,
                Sw::OK
            );
            fs.put(consts::EF_SIG_COUNT, &[0, 0, 73]).unwrap();
            (fs, medium)
        },
        |fs| {
            let (bytes, sw) = execute(
                fs,
                &apdu(consts::INS_PSO, 0x9E, 0x9A, &[0x42; 32]),
                consts::PW1_MODE81,
            );
            if sw != Sw::OK {
                assert!(bytes.is_empty());
            }
            *response.borrow_mut() = bytes;
            sw == Sw::OK
        },
        boot,
        |fs, _, _, completed, medium| {
            let counter = medium.value(consts::EF_SIG_COUNT).unwrap();
            assert!([vec![0, 0, 73], vec![0, 0, 74]].contains(&counter));
            if completed {
                assert_eq!(counter, [0, 0, 74]);
                p256_vk(&[0x11; 32])
                    .verify_prehash(
                        &[0x42; 32],
                        &p256::ecdsa::Signature::from_slice(&response.borrow()).unwrap(),
                    )
                    .unwrap();
            }
            retained(fs, medium);
        }
    ));
}

#[test]
fn rsa_import_preserves_its_signer_public_record_origin_and_signature_counter() {
    let p = hx(RSA_P);
    let q = hx(RSA_Q);
    let key = rsk_rsa::rsa_from_pqe(&[1, 0, 1], &p, &q).unwrap();
    for (crt, fid, tag) in [
        (0xB6, consts::EF_PK_SIG, 0xC1),
        (0xB8, consts::EF_PK_DEC, 0xC2),
        (0xA4, consts::EF_PK_AUT, 0xC3),
    ] {
        let provision = || {
            let (mut fs, medium) = fixture();
            assert_eq!(
                execute(
                    &mut fs,
                    &apdu(consts::INS_PUT_DATA, 0, tag, consts::DEFAULT_ALGO),
                    consts::PW3_MODE83
                )
                .1,
                Sw::OK
            );
            fs.put(consts::EF_SIG_COUNT, &[0, 0, 73]).unwrap();
            (fs, medium)
        };
        let raw = rsa_import(crt, &[1, 0, 1], &p, &q);
        let (mut reference, medium) = provision();
        assert_eq!(execute(&mut reference, &raw, consts::PW3_MODE83).1, Sw::OK);
        let expected = medium.value(fid.get());
        let public = medium.value(consts::slot_pub_fid(fid));
        assert!(!sweep_restarts(
            provision,
            |fs| execute(fs, &raw, consts::PW3_MODE83).1 == Sw::OK,
            boot,
            |fs, _, _, completed, medium| {
                let private = medium.value(fid.get());
                assert!(private.is_none() || private == expected);
                let actual_public = medium.value(consts::slot_pub_fid(fid));
                assert!(actual_public.is_none() || actual_public == public);
                if private.is_some() {
                    assert_eq!(crate::origin::of(fs, fid), crate::origin::ORIGIN_IMPORTED);
                    let rng = RefCell::new(LcgRng(7));
                    let presence = RefCell::new(crate::AlwaysConfirm);
                    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
                    verify_pin(&mut app, fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
                    assert_eq!(
                        crate::keys::load_rsa_key(&dev(), fs, &app.sess, fid)
                            .unwrap()
                            .n_be(),
                        key.n_be()
                    );
                }
                if actual_public.is_some() {
                    assert_eq!(private, expected);
                }
                if completed {
                    assert_eq!(private, expected);
                    assert_eq!(actual_public, public);
                }
                let count = medium.value(consts::EF_SIG_COUNT).unwrap();
                if fid == consts::EF_PK_SIG {
                    assert!([vec![0, 0, 73], vec![0, 0, 0]].contains(&count));
                    if count == [0, 0, 0] {
                        assert_eq!(actual_public, public);
                    }
                    if completed {
                        assert_eq!(count, [0, 0, 0]);
                    }
                } else {
                    assert_eq!(count, [0, 0, 73]);
                }
                retained(fs, medium);
            }
        ));
    }
}
