// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;

const NEIGHBOR: u16 = 0xB000;
const NEW_PIN: [u8; PIN_WIRE_LEN] = *b"87654321";

fn device() -> Device<'static> {
    Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
        latched: false,
    }
}

fn fixture() -> (Fs<Cut>, CutMedium) {
    let (mut fs, medium) = new_cut_fs();
    files::scan_files(&device(), &mut fs, &mut TestRng(91)).unwrap();
    fs.put(NEIGHBOR, b"another applet").unwrap();
    fs.meta_add(NEIGHBOR, b"metadata").unwrap();
    (fs, medium)
}

fn boot(fs: &mut Fs<Cut>) {
    let _ = files::scan_files(&device(), fs, &mut TestRng(91));
}

fn send(fs: &mut Fs<Cut>, ins: u8, p1: u8, p2: u8, body: &[u8], mgm: bool) -> Sw {
    let rng = RefCell::new(TestRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &touch);
    select(&mut app, fs);
    if mgm {
        auth_mgm(&mut app, fs);
    }
    run(&mut app, fs, ins, p1, p2, body).0
}

fn retained(fs: &mut Fs<Cut>, medium: &CutMedium) {
    assert_eq!(
        medium.value(NEIGHBOR).as_deref(),
        Some(&b"another applet"[..])
    );
    let mut meta = [0; 8];
    assert_eq!(fs.meta_find(NEIGHBOR, &mut meta), Some(8));
    assert_eq!(&meta, b"metadata");
}

fn point(fs: &mut Fs<Cut>, slot: u8) -> Option<Vec<u8>> {
    if !fs.has_key(key_fid(slot)) {
        return None;
    }
    let key = seal::load_ec_key(&device(), fs, key_fid(slot)).unwrap();
    let mut out = [0; MAX_EC_POINT];
    let n = key.public_point(&mut out).unwrap();
    Some(out[..n].to_vec())
}

#[test]
fn regular_key_generation_and_import_never_repair_a_head_with_the_preceding_policy() {
    for algo in [ALGO_ECCP256, ALGO_ECCP384, ALGO_ED25519, ALGO_X25519] {
        for import in [false, true] {
            for replace in [false, true] {
                let provision = || {
                    let (mut fs, medium) = fixture();
                    fs.put(
                        cert_fid_for_slot(SLOT_AUTHENTICATION).unwrap(),
                        b"owner certificate",
                    )
                    .unwrap();
                    if replace {
                        let curve = match algo {
                            ALGO_ECCP256 => Curve::P256,
                            ALGO_ECCP384 => Curve::P384,
                            ALGO_ED25519 => Curve::Ed25519,
                            ALGO_X25519 => Curve::X25519,
                            _ => unreachable!(),
                        };
                        let n = if algo == ALGO_ECCP384 { 48 } else { 32 };
                        let key = PrivKey::from_scalar(curve, &vec![0x11; n]).unwrap();
                        seal::store_ec_key(
                            &device(),
                            &mut fs,
                            &mut TestRng(17),
                            key_fid(SLOT_AUTHENTICATION),
                            &key,
                        )
                        .unwrap();
                        fs.meta_add(
                            key_fid(SLOT_AUTHENTICATION).get(),
                            &[algo, PINPOLICY_ONCE, TOUCHPOLICY_NEVER, ORIGIN_GENERATED],
                        )
                        .unwrap();
                    }
                    (fs, medium)
                };
                let mut body = if import {
                    let n = if algo == ALGO_ECCP384 { 48 } else { 32 };
                    let tag = match algo {
                        ALGO_ED25519 => 0x07,
                        ALGO_X25519 => 0x08,
                        _ => 0x06,
                    };
                    let mut body = vec![tag, n];
                    body.extend(std::iter::repeat_n(0x33, usize::from(n)));
                    body
                } else {
                    gen_template(algo)
                };
                let pin = PINPOLICY_ALWAYS;
                let touch = TOUCHPOLICY_ALWAYS;
                if import {
                    body.extend([0xAA, 1, pin, 0xAB, 1, touch]);
                } else {
                    body[1] += 6;
                    body.extend([0xAA, 1, pin, 0xAB, 1, touch]);
                }
                let (ins, p1) = if import {
                    (INS_IMPORT_ASYM, algo)
                } else {
                    (INS_ASYM_KEYGEN, 0)
                };
                let (mut reference, _) = provision();
                let before = point(&mut reference, SLOT_AUTHENTICATION);
                assert_eq!(
                    send(&mut reference, ins, p1, SLOT_AUTHENTICATION, &body, true),
                    Sw::OK
                );
                let after = point(&mut reference, SLOT_AUTHENTICATION).unwrap();
                assert_ne!(before.as_ref(), Some(&after));
                assert!(!sweep_restarts(
                    provision,
                    |fs| send(fs, ins, p1, SLOT_AUTHENTICATION, &body, true) == Sw::OK,
                    boot,
                    |fs, _, _, completed, medium| {
                        let actual = point(fs, SLOT_AUTHENTICATION);
                        assert!(actual == before || actual.as_ref() == Some(&after));
                        let mut head = [0; 4 + MAX_EC_POINT];
                        let headed = fs
                            .meta_find(key_fid(SLOT_AUTHENTICATION).get(), &mut head)
                            .is_some();
                        if actual.as_ref() == Some(&after) && headed {
                            assert_eq!(
                                &head[..4],
                                &[
                                    algo,
                                    pin,
                                    touch,
                                    if import {
                                        ORIGIN_IMPORTED
                                    } else {
                                        ORIGIN_GENERATED
                                    }
                                ]
                            );
                        }
                        if completed {
                            assert_eq!(actual.as_ref(), Some(&after));
                            assert!(headed);
                            assert_eq!(
                                send(fs, INS_ATTESTATION, SLOT_AUTHENTICATION, 0, &[], false),
                                if import { Sw::WRONG_DATA } else { Sw::OK }
                            );
                        }
                        if actual.is_some() && !headed {
                            let rng = RefCell::new(TestRng(9));
                            let presence = RefCell::new(AlwaysConfirm);
                            let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
                            select(&mut app, fs);
                            assert_eq!(
                                run(&mut app, fs, INS_GET_METADATA, 0, SLOT_AUTHENTICATION, &[]).0,
                                Sw::REFERENCE_NOT_FOUND
                            );
                            assert_eq!(
                                run(&mut app, fs, INS_ATTESTATION, SLOT_AUTHENTICATION, 0, &[]).0,
                                Sw::REFERENCE_NOT_FOUND
                            );
                            let request =
                                [&[0x7C, 0x24, 0x82, 0, 0x81, 0x20][..], &[0x42; 32]].concat();
                            assert_eq!(
                                run(
                                    &mut app,
                                    fs,
                                    INS_AUTHENTICATE,
                                    algo,
                                    SLOT_AUTHENTICATION,
                                    &request
                                )
                                .0,
                                Sw::REFERENCE_NOT_FOUND
                            );
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
    }
}

#[test]
fn deleting_a_key_with_move_keeps_its_certificate_and_never_writes_the_sentinel_slot() {
    let provision = || {
        let (mut fs, medium) = fixture();
        assert_eq!(
            send(
                &mut fs,
                INS_ASYM_KEYGEN,
                0,
                SLOT_AUTHENTICATION,
                &gen_template(ALGO_ECCP256),
                true
            ),
            Sw::OK
        );
        fs.put(
            cert_fid_for_slot(SLOT_AUTHENTICATION).unwrap(),
            b"owner certificate",
        )
        .unwrap();
        (fs, medium)
    };
    let (mut reference, _) = provision();
    let before = point(&mut reference, SLOT_AUTHENTICATION).unwrap();
    assert!(!sweep_restarts(
        provision,
        |fs| send(fs, INS_MOVE_KEY, 0xFF, SLOT_AUTHENTICATION, &[], true) == Sw::OK,
        boot,
        |fs, _, _, completed, medium| {
            let actual = point(fs, SLOT_AUTHENTICATION);
            assert!(actual.is_none() || actual.as_ref() == Some(&before));
            if completed {
                assert!(actual.is_none());
            }
            assert!(!fs.has_data(key_fid(0xFF).get()));
            assert!(!fs.has_data(pubkey_fid(0xFF)));
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

#[test]
fn reference_changes_and_retry_updates_keep_complete_verifiers_across_two_boots() {
    let cases = [
        (INS_VERIFY, REF_PIN, DEFAULT_PIN.to_vec(), false),
        (INS_VERIFY, REF_PIN, b"00000000".to_vec(), false),
        (
            INS_CHANGE_PIN,
            REF_PIN,
            [DEFAULT_PIN, NEW_PIN].concat(),
            false,
        ),
        (
            INS_CHANGE_PIN,
            REF_PUK,
            [DEFAULT_PUK, NEW_PIN].concat(),
            false,
        ),
        (
            INS_RESET_RETRY,
            REF_PIN,
            [DEFAULT_PUK, NEW_PIN].concat(),
            false,
        ),
        (INS_SET_RETRIES, 4, vec![], true),
    ];
    for (ins, p2, body, mgm) in cases {
        let provision = || {
            let (mut fs, medium) = fixture();
            if ins == INS_RESET_RETRY {
                fs.put(EF_RETRIES, &[3, 0, 3, 3]).unwrap();
            }
            if ins == INS_SET_RETRIES {
                files::put_pin_verifier(&device(), &mut fs, EF_PIN, &NEW_PIN, None).unwrap();
                files::put_pin_verifier(&device(), &mut fs, EF_PUK, b"abcdefgh", None).unwrap();
            }
            (fs, medium)
        };
        let command = |fs: &mut Fs<Cut>| {
            let rng = RefCell::new(TestRng(7));
            let touch = RefCell::new(AlwaysConfirm);
            let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &touch);
            select(&mut app, fs);
            if mgm {
                auth_mgm(&mut app, fs);
                if run(&mut app, fs, INS_VERIFY, 0, REF_PIN, &NEW_PIN).0 != Sw::OK {
                    return false;
                }
            }
            let sw = run(&mut app, fs, ins, if mgm { 5 } else { 0 }, p2, &body).0;
            sw == Sw::OK || (ins == INS_VERIFY && body == b"00000000" && sw == Sw::retries(2))
        };
        let (mut reference, medium) = provision();
        let old_pin = medium.value(EF_PIN).unwrap();
        let old_puk = medium.value(EF_PUK).unwrap();
        assert!(command(&mut reference));
        let new_pin = medium.value(EF_PIN).unwrap();
        let new_puk = medium.value(EF_PUK).unwrap();
        let mut final_retries = [0; 4];
        assert_eq!(reference.read(EF_RETRIES, &mut final_retries), Some(4));
        let initial = if ins == INS_RESET_RETRY {
            [3, 0, 3, 3]
        } else {
            [3, 3, 3, 3]
        };
        let mut spent = initial;
        spent[if p2 == REF_PUK || ins == INS_RESET_RETRY {
            RETRY_PUK + 1
        } else {
            RETRY_PIN + 1
        }] -= 1;
        assert!(!sweep_restarts(
            provision,
            command,
            boot,
            |fs, _, _, completed, medium| {
                let pin = medium.value(EF_PIN).unwrap();
                let puk = medium.value(EF_PUK).unwrap();
                assert!(pin == old_pin || pin == new_pin);
                assert!(puk == old_puk || puk == new_puk);
                let mut retry = [0; 4];
                assert_eq!(fs.read(EF_RETRIES, &mut retry), Some(4));
                assert!([initial, spent, final_retries].contains(&retry));
                if completed {
                    assert_eq!(pin, new_pin);
                    assert_eq!(puk, new_puk);
                    assert_eq!(retry, final_retries);
                }
                let rng = RefCell::new(TestRng(9));
                let touch = RefCell::new(AlwaysConfirm);
                let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &touch);
                select(&mut app, fs);
                assert!(!app.sess.has_pin && !app.sess.has_mgm);
                retained(fs, medium);
            }
        ));
    }
}

#[test]
fn fixed_and_pooled_objects_are_whole_after_two_boots() {
    for id in [0xC105, 0xFFF0, 0xFFF1] {
        for initial in [false, true] {
            for delete in [false, true] {
                if delete && !initial {
                    continue;
                }
                let before = initial.then(|| b"old object".to_vec());
                let after = (!delete).then(|| b"new object".to_vec());
                let provision = || {
                    let (mut fs, medium) = fixture();
                    if let Some(old) = &before {
                        assert_eq!(
                            send(
                                &mut fs,
                                INS_PUT_DATA,
                                0x3F,
                                0xFF,
                                &object_body([0x5F, (id >> 8) as u8, id as u8], old),
                                true
                            ),
                            Sw::OK
                        );
                    }
                    (fs, medium)
                };
                let body = object_body(
                    [0x5F, (id >> 8) as u8, id as u8],
                    after.as_deref().unwrap_or_default(),
                );
                assert!(!sweep_restarts(
                    provision,
                    |fs| send(fs, INS_PUT_DATA, 0x3F, 0xFF, &body, true) == Sw::OK,
                    boot,
                    |fs, _, _, completed, medium| {
                        let actual = if let Some(fid) = object_fid(0x5F0000 | id) {
                            medium.value(fid)
                        } else {
                            let mut out = [0; crate::objects::RECORD_MAX];
                            crate::objects::read(fs, 0x5F0000 | id, &mut out)
                                .unwrap()
                                .map(|n| out[..n].to_vec())
                        };
                        assert!(actual == before || actual == after);
                        if completed {
                            assert_eq!(actual, after);
                        }
                        if object_fid(0x5F0000 | id).is_none() {
                            assert_eq!(pooled(fs), usize::from(actual.is_some()));
                        }
                        retained(fs, medium);
                    }
                ));
            }
        }
    }
}

#[path = "restart_repair_tests.rs"]
mod repair;
