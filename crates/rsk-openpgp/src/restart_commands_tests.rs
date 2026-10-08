// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;
use rsk_fs::storage::faults::{Cut, CutMedium};

const NEIGHBOR: u16 = 0xB000;

#[path = "restart_metadata_tests.rs"]
mod metadata;

fn fixture() -> (Fs<Cut>, CutMedium) {
    let (storage, medium) = Cut::new();
    let mut fs = Fs::new(storage);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    fs.put(NEIGHBOR, b"another applet").unwrap();
    fs.meta_add(NEIGHBOR, b"metadata").unwrap();
    (fs, medium)
}

fn apdu(ins: u8, p1: u8, p2: u8, body: &[u8]) -> Vec<u8> {
    let mut raw = vec![0, ins, p1, p2];
    if !body.is_empty() {
        raw.push(u8::try_from(body.len()).unwrap());
        raw.extend(body);
    }
    raw
}

fn execute(fs: &mut Fs<Cut>, raw: &[u8], mode: u8) -> (Vec<u8>, Sw) {
    let rng = RefCell::new(LcgRng(71));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let verified = run(
        &mut app,
        fs,
        &apdu(
            consts::INS_VERIFY,
            0,
            mode,
            if mode == consts::PW3_MODE83 {
                consts::PW3_DEFAULT
            } else {
                consts::PW1_DEFAULT
            },
        ),
    );
    if verified.1 != Sw::OK {
        return verified;
    }
    run(&mut app, fs, raw)
}

fn boot(fs: &mut Fs<Cut>) {
    let _ = scan_files(&dev(), fs, &mut CountRng(91));
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

#[test]
fn data_objects_touch_flags_and_password_status_keep_complete_values_across_two_boots() {
    let cases: &[(u16, &[u8], &[u8])] = &[
        (consts::EF_LOGIN_DATA, b"old", b"new"),
        (consts::EF_CH_NAME, b"Old<<Name", b"New<<Name"),
        (consts::EF_LANG_PREF, b"en", b"fr"),
        (consts::EF_SEX, b"1", b"2"),
        (
            consts::EF_URI_URL,
            b"https://old.example",
            b"https://new.example",
        ),
        (consts::EF_UIF_SIG, &[0, 0x20], &[1, 0x20]),
        (consts::EF_UIF_DEC, &[0, 0x20], &[1, 0x20]),
        (consts::EF_UIF_AUT, &[0, 0x20], &[1, 0x20]),
        (consts::EF_UIF_ATT, &[0, 0x20], &[1, 0x20]),
        (consts::EF_PRIV_DO_1, b"old", b"new"),
        (consts::EF_PRIV_DO_2, b"old", b"new"),
        (consts::EF_PRIV_DO_3, b"old", b"new"),
        (consts::EF_PRIV_DO_4, b"old", b"new"),
        (
            consts::EF_FP_SIG,
            &[0x11; consts::FP_LEN],
            &[0x33; consts::FP_LEN],
        ),
        (
            consts::EF_FP_DEC,
            &[0x11; consts::FP_LEN],
            &[0x33; consts::FP_LEN],
        ),
        (
            consts::EF_FP_AUT,
            &[0x11; consts::FP_LEN],
            &[0x33; consts::FP_LEN],
        ),
        (
            consts::EF_FP_ATT,
            &[0x11; consts::FP_LEN],
            &[0x33; consts::FP_LEN],
        ),
        (
            consts::EF_FP_CA1,
            &[0x11; consts::FP_LEN],
            &[0x33; consts::FP_LEN],
        ),
        (
            consts::EF_FP_CA2,
            &[0x11; consts::FP_LEN],
            &[0x33; consts::FP_LEN],
        ),
        (
            consts::EF_FP_CA3,
            &[0x11; consts::FP_LEN],
            &[0x33; consts::FP_LEN],
        ),
        (
            consts::EF_FP_CA4,
            &[0x11; consts::FP_LEN],
            &[0x33; consts::FP_LEN],
        ),
        (
            consts::EF_TS_SIG,
            &[0x11; consts::TS_LEN],
            &[0x33; consts::TS_LEN],
        ),
        (
            consts::EF_TS_DEC,
            &[0x11; consts::TS_LEN],
            &[0x33; consts::TS_LEN],
        ),
        (
            consts::EF_TS_AUT,
            &[0x11; consts::TS_LEN],
            &[0x33; consts::TS_LEN],
        ),
        (
            consts::EF_TS_ATT,
            &[0x11; consts::TS_LEN],
            &[0x33; consts::TS_LEN],
        ),
    ];
    for &(tag, old, new) in cases {
        let mode = if matches!(tag, consts::EF_PRIV_DO_1 | consts::EF_PRIV_DO_3) {
            consts::PW1_MODE82
        } else {
            consts::PW3_MODE83
        };
        for delete in [false, true] {
            if delete
                && (consts::FP_DOS.contains(&tag)
                    || consts::CA_FP_DOS.contains(&tag)
                    || consts::TS_DOS.contains(&tag))
            {
                continue;
            }
            if delete
                && matches!(
                    tag,
                    consts::EF_SEX
                        | consts::EF_UIF_SIG
                        | consts::EF_UIF_DEC
                        | consts::EF_UIF_AUT
                        | consts::EF_UIF_ATT
                )
            {
                continue;
            }
            let provision = || {
                let (mut fs, medium) = fixture();
                assert_eq!(
                    execute(
                        &mut fs,
                        &apdu(consts::INS_PUT_DATA, (tag >> 8) as u8, tag as u8, old),
                        mode
                    )
                    .1,
                    Sw::OK
                );
                (fs, medium)
            };
            let raw = apdu(
                consts::INS_PUT_DATA,
                (tag >> 8) as u8,
                tag as u8,
                if delete { &[] } else { new },
            );
            let (mut reference, medium) = provision();
            let before = medium.value(tag);
            assert_eq!(
                execute(&mut reference, &raw, mode).1,
                Sw::OK,
                "tag {tag:#06x}"
            );
            let after = medium.value(tag);
            assert_ne!(before, after);
            assert!(!sweep_restarts(
                provision,
                |fs| execute(fs, &raw, mode).1 == Sw::OK,
                boot,
                |fs, _, _, completed, medium| {
                    let actual = medium.value(tag);
                    assert!(actual == before || actual == after);
                    if completed && !delete {
                        assert_eq!(actual, after);
                    }
                    retained(fs, medium);
                }
            ));
        }
    }
    let raw = apdu(consts::INS_PUT_DATA, 0, 0xC4, &[0]);
    assert!(!sweep_restarts(
        fixture,
        |fs| execute(fs, &raw, consts::PW3_MODE83).1 == Sw::OK,
        boot,
        |fs, _, _, completed, medium| {
            let mut status = [0; 7];
            fs.read(consts::EF_PW_PRIV, &mut status).unwrap();
            assert!(status[0] <= 1);
            assert_eq!(&status[1..4], &[127; 3]);
            assert_eq!(status[4], 3);
            assert_eq!(status[5], 0);
            assert!((2..=3).contains(&status[6]));
            if completed {
                assert_eq!(status[0], 0);
            }
            retained(fs, medium);
        }
    ));
}

#[test]
fn aes_key_replacement_preserves_one_whole_key_and_the_owner_dek() {
    for len in [16, 32] {
        let old = vec![0x11; len];
        let new = vec![0x33; len];
        let provision = || {
            let (mut fs, medium) = fixture();
            assert_eq!(
                execute(
                    &mut fs,
                    &apdu(consts::INS_PUT_DATA, 0, 0xD5, &old),
                    consts::PW3_MODE83
                )
                .1,
                Sw::OK
            );
            (fs, medium)
        };
        let (_, baseline) = provision();
        let dek = baseline.value(consts::EF_DEK_PW3.get());
        assert!(!sweep_restarts(
            provision,
            |fs| execute(
                fs,
                &apdu(consts::INS_PUT_DATA, 0, 0xD5, &new),
                consts::PW3_MODE83
            )
            .1 == Sw::OK,
            boot,
            |fs, _, _, completed, medium| {
                let rng = RefCell::new(LcgRng(71));
                let presence = RefCell::new(crate::AlwaysConfirm);
                let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
                verify_pin(&mut app, fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
                let (key, n) = crate::keys::load_aes_key(&dev(), fs, &app.sess).unwrap();
                let actual = &key.expose()[..n];
                assert!(actual == old || actual == new);
                if completed {
                    assert_eq!(actual, new);
                }
                assert_eq!(medium.value(consts::EF_DEK_PW3.get()), dek);
                retained(fs, medium);
            }
        ));
    }
}

#[test]
fn key_generation_and_import_keep_the_declared_non_atomic_public_and_origin_prefixes() {
    for (crt, fid, attr, attribute) in [
        (0xB6, consts::EF_PK_SIG, ATTR_P256, consts::EF_ALGO_SIG),
        (0xB8, consts::EF_PK_DEC, ATTR_P256_ECDH, consts::EF_ALGO_DEC),
        (0xA4, consts::EF_PK_AUT, ATTR_P256, consts::EF_ALGO_AUT),
    ] {
        for import in [false, true] {
            let provision = || {
                let (mut fs, medium) = fixture();
                assert_eq!(
                    execute(
                        &mut fs,
                        &apdu(
                            consts::INS_PUT_DATA,
                            (attribute >> 8) as u8,
                            attribute as u8,
                            attr
                        ),
                        consts::PW3_MODE83
                    )
                    .1,
                    Sw::OK
                );
                assert_eq!(
                    execute(&mut fs, &ec_import(crt, &[0x11; 32]), consts::PW3_MODE83).1,
                    Sw::OK
                );
                if import {
                    crate::origin::mark(&mut fs, fid, crate::origin::ORIGIN_GENERATED).unwrap();
                }
                fs.put(consts::EF_SIG_COUNT, &[0, 0, 73]).unwrap();
                (fs, medium)
            };
            let raw = if import {
                ec_import(crt, &[0x33; 32])
            } else {
                apdu(consts::INS_KEYPAIR_GEN, 0x80, 0, &[crt, 0])
            };
            let (mut reference, medium) = provision();
            let before = medium.value(fid.get());
            let old_public = medium.value(consts::slot_pub_fid(fid));
            medium.clear_ops();
            assert_eq!(execute(&mut reference, &raw, consts::PW3_MODE83).1, Sw::OK);
            let healthy_cost = u32::try_from(medium.ops().len()).unwrap();
            let after = medium.value(fid.get());
            let new_public = medium.value(consts::slot_pub_fid(fid));
            let aes = medium.value(consts::EF_AES_KEY.get());
            assert_ne!(before, after);
            assert!(!sweep_restarts(
                provision,
                |fs| execute(fs, &raw, consts::PW3_MODE83).1 == Sw::OK,
                boot,
                |fs, first, _, completed, medium| {
                    let key = medium.value(fid.get());
                    let public = medium.value(consts::slot_pub_fid(fid));
                    assert!(key == before || key == after);
                    assert!(public == old_public || public == new_public);
                    if public == new_public {
                        assert_eq!(key, after, "public identity committed before its signer");
                    }
                    if import && key == after {
                        assert_eq!(crate::origin::of(fs, fid), crate::origin::ORIGIN_IMPORTED);
                    }
                    if !import && crate::origin::of(fs, fid) == crate::origin::ORIGIN_GENERATED {
                        assert_eq!(key, after);
                    }
                    if fid == consts::EF_PK_SIG {
                        let counter = medium.value(consts::EF_SIG_COUNT).unwrap();
                        assert!([vec![0, 0, 73], vec![0, 0, 0]].contains(&counter));
                        if counter == [0, 0, 0] {
                            assert_eq!(public, new_public);
                        }
                        if completed {
                            assert_eq!(counter, [0, 0, 0]);
                        }
                    }
                    if fid == consts::EF_PK_DEC {
                        let value = medium.value(consts::EF_AES_KEY.get());
                        assert!(value.is_none() || value == aes);
                        if value.is_some() {
                            assert_eq!(public, new_public);
                        }
                        if first >= healthy_cost {
                            assert_eq!(value, aes);
                        }
                    }
                    if completed {
                        assert_eq!(key, after);
                        assert_eq!(public, new_public);
                        if import || first >= healthy_cost {
                            assert_eq!(
                                crate::origin::of(fs, fid),
                                if import {
                                    crate::origin::ORIGIN_IMPORTED
                                } else {
                                    crate::origin::ORIGIN_GENERATED
                                }
                            );
                        }
                    }
                    retained(fs, medium);
                }
            ));
        }
    }
}
