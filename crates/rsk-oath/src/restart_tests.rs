// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;

const NEIGHBOR: u16 = 0xB000;

fn device() -> Device<'static> {
    Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: None,
        latched: false,
    }
}

fn boot(fs: &mut Fs<Cut>) {
    migrate_seal(&device(), fs, &mut CountRng(91));
    let rng = RefCell::new(CountRng(9));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let _ = select(&mut app, fs);
}

fn plain(fs: &mut Fs<Cut>, fid: u16) -> Option<Vec<u8>> {
    if !fs.has_data(fid) {
        return None;
    }
    let mut out = Secret::<[u8; CRED_MAX]>::zeroed();
    let n = seal::seal_read(&device(), fs, KeyFid::new(fid), &mut out).unwrap();
    Some(out.expose()[..n].to_vec())
}

fn fixture(kind: u8) -> (Fs<Cut>, CutMedium) {
    let (mut fs, medium) = new_cut_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    select(&mut app, &mut fs);
    let mut data = put_data(b"subject", kind, 6, SECRET_SHA1, false, None);
    if kind == 0x21 {
        data.extend([TAG_PROPERTY, PROP_INCREASING]);
    }
    assert_eq!(put(&mut app, &mut fs, &data), Sw::OK);
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"neighbor", 0x21, 6, SECRET_SHA256, false, None)
        ),
        Sw::OK
    );
    fs.put(NEIGHBOR, b"another applet").unwrap();
    fs.meta_add(NEIGHBOR, b"metadata").unwrap();
    (fs, medium)
}

fn send(fs: &mut Fs<Cut>, raw: &[u8]) -> (Sw, Vec<u8>) {
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    select(&mut app, fs);
    run(&mut app, fs, raw)
}

fn retained(fs: &mut Fs<Cut>, medium: &CutMedium, neighbor: &[u8]) {
    assert_eq!(
        medium.value(NEIGHBOR).as_deref(),
        Some(&b"another applet"[..])
    );
    let mut meta = [0; 16];
    assert_eq!(fs.meta_find(NEIGHBOR, &mut meta), Some(8));
    assert_eq!(&meta[..8], b"metadata");
    assert_eq!(plain(fs, EF_OATH_CRED + 1).as_deref(), Some(neighbor));
}

#[test]
fn credential_writes_and_moving_factors_survive_two_fresh_boots_without_replay() {
    let calc = [
        tlv(TAG_NAME, b"subject"),
        tlv(TAG_CHALLENGE, &1u64.to_be_bytes()),
    ]
    .concat();
    let rename = [tlv(TAG_NAME, b"subject"), tlv(TAG_NAME, b"renamed")].concat();
    let cases = [
        (
            0x21,
            apdu(
                INS_PUT,
                0,
                0,
                &put_data(b"subject", 0x21, 8, SECRET_SHA256, true, None),
            ),
        ),
        (0x21, apdu(INS_DELETE, 0, 0, &tlv(TAG_NAME, b"subject"))),
        (0x21, apdu(INS_RENAME, 0, 0, &rename)),
        (0x11, apdu(INS_CALCULATE, 0, 0, &calc)),
        (0x11, apdu(INS_CALCULATE, 0, 1, &calc)),
        (0x21, apdu(INS_CALCULATE, 0, 1, &calc)),
        (
            0x21,
            apdu(INS_CALC_ALL, 0, 1, &tlv(TAG_CHALLENGE, &1u64.to_be_bytes())),
        ),
    ];
    for (kind, raw) in cases {
        let (mut reference, _) = fixture(kind);
        let before = plain(&mut reference, EF_OATH_CRED);
        let neighbor = plain(&mut reference, EF_OATH_CRED + 1).unwrap();
        assert_eq!(send(&mut reference, &raw).0, Sw::OK, "{raw:?}");
        let after = plain(&mut reference, EF_OATH_CRED);
        assert_ne!(before, after);
        assert!(!sweep_restarts(
            || fixture(kind),
            |fs| {
                let (sw, body) = send(fs, &raw);
                if sw == Sw::MEMORY_FAILURE {
                    assert!(body.is_empty(), "a refused advance leaked an OTP");
                }
                sw == Sw::OK
            },
            boot,
            |fs, first, second, completed, medium| {
                assert_eq!(second, 0, "modern OATH recovery must be read-only");
                let stored = plain(fs, EF_OATH_CRED);
                assert!(stored == before || stored == after, "{raw:?}, cut {first}");
                if completed {
                    assert_eq!(stored, after, "{raw:?}, cut {first}");
                }
                retained(fs, medium, &neighbor);
            }
        ));
    }
}

#[test]
fn otp_pin_install_change_and_retry_spends_keep_the_verifier_and_close_the_session() {
    for ins in [INS_SET_PIN, INS_CHANGE_PIN, INS_VERIFY_PIN] {
        let provision = || {
            let (mut fs, medium) = fixture(0x21);
            if ins != INS_SET_PIN {
                assert_eq!(
                    send(
                        &mut fs,
                        &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
                    )
                    .0,
                    Sw::OK
                );
            }
            (fs, medium)
        };
        let (mut reference, _) = provision();
        let neighbor = plain(&mut reference, EF_OATH_CRED + 1).unwrap();
        let before = reference.read(EF_OTP_PIN, &mut [0; OTP_PIN_REC_V1]);
        let raw = if ins == INS_CHANGE_PIN {
            apdu(
                ins,
                0,
                0,
                &[tlv(TAG_PASSWORD, b"1234"), tlv(TAG_NEW_PASSWORD, b"5678")].concat(),
            )
        } else {
            apdu(ins, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
        };
        assert_eq!(send(&mut reference, &raw).0, Sw::OK);
        let new = OathApplet::otp_pin_record_v1(
            &device(),
            if ins == INS_CHANGE_PIN {
                b"5678"
            } else {
                b"1234"
            },
        );
        let old = OathApplet::otp_pin_record_v1(&device(), b"1234");
        assert!(!sweep_restarts(
            provision,
            |fs| send(fs, &raw).0 == Sw::OK,
            boot,
            |fs, _, _, completed, medium| {
                let mut rec = [0; OTP_PIN_REC_V1];
                if let Some(n) = fs.read(EF_OTP_PIN, &mut rec) {
                    assert_eq!(n, rec.len());
                    assert!(rec[1..] == old[1..] || rec[1..] == new[1..]);
                    assert!(rec[0] <= MAX_OTP_COUNTER);
                    if completed && ins != INS_VERIFY_PIN {
                        assert_eq!(rec, new);
                    }
                } else {
                    assert!(before.is_none() && !completed);
                }
                let rng = RefCell::new(CountRng(9));
                let touch = RefCell::new(AlwaysConfirm);
                let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
                select(&mut app, fs);
                assert!(!app.otp_pin_verified, "a boot inherited PIN authorization");
                retained(fs, medium, &neighbor);
            }
        ));
    }
}

#[test]
fn reset_replay_can_be_interrupted_without_removing_gates_over_surviving_credentials() {
    let reset = apdu(INS_RESET, 0xDE, 0xAD, &[]);
    let inspect = |fs: &mut Fs<Cut>| {
        let live = fs.has_data(EF_OATH_CRED) || fs.has_data(EF_OATH_CRED + 1);
        if live {
            assert!(fs.has_key(EF_OATH_CODE));
            assert!(fs.has_data(EF_OTP_PIN));
            assert_eq!(
                send(fs, &apdu(INS_LIST, 0, 0, &[])).0,
                Sw::SECURITY_STATUS_NOT_SATISFIED
            );
        }
    };
    assert!(sweep_restarts(
        || {
            let (mut fs, medium) = fixture(0x21);
            assert_eq!(
                send(
                    &mut fs,
                    &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
                )
                .0,
                Sw::OK
            );
            let mut legacy = vec![ALG_HMAC_SHA1];
            legacy.extend(SECRET_SHA1);
            assert!(seal::seal_put(
                &device(),
                &mut fs,
                &mut CountRng(7),
                EF_OATH_CODE,
                &legacy
            ));
            (fs, medium)
        },
        |fs| send(fs, &reset).0 == Sw::OK,
        |fs| {
            boot(fs);
            inspect(fs);
            let _ = send(fs, &reset);
        },
        |fs, _, _, _, medium| {
            for fid in [
                EF_OATH_CRED,
                EF_OATH_CRED + 1,
                EF_OATH_CODE.get(),
                EF_OTP_PIN,
            ] {
                assert!(!fs.has_data(fid));
            }
            assert_eq!(
                medium.value(NEIGHBOR).as_deref(),
                Some(&b"another applet"[..])
            );
            let mut meta = [0; 8];
            assert_eq!(fs.meta_find(NEIGHBOR, &mut meta), Some(8));
            assert_eq!(&meta, b"metadata");
        }
    ));
}

fn code_change(fs: &mut Fs<Cut>, old: Option<&[u8]>, new: Option<&[u8]>) -> Sw {
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let (_, selected) = select(&mut app, fs);
    if let Some(secret) = old {
        let challenge = find_tag(&selected, TAG_CHALLENGE.into()).unwrap();
        let body = [
            tlv(TAG_RESPONSE, &hmac_sha1(secret, challenge)),
            tlv(TAG_CHALLENGE, &[9; CHALLENGE_LEN]),
        ]
        .concat();
        assert_eq!(
            run(&mut app, fs, &apdu(INS_VALIDATE, 0, 0, &body)).0,
            Sw::OK
        );
    }
    match new {
        Some(secret) => {
            let mut key = vec![ALG_HMAC_SHA1];
            key.extend(secret);
            let challenge = [7; CHALLENGE_LEN];
            let body = [
                tlv(TAG_KEY, &key),
                tlv(TAG_CHALLENGE, &challenge),
                tlv(TAG_RESPONSE, &hmac_sha1(secret, &challenge)),
            ]
            .concat();
            run(&mut app, fs, &apdu(INS_SET_CODE, 0, 0, &body)).0
        }
        None => run(&mut app, fs, &apdu(INS_SET_CODE, 0, 0, &tlv(TAG_KEY, &[]))).0,
    }
}

#[test]
fn access_code_install_replace_and_clear_keep_the_password_safe_pin() {
    for (old, new) in [
        (None, Some(SECRET_SHA1)),
        (Some(SECRET_SHA1), Some(SECRET_SHA256)),
        (Some(SECRET_SHA1), None),
    ] {
        let provision = || {
            let (mut fs, medium) = fixture(0x21);
            assert_eq!(
                send(
                    &mut fs,
                    &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
                )
                .0,
                Sw::OK
            );
            if let Some(secret) = old {
                assert_eq!(code_change(&mut fs, None, Some(secret)), Sw::OK);
            }
            (fs, medium)
        };
        let (mut reference, medium) = provision();
        let pin = medium.value(EF_OTP_PIN).unwrap();
        let neighbor = plain(&mut reference, EF_OATH_CRED + 1).unwrap();
        let before = plain(&mut reference, EF_OATH_CODE.get());
        assert_eq!(code_change(&mut reference, old, new), Sw::OK);
        let after = plain(&mut reference, EF_OATH_CODE.get());
        assert!(!sweep_restarts(
            provision,
            |fs| code_change(fs, old, new) == Sw::OK,
            boot,
            |fs, _, _, completed, medium| {
                let actual = plain(fs, EF_OATH_CODE.get());
                assert!(actual == before || actual == after);
                if completed {
                    assert_eq!(actual, after);
                }
                assert_eq!(medium.value(EF_OTP_PIN), Some(pin.clone()));
                let rng = RefCell::new(CountRng(9));
                let touch = RefCell::new(AlwaysConfirm);
                let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
                select(&mut app, fs);
                assert_eq!(
                    run(&mut app, fs, &apdu(INS_LIST, 0, 0, &[])).0,
                    if actual.is_some() {
                        Sw::SECURITY_STATUS_NOT_SATISFIED
                    } else {
                        Sw::OK
                    }
                );
                assert!(!app.otp_pin_verified);
                retained(fs, medium, &neighbor);
            }
        ));
    }
}

#[path = "restart_migration_tests.rs"]
mod migration;
