// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn device() -> Device<'static> {
    Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: None,
        latched: false,
    }
}

#[test]
fn a_legacy_plaintext_access_code_migrates_without_changing_mutual_authentication() {
    let (mut fs, medium) = new_cut_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"protected", 0x21, 6, SECRET_SHA1, false, None)
        ),
        Sw::OK
    );
    let mut legacy = vec![ALG_HMAC_SHA1];
    legacy.extend(SECRET_SHA1);
    fs.put_key(EF_OATH_CODE, rsk_fs::Sealed::wrap(&legacy))
        .unwrap();
    assert!(!migrate_seal(&device(), &mut fs, &mut *rng.borrow_mut()));
    let sealed = medium.value(EF_OATH_CODE.get()).unwrap();
    assert_ne!(sealed, legacy);
    let generation = fs.write_gen();
    assert!(!migrate_seal(&device(), &mut fs, &mut *rng.borrow_mut()));
    assert_eq!(medium.value(EF_OATH_CODE.get()), Some(sealed));
    assert_eq!(fs.write_gen(), generation);
    let (sw, selected) = select(&mut app, &mut fs);
    assert_eq!(sw, Sw::OK);
    let challenge = find_tag(&selected, TAG_CHALLENGE.into()).unwrap();
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[])),
        (Sw::SECURITY_STATUS_NOT_SATISFIED, vec![])
    );
    let host_challenge = [9; CHALLENGE_LEN];
    let validate = [
        tlv(TAG_RESPONSE, &hmac_sha1(SECRET_SHA1, challenge)),
        tlv(TAG_CHALLENGE, &host_challenge),
    ]
    .concat();
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_VALIDATE, 0, 0, &validate)),
        (
            Sw::OK,
            tlv(TAG_RESPONSE, &hmac_sha1(SECRET_SHA1, &host_challenge))
        )
    );
    let body = [
        tlv(TAG_NAME, b"protected"),
        tlv(TAG_CHALLENGE, &1u64.to_be_bytes()),
    ]
    .concat();
    let mut expected = vec![TAG_RESPONSE + 1, 5, 6];
    expected.extend(287082u32.to_be_bytes());
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 1, &body)),
        (Sw::OK, expected)
    );
}

#[test]
fn oversized_and_incomplete_legacy_records_are_preserved_without_resealing() {
    let bad = [
        vec![0xA5; seal::MAX_BLOB + 1],
        vec![0xA5; CRED_MAX + 1],
        tlv(TAG_NAME, b"missing-key"),
    ];
    for legacy in bad {
        let (mut fs, medium) = new_cut_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        assert_eq!(
            put(
                &mut app,
                &mut fs,
                &put_data(b"healthy", 0x21, 6, SECRET_SHA1, false, None)
            ),
            Sw::OK
        );
        let healthy = medium.value(EF_OATH_CRED);
        let bad_fid = KeyFid::new(EF_OATH_CRED + 1);
        fs.put_key(bad_fid, rsk_fs::Sealed::wrap(&legacy)).unwrap();
        let generation = fs.write_gen();
        for _ in 0..2 {
            assert!(!migrate_seal(&device(), &mut fs, &mut *rng.borrow_mut()));
            assert_eq!(medium.value(bad_fid.get()), Some(legacy.clone()));
            assert_eq!(medium.value(EF_OATH_CRED), healthy);
            assert_eq!(fs.write_gen(), generation);
        }
        let body = [
            tlv(TAG_NAME, b"healthy"),
            tlv(TAG_CHALLENGE, &1u64.to_be_bytes()),
        ]
        .concat();
        let mut expected = vec![TAG_RESPONSE + 1, 5, 6];
        expected.extend(287082u32.to_be_bytes());
        assert_eq!(
            run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 1, &body)),
            (Sw::OK, expected)
        );
    }
}

#[test]
fn interrupted_access_code_migration_and_recovery_preserve_the_authentication_key() {
    let mut legacy = vec![ALG_HMAC_SHA1];
    legacy.extend(SECRET_SHA1);
    rsk_fs::cut::sweep_recovery(
        |fs| {
            fs.put_key(EF_OATH_CODE, rsk_fs::Sealed::wrap(&legacy))
                .unwrap();
        },
        |fs, ()| {
            migrate_seal(&device(), fs, &mut CountRng(7));
        },
        |fs| {
            let mut raw = [0; seal::MAX_BLOB];
            let n = fs.read_key(EF_OATH_CODE, &mut raw).unwrap();
            if raw[..n] != legacy {
                let mut plaintext = Secret::<[u8; CRED_MAX]>::zeroed();
                let n = seal::open(&device(), &raw[..n], &mut plaintext).unwrap();
                assert_eq!(&plaintext.expose()[..n], &legacy);
            }
            migrate_seal(&device(), fs, &mut CountRng(7));
        },
        |fs, _, _| {
            let generation = fs.write_gen();
            assert!(!migrate_seal(&device(), fs, &mut CountRng(7)));
            assert_eq!(fs.write_gen(), generation);
            let rng = RefCell::new(CountRng(7));
            let touch = RefCell::new(AlwaysConfirm);
            let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
            let (_, selected) = select(&mut app, fs);
            let challenge = find_tag(&selected, TAG_CHALLENGE.into()).unwrap();
            let host = [9; CHALLENGE_LEN];
            let body = [
                tlv(TAG_RESPONSE, &hmac_sha1(SECRET_SHA1, challenge)),
                tlv(TAG_CHALLENGE, &host),
            ]
            .concat();
            assert_eq!(
                run(&mut app, fs, &apdu(INS_VALIDATE, 0, 0, &body)),
                (Sw::OK, tlv(TAG_RESPONSE, &hmac_sha1(SECRET_SHA1, &host)))
            );
        },
    );
}
