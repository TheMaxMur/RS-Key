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
fn an_empty_or_unknown_access_code_cannot_validate_the_session() {
    for (code, expected) in [
        (&[][..], Sw::DATA_INVALID),
        (&[0x0f, 1][..], Sw::WRONG_DATA),
    ] {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        assert!(seal::seal_put(
            &device(),
            &mut fs,
            &mut CountRng(3),
            EF_OATH_CODE,
            code
        ));
        assert_eq!(select(&mut app, &mut fs).0, Sw::OK);
        assert!(!app.validated);
        let generation = fs.write_gen();
        let body = [tlv(TAG_RESPONSE, &[0; 20]), tlv(TAG_CHALLENGE, &[0; 8])].concat();
        assert_eq!(
            run(&mut app, &mut fs, &apdu(INS_VALIDATE, 0, 0, &body)),
            (expected, vec![])
        );
        assert!(!app.validated);
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(
            run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[])),
            (Sw::SECURITY_STATUS_NOT_SATISFIED, vec![])
        );
    }
}

#[test]
fn hotp_counter_and_legacy_width_follow_their_stored_contracts() {
    for (imf, digits, calculate, verify) in [
        (None, 6, Sw::WRONG_DATA, Sw::WRONG_DATA),
        (Some(&[0; 7][..]), 6, Sw::WRONG_DATA, Sw::WRONG_DATA),
        (Some(&[0; 8][..]), 0, Sw::OK, Sw::DATA_INVALID),
    ] {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        let mut key = vec![0x11, digits];
        key.extend(SECRET_SHA1);
        let mut blob = [tlv(TAG_NAME, b"hotp"), tlv(TAG_KEY, &key)].concat();
        if let Some(imf) = imf {
            blob.extend(tlv(TAG_IMF, imf));
        }
        assert!(seal::seal_put(
            &device(),
            &mut fs,
            &mut CountRng(3),
            KeyFid::new(EF_OATH_CRED),
            &blob
        ));
        let verify_body = [tlv(TAG_NAME, b"hotp"), tlv(TAG_RESPONSE, &[0; 4])].concat();
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                &apdu(INS_VERIFY_CODE, 0, 0, &verify_body)
            ),
            (verify, vec![])
        );
        let mut calculate_body = tlv(TAG_NAME, b"hotp");
        calculate_body.extend(tlv(TAG_CHALLENGE, &[0; 8]));
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                &apdu(INS_CALCULATE, 0, 1, &calculate_body)
            )
            .0,
            calculate
        );
    }
}

#[test]
fn renaming_a_full_legacy_record_refuses_without_replacing_it() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut key = vec![0x21, 6];
    key.extend(SECRET_SHA1);
    let mut blob = [tlv(TAG_NAME, b"a"), tlv(TAG_KEY, &key)].concat();
    blob.extend([TAG_PWS_METADATA, 0x82, 3, 0xdd]);
    blob.extend([0x77; 989]);
    assert_eq!(blob.len(), 1020);
    let fid = KeyFid::new(EF_OATH_CRED);
    assert!(seal::seal_put(
        &device(),
        &mut fs,
        &mut CountRng(3),
        fid,
        &blob
    ));
    let mut before = [0; seal::MAX_BLOB];
    let n = fs.read_key(fid, &mut before).unwrap();
    let generation = fs.write_gen();
    let body = [tlv(TAG_NAME, b"a"), tlv(TAG_NAME, &[b'x'; NAME_MAX])].concat();
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_RENAME, 0, 0, &body)),
        (Sw::FILE_FULL, vec![])
    );
    let mut after = [0; seal::MAX_BLOB];
    assert_eq!(fs.read_key(fid, &mut after), Some(n));
    assert_eq!(after, before);
    assert_eq!(fs.write_gen(), generation);
}
