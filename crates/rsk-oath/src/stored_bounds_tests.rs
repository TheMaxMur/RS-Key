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
fn extended_list_skips_a_legacy_name_that_cannot_fit_its_wire_length() {
    let mut fs = new_fs();
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
    let mut legacy = vec![TAG_NAME, 0x81, 254];
    legacy.extend([b'x'; 254]);
    let mut key = vec![0x21, 6];
    key.extend(SECRET_SHA1);
    legacy.extend(tlv(TAG_KEY, &key));
    assert!(seal::seal_put(
        &device(),
        &mut fs,
        &mut CountRng(3),
        KeyFid::new(EF_OATH_CRED + 1),
        &legacy
    ));
    let generation = fs.write_gen();
    let mut expected = vec![TAG_NAME_LIST, 9, 0x21];
    expected.extend(b"healthy");
    expected.push(0);
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[1])),
        (Sw::OK, expected)
    );
    assert_eq!(fs.write_gen(), generation);
}

#[test]
fn get_omits_only_the_oversized_legacy_password_safe_field() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut legacy = put_data(b"site", 0x21, 6, SECRET_SHA1, false, None);
    legacy.extend(tlv(TAG_PWS_LOGIN, b"login"));
    legacy.extend([TAG_PWS_PASSWORD, 0x82, 1, 0]);
    legacy.extend([0xA5; 256]);
    legacy.extend(tlv(TAG_PWS_METADATA, b"metadata"));
    assert!(seal::seal_put(
        &device(),
        &mut fs,
        &mut CountRng(3),
        KeyFid::new(EF_OATH_CRED),
        &legacy
    ));
    let generation = fs.write_gen();
    let expected = [
        tlv(TAG_NAME, b"site"),
        tlv(TAG_PWS_LOGIN, b"login"),
        tlv(TAG_PWS_METADATA, b"metadata"),
    ]
    .concat();
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"site"))
        ),
        (Sw::OK, expected)
    );
    assert_eq!(fs.write_gen(), generation);
}

#[test]
fn opening_beyond_the_plaintext_ceiling_cannot_touch_even_a_large_output() {
    let oversized = vec![0xA5; seal::MAX_BLOB + 1];
    let mut out = Secret::new([0x5A; CRED_MAX + 1]);
    assert_eq!(seal::open(&device(), &oversized, &mut out), None);
    assert_eq!(out.expose(), &[0x5A; CRED_MAX + 1]);
    let mut fs = new_fs();
    let fid = KeyFid::new(EF_OATH_CRED);
    assert!(seal::seal_put(
        &device(),
        &mut fs,
        &mut CountRng(3),
        fid,
        &[0xA5; CRED_MAX]
    ));
    assert_eq!(
        seal::seal_read(&device(), &mut fs, fid, &mut out),
        Some(CRED_MAX)
    );
    assert_eq!(&out.expose()[..CRED_MAX], &[0xA5; CRED_MAX]);
    assert_eq!(out.expose()[CRED_MAX], 0x5A);
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

#[test]
fn renaming_a_legacy_duplicate_name_changes_only_its_first_name_tlv() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut plaintext = put_data(b"first", 0x21, 6, SECRET_SHA1, false, None);
    plaintext.extend(tlv(TAG_NAME, b"second"));
    let fid = KeyFid::new(EF_OATH_CRED);
    assert!(seal::seal_put(
        &device(),
        &mut fs,
        &mut *rng.borrow_mut(),
        fid,
        &plaintext
    ));
    assert_eq!(select(&mut app, &mut fs).0, Sw::OK);
    let mut pair = tlv(TAG_NAME, b"first");
    pair.extend(tlv(TAG_NAME, b"renamed"));
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_RENAME, 0, 0, &pair)).0,
        Sw::OK
    );
    let mut output = Secret::<[u8; CRED_MAX]>::zeroed();
    let n = seal::seal_read(&device(), &mut fs, fid, &mut output).unwrap();
    let names: Vec<_> = rsk_sdk::tlv::Tlv::new(&output.expose()[..n])
        .filter(|(tag, _)| *tag == TAG_NAME as u16)
        .map(|(_, value)| value.to_vec())
        .collect();
    assert_eq!(names, [b"renamed".to_vec(), b"second".to_vec()]);
}

#[test]
fn an_unvalidated_reselect_keeps_the_access_code_gate_closed() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut code = vec![ALG_HMAC_SHA1];
    code.extend_from_slice(&[0x5a; 16]);
    assert!(seal::seal_put(
        &device(),
        &mut fs,
        &mut *rng.borrow_mut(),
        EF_OATH_CODE,
        &code
    ));
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(select(&mut app, &mut fs).0, Sw::OK);
    assert!(!app.validated);
    let generation = fs.write_gen();
    let mut out = [0; 128];
    assert_eq!(
        Applet::select(&mut app, true, &mut fs, &mut ResBuf::new(&mut out)),
        Sw::OK
    );
    assert!(!app.validated);
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[])).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(fs.write_gen(), generation);
}
