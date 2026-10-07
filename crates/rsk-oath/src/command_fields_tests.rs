// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn extended_put(body: &[u8]) -> Vec<u8> {
    let mut request = vec![0, INS_PUT, 0, 0, 0];
    request.extend(u16::try_from(body.len()).unwrap().to_be_bytes());
    request.extend(body);
    request
}

#[test]
fn an_unsupported_access_code_algorithm_cannot_install_a_code() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let challenge = [0u8; CHALLENGE_LEN];
    let mut key = vec![0];
    key.extend(SECRET_SHA1);
    let mut body = tlv(TAG_KEY, &key);
    body.extend(tlv(TAG_CHALLENGE, &challenge));
    body.extend(tlv(TAG_RESPONSE, &hmac_sha1(SECRET_SHA1, &challenge)));
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_SET_CODE, 0, 0, &body)),
        (Sw::WRONG_DATA, vec![])
    );
    assert!(!fs.has_key(EF_OATH_CODE));
    assert!(app.validated);
    body[2] = ALG_HMAC_SHA1;
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_SET_CODE, 0, 0, &body)),
        (Sw::OK, vec![])
    );
    assert!(fs.has_key(EF_OATH_CODE));
}

#[test]
fn a_rename_without_its_second_name_preserves_the_credential() {
    let (mut fs, medium) = new_cut_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"old", 0x21, 6, SECRET_SHA1, false, None)
        ),
        Sw::OK
    );
    let before = medium.value(EF_OATH_CRED);
    let mut body = tlv(TAG_NAME, b"old");
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_RENAME, 0, 0, &body)),
        (SW_WRONG_DATA, vec![])
    );
    assert_eq!(medium.value(EF_OATH_CRED), before);
    body.extend(tlv(TAG_NAME, b"new"));
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_RENAME, 0, 0, &body)),
        (Sw::OK, vec![])
    );
    let mut expected = vec![TAG_NAME_LIST, 4, 0x21];
    expected.extend(b"new");
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[])),
        (Sw::OK, expected)
    );
}

#[test]
fn malformed_get_names_cannot_return_a_password_safe_record() {
    let (mut fs, medium) = new_cut_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut credential = put_data(b"site", 0x21, 6, SECRET_SHA1, false, None);
    credential.extend(tlv(TAG_PWS_PASSWORD, b"password"));
    assert_eq!(put(&mut app, &mut fs, &credential), Sw::OK);
    let before = medium.value(EF_OATH_CRED);
    let wrong_first = [tlv(TAG_KEY, b"site"), tlv(TAG_NAME, b"site")].concat();
    for body in [wrong_first, vec![TAG_NAME, 4, b's']] {
        assert_eq!(
            run(&mut app, &mut fs, &apdu(INS_GET_CREDENTIAL, 0, 0, &body)),
            (SW_WRONG_DATA, vec![])
        );
        assert_eq!(medium.value(EF_OATH_CRED), before);
    }
    let (sw, body) = run(
        &mut app,
        &mut fs,
        &apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"site")),
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(
        find_tag(&body, TAG_PWS_PASSWORD.into()),
        Some(b"password".as_slice())
    );
}

#[test]
fn a_refused_individual_mark_write_cannot_emit_a_code() {
    let (mut fs, medium) = new_cut_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut credential = put_data(b"monotonic", 0x21, 6, SECRET_SHA1, false, None);
    credential.extend([TAG_PROPERTY, PROP_INCREASING]);
    assert_eq!(put(&mut app, &mut fs, &credential), Sw::OK);
    let before = medium.value(EF_OATH_CRED);
    let body = [
        tlv(TAG_NAME, b"monotonic"),
        tlv(TAG_CHALLENGE, &1u64.to_be_bytes()),
    ]
    .concat();
    let request = apdu(INS_CALCULATE, 0, 1, &body);
    medium.arm(0);
    assert_eq!(
        run(&mut app, &mut fs, &request),
        (Sw::MEMORY_FAILURE, vec![])
    );
    assert_eq!(medium.value(EF_OATH_CRED), before);
    medium.arm(u32::MAX);
    let mut expected = vec![TAG_RESPONSE + 1, 5, 6];
    expected.extend(287082u32.to_be_bytes());
    assert_eq!(run(&mut app, &mut fs, &request), (Sw::OK, expected));
    assert_eq!(run(&mut app, &mut fs, &request), (Sw::WRONG_DATA, vec![]));
}

#[test]
fn bulk_hotp_with_an_increasing_property_keeps_its_counter_unspent() {
    let (mut fs, medium) = new_cut_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut credential = put_data(b"hotp", 0x11, 6, SECRET_SHA1, false, None);
    credential.extend([TAG_PROPERTY, PROP_INCREASING]);
    assert_eq!(put(&mut app, &mut fs, &credential), Sw::OK);
    let before = medium.value(EF_OATH_CRED);
    let challenge = tlv(TAG_CHALLENGE, &1u64.to_be_bytes());
    let mut expected = tlv(TAG_NAME, b"hotp");
    expected.extend([TAG_NO_RESPONSE, 1, 6]);
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_CALC_ALL, 0, 1, &challenge)),
        (Sw::OK, expected)
    );
    assert_eq!(medium.value(EF_OATH_CRED), before);
    let body = [tlv(TAG_NAME, b"hotp"), challenge].concat();
    let mut expected = vec![TAG_RESPONSE + 1, 5, 6];
    expected.extend(755224u32.to_be_bytes());
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 1, &body)),
        (Sw::OK, expected)
    );
}

#[test]
fn a_password_safe_value_beyond_one_octet_cannot_be_stored() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    for tag in [TAG_PWS_LOGIN, TAG_PWS_PASSWORD, TAG_PWS_METADATA] {
        let mut body = put_data(b"site", 0x21, 6, SECRET_SHA1, false, None);
        body.extend([tag, 0x82, 1, 0]);
        body.extend([0xA5; 256]);
        assert_eq!(
            run(&mut app, &mut fs, &extended_put(&body)),
            (Sw::WRONG_DATA, vec![])
        );
        assert!(!fs.has_key(KeyFid::new(EF_OATH_CRED)));
    }
    let mut body = put_data(b"site", 0x21, 6, SECRET_SHA1, false, None);
    body.extend([TAG_PWS_PASSWORD, 0x81, u8::MAX]);
    body.extend([0xA5; 255]);
    assert_eq!(
        run(&mut app, &mut fs, &extended_put(&body)),
        (Sw::OK, vec![])
    );
    let (sw, answer) = run(
        &mut app,
        &mut fs,
        &apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"site")),
    );
    assert_eq!(sw, Sw::OK);
    let mut expected = tlv(TAG_NAME, b"site");
    expected.extend([TAG_PWS_PASSWORD, u8::MAX]);
    expected.extend([0xA5; 255]);
    assert_eq!(answer, expected);
}
