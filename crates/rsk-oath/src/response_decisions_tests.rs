// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn extended_list_marks_each_password_safe_field_independently() {
    for field in [
        None,
        Some(TAG_PWS_LOGIN),
        Some(TAG_PWS_PASSWORD),
        Some(TAG_PWS_METADATA),
    ] {
        for touch_required in [false, true] {
            let mut fs = new_fs();
            let rng = RefCell::new(CountRng(7));
            let touch = RefCell::new(AlwaysConfirm);
            let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
            let mut data = put_data(b"a", 0x21, 6, SECRET_SHA1, touch_required, None);
            if let Some(tag) = field {
                data.extend(tlv(tag, b"value"));
            }
            assert_eq!(put(&mut app, &mut fs, &data), Sw::OK);
            let generation = fs.write_gen();
            let expected = u8::from(touch_required) | if field.is_some() { 4 } else { 0 };
            assert_eq!(
                run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[1])),
                (Sw::OK, vec![TAG_NAME_LIST, 3, 0x21, b'a', expected])
            );
            for request in [&[][..], &[2][..]] {
                assert_eq!(
                    run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, request)),
                    (Sw::OK, vec![TAG_NAME_LIST, 2, 0x21, b'a'])
                );
            }
            assert_eq!(fs.write_gen(), generation);
        }
    }
}

#[test]
fn short_password_safe_replies_only_contain_complete_fields() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut data = put_data(b"a", 0x21, 6, SECRET_SHA1, false, None);
    data.extend(tlv(TAG_PWS_LOGIN, b"alice"));
    data.extend(tlv(TAG_PWS_PASSWORD, b"password"));
    data.extend(tlv(TAG_PWS_METADATA, b"m"));
    assert_eq!(put(&mut app, &mut fs, &data), Sw::OK);
    let generation = fs.write_gen();
    let raw = apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"a"));
    let parsed = Apdu::parse(&raw).unwrap();
    let name = tlv(TAG_NAME, b"a");
    let login = tlv(TAG_PWS_LOGIN, b"alice");
    let password = tlv(TAG_PWS_PASSWORD, b"password");
    let metadata = tlv(TAG_PWS_METADATA, b"m");
    for (capacity, expected) in [
        (0, vec![]),
        (1, vec![]),
        (2, vec![]),
        (3, name.clone()),
        (5, name.clone()),
        (6, [name.clone(), metadata.clone()].concat()),
        (10, [name.clone(), login.clone()].concat()),
        (13, [name.clone(), login.clone(), metadata.clone()].concat()),
        (20, [name.clone(), login.clone(), password.clone()].concat()),
        (
            23,
            [
                name.clone(),
                login.clone(),
                password.clone(),
                metadata.clone(),
            ]
            .concat(),
        ),
    ] {
        let mut backing = [0xA5; 64];
        let mut res = ResBuf::new(&mut backing[..capacity]);
        assert_eq!(
            Applet::process(&mut app, &parsed, &mut fs, &mut res),
            Sw::OK
        );
        assert_eq!(res.as_slice(), expected);
        assert_eq!(&backing[expected.len()..], &[0xA5; 64][expected.len()..]);
        assert_eq!(fs.write_gen(), generation);
    }
    assert_eq!(
        run(&mut app, &mut fs, &raw),
        (Sw::OK, [name, login, password, metadata].concat())
    );
}
