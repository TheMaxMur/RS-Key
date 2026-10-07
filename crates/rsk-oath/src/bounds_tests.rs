// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[path = "command_fields_tests.rs"]
mod command_fields;

#[test]
fn public_enumeration_and_bulk_codes_skip_malformed_stored_credentials() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: None,
        latched: false,
    };
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"good", 0x21, 6, SECRET_SHA1, false, None)
        ),
        Sw::OK
    );
    for (offset, body) in [
        tlv(TAG_NAME, b"no-key"),
        tlv(TAG_KEY, &[0x21, 6]),
        [tlv(TAG_NAME, b"empty-key"), tlv(TAG_KEY, &[])].concat(),
    ]
    .iter()
    .enumerate()
    {
        assert!(seal::seal_put(
            &dev,
            &mut fs,
            &mut CountRng(3),
            KeyFid::new(EF_OATH_CRED + 1 + offset as u16),
            body
        ));
    }
    fs.put_key(
        KeyFid::new(EF_OATH_CRED + 4),
        rsk_fs::Sealed::wrap(b"broken seal"),
    )
    .unwrap();
    let mut names = Vec::new();
    assert_eq!(
        for_each_cred(&dev, &mut fs, |cred| names.push(cred.name.to_vec())),
        1
    );
    assert_eq!(names, [b"good".to_vec()]);
    let mut listed = vec![TAG_NAME_LIST, 5, 0x21];
    listed.extend(b"good");
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[])),
        (Sw::OK, listed)
    );
    let mut expected = tlv(TAG_NAME, b"good");
    expected.extend([TAG_RESPONSE + 1, 5, 6]);
    expected.extend(287082u32.to_be_bytes());
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_CALC_ALL, 0, 1, &tlv(TAG_CHALLENGE, &1u64.to_be_bytes()))
        ),
        (Sw::OK, expected)
    );
    let mut calculate = tlv(TAG_NAME, b"no-key");
    calculate.extend(tlv(TAG_CHALLENGE, &[0; 8]));
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 1, &calculate)),
        (Sw::WRONG_DATA, vec![])
    );
    let mut calculate = tlv(TAG_NAME, b"empty-key");
    calculate.extend(tlv(TAG_CHALLENGE, &[0; 8]));
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 1, &calculate)),
        (Sw::WRONG_DATA, vec![])
    );
}

#[test]
fn a_page_whose_current_credential_no_longer_opens_refuses_its_tail() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"credential", 0x21, 6, SECRET_SHA1, false, None)
        ),
        Sw::OK
    );
    let raw = [0, INS_LIST, 0, 0, 4];
    let request = Apdu::parse(&raw).unwrap();
    let mut bytes = [0; 4];
    let mut response = ResBuf::new(&mut bytes);
    let sw = Applet::process(&mut app, &request, &mut fs, &mut response);
    assert_eq!(sw.sw1(), 0x61);
    assert_eq!(response.len(), 4);
    fs.put_key(
        KeyFid::new(EF_OATH_CRED),
        rsk_fs::Sealed::wrap(b"broken seal"),
    )
    .unwrap();
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_SEND_REMAINING, 0, 0, &[])),
        (Sw::MEMORY_FAILURE, vec![])
    );
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_SEND_REMAINING, 0, 0, &[])),
        (Sw::INS_NOT_SUPPORTED, vec![])
    );
}

#[test]
fn bulk_calculate_cannot_emit_a_code_when_its_high_water_mark_write_is_refused() {
    let (mut fs, medium) = new_cut_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut credential = put_data(b"monotonic", 0x21, 6, SECRET_SHA1, false, None);
    credential.extend([TAG_PROPERTY, PROP_INCREASING]);
    assert_eq!(put(&mut app, &mut fs, &credential), Sw::OK);
    let before = medium.value(EF_OATH_CRED);
    medium.arm(0);
    let body = tlv(TAG_CHALLENGE, &1u64.to_be_bytes());
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_CALC_ALL, 0, 1, &body)),
        (Sw::MEMORY_FAILURE, vec![])
    );
    assert_eq!(medium.value(EF_OATH_CRED), before);
    medium.arm(u32::MAX);
    let (sw, response) = run(&mut app, &mut fs, &apdu(INS_CALC_ALL, 0, 1, &body));
    assert_eq!(sw, Sw::OK);
    let mut expected = vec![6];
    expected.extend(287082u32.to_be_bytes());
    assert_eq!(
        find_tag(&response, (TAG_RESPONSE + 1).into()),
        Some(expected.as_slice())
    );
    assert_ne!(medium.value(EF_OATH_CRED), before);
}

#[test]
fn both_tlv_walkers_decode_two_octet_lengths_and_refuse_truncation() {
    let mut bytes = vec![TAG_PWS_METADATA, 0x82, 1, 0];
    bytes.extend(0..=u8::MAX);
    assert_eq!(tlv_at(&bytes, 0), Some((TAG_PWS_METADATA, 4..260)));
    assert_eq!(
        PutIter::new(&bytes).collect::<Vec<_>>(),
        [(TAG_PWS_METADATA, &bytes[4..])]
    );
    for len in 1..bytes.len() {
        assert!(tlv_at(&bytes[..len], 0).is_none());
        let mut iter = PutIter::new(&bytes[..len]);
        assert_eq!(iter.next(), None);
        assert_eq!(iter.rest, &bytes[..len]);
    }
    assert_eq!(find_tag_range(&bytes, TAG_NAME), None);
    assert_eq!(tlv_at(&bytes, bytes.len()), None);
}

#[test]
fn a_tlv_larger_than_the_format_is_refused_before_writing() {
    let mut out = [0x55; 8];
    let mut len = 0;
    assert!(!emit_tlv(
        &mut out,
        &mut len,
        TAG_NAME,
        &vec![0; usize::from(u16::MAX) + 1]
    ));
    assert_eq!(out, [0x55; 8]);
    assert_eq!(len, 0);
}

#[test]
fn every_public_hash_label_is_explicit() {
    for (algo, label) in [
        (ALG_HMAC_SHA1, "SHA1"),
        (ALG_HMAC_SHA256, "SHA256"),
        (ALG_HMAC_SHA512, "SHA512"),
        (0, "?"),
        (u8::MAX, "?"),
    ] {
        assert_eq!(algo_name(algo), label);
    }
}

#[test]
fn a_refused_put_or_rename_preserves_the_previous_credential() {
    let (mut fs, medium) = new_cut_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let old = put_data(b"old", 0x21, 6, SECRET_SHA1, false, None);
    assert_eq!(put(&mut app, &mut fs, &old), Sw::OK);
    let (_, before) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
    medium.arm(0);
    let updated = put_data(b"old", 0x21, 8, SECRET_SHA256, false, None);
    assert_eq!(put(&mut app, &mut fs, &updated), Sw::MEMORY_FAILURE);
    let mut rename = tlv(TAG_NAME, b"old");
    rename.extend(tlv(TAG_NAME, b"new"));
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_RENAME, 0, 0, &rename)).0,
        Sw::MEMORY_FAILURE
    );
    medium.arm(u32::MAX);
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[])),
        (Sw::OK, before)
    );
    let mut request = tlv(TAG_NAME, b"old");
    request.extend(tlv(TAG_CHALLENGE, &1u64.to_be_bytes()));
    let mut expected = vec![TAG_RESPONSE + 1, 5, 6];
    expected.extend(287082u32.to_be_bytes());
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 1, &request)),
        (Sw::OK, expected)
    );
}

#[test]
fn validate_keeps_a_corrupt_access_code_locked() {
    for code in [
        vec![0xff],
        vec![0xff, 0x55],
        vec![ALG_HMAC_SHA1; OATH_CODE_MAX + 1],
    ] {
        let mut fs = new_fs();
        let rng = RefCell::new(CountRng(7));
        let dev = Device {
            serial_hash: &[0x22; 32],
            serial_id: &SERIAL,
            otp_key: None,
            latched: false,
        };
        assert!(seal::seal_put(
            &dev,
            &mut fs,
            &mut *rng.borrow_mut(),
            EF_OATH_CODE,
            &code
        ));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        select(&mut app, &mut fs);
        let mut body = tlv(TAG_RESPONSE, &[0; 20]);
        body.extend(tlv(TAG_CHALLENGE, &[0; 8]));
        let result = run(&mut app, &mut fs, &apdu(INS_VALIDATE, 0, 0, &body));
        assert_eq!(
            result,
            (
                if code.len() <= 2 {
                    Sw::WRONG_DATA
                } else {
                    Sw::DATA_INVALID
                },
                vec![]
            )
        );
        assert!(!app.validated);
        assert_eq!(
            run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[])).0,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
    }
}

#[test]
fn an_inconsistent_apdu_length_never_reads_or_writes_a_body() {
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    for ins in [
        INS_PUT,
        INS_DELETE,
        INS_SET_CODE,
        INS_VALIDATE,
        INS_CALCULATE,
        INS_CALC_ALL,
        INS_VERIFY_CODE,
        INS_RENAME,
        INS_GET_CREDENTIAL,
        INS_SET_PIN,
        INS_CHANGE_PIN,
        INS_VERIFY_PIN,
    ] {
        let mut fs = new_fs();
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        let pin = apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"));
        if matches!(ins, INS_CHANGE_PIN | INS_VERIFY_PIN) {
            assert_eq!(run(&mut app, &mut fs, &pin).0, Sw::OK);
        }
        let mut before = [0; OTP_PIN_REC_V1];
        let size = fs.read(EF_OTP_PIN, &mut before);
        let raw = apdu(ins, 0, 0, &[]);
        let mut request = Apdu::parse(&raw).unwrap();
        // Apdu::parse establishes this bound; direct Applet callers can construct
        // an inconsistent public Apdu, so this exercises the second boundary.
        request.nc = 1;
        let mut bytes = [0x55; 64];
        let mut response = ResBuf::new(&mut bytes);
        assert_eq!(
            Applet::process(&mut app, &request, &mut fs, &mut response),
            Sw::WRONG_LENGTH,
            "INS={ins:02X}"
        );
        assert!(response.is_empty());
        let mut after = [0; OTP_PIN_REC_V1];
        assert_eq!(fs.read(EF_OTP_PIN, &mut after), size);
        assert_eq!(after, before);
        assert!(!fs.has_key(KeyFid::new(EF_OATH_CRED)));
    }
}

#[test]
fn every_data_command_refuses_an_unread_latched_key() {
    fn unread(_: &mut [u8; 32]) -> bool {
        false
    }
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut calc = tlv(TAG_NAME, b"acct");
    calc.extend(tlv(TAG_CHALLENGE, &[0; 8]));
    let mut rename = tlv(TAG_NAME, b"acct");
    rename.extend(tlv(TAG_NAME, b"other"));
    let mut key = vec![ALG_HMAC_SHA1];
    key.extend([0x55; 16]);
    let mut set_code = tlv(TAG_KEY, &key);
    set_code.extend(tlv(TAG_CHALLENGE, &[0; CHALLENGE_LEN]));
    set_code.extend(tlv(
        TAG_RESPONSE,
        &hmac_sha1(&[0x55; 16], &[0; CHALLENGE_LEN]),
    ));
    let mut validate = tlv(TAG_RESPONSE, &[0; 20]);
    validate.extend(tlv(TAG_CHALLENGE, &[0; CHALLENGE_LEN]));
    for (ins, body) in [
        (INS_DELETE, tlv(TAG_NAME, b"acct")),
        (INS_SET_CODE, set_code),
        (INS_LIST, vec![]),
        (INS_VALIDATE, validate),
        (INS_CALCULATE, calc),
        (INS_CALC_ALL, tlv(TAG_CHALLENGE, &[0; 8])),
        (INS_VERIFY_CODE, tlv(TAG_NAME, b"acct")),
        (INS_RENAME, rename),
        (INS_GET_CREDENTIAL, tlv(TAG_NAME, b"acct")),
        (INS_SET_PIN, tlv(TAG_PASSWORD, b"1234")),
    ] {
        let mut fs = new_fs();
        let mut app = OathApplet::new(
            SERIAL,
            [0x22; 32],
            Some(rsk_crypto::FusedKey::latched(unread)),
            &rng,
            &touch,
        );
        assert_eq!(
            run(&mut app, &mut fs, &apdu(ins, 0, 0, &body)),
            (Sw::FUSED_KEY_UNREAD, vec![]),
            "INS={ins:02X}"
        );
        assert!(!fs.has_key(KeyFid::new(EF_OATH_CRED)));
        assert!(!fs.has_key(KeyFid::new(EF_OTP_PIN)));
        assert!(!fs.has_key(EF_OATH_CODE));
    }
}

#[test]
fn verify_code_refuses_unusable_legacy_credential_fields() {
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: None,
        latched: false,
    };
    let mut request = tlv(TAG_NAME, b"acct");
    request.extend(tlv(TAG_RESPONSE, &755224u32.to_be_bytes()));
    let mut cases = vec![(vec![], Sw::DATA_INVALID)];
    for (key, counter, expected) in [
        (&[][..], Some(&[0; 8][..]), Sw::WRONG_DATA),
        (&[0x21, 6][..], Some(&[0; 8][..]), Sw::DATA_INVALID),
        (&[0x11, 6][..], None, Sw::WRONG_DATA),
        (&[0x11, 6][..], Some(&[0; 7][..]), Sw::WRONG_DATA),
        (&[0x1f, 6][..], Some(&[0; 8][..]), Sw::EXEC_ERROR),
        (&[0x11, 0][..], Some(&[0; 8][..]), Sw::DATA_INVALID),
    ] {
        let mut blob = tlv(TAG_NAME, b"acct");
        blob.extend(tlv(TAG_KEY, key));
        if let Some(counter) = counter {
            blob.extend(tlv(TAG_IMF, counter));
        }
        cases.push((blob, expected));
    }
    for (blob, expected) in cases {
        let mut fs = new_fs();
        if !blob.is_empty() {
            assert!(seal::seal_put(
                &dev,
                &mut fs,
                &mut *rng.borrow_mut(),
                KeyFid::new(EF_OATH_CRED),
                &blob
            ));
        }
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        assert_eq!(
            run(&mut app, &mut fs, &apdu(INS_VERIFY_CODE, 0, 0, &request)),
            (expected, vec![]),
            "blob={blob:02X?}"
        );
    }
}

#[test]
fn a_short_verify_code_response_is_not_an_authentication_attempt() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"acct", 0x11, 6, SECRET_SHA1, false, None)
        ),
        Sw::OK
    );
    for (response, expected) in [
        (None, SW_WRONG_DATA),
        (Some(&[0, 0, 0][..]), Sw::WRONG_DATA),
    ] {
        let mut body = tlv(TAG_NAME, b"acct");
        if let Some(response) = response {
            body.extend(tlv(TAG_RESPONSE, response));
        }
        assert_eq!(
            run(&mut app, &mut fs, &apdu(INS_VERIFY_CODE, 0, 0, &body)),
            (expected, vec![])
        );
    }
}

#[test]
fn a_failed_pin_write_does_not_install_an_unlock_secret() {
    let (mut fs, medium) = new_cut_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    medium.arm(0);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
        ),
        (Sw::MEMORY_FAILURE, vec![])
    );
    assert!(!fs.has_key(KeyFid::new(EF_OTP_PIN)));
}

#[test]
fn an_empty_or_unknown_pin_record_cannot_spend_a_retry() {
    let mut fs = new_fs();
    assert!(!OathApplet::spend_otp_retry(&mut fs, &mut []));
    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: None,
        latched: false,
    };
    for record in [vec![], vec![MAX_OTP_COUNTER], vec![MAX_OTP_COUNTER, 0xff]] {
        assert!(!OathApplet::otp_pin_matches(&dev, &record, b"1234"));
    }
    assert!(!fs.has_key(KeyFid::new(EF_OTP_PIN)));
}

#[path = "recovery_decisions_tests.rs"]
mod recovery_decisions;

#[path = "reset_walk_tests.rs"]
mod reset_walk;

#[path = "migration_decisions_tests.rs"]
mod migration_decisions;
