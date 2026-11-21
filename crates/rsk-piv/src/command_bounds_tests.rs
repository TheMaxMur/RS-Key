// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn crypto_rng_bridges_forward_the_whole_requested_window() {
    struct Entropy(Vec<usize>);
    impl Rng for Entropy {
        fn fill(&mut self, bytes: &mut [u8]) {
            self.0.push(bytes.len());
            bytes.fill(0x43);
        }
    }
    for rsa in [false, true] {
        let mut entropy = Entropy(vec![]);
        for n in [0, 1, 16, 32, 64] {
            let mut bytes = [0xa5; 66];
            if rsa {
                rsk_rsa::Rng::fill(&mut RsaRng(&mut entropy), &mut bytes[1..n + 1]);
            } else {
                rsk_ec::Rng::fill(&mut EcRng(&mut entropy), &mut bytes[1..n + 1]);
            }
            assert_eq!(&bytes[1..n + 1], vec![0x43; n]);
            assert_eq!(bytes[0], 0xa5);
            assert!(bytes[n + 1..].iter().all(|byte| *byte == 0xa5));
        }
        assert_eq!(entropy.0, [0, 1, 16, 32, 64]);
    }
}

#[test]
fn a_short_object_id_cannot_alias_a_pooled_object() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    let object = object_body([0x5f, 0x12, 0x34], b"stored");
    assert_eq!(
        run(&mut app, &mut fs, INS_PUT_DATA, 0x3f, 0xff, &object).0,
        Sw::OK
    );
    assert_eq!(
        run(&mut app, &mut fs, INS_GET_DATA, 0x3f, 0xff, &object[..5]),
        (Sw::OK, [b"\x53\x06".as_slice(), b"stored"].concat())
    );
    let generation = fs.write_gen();
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_GET_DATA,
            0x3f,
            0xff,
            &[TAG_DATA_PATH, 2, 0x12, 0x34]
        ),
        (Sw::FILE_NOT_FOUND, vec![])
    );
    assert_eq!(fs.write_gen(), generation);
}

#[test]
fn management_protection_preserves_the_maximum_timestamp() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let fid = EF_PIVMAN_DATA;
    let mut prior = vec![PIVMAN_TAG, 18, PIVMAN_TS_TAG, 16];
    prior.extend([0x55; 16]);
    fs.put(fid, &prior).unwrap();
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
        latched: false,
    };
    assert_eq!(
        protect_mgm_key(&dev, &mut fs, &mut *rng.borrow_mut()),
        Sw::OK
    );
    let mut stored = [0; 64];
    let n = fs.read(fid, &mut stored).unwrap();
    let mut expected = vec![
        PIVMAN_TAG,
        21,
        PIVMAN_FLAGS_TAG,
        1,
        PIVMAN_FLAG_MGM_PROTECTED,
        PIVMAN_TS_TAG,
        16,
    ];
    expected.extend([0x55; 16]);
    assert_eq!(&stored[..n], expected);
}

#[test]
fn reset_requires_both_references_to_be_blocked_independently() {
    for (pin_left, puk_left) in [(0, 0), (0, 1), (1, 0), (1, 1)] {
        let rng = RefCell::new(TestRng(7));
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                INS_ASYM_KEYGEN,
                0,
                SLOT_AUTHENTICATION,
                &gen_template(ALGO_ECCP256)
            )
            .0,
            Sw::OK
        );
        set_retries_left(&mut fs, RETRY_PIN, pin_left).unwrap();
        set_retries_left(&mut fs, RETRY_PUK, puk_left).unwrap();
        let generation = fs.write_gen();
        let result = run(&mut app, &mut fs, INS_RESET, 0, 0, &[]);
        if pin_left == 0 && puk_left == 0 {
            assert_eq!(result, (Sw::OK, vec![]));
            assert!(!fs.has_key(key_fid(SLOT_AUTHENTICATION)));
            assert!(!app.sess.has_pin && !app.sess.pin_fresh && !app.sess.has_mgm);
            assert_eq!(retries_left(&mut fs, RETRY_PIN), Ok(DEFAULT_RETRIES));
            assert_eq!(retries_left(&mut fs, RETRY_PUK), Ok(DEFAULT_RETRIES));
        } else {
            assert_eq!(
                result,
                (Sw::WRONG_DATA, vec![]),
                "PIN={pin_left}, PUK={puk_left}"
            );
            assert_eq!(fs.write_gen(), generation);
            assert!(fs.has_key(key_fid(SLOT_AUTHENTICATION)));
            assert!(app.sess.has_pin && app.sess.pin_fresh && app.sess.has_mgm);
            assert_eq!(retries_left(&mut fs, RETRY_PIN), Ok(pin_left));
            assert_eq!(retries_left(&mut fs, RETRY_PUK), Ok(puk_left));
        }
    }
}

#[test]
fn data_paths_outside_the_supported_width_preserve_the_card() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    for path in [&[0x5C, 0, 0][..], &[0x5C, 4, 0, 0, 0, 0][..]] {
        let generation = fs.write_gen();
        assert_eq!(
            run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, path),
            (Sw::FILE_NOT_FOUND, vec![])
        );
        assert_eq!(fs.write_gen(), generation);
        assert!(app.sess.has_pin && app.sess.pin_fresh && app.sess.has_mgm);
    }
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_GET_DATA,
            0x3F,
            0xFF,
            &[0x5C, 1, DISCOVERY_ID as u8]
        )
        .0,
        Sw::OK
    );
}

#[test]
fn printed_data_swallows_only_a_complete_management_key_escrow() {
    for (outer, key_len, bytes, escrow) in [
        (18, 16, 16, true),
        (19, 16, 16, false),
        (18, 15, 16, false),
        (22, 20, 20, false),
    ] {
        let rng = RefCell::new(TestRng(7));
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        let path = [TAG_DATA_PATH, 3, 0x5F, 0xC1, 9];
        let original = [TAG_DATA_OBJECT, 1, 0x42];
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                INS_PUT_DATA,
                0x3F,
                0xFF,
                &[path.as_slice(), &original].concat()
            )
            .0,
            Sw::OK
        );
        let mut body = vec![PROTECTED_TAG, outer, PROTECTED_MGM_TAG, key_len];
        body.extend(vec![0x5A; bytes]);
        let mut object = vec![TAG_DATA_OBJECT, body.len() as u8];
        object.extend_from_slice(&body);
        let generation = fs.write_gen();
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                INS_PUT_DATA,
                0x3F,
                0xFF,
                &[path.as_slice(), &object].concat()
            ),
            (Sw::OK, vec![])
        );
        if escrow {
            assert_eq!(fs.write_gen(), generation);
        }
        assert_eq!(
            run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &path),
            (Sw::OK, if escrow { original.to_vec() } else { object })
        );
        assert!(app.sess.has_pin && app.sess.pin_fresh && app.sess.has_mgm);
    }
}

#[test]
fn command_parameter_refusals_leave_management_key_and_pin_in_force() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    for (ins, p1, p2, body, expected) in [
        (
            INS_ATTESTATION,
            SLOT_AUTHENTICATION,
            1,
            &[][..],
            Sw::INCORRECT_P1P2,
        ),
        (INS_RESET, 1, 0, &[][..], Sw::INCORRECT_P1P2),
        (INS_RESET, 0, 1, &[][..], Sw::INCORRECT_P1P2),
        (INS_GET_METADATA, 1, REF_PIN, &[][..], Sw::INCORRECT_P1P2),
        (INS_SET_MGMKEY, 0, 0xff, &[][..], Sw::INCORRECT_P1P2),
        (INS_SET_MGMKEY, 0xff, 0, &[][..], Sw::INCORRECT_P1P2),
        (INS_SET_MGMKEY, 0xff, 0xff, &[][..], Sw::WRONG_LENGTH),
        (
            INS_SET_MGMKEY,
            0xff,
            0xff,
            &[ALGO_AES128, SLOT_AUTHENTICATION, 16, 0, 0][..],
            Sw::WRONG_DATA,
        ),
        (
            INS_SET_MGMKEY,
            0xff,
            0xff,
            &[ALGO_AES128, SLOT_CARDMGM, 15, 0, 0][..],
            Sw::WRONG_DATA,
        ),
        (
            INS_SET_MGMKEY,
            0xff,
            0xff,
            &[ALGO_AES128, SLOT_CARDMGM, 16, 0, 0][..],
            Sw::WRONG_LENGTH,
        ),
        (
            INS_ASYM_KEYGEN,
            0,
            SLOT_AUTHENTICATION,
            &[0xac, 0][..],
            Sw::WRONG_DATA,
        ),
        (
            INS_ASYM_KEYGEN,
            0,
            SLOT_AUTHENTICATION,
            &[0xac, 3, 0x80, 1, 0xff][..],
            Sw::WRONG_DATA,
        ),
    ] {
        let (sw, out) = run(&mut app, &mut fs, ins, p1, p2, body);
        assert_eq!(sw, expected, "ins={ins:#x}, p1={p1:#x}, p2={p2:#x}");
        assert!(out.is_empty());
        assert!(app.sess.has_pin);
        assert!(app.sess.has_mgm);
        assert!(!fs.has_key(key_fid(SLOT_AUTHENTICATION)));
    }
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
}

#[test]
fn rsa_shortcut_declines_invalid_parameters_before_the_prime_search() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let template = gen_template(ALGO_RSA2048);
    assert!(
        app.rsa_generate_params(&mut fs, 0, SLOT_AUTHENTICATION, &template)
            .is_none()
    );
    auth_mgm(&mut app, &mut fs);
    for (p1, slot, body) in [
        (1, SLOT_AUTHENTICATION, template.as_slice()),
        (0, SLOT_CARDMGM, template.as_slice()),
        (0, SLOT_AUTHENTICATION, &[][..]),
        (
            0,
            SLOT_AUTHENTICATION,
            &[0xac, 3, 0x80, 1, ALGO_ECCP256][..],
        ),
    ] {
        assert!(app.rsa_generate_params(&mut fs, p1, slot, body).is_none());
        assert!(!fs.has_key(key_fid(SLOT_AUTHENTICATION)));
    }
    assert_eq!(
        app.rsa_generate_params(&mut fs, 0, SLOT_AUTHENTICATION, &template),
        Some((
            SLOT_AUTHENTICATION,
            2048,
            [PINPOLICY_ONCE, TOUCHPOLICY_NEVER]
        ))
    );
}

#[test]
fn incomplete_metadata_never_returns_a_partial_success_record() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    for reference in [REF_PIN, REF_PUK] {
        let fid = if reference == REF_PIN { EF_PIN } else { EF_PUK };
        let mut original = [0; PIN_REC_LEN];
        assert_eq!(fs.read(fid, &mut original), Some(PIN_REC_LEN));
        for len in [0, 1, PIN_REC_LEN - 1] {
            fs.put(fid, &original[..len]).unwrap();
            let (sw, body) = run(&mut app, &mut fs, INS_GET_METADATA, 0, reference, &[]);
            assert_eq!(sw, Sw::REFERENCE_NOT_FOUND);
            assert!(body.is_empty());
        }
        fs.put(fid, &original).unwrap();
    }
    fs.put(EF_RETRIES, &[3, 3, 3]).unwrap();
    for (ins, reference) in [
        (INS_VERIFY, REF_PIN),
        (INS_GET_METADATA, REF_PIN),
        (INS_RESET, 0),
    ] {
        let (sw, body) = run(&mut app, &mut fs, ins, 0, reference, &[]);
        assert_eq!(sw, Sw::REFERENCE_NOT_FOUND);
        assert!(body.is_empty());
    }
    fs.meta_delete(key_fid(SLOT_CARDMGM).get()).unwrap();
    for head in [&[][..], &[ALGO_AES192], &[ALGO_AES192, MGM_PIN_POLICY]] {
        fs.meta_add(key_fid(SLOT_CARDMGM).get(), head).unwrap();
        let (sw, body) = run(&mut app, &mut fs, INS_GET_METADATA, 0, SLOT_CARDMGM, &[]);
        assert_eq!(sw, Sw::REFERENCE_NOT_FOUND);
        assert!(body.is_empty());
    }
    fs.meta_add(
        key_fid(SLOT_AUTHENTICATION).get(),
        &[ALGO_ECCP256, PINPOLICY_ONCE, TOUCHPOLICY_NEVER],
    )
    .unwrap();
    let (sw, body) = run(
        &mut app,
        &mut fs,
        INS_GET_METADATA,
        0,
        SLOT_AUTHENTICATION,
        &[],
    );
    assert_eq!(sw, Sw::REFERENCE_NOT_FOUND);
    assert!(body.is_empty());
}

#[test]
fn a_short_select_response_never_reports_success() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    let expected = select(&mut app, &mut fs);
    for cap in 0..=expected.len() {
        let mut out = vec![0; cap];
        let mut response = ResBuf::new(&mut out);
        let sw = Applet::select(&mut app, true, &mut fs, &mut response);
        assert_eq!(
            sw,
            if cap == expected.len() {
                Sw::OK
            } else {
                Sw::WRONG_LENGTH
            }
        );
        assert_eq!(response.as_slice(), &expected[..response.len()]);
    }
}

#[test]
fn data_object_and_public_key_responses_refuse_truncation() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            SLOT_AUTHENTICATION,
            &gen_template(ALGO_ECCP256)
        )
        .0,
        Sw::OK
    );
    for raw in [
        apdu_bytes(INS_GET_DATA, 0x3f, 0xff, &[0x5c, 3, 0x5f, 0xc1, 2]),
        apdu_bytes(INS_GET_METADATA, 0, SLOT_AUTHENTICATION, &[]),
    ] {
        let apdu = Apdu::parse(&raw).unwrap();
        let mut full = [0; 256];
        let mut response = ResBuf::new(&mut full);
        assert_eq!(
            Applet::process(&mut app, &apdu, &mut fs, &mut response),
            Sw::OK
        );
        let expected = response.as_slice().to_vec();
        for cap in 0..=expected.len() {
            let mut out = vec![0; cap];
            let mut response = ResBuf::new(&mut out);
            assert_eq!(
                Applet::process(&mut app, &apdu, &mut fs, &mut response),
                if cap == expected.len() {
                    Sw::OK
                } else {
                    Sw::WRONG_LENGTH
                },
                "ins={:#x}, cap={cap}",
                apdu.ins
            );
            if cap == expected.len() {
                assert_eq!(response.as_slice(), expected);
            }
        }
    }
}

#[test]
fn dynamic_auth_response_refuses_every_short_buffer() {
    for payload_len in [0, 8, 16, 128, 256] {
        let payload = vec![0xa5; payload_len];
        let mut full = vec![0; payload_len + 12];
        let mut response = ResBuf::new(&mut full);
        dyn_auth_resp(&mut response, 0x82, &payload).unwrap();
        let expected = response.as_slice().to_vec();
        for cap in 0..=expected.len() {
            let mut out = vec![0; cap];
            let mut response = ResBuf::new(&mut out);
            assert_eq!(
                dyn_auth_resp(&mut response, 0x82, &payload),
                if cap == expected.len() {
                    Ok(())
                } else {
                    Err(Sw::WRONG_LENGTH)
                }
            );
            assert_eq!(response.as_slice(), &expected[..response.len()]);
        }
    }
}

#[test]
fn set_retries_reports_a_refused_write_without_revoking_verified_status() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut refusals = 0;
    let mut completed = 0;
    for budget in 0..=5 {
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        let (mut fs, medium) = new_cut_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        medium.arm(budget);
        let (sw, out) = run(&mut app, &mut fs, INS_SET_RETRIES, 5, 4, &[]);
        assert!(out.is_empty());
        match sw {
            Sw::MEMORY_FAILURE => {
                refusals += 1;
                assert!(app.sess.has_pin);
            }
            Sw::OK => {
                completed += 1;
                assert!(!app.sess.has_pin);
            }
            other => panic!("budget {budget}: {other:?}"),
        }
        medium.arm(u32::MAX);
        verify_pin(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
    }
    assert!(refusals > 0 && completed > 0);
}
