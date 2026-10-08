// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn an_unread_signature_counter_refuses_get_data_then_recovers_without_writing() {
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    let rng = RefCell::new(CountRng(7));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let mut out = [0; 64];
    assert_eq!(
        app.select(false, &mut fs, &mut ResBuf::new(&mut out)),
        Sw::OK
    );
    let request = [0, consts::INS_GET_DATA, 0, consts::EF_SEC_TPL as u8];
    let baseline = run(&mut app, &mut fs, &request);
    assert_eq!(baseline, (vec![0x7a, 5, 0x93, 3, 0, 0, 0], Sw::OK));
    let generation = fs.write_gen();
    medium.stick(Some(consts::EF_SIG_COUNT));
    assert_eq!(
        run(&mut app, &mut fs, &request),
        (vec![], Sw::MEMORY_FAILURE)
    );
    assert_eq!(fs.write_gen(), generation);
    medium.stick(None);
    assert_eq!(run(&mut app, &mut fs, &request), baseline);
    assert_eq!(fs.write_gen(), generation);
}

#[test]
fn legacy_two_prime_cfb_keys_migrate_through_both_rsa_readers() {
    use rsk_crypto::aes::aes_encrypt_cfb_256;
    use rsk_secret::Secret;
    for signing in [false, true] {
        let rng = RefCell::new(CountRng(7));
        let presence = RefCell::new(crate::AlwaysConfirm);
        let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
        let mut fs = make_fs();
        verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
        let mut dek = Secret::<[u8; consts::DEK_SIZE]>::zeroed();
        crate::pin::load_dek(&dev(), &mut fs, &app.sess, &mut dek).unwrap();
        let mut key = Secret::<[u8; 32]>::zeroed();
        key.expose_mut()
            .copy_from_slice(&dek.expose()[consts::IV_SIZE..]);
        let mut iv = Secret::<[u8; consts::IV_SIZE]>::zeroed();
        iv.expose_mut()
            .copy_from_slice(&dek.expose()[..consts::IV_SIZE]);
        let mut legacy = Secret::<[u8; 256]>::zeroed();
        legacy.expose_mut()[..128].copy_from_slice(&hx(RSA_P));
        legacy.expose_mut()[128..].copy_from_slice(&hx(RSA_Q));
        aes_encrypt_cfb_256(key.expose(), iv.expose(), legacy.expose_mut()).unwrap();
        fs.put_key(consts::EF_PK_SIG, rsk_fs::Sealed::wrap(legacy.expose()))
            .unwrap();
        if signing {
            verify_pin(&mut app, &mut fs, consts::PW1_MODE81, consts::PW1_DEFAULT);
            let (hash, signature) = rsk_rsa::vectors::SIGN_SHA256[0];
            let data = [DI_SHA256, &hx(hash)].concat();
            let mut raw = vec![0, consts::INS_PSO, 0x9e, 0x9a, data.len() as u8];
            raw.extend_from_slice(&data);
            let (actual, sw) = run(&mut app, &mut fs, &raw);
            assert_eq!(sw, Sw::OK);
            assert_eq!(actual, hx(signature));
        } else {
            let loaded =
                crate::keys::load_rsa_key(&dev(), &mut fs, &app.sess, consts::EF_PK_SIG).unwrap();
            assert_eq!(loaded.n_be(), hx(rsk_rsa::vectors::N_HEX));
            assert_eq!(loaded.e_be(), rsk_rsa::RSA_PUB_EXP_BE);
        }
        assert_eq!(
            fs.size(consts::EF_PK_SIG.get()),
            Some(5 * 128 + crate::keys::DEK_SEAL_OVERHEAD)
        );
        let generation = fs.write_gen();
        let loaded =
            crate::keys::load_rsa_key(&dev(), &mut fs, &app.sess, consts::EF_PK_SIG).unwrap();
        assert_eq!(loaded.n_be(), hx(rsk_rsa::vectors::N_HEX));
        assert_eq!(fs.write_gen(), generation);
    }
}

#[test]
fn each_empty_rsa_component_refuses_import_without_replacing_the_key() {
    let rng = RefCell::new(CountRng(7));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let mut fs = make_fs();
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    let e = rsk_rsa::RSA_PUB_EXP_BE;
    let p = hx(RSA_P);
    let q = hx(RSA_Q);
    assert_eq!(
        run(&mut app, &mut fs, &rsa_import(consts::CRT_SIG, e, &p, &q)).1,
        Sw::OK
    );
    let mut original = [0; 1024];
    let n = fs.read(consts::EF_PK_SIG.get(), &mut original).unwrap();
    let generation = fs.write_gen();
    for (e, p, q) in [
        (&[][..], &p[..], &q[..]),
        (e, &[][..], &q[..]),
        (e, &p[..], &[][..]),
    ] {
        assert_eq!(
            run(&mut app, &mut fs, &rsa_import(consts::CRT_SIG, e, p, q)),
            (vec![], Sw::WRONG_DATA)
        );
        assert_eq!(fs.write_gen(), generation);
        assert!(app.sess.has_pw3);
        let mut retained = [0; 1024];
        assert_eq!(fs.read(consts::EF_PK_SIG.get(), &mut retained), Some(n));
        assert_eq!(retained, original);
    }
}

#[test]
fn refused_put_data_writes_preserve_the_previous_value_and_admin_grant() {
    use rsk_fs::storage::faults::Cut;
    for (tag, target, before, after) in [
        (
            consts::EF_CH_CERT,
            consts::EF_CH_1,
            &b"old certificate"[..],
            &b"new certificate"[..],
        ),
        (
            consts::EF_LOGIN_DATA,
            consts::EF_LOGIN_DATA,
            &b"old login"[..],
            &b"new login"[..],
        ),
        (
            consts::EF_UIF_SIG,
            consts::EF_UIF_SIG,
            &[1, 0][..],
            &[0, 0][..],
        ),
        (consts::EF_PW_STATUS, consts::EF_PW_PRIV, &[1][..], &[0][..]),
    ] {
        let rng = RefCell::new(CountRng(7));
        let presence = RefCell::new(crate::AlwaysConfirm);
        let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
        let (backend, medium) = Cut::new();
        let mut fs = Fs::new(backend);
        fs.scan();
        scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
        verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
        assert_eq!(
            put(&mut app, &mut fs, (tag >> 8) as u8, tag as u8, before),
            Sw::OK
        );
        let original = medium.value(target).unwrap();
        let generation = fs.write_gen();
        medium.arm(0);
        assert_eq!(
            put(&mut app, &mut fs, (tag >> 8) as u8, tag as u8, after),
            Sw::MEMORY_FAILURE
        );
        assert_eq!(medium.value(target), Some(original));
        assert_eq!(fs.write_gen(), generation);
        assert!(app.sess.has_pw3);
        medium.arm(u32::MAX);
        assert_eq!(
            put(&mut app, &mut fs, (tag >> 8) as u8, tag as u8, after),
            Sw::OK
        );
        assert_eq!(&medium.value(target).unwrap()[..after.len()], after);
    }
}

#[test]
fn an_attribute_change_refuses_each_failed_key_retirement_before_committing() {
    use rsk_fs::storage::faults::RemoveStuck;
    for fid in [consts::EF_PK_SIG.get(), consts::EF_PB_SIG] {
        let rng = RefCell::new(CountRng(7));
        let presence = RefCell::new(crate::AlwaysConfirm);
        let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
        let (backend, medium) = RemoveStuck::new();
        let mut fs = Fs::new(backend);
        fs.scan();
        scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
        verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
        assert_eq!(
            put(&mut app, &mut fs, 0, consts::EF_ALGO_SIG as u8, ATTR_P256),
            Sw::OK
        );
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                &[0, consts::INS_KEYPAIR_GEN, 0x80, 0, 2, consts::CRT_SIG, 0]
            )
            .1,
            Sw::OK
        );
        medium.refuse(Some(fid));
        assert_eq!(
            put(
                &mut app,
                &mut fs,
                0,
                consts::EF_ALGO_SIG as u8,
                consts::DEFAULT_ALGO
            ),
            Sw::MEMORY_FAILURE
        );
        assert!(medium.live(fid));
        let mut attr = [0; 16];
        let n = fs.read(consts::EF_ALGO_PRIV1, &mut attr).unwrap();
        assert_eq!(&attr[..n], ATTR_P256);
        assert!(app.sess.has_pw3);
        medium.refuse(None);
        assert_eq!(
            put(
                &mut app,
                &mut fs,
                0,
                consts::EF_ALGO_SIG as u8,
                consts::DEFAULT_ALGO
            ),
            Sw::OK
        );
        assert!(!medium.live(consts::EF_PK_SIG.get()));
        assert!(!medium.live(consts::EF_PB_SIG));
    }
}

#[test]
fn each_key_source_consumer_refuses_an_unread_source_without_mutating_state() {
    fn unread(_: &mut [u8; 32]) -> bool {
        false
    }
    let command = |ins, p1, p2, data: &[u8]| {
        let cla = if ins == consts::INS_ATTEST {
            rsk_sdk::apdu::CLA_PROPRIETARY
        } else {
            0
        };
        let mut raw = vec![cla, ins, p1, p2];
        if !data.is_empty() {
            raw.push(data.len() as u8);
            raw.extend_from_slice(data);
        }
        raw
    };
    let commands = [
        command(
            consts::INS_PUT_DATA,
            0,
            consts::EF_RESET_CODE as u8,
            b"87654321",
        ),
        command(
            consts::INS_PUT_DATA,
            0,
            consts::EF_AES_KEY.get() as u8,
            &[0x11; 16],
        ),
        command(consts::INS_PUT_DATA, 0, consts::EF_KDF as u8, &[0x81, 1, 0]),
        command(consts::INS_RESET_RETRY, 2, consts::PW1_MODE81, b"654321"),
        ec_import(consts::CRT_SIG, &[0x11; 32]),
        command(consts::INS_PSO, 0x9e, 0x9a, &[0x42; 32]),
        command(consts::INS_INTERNAL_AUT, 0, 0, &[0x42; 32]),
        command(consts::INS_KEYPAIR_GEN, 0x80, 0, &[consts::CRT_SIG, 0]),
        command(consts::INS_ATTEST, consts::KEY_REF_SIG, 0, &[]),
        command(consts::INS_TERMINATE_DF, 0, 0, &[]),
    ];
    for raw in commands {
        let rng = RefCell::new(CountRng(7));
        let presence = RefCell::new(crate::AlwaysConfirm);
        let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
        let mut fs = make_fs();
        verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
        assert_eq!(put(&mut app, &mut fs, 0, 0xc1, ATTR_P256), Sw::OK);
        assert_eq!(put(&mut app, &mut fs, 0, 0xc3, ATTR_P256), Sw::OK);
        assert_eq!(keygen(&mut app, &mut fs, 0x80, consts::CRT_SIG).1, Sw::OK);
        assert_eq!(keygen(&mut app, &mut fs, 0x80, consts::CRT_AUT).1, Sw::OK);
        verify_pin(&mut app, &mut fs, consts::PW1_MODE81, consts::PW1_DEFAULT);
        verify_pin(&mut app, &mut fs, consts::PW1_MODE82, consts::PW1_DEFAULT);
        let generation = fs.write_gen();
        let draws = rng.borrow().0;
        app.mkek_source = Some(FusedKey::latched(unread));
        assert_eq!(
            run(&mut app, &mut fs, &raw),
            (vec![], Sw::FUSED_KEY_UNREAD),
            "INS {:02x}",
            raw[1]
        );
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(rng.borrow().0, draws);
        assert!(app.sess.has_pw1 && app.sess.has_pw2 && app.sess.has_pw3);
        app.mkek_source = None;
        let expected = if raw[1] == consts::INS_PUT_DATA && raw[3] == consts::EF_KDF as u8 {
            Sw::CONDITIONS_NOT_SATISFIED
        } else {
            Sw::OK
        };
        assert_eq!(
            run(&mut app, &mut fs, &raw).1,
            expected,
            "healthy INS {:02x}",
            raw[1]
        );
    }
}

#[test]
fn legacy_ec_and_aes_keys_are_read_and_resealed_under_the_same_dek() {
    use rsk_crypto::aes::aes_encrypt_cfb_256;
    use rsk_secret::Secret;
    let rng = RefCell::new(CountRng(7));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let mut fs = make_fs();
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    let mut dek = Secret::<[u8; consts::DEK_SIZE]>::zeroed();
    crate::pin::load_dek(&dev(), &mut fs, &app.sess, &mut dek).unwrap();
    let key: [u8; 32] = dek.expose()[consts::IV_SIZE..].try_into().unwrap();
    let nonce_key: [u8; consts::IV_SIZE] = dek.expose()[..consts::IV_SIZE].try_into().unwrap();
    let mut legacy = [vec![rsk_ec::Curve::P256.id()], vec![0x11; 32]].concat();
    aes_encrypt_cfb_256(&key, &nonce_key, &mut legacy).unwrap();
    fs.put_key(consts::EF_PK_SIG, rsk_fs::Sealed::wrap(&legacy))
        .unwrap();
    let loaded = crate::keys::load_ec_key(&dev(), &mut fs, &app.sess, consts::EF_PK_SIG).unwrap();
    let expected = rsk_ec::PrivKey::from_scalar(rsk_ec::Curve::P256, &[0x11; 32]).unwrap();
    let mut point = [0; rsk_ec::MAX_EC_POINT];
    let mut wanted = point;
    assert_eq!(
        loaded.public_point(&mut point),
        expected.public_point(&mut wanted)
    );
    assert_eq!(point, wanted);
    assert_eq!(fs.size(consts::EF_PK_SIG.get()), Some(33 + 28));
    for width in [16, 32] {
        let mut legacy = vec![0x11; width];
        aes_encrypt_cfb_256(&key, &nonce_key, &mut legacy).unwrap();
        fs.put_key(consts::EF_AES_KEY, rsk_fs::Sealed::wrap(&legacy))
            .unwrap();
        let (loaded, n) = crate::keys::load_aes_key(&dev(), &mut fs, &app.sess).unwrap();
        assert_eq!(n, width);
        assert_eq!(&loaded.expose()[..n], &[0x11; 32][..n]);
        assert_eq!(
            fs.size(consts::EF_AES_KEY.get()),
            Some(if width == 32 { width + 28 } else { width })
        );
    }
}

#[test]
fn malformed_import_tags_and_parameters_preserve_the_key_and_grants() {
    let rng = RefCell::new(CountRng(7));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let mut fs = make_fs();
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    assert_eq!(put(&mut app, &mut fs, 0, 0xc1, ATTR_P256), Sw::OK);
    let valid = ec_import(consts::CRT_SIG, &[0x11; 32]);
    assert_eq!(run(&mut app, &mut fs, &valid).1, Sw::OK);
    let mut key = [0; 128];
    let n = fs.read(consts::EF_PK_SIG.get(), &mut key).unwrap();
    let generation = fs.write_gen();
    for (offset, value, expected) in [
        (2, 0, Sw::WRONG_P1P2),
        (3, 0, Sw::WRONG_P1P2),
        (5, 0, Sw::WRONG_DATA),
        (9, 0, Sw::WRONG_DATA),
        (10, 0, Sw::WRONG_DATA),
        (14, 0, Sw::WRONG_DATA),
        (15, 0, Sw::WRONG_DATA),
    ] {
        let mut bad = valid.clone();
        bad[offset] = value;
        assert_eq!(
            run(&mut app, &mut fs, &bad),
            (vec![], expected),
            "offset {offset}"
        );
        let mut after = [0; 128];
        assert_eq!(fs.read(consts::EF_PK_SIG.get(), &mut after), Some(n));
        assert_eq!(after, key);
        assert_eq!(fs.write_gen(), generation);
        assert!(app.sess.has_pw3);
    }
}

#[test]
fn ehl_optional_public_value_and_unknown_tag_have_distinct_results() {
    let body = [0x7f, 0x48, 2, 0x99, 1, 0x5f, 0x48, 1, 0x04];
    let (offsets, lengths) = crate::importdata::parse_ehl_body(&body, 0).unwrap();
    assert_eq!(offsets[8], Some(8));
    assert_eq!(lengths[8], 1);
    let mut bad = body;
    bad[3] = 0x98;
    assert_eq!(
        crate::importdata::parse_ehl_body(&bad, 0),
        Err(Sw::WRONG_DATA)
    );
}

#[test]
fn malformed_ecdh_templates_cannot_supply_a_peer_point() {
    let valid = [0xa6, 6, 0x7f, 0x49, 3, 0x86, 1, 0x04];
    assert_eq!(crate::pso::parse_ecdh_point(&valid), Some(&[0x04][..]));
    for offset in [0, 2, 3, 5] {
        let mut bad = valid;
        bad[offset] ^= 1;
        assert_eq!(crate::pso::parse_ecdh_point(&bad), None, "offset {offset}");
    }
    for n in 0..valid.len() {
        assert_eq!(
            crate::pso::parse_ecdh_point(&valid[..n]),
            None,
            "length {n}"
        );
    }
}

#[test]
fn internal_authenticate_rejects_each_parameter_without_using_the_key() {
    let rng = RefCell::new(CountRng(7));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let mut fs = make_fs();
    verify_pin(&mut app, &mut fs, consts::PW1_MODE82, consts::PW1_DEFAULT);
    let generation = fs.write_gen();
    for (p1, p2) in [(1, 0), (0, 1)] {
        assert_eq!(
            run(&mut app, &mut fs, &[0, consts::INS_INTERNAL_AUT, p1, p2]),
            (vec![], Sw::WRONG_P1P2)
        );
        assert!(app.sess.has_pw2);
        assert_eq!(fs.write_gen(), generation);
    }
}

#[test]
fn rsa_keepalive_preflight_distinguishes_read_ec_and_bad_parameters() {
    let mut fs = make_fs();
    let mut sess = Session::new();
    sess.has_pw3 = true;
    let crt = [consts::CRT_SIG, 0];
    assert_eq!(
        crate::keypairgen::rsa_generate_params(&mut fs, &sess, 0x81, 0, &crt),
        Ok(None)
    );
    assert_eq!(
        crate::keypairgen::rsa_generate_params(&mut fs, &sess, 0x80, 1, &crt),
        Err(Sw::WRONG_P1P2)
    );
    fs.put(consts::EF_ALGO_PRIV1, ATTR_P256).unwrap();
    let generation = fs.write_gen();
    assert_eq!(
        crate::keypairgen::rsa_generate_params(&mut fs, &sess, 0x80, 0, &crt),
        Ok(None)
    );
    assert_eq!(fs.write_gen(), generation);
}

#[test]
fn aes_pso_refuses_each_length_boundary_before_writing_output() {
    let rng = RefCell::new(LcgRng(31));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let mut fs = make_fs();
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    assert_eq!(put(&mut app, &mut fs, 0, 0xd5, &[0x11; 16]), Sw::OK);
    verify_pin(&mut app, &mut fs, consts::PW1_MODE82, consts::PW1_DEFAULT);
    let generation = fs.write_gen();
    for (encipher, data, room) in [
        (true, vec![], 17),
        (true, vec![0; 15], 17),
        (true, vec![0; 16], 16),
        (false, vec![2], 16),
        (false, vec![2; 16], 16),
        (false, vec![2; 17], 15),
    ] {
        let mut raw = vec![
            0,
            consts::INS_PSO,
            if encipher { 0x86 } else { 0x80 },
            if encipher { 0x80 } else { 0x86 },
            data.len() as u8,
        ];
        raw.extend_from_slice(&data);
        if data.is_empty() {
            raw.truncate(4);
        }
        let apdu = Apdu::parse(&raw).unwrap();
        let mut out = [0xa5; 17];
        assert_eq!(
            crate::pso::pso(
                &dev(),
                &mut fs,
                &mut app.sess,
                &mut LcgRng(7),
                &mut crate::AlwaysConfirm,
                &apdu,
                &mut out[..room]
            ),
            (0, Sw::WRONG_LENGTH)
        );
        assert_eq!(out, [0xa5; 17]);
        assert!(app.sess.has_pw2);
        assert_eq!(fs.write_gen(), generation);
    }
}

#[test]
fn an_oversized_selected_certificate_refuses_instead_of_committing_a_prefix() {
    let rng = RefCell::new(CountRng(7));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let mut fs = make_fs();
    fs.put(consts::EF_CH_1, &[0x42; 65]).unwrap();
    let generation = fs.write_gen();
    let mut output = [0xa5; 64];
    let mut res = ResBuf::new(&mut output);
    assert_eq!(
        app.read_cert_occurrence(&mut fs, &mut res),
        Sw::MEMORY_FAILURE
    );
    assert!(res.is_empty());
    assert_eq!(fs.write_gen(), generation);
}

#[test]
fn an_unread_key_source_refuses_a_completed_rsa_job_and_terminated_activation() {
    fn unread(_: &mut [u8; 32]) -> bool {
        false
    }
    let rng = RefCell::new(CountRng(7));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        Some(FusedKey::latched(unread)),
        &rng,
        &presence,
    );
    let mut fs = make_fs();
    let key = rsk_rsa::rsa_from_pqe(rsk_rsa::RSA_PUB_EXP_BE, &hx(RSA_P), &hx(RSA_Q)).unwrap();
    let mut output = [0xa5; 512];
    let generation = fs.write_gen();
    let draws = rng.borrow().0;
    assert_eq!(
        app.rsa_generate_finish(
            &mut fs,
            &mut *rng.borrow_mut(),
            consts::EF_PK_SIG,
            &key,
            &mut output
        ),
        (0, Sw::FUSED_KEY_UNREAD)
    );
    assert_eq!(output, [0xa5; 512]);
    assert_eq!(fs.write_gen(), generation);
    assert_eq!(rng.borrow().0, draws);
    fs.put(consts::EF_TERMINATED, &[1]).unwrap();
    let generation = fs.write_gen();
    assert_eq!(
        run(&mut app, &mut fs, &[0, consts::INS_ACTIVATE_FILE, 0, 0]),
        (vec![], Sw::FUSED_KEY_UNREAD)
    );
    assert_eq!(fs.write_gen(), generation);
    assert_eq!(rng.borrow().0, draws);
}

#[test]
fn a_kdf_change_cannot_replace_references_when_the_standing_dek_will_not_open() {
    let rng = RefCell::new(CountRng(7));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let mut fs = make_fs();
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    fs.put_key(consts::EF_DEK_PW3, rsk_fs::Sealed::wrap(&[0; 3]))
        .unwrap();
    let generation = fs.write_gen();
    let mut before = [0; 34];
    let n = fs.read(consts::EF_PW3, &mut before).unwrap();
    assert_eq!(
        put(&mut app, &mut fs, 0, consts::EF_KDF as u8, &[0x81, 1, 0]),
        Sw::EXEC_ERROR
    );
    assert_eq!(fs.write_gen(), generation);
    let mut after = [0; 34];
    assert_eq!(fs.read(consts::EF_PW3, &mut after), Some(n));
    assert_eq!(after, before);
    assert!(app.sess.has_pw3);
}

#[test]
fn empty_algorithm_and_uif_records_use_the_documented_defaults_without_granting_a_key() {
    let rng = RefCell::new(CountRng(7));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let mut fs = make_fs();
    verify_pin(&mut app, &mut fs, consts::PW1_MODE81, consts::PW1_DEFAULT);
    verify_pin(&mut app, &mut fs, consts::PW1_MODE82, consts::PW1_DEFAULT);
    for fid in [
        consts::EF_ALGO_PRIV1,
        consts::EF_ALGO_PRIV3,
        consts::EF_UIF_SIG,
        consts::EF_UIF_AUT,
    ] {
        fs.put(fid, &[]).unwrap();
    }
    let generation = fs.write_gen();
    for raw in [
        vec![0, consts::INS_PSO, 0x9e, 0x9a, 1, 0],
        vec![0, consts::INS_INTERNAL_AUT, 0, 0, 1, 0],
    ] {
        assert_eq!(
            run(&mut app, &mut fs, &raw),
            (vec![], Sw::CONDITIONS_NOT_SATISFIED)
        );
    }
    assert_eq!(fs.write_gen(), generation);
}

#[test]
fn absent_pw_status_keeps_a_standing_pw1_and_empty_attributes_do_not_invalidate_a_default_key() {
    let mut fs = make_fs();
    let mut session = crate::Session::new();
    session.has_pw1 = true;
    fs.force_delete(consts::EF_PW_PRIV).unwrap();
    let generation = fs.write_gen();
    crate::keys::spend_one_shot_pw1(&mut fs, &mut session);
    assert!(session.has_pw1);
    assert_eq!(fs.write_gen(), generation);

    let rng = RefCell::new(CountRng(7));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let mut fs = make_fs();
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    fs.put(consts::EF_ALGO_PRIV1, &[]).unwrap();
    fs.put_key(consts::EF_PK_SIG, rsk_fs::Sealed::wrap(b"existing key"))
        .unwrap();
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            0,
            consts::EF_ALGO_SIG as u8,
            consts::DEFAULT_ALGO
        ),
        Sw::OK
    );
    let mut key = [0; 32];
    assert_eq!(fs.read_key(consts::EF_PK_SIG, &mut key), Some(12));
    assert_eq!(&key[..12], b"existing key");
    for stored in [None, Some(&[][..])] {
        fs.force_delete(consts::EF_UIF_SIG).unwrap();
        if let Some(value) = stored {
            fs.put(consts::EF_UIF_SIG, value).unwrap();
        }
        assert_eq!(
            put(&mut app, &mut fs, 0, consts::EF_UIF_SIG as u8, &[1, 0x20]),
            Sw::OK
        );
        let mut uif = [0; 2];
        assert_eq!(fs.read(consts::EF_UIF_SIG, &mut uif), Some(2));
        assert_eq!(uif, [1, 0x20]);
    }
}

#[test]
fn retry_updates_refuse_short_maximum_or_live_counter_records_without_writing() {
    for maximum in [false, true] {
        let mut fs = make_fs();
        let mut session = crate::Session::new();
        session.has_pw3 = true;
        fs.put(
            if maximum {
                consts::EF_PW_RETRIES
            } else {
                consts::EF_PW_PRIV
            },
            &[0],
        )
        .unwrap();
        let generation = fs.write_gen();
        assert_eq!(
            crate::retries::set_pin_retries(&mut fs, &session, &[1, 0, 0]),
            Sw::MEMORY_FAILURE
        );
        assert_eq!(fs.write_gen(), generation);
    }
}
