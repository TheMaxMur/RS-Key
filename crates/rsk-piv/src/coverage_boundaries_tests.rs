// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn an_accelerator_result_of_an_unadvertised_width_cannot_replace_a_slot() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    let fid = key_fid(SLOT_AUTHENTICATION);
    fs.put_key(fid, rsk_fs::Sealed::wrap(&[0xa5; 32])).unwrap();
    let generation = fs.write_gen();
    let key = rsk_rsa::rsa_from_pqe(
        rsk_rsa::RSA_PUB_EXP_BE,
        &rsk_rsa::vectors::hex(rsk_rsa::vectors::P640_HEX),
        &rsk_rsa::vectors::hex(rsk_rsa::vectors::Q640_HEX),
    )
    .unwrap();
    let mut entropy = TestRng(9);
    let mut out = [0xa5; 512];
    assert_eq!(
        app.rsa_generate_finish(
            &mut fs,
            &mut entropy,
            SLOT_AUTHENTICATION,
            [PINPOLICY_ONCE, TOUCHPOLICY_NEVER],
            &key,
            &mut out
        ),
        (0, Sw::EXEC_ERROR)
    );
    assert_eq!(out, [0xa5; 512]);
    assert_eq!(entropy.0, 9);
    assert_eq!(fs.write_gen(), generation);
    let mut retained = [0; 32];
    assert_eq!(fs.read_key(fid, &mut retained), Some(32));
    assert_eq!(retained, [0xa5; 32]);
}

#[cfg(not(feature = "fips-profile"))]
#[test]
fn each_edwards_import_requires_its_nonempty_named_scalar_before_retirement() {
    for (algo, tag) in [(ALGO_ED25519, 0x07), (ALGO_X25519, 0x08)] {
        let rng = RefCell::new(TestRng(7));
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        let mut valid = vec![tag, 32];
        valid.extend_from_slice(&[0x11; 32]);
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                INS_IMPORT_ASYM,
                algo,
                SLOT_AUTHENTICATION,
                &valid
            )
            .0,
            Sw::OK
        );
        let fid = key_fid(SLOT_AUTHENTICATION);
        let mut original = [0; 128];
        let n = fs.read_key(fid, &mut original).unwrap();
        let generation = fs.write_gen();
        for data in [&[][..], &[tag, 0][..], &[0x06, 1, 0][..]] {
            assert_eq!(
                run(
                    &mut app,
                    &mut fs,
                    INS_IMPORT_ASYM,
                    algo,
                    SLOT_AUTHENTICATION,
                    data
                ),
                (Sw::WRONG_DATA, vec![])
            );
            assert_eq!(fs.write_gen(), generation);
            let mut retained = [0; 128];
            assert_eq!(fs.read_key(fid, &mut retained), Some(n));
            assert_eq!(retained, original);
        }
    }
}

#[test]
fn a_management_key_restored_under_another_algorithm_cannot_finish_an_old_handshake() {
    for single in [false, true] {
        let rng = RefCell::new(TestRng(7));
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        let tag = if single { 0x81 } else { 0x80 };
        let (status, reply) = run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_AES192,
            SLOT_CARDMGM,
            &[0x7c, 2, tag, 0],
        );
        assert_eq!(status, Sw::OK);
        let mut witness: [u8; 16] = reply[4..20].try_into().unwrap();
        let key = Secret::new([0x11; 16]);
        let dev = Device {
            serial_hash: &HASH,
            serial_id: &SERIAL,
            otp_key: None,
            latched: false,
        };
        mgm_put(
            &dev,
            &mut fs,
            &mut *rng.borrow_mut(),
            ALGO_AES128,
            TOUCHPOLICY_NEVER,
            key.expose(),
        )
        .unwrap();
        let response = if single {
            rsk_crypto::aes_ecb_encrypt_block(key.expose(), &mut witness).unwrap();
            [vec![0x7c, 0x12, 0x82, 0x10], witness.to_vec()].concat()
        } else {
            rsk_crypto::aes_ecb_decrypt_block(&DEFAULT_MGM, &mut witness).unwrap();
            [
                vec![0x7c, 0x24, 0x80, 0x10],
                witness.to_vec(),
                vec![0x81, 0x10],
                vec![0xa5; 16],
            ]
            .concat()
        };
        let generation = fs.write_gen();
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                INS_AUTHENTICATE,
                ALGO_AES128,
                SLOT_CARDMGM,
                &response
            ),
            (Sw::WRONG_DATA, vec![])
        );
        assert_eq!(fs.write_gen(), generation);
        assert!(!app.sess.has_mgm);
    }
}

#[test]
fn duplicate_restored_object_ids_do_not_replace_the_first_pool_record() {
    let mut fs = new_fs();
    let id = 0x5fff10;
    crate::objects::write(&mut fs, id, b"first").unwrap();
    let first = *crate::objects::POOL.start();
    let mut record = [0; 7];
    assert_eq!(fs.read(first, &mut record), Some(record.len()));
    record[2..].copy_from_slice(b"other");
    fs.put(first + 1, &record).unwrap();
    let generation = fs.write_gen();
    let mut output = [0; crate::objects::RECORD_MAX];
    assert_eq!(crate::objects::read(&mut fs, id, &mut output), Ok(Some(5)));
    assert_eq!(&output[..5], b"first");
    assert_eq!(fs.write_gen(), generation);
    crate::objects::write(&mut fs, id, b"updated").unwrap();
    assert_eq!(fs.read(first + 1, &mut record), Some(record.len()));
    assert_eq!(&record[2..], b"other");
    assert_eq!(crate::objects::read(&mut fs, id, &mut output), Ok(Some(7)));
    assert_eq!(&output[..7], b"updated");
}

#[test]
fn a_disappearing_escrow_record_between_probes_produces_no_rewrite() {
    let (backend, medium) = rsk_fs::read_change::ChangingRead::new();
    let mut fs = Fs::new(backend);
    fs.put(
        EF_PIVMAN_DATA,
        &[0x80, 3, 0x81, 1, PIVMAN_FLAG_MGM_PROTECTED],
    )
    .unwrap();
    let generation = fs.write_gen();
    medium.replace_on_read(EF_PIVMAN_DATA, 1, None);
    assert!(escrow_revocation(&mut fs).unwrap().is_none());
    assert!(medium.served());
    assert_eq!(fs.write_gen(), generation);
}

#[test]
fn a_direct_escrow_read_without_pin_grant_preserves_the_response_and_store() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    let mut out = [0xa5; 64];
    let generation = fs.write_gen();
    let mut res = ResBuf::new(&mut out);
    assert_eq!(
        app.get_protected_mgm(&mut fs, &mut res),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert!(res.is_empty());
    assert_eq!(out, [0xa5; 64]);
    assert_eq!(fs.write_gen(), generation);
    assert!(!app.sess.has_pin);
}

#[test]
fn a_direct_retry_setter_refuses_an_unknown_pair_without_rewriting_counters() {
    let mut fs = new_fs();
    let counters = [3, 2, 3, 1];
    fs.put(EF_RETRIES, &counters).unwrap();
    let generation = fs.write_gen();
    assert_eq!(
        set_retries_left(&mut fs, 3, 9),
        Err(Sw::REFERENCE_NOT_FOUND)
    );
    assert_eq!(fs.write_gen(), generation);
    let mut retained = [0; 4];
    assert_eq!(fs.read(EF_RETRIES, &mut retained), Some(4));
    assert_eq!(retained, counters);
}

#[test]
fn direct_management_key_updates_refuse_inconsistent_apdu_windows_without_retirement() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    app.sess.has_mgm = true;
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
        latched: false,
    };
    let mut fs = new_fs();
    let empty = Apdu::parse(&[0, INS_SET_MGMKEY, 0xff, 0xff]).unwrap();
    for data in [&[][..], &[ALGO_AES128, SLOT_CARDMGM, 16][..]] {
        let request = Apdu {
            nc: 19,
            data,
            ..empty
        };
        assert_eq!(app.set_mgmkey(&dev, &mut fs, &request), Sw::WRONG_LENGTH);
        assert_eq!(fs.write_gen(), 0);
        assert!(app.sess.has_mgm);
    }
}
