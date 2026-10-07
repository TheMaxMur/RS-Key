// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn device() -> Device<'static> {
    Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
        latched: false,
    }
}

#[test]
fn a_failed_final_escrow_revocation_leaves_the_replacement_key_in_force() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let refuse = Rc::new(Cell::new(None));
    let mut fs = Fs::new(RefuseWrite {
        inner: RamStorage::new(),
        refuse: refuse.clone(),
        refuse_remove: Rc::new(Cell::new(None)),
    });
    fs.scan();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    let admin = [
        PIVMAN_TAG,
        9,
        PIVMAN_FLAGS_TAG,
        1,
        1 | PIVMAN_FLAG_MGM_PROTECTED,
        PIVMAN_TS_TAG,
        4,
        0xde,
        0xad,
        0xbe,
        0xef,
    ];
    fs.put(EF_PIVMAN_DATA, &admin).unwrap();
    verify_pin(&mut app, &mut fs);
    let printed = [TAG_DATA_PATH, 3, 0x5f, 0xc1, 9];
    assert_eq!(
        run(&mut app, &mut fs, INS_GET_DATA, 0x3f, 0xff, &printed).0,
        Sw::OK
    );
    let replacement = [0x5a; 32];
    let mut request = vec![ALGO_AES256, SLOT_CARDMGM, 32];
    request.extend_from_slice(&replacement);
    refuse.set(Some(EF_PIVMAN_DATA));
    assert_eq!(
        run(&mut app, &mut fs, INS_SET_MGMKEY, 0xff, 0xff, &request),
        (Sw::MEMORY_FAILURE, vec![])
    );
    let key = mgm_read(&device(), &mut fs).unwrap();
    assert_eq!(key.key(), replacement);
    assert_eq!(key.policy, Some((ALGO_AES256, TOUCHPOLICY_NEVER)));
    let mut stored = [0; 11];
    assert_eq!(fs.read(EF_PIVMAN_DATA, &mut stored), Some(admin.len()));
    assert_eq!(stored, admin);
    assert!(mgm_is_protected(&mut fs));

    let mut fresh = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    select(&mut fresh, &mut fs);
    let (sw, witness) = run(
        &mut fresh,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_AES256,
        SLOT_CARDMGM,
        &[0x7c, 2, 0x80, 0],
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(&witness[..4], &[0x7c, 0x12, 0x80, 0x10]);
    let mut plain: [u8; 16] = witness[4..].try_into().unwrap();
    rsk_crypto::aes_ecb_decrypt_block(&replacement, &mut plain).unwrap();
    let challenge = [0xa5; 16];
    let mut auth = vec![0x7c, 0x24, 0x80, 0x10];
    auth.extend_from_slice(&plain);
    auth.extend_from_slice(&[0x81, 0x10]);
    auth.extend_from_slice(&challenge);
    let (sw, response) = run(
        &mut fresh,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_AES256,
        SLOT_CARDMGM,
        &auth,
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(&response[..4], &[0x7c, 0x12, 0x82, 0x10]);
    let mut expected = challenge;
    rsk_crypto::aes_ecb_encrypt_block(&replacement, &mut expected).unwrap();
    assert_eq!(&response[4..], expected);

    refuse.set(None);
    assert_eq!(
        run(&mut fresh, &mut fs, INS_SET_MGMKEY, 0xff, 0xff, &request),
        (Sw::OK, vec![])
    );
    let mut revoked = admin;
    revoked[4] = 1;
    assert_eq!(fs.read(EF_PIVMAN_DATA, &mut stored), Some(revoked.len()));
    assert_eq!(stored, revoked);
    assert!(!mgm_is_protected(&mut fs));
    verify_pin(&mut fresh, &mut fs);
    assert_eq!(
        run(&mut fresh, &mut fs, INS_GET_DATA, 0x3f, 0xff, &printed),
        (Sw::FILE_NOT_FOUND, vec![])
    );
}

#[test]
fn management_key_replacement_requires_its_complete_metadata_head() {
    for head in [
        None,
        Some(&[][..]),
        Some(&[ALGO_AES192][..]),
        Some(&[ALGO_AES192, 0][..]),
    ] {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        fs.meta_delete(key_fid(SLOT_CARDMGM).get()).unwrap();
        if let Some(head) = head {
            fs.meta_add(key_fid(SLOT_CARDMGM).get(), head).unwrap();
        }
        let generation = fs.write_gen();
        let mut new = vec![ALGO_AES256, SLOT_CARDMGM, 32];
        new.extend([0x5a; 32]);
        assert_eq!(
            run(&mut app, &mut fs, INS_SET_MGMKEY, 0xff, 0xff, &new),
            (Sw::REFERENCE_NOT_FOUND, vec![])
        );
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(mgm_read(&device(), &mut fs).unwrap().key(), DEFAULT_MGM);
    }
}

#[test]
fn protected_management_key_reads_refuse_corruption_and_truncation() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    assert_eq!(
        protect_mgm_key(&device(), &mut fs, &mut TestRng(42)),
        Sw::OK
    );
    let get = apdu_bytes(INS_GET_DATA, 0x3f, 0xff, &[0x5c, 3, 0x5f, 0xc1, 9]);
    let apdu = Apdu::parse(&get).unwrap();
    let (_, complete) = run(&mut app, &mut fs, INS_GET_DATA, 0x3f, 0xff, apdu.data);
    assert_eq!(complete.len(), 38);
    for capacity in 0..complete.len() {
        let mut bytes = vec![0; capacity];
        let mut res = ResBuf::new(&mut bytes);
        assert_eq!(app.process(&apdu, &mut fs, &mut res), Sw::WRONG_LENGTH);
    }
    fs.put_key(key_fid(SLOT_CARDMGM), Sealed::wrap(b"broken seal"))
        .unwrap();
    let generation = fs.write_gen();
    assert_eq!(
        run(&mut app, &mut fs, INS_GET_DATA, 0x3f, 0xff, apdu.data),
        (Sw::MEMORY_FAILURE, vec![])
    );
    assert_eq!(fs.write_gen(), generation);
    fs.delete_key(key_fid(SLOT_CARDMGM)).unwrap();
    assert_eq!(
        run(&mut app, &mut fs, INS_GET_DATA, 0x3f, 0xff, apdu.data),
        (Sw::REFERENCE_NOT_FOUND, vec![])
    );
}

#[test]
fn pin_and_puk_migration_refuse_each_interrupted_write() {
    for (fid, retry, pin) in [
        (EF_PIN, RETRY_PIN, DEFAULT_PIN),
        (EF_PUK, RETRY_PUK, DEFAULT_PUK),
    ] {
        for budget in 0..=4 {
            let rng = RefCell::new(TestRng(7));
            let pres = RefCell::new(AlwaysConfirm);
            let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
            let (mut fs, medium) = new_cut_fs();
            select(&mut app, &mut fs);
            fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
            let before = medium.value(fid).unwrap();
            let fused = Device {
                otp_key: Some(&[0x55; 32]),
                ..device()
            };
            medium.arm(budget);
            let sw = check_ref(&fused, &mut fs, fid, retry, &pin);
            assert_eq!(
                sw,
                if budget == 4 {
                    Sw::OK
                } else {
                    Sw::MEMORY_FAILURE
                },
                "budget={budget}"
            );
            if budget < 3 {
                assert_eq!(medium.value(fid), Some(before));
            }
            medium.arm(u32::MAX);
            assert_eq!(check_ref(&fused, &mut fs, fid, retry, &pin), Sw::OK);
            let stored = medium.value(fid).unwrap();
            assert_eq!(&stored[2..], fused.pin_derive_verifier(&pin).expose());
            assert_eq!(retries_left(&mut fs, retry), Ok(DEFAULT_RETRIES));
            assert!(!fs.has_data(rsk_fs::EF_HARDENED));
        }
    }
}

#[test]
fn protecting_a_management_key_reports_each_failed_store() {
    for budget in 0..=4 {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let (mut fs, medium) = new_cut_fs();
        select(&mut app, &mut fs);
        medium.arm(budget);
        let sw = protect_mgm_key(&device(), &mut fs, &mut TestRng(42));
        medium.arm(u32::MAX);
        if sw == Sw::OK {
            assert!(mgm_is_protected(&mut fs));
            let mgm = mgm_read(&device(), &mut fs).unwrap();
            assert_eq!(mgm.policy, Some((ALGO_AES256, TOUCHPOLICY_NEVER)));
            assert_ne!(mgm.key(), DEFAULT_MGM);
        } else {
            assert_eq!(sw, Sw::MEMORY_FAILURE);
            assert!(!mgm_is_protected(&mut fs));
        }
    }
}
