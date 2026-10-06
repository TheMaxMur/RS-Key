// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn generated(app: &mut PivApplet, fs: &mut Fs<RamStorage>, algo: u8) {
    select(app, fs);
    auth_mgm(app, fs);
    verify_pin(app, fs);
    assert_eq!(
        run(
            app,
            fs,
            INS_ASYM_KEYGEN,
            0,
            SLOT_AUTHENTICATION,
            &gen_template(algo)
        )
        .0,
        Sw::OK
    );
}

fn stored(fs: &mut Fs<RamStorage>, fid: u16) -> Vec<u8> {
    let mut record = [0; 1024];
    let n = fs.read(fid, &mut record).unwrap();
    record[..n].to_vec()
}

#[test]
fn attestation_refusals_preserve_the_generated_key_and_session() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    generated(&mut app, &mut fs, ALGO_ECCP256);
    let slot = SLOT_AUTHENTICATION;
    let key = stored(&mut fs, key_fid(slot).get());
    let f9 = stored(&mut fs, key_fid(SLOT_ATTESTATION).get());
    let mut meta = [0; 4 + MAX_EC_POINT];
    let n = fs.meta_find(key_fid(slot).get(), &mut meta).unwrap();
    let head = meta[..n].to_vec();

    for (requested, expected) in [
        (SLOT_CARDMGM, Sw::REFERENCE_NOT_FOUND),
        (SLOT_SIGNATURE, Sw::REFERENCE_NOT_FOUND),
    ] {
        let generation = fs.write_gen();
        let (sw, body) = run(&mut app, &mut fs, INS_ATTESTATION, requested, 0, &[]);
        assert_eq!(sw, expected);
        assert!(body.is_empty());
        assert_eq!(fs.write_gen(), generation);
    }
    for missing_fid in [key_fid(slot), key_fid(SLOT_ATTESTATION)] {
        fs.delete_key(missing_fid).unwrap();
        let generation = fs.write_gen();
        let (sw, body) = run(&mut app, &mut fs, INS_ATTESTATION, slot, 0, &[]);
        assert_eq!(sw, Sw::REFERENCE_NOT_FOUND);
        assert!(body.is_empty());
        assert_eq!(fs.write_gen(), generation);
        fs.put(
            missing_fid.get(),
            if missing_fid == key_fid(slot) {
                &key
            } else {
                &f9
            },
        )
        .unwrap();
    }
    fs.meta_delete(key_fid(slot).get()).unwrap();
    let generation = fs.write_gen();
    assert_eq!(
        run(&mut app, &mut fs, INS_ATTESTATION, slot, 0, &[]),
        (Sw::REFERENCE_NOT_FOUND, Vec::new())
    );
    assert_eq!(fs.write_gen(), generation);
    for malformed in [
        &head[..3],
        &[0xFF, PINPOLICY_ONCE, TOUCHPOLICY_NEVER, ORIGIN_GENERATED],
    ] {
        fs.meta_add(key_fid(slot).get(), malformed).unwrap();
        let generation = fs.write_gen();
        assert_eq!(
            run(&mut app, &mut fs, INS_ATTESTATION, slot, 0, &[]),
            (Sw::WRONG_DATA, Vec::new())
        );
        assert_eq!(fs.write_gen(), generation);
    }
    fs.meta_add(key_fid(slot).get(), &head).unwrap();
    assert_eq!(stored(&mut fs, key_fid(slot).get()), key);
    assert_eq!(stored(&mut fs, key_fid(SLOT_ATTESTATION).get()), f9);
    assert!(app.sess.has_pin && app.sess.pin_fresh && app.sess.has_mgm);
    let generation = fs.write_gen();
    let (sw, body) = run(&mut app, &mut fs, INS_ATTESTATION, slot, 0, &[]);
    assert_eq!(sw, Sw::OK);
    assert!(x509_parser::parse_x509_certificate(&body).is_ok());
    assert_eq!(fs.write_gen(), generation);
    assert!(app.sess.pin_fresh);
}

#[test]
fn a_torn_attestation_or_slot_key_returns_no_certificate() {
    for algo in [ALGO_RSA2048, ALGO_ECCP256, ALGO_ED25519, ALGO_X25519] {
        let rng = RefCell::new(TestRng(7));
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        let mut fs = new_fs();
        generated(&mut app, &mut fs, algo);
        for fid in [key_fid(SLOT_ATTESTATION), key_fid(SLOT_AUTHENTICATION)] {
            let key = stored(&mut fs, fid.get());
            fs.put(fid.get(), &key[..key.len() - 1]).unwrap();
            let generation = fs.write_gen();
            assert_eq!(
                run(
                    &mut app,
                    &mut fs,
                    INS_ATTESTATION,
                    SLOT_AUTHENTICATION,
                    0,
                    &[]
                ),
                (Sw::MEMORY_FAILURE, Vec::new())
            );
            assert_eq!(fs.write_gen(), generation);
            assert!(app.sess.has_pin && app.sess.pin_fresh && app.sess.has_mgm);
            assert_eq!(stored(&mut fs, fid.get()), key[..key.len() - 1]);
            fs.put(fid.get(), &key).unwrap();
        }
        let (sw, body) = run(
            &mut app,
            &mut fs,
            INS_ATTESTATION,
            SLOT_AUTHENTICATION,
            0,
            &[],
        );
        assert_eq!(sw, Sw::OK);
        assert!(x509_parser::parse_x509_certificate(&body).is_ok());
    }
}

#[test]
fn attestation_short_output_leaves_no_partial_certificate_or_spent_pin() {
    for algo in [ALGO_ECCP256, ALGO_ED25519, ALGO_X25519] {
        let rng = RefCell::new(TestRng(7));
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        let mut fs = new_fs();
        generated(&mut app, &mut fs, algo);
        let apdu = apdu_bytes(INS_ATTESTATION, SLOT_AUTHENTICATION, 0, &[]);
        for capacity in [0, 1, 32, 128] {
            let mut output = [0xA5; 128];
            let generation = fs.write_gen();
            let mut res = ResBuf::new(&mut output[..capacity]);
            assert_eq!(
                app.process(&Apdu::parse(&apdu).unwrap(), &mut fs, &mut res),
                Sw::WRONG_LENGTH
            );
            assert!(res.is_empty());
            assert_eq!(output, [0xA5; 128]);
            assert_eq!(fs.write_gen(), generation);
            assert!(app.sess.has_pin && app.sess.pin_fresh && app.sess.has_mgm);
        }
        let (sw, body) = run(
            &mut app,
            &mut fs,
            INS_ATTESTATION,
            SLOT_AUTHENTICATION,
            0,
            &[],
        );
        assert_eq!(sw, Sw::OK);
        assert!(x509_parser::parse_x509_certificate(&body).is_ok());
    }
}
