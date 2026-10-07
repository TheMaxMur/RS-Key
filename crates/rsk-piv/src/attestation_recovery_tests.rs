// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::faults::ProbeStuck;
use rsk_sdk::tlv::Tlv;

fn identity() -> Device<'static> {
    Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
        latched: false,
    }
}

fn stored<S: Storage>(fs: &mut Fs<S>, fid: u16) -> Option<Vec<u8>> {
    let mut bytes = [0; rsk_fs::MAX_VALUE_BYTES];
    fs.read(fid, &mut bytes)
        .map(|n| bytes[..n.min(bytes.len())].to_vec())
}

fn assert_current_chain<S: Storage>(app: &mut PivApplet, fs: &mut Fs<S>) -> Vec<u8> {
    let (sw, metadata) = run(app, fs, INS_GET_METADATA, 0, SLOT_ATTESTATION, &[]);
    assert_eq!(sw, Sw::OK);
    let point = find_tag(find_tag(&metadata, 4).unwrap(), 0x86).unwrap();
    let (sw, object) = run(
        app,
        fs,
        INS_GET_DATA,
        0x3f,
        0xff,
        &[TAG_DATA_PATH, 3, 0x5f, 0xff, 1],
    );
    assert_eq!(sw, Sw::OK, "a healthy retry must finish the F9 certificate");
    let der = find_tag(find_tag(&object, TAG_DATA_OBJECT as u16).unwrap(), 0x70).unwrap();
    let (_, certificate) = x509_parser::parse_x509_certificate(der).unwrap();
    let public = certificate.subject_pki.subject_public_key.data.as_ref();
    assert_eq!(public, point, "F9 certificate names a preceding key");
    let verifier = p384::ecdsa::VerifyingKey::from_sec1_bytes(public).unwrap();
    let digest: [u8; 48] = sha2::Sha384::digest(certificate.tbs_certificate.as_ref()).into();
    let signature = p384::ecdsa::Signature::from_der(&certificate.signature_value.data).unwrap();
    verifier.verify_prehash(&digest, &signature).unwrap();
    auth_mgm(app, fs);
    verify_pin(app, fs);
    assert_eq!(
        run(
            app,
            fs,
            INS_ASYM_KEYGEN,
            0,
            SLOT_AUTHENTICATION,
            &gen_template(ALGO_ECCP256)
        )
        .0,
        Sw::OK
    );
    let (sw, leaf) = run(app, fs, INS_ATTESTATION, SLOT_AUTHENTICATION, 0, &[]);
    assert_eq!(sw, Sw::OK);
    let (_, leaf) = x509_parser::parse_x509_certificate(&leaf).unwrap();
    let digest: [u8; 32] = sha2::Sha256::digest(leaf.tbs_certificate.as_ref()).into();
    let signature = p384::ecdsa::Signature::from_der(&leaf.signature_value.data).unwrap();
    verifier.verify_prehash(&digest, &signature).unwrap();
    object
}

#[test]
fn a_refused_first_certificate_write_is_completed_after_remount_without_replacing_f9() {
    let refuse = Rc::new(Cell::new(Some(EF_ATTESTATION_CERT)));
    let mut fs = Fs::new(RefuseWrite {
        inner: RamStorage::new(),
        refuse: refuse.clone(),
        refuse_remove: Rc::new(Cell::new(None)),
    });
    fs.scan();
    fs.put(0xb000, b"neighbor").unwrap();
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut output = [0xa5; 256];
    let mut response = ResBuf::new(&mut output);
    assert_eq!(
        Applet::select(&mut app, false, &mut fs, &mut response),
        Sw::MEMORY_FAILURE
    );
    assert!(response.as_slice().is_empty());
    assert_eq!(output, [0xa5; 256]);
    let key = stored(&mut fs, key_fid(SLOT_ATTESTATION).get()).unwrap();
    let gates = [EF_PIN, EF_PUK, EF_RETRIES, key_fid(SLOT_CARDMGM).get()]
        .map(|fid| (fid, stored(&mut fs, fid)));
    assert_eq!(stored(&mut fs, EF_ATTESTATION_CERT), None);
    refuse.set(None);
    let mut fs = Fs::new(fs.into_storage());
    fs.scan();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    select(&mut app, &mut fs);
    assert_eq!(stored(&mut fs, key_fid(SLOT_ATTESTATION).get()), Some(key));
    for (fid, before) in gates {
        assert_eq!(stored(&mut fs, fid), before);
    }
    let certificate = assert_current_chain(&mut app, &mut fs);
    let generation = fs.write_gen();
    assert_eq!(scan_files(&identity(), &mut fs, &mut TestRng(19)), Ok(true));
    assert_eq!(fs.write_gen(), generation);
    assert_eq!(
        stored(&mut fs, EF_ATTESTATION_CERT),
        Some(
            find_tag(&certificate, TAG_DATA_OBJECT as u16)
                .unwrap()
                .to_vec()
        )
    );
    assert_eq!(
        stored(&mut fs, 0xb000).as_deref(),
        Some(b"neighbor".as_slice())
    );
}

#[test]
fn f9_recreation_retires_the_preceding_certificate_before_committing_a_new_key() {
    let refuse = Rc::new(Cell::new(None));
    let mut fs = Fs::new(RefuseWrite {
        inner: RamStorage::new(),
        refuse: refuse.clone(),
        refuse_remove: Rc::new(Cell::new(None)),
    });
    fs.scan();
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    select(&mut app, &mut fs);
    let preceding = stored(&mut fs, EF_ATTESTATION_CERT).unwrap();
    let old_key = stored(&mut fs, key_fid(SLOT_ATTESTATION).get()).unwrap();
    fs.delete_key(key_fid(SLOT_ATTESTATION)).unwrap();
    refuse.set(Some(EF_ATTESTATION_CERT));
    let mut fs = Fs::new(fs.into_storage());
    fs.scan();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut output = [0; 256];
    assert_eq!(
        Applet::select(&mut app, false, &mut fs, &mut ResBuf::new(&mut output)),
        Sw::MEMORY_FAILURE
    );
    let new_key = stored(&mut fs, key_fid(SLOT_ATTESTATION).get()).unwrap();
    assert_ne!(new_key, old_key);
    assert_ne!(
        stored(&mut fs, EF_ATTESTATION_CERT),
        Some(preceding),
        "a preceding certificate survived over a newly committed F9 key"
    );
    assert_eq!(stored(&mut fs, EF_ATTESTATION_CERT), None);
    refuse.set(None);
    let mut fs = Fs::new(fs.into_storage());
    fs.scan();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    select(&mut app, &mut fs);
    assert_eq!(
        stored(&mut fs, key_fid(SLOT_ATTESTATION).get()),
        Some(new_key)
    );
    assert_current_chain(&mut app, &mut fs);
}

#[test]
fn a_faulted_certificate_probe_refuses_without_replacing_the_attestation_identity() {
    let (backend, medium) = ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    select(&mut app, &mut fs);
    let key = medium.value(key_fid(SLOT_ATTESTATION).get());
    let cert = medium.value(EF_ATTESTATION_CERT);
    let generation = fs.write_gen();
    medium.stick(Some(EF_ATTESTATION_CERT));
    assert_eq!(
        scan_files(&identity(), &mut fs, &mut TestRng(19)),
        Err(Sw::MEMORY_FAILURE)
    );
    medium.stick(None);
    assert_eq!(fs.write_gen(), generation);
    assert_eq!(medium.value(key_fid(SLOT_ATTESTATION).get()), key);
    assert_eq!(medium.value(EF_ATTESTATION_CERT), cert);
}

#[test]
fn certificate_repair_refuses_an_unreadable_existing_key_without_regenerating_it() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    fs.delete(EF_ATTESTATION_CERT).unwrap();
    fs.put_key(key_fid(SLOT_ATTESTATION), Sealed::wrap(b"unreadable key"))
        .unwrap();
    let key = stored(&mut fs, key_fid(SLOT_ATTESTATION).get());
    let generation = fs.write_gen();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut output = [0xa5; 256];
    let mut response = ResBuf::new(&mut output);
    assert_eq!(
        Applet::select(&mut app, false, &mut fs, &mut response),
        Sw::MEMORY_FAILURE
    );
    assert!(response.as_slice().is_empty());
    assert_eq!(output, [0xa5; 256]);
    assert_eq!(fs.write_gen(), generation);
    assert_eq!(stored(&mut fs, key_fid(SLOT_ATTESTATION).get()), key);
    assert_eq!(stored(&mut fs, EF_ATTESTATION_CERT), None);
}

#[test]
fn a_refused_certificate_retirement_stops_f9_recreation_before_the_key_write() {
    let remove = Rc::new(Cell::new(None));
    let mut fs = Fs::new(RefuseWrite {
        inner: RamStorage::new(),
        refuse: Rc::new(Cell::new(None)),
        refuse_remove: remove.clone(),
    });
    fs.scan();
    scan_files(&identity(), &mut fs, &mut TestRng(7)).unwrap();
    let certificate = stored(&mut fs, EF_ATTESTATION_CERT);
    fs.delete_key(key_fid(SLOT_ATTESTATION)).unwrap();
    remove.set(Some(EF_ATTESTATION_CERT));
    assert_eq!(
        scan_files(&identity(), &mut fs, &mut TestRng(19)),
        Err(Sw::MEMORY_FAILURE)
    );
    assert_eq!(
        stored(&mut fs, key_fid(SLOT_ATTESTATION).get()),
        None,
        "a refused certificate retirement committed a replacement F9 key"
    );
    assert_eq!(stored(&mut fs, EF_ATTESTATION_CERT), certificate);
}

#[test]
fn certificate_repair_refuses_an_existing_key_of_a_different_curve() {
    for curve in [Curve::P256, Curve::Ed25519] {
        let mut fs = new_fs();
        scan_files(&identity(), &mut fs, &mut TestRng(7)).unwrap();
        let key = PrivKey::from_scalar(curve, &[1; 32]).unwrap();
        seal::store_ec_key(
            &identity(),
            &mut fs,
            &mut TestRng(17),
            key_fid(SLOT_ATTESTATION),
            &key,
        )
        .unwrap();
        fs.delete(EF_ATTESTATION_CERT).unwrap();
        let before = stored(&mut fs, key_fid(SLOT_ATTESTATION).get());
        let generation = fs.write_gen();
        assert_eq!(
            scan_files(&identity(), &mut fs, &mut TestRng(19)),
            Err(Sw::MEMORY_FAILURE)
        );
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(stored(&mut fs, key_fid(SLOT_ATTESTATION).get()), before);
        assert_eq!(stored(&mut fs, EF_ATTESTATION_CERT), None);
    }
}

#[test]
fn an_empty_certificate_is_repaired_under_the_existing_f9_key() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let key = stored(&mut fs, key_fid(SLOT_ATTESTATION).get());
    fs.put(EF_ATTESTATION_CERT, &[]).unwrap();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    select(&mut app, &mut fs);
    assert_eq!(stored(&mut fs, key_fid(SLOT_ATTESTATION).get()), key);
    assert_current_chain(&mut app, &mut fs);
}

#[test]
fn certificate_repair_retires_a_legacy_stale_point_even_when_refresh_is_refused() {
    for empty in [false, true] {
        let refuse = Rc::new(Cell::new(None));
        let mut fs = Fs::new(RefuseWrite {
            inner: RamStorage::new(),
            refuse: refuse.clone(),
            refuse_remove: Rc::new(Cell::new(None)),
        });
        fs.scan();
        let rng = RefCell::new(TestRng(7));
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        select(&mut app, &mut fs);
        let key = stored(&mut fs, key_fid(SLOT_ATTESTATION).get());
        fs.put(pubkey_fid(SLOT_ATTESTATION), &[0x5a; 97]).unwrap();
        if empty {
            fs.put(EF_ATTESTATION_CERT, &[]).unwrap();
        } else {
            fs.delete(EF_ATTESTATION_CERT).unwrap();
        }
        refuse.set(Some(pubkey_fid(SLOT_ATTESTATION)));
        let mut fs = Fs::new(fs.into_storage());
        fs.scan();
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        select(&mut app, &mut fs);
        assert_eq!(stored(&mut fs, key_fid(SLOT_ATTESTATION).get()), key);
        assert_current_chain(&mut app, &mut fs);
        assert_eq!(stored(&mut fs, pubkey_fid(SLOT_ATTESTATION)), None);
    }
}

#[test]
fn a_refused_cache_retirement_preserves_the_existing_f9_and_owes_certificate_repair() {
    let remove = Rc::new(Cell::new(None));
    let mut fs = Fs::new(RefuseWrite {
        inner: RamStorage::new(),
        refuse: Rc::new(Cell::new(None)),
        refuse_remove: remove.clone(),
    });
    fs.scan();
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    select(&mut app, &mut fs);
    let key = stored(&mut fs, key_fid(SLOT_ATTESTATION).get());
    fs.delete(EF_ATTESTATION_CERT).unwrap();
    let point = stored(&mut fs, pubkey_fid(SLOT_ATTESTATION));
    remove.set(Some(pubkey_fid(SLOT_ATTESTATION)));
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut out = [0xa5; 256];
    let mut response = ResBuf::new(&mut out);
    assert_eq!(
        Applet::select(&mut app, false, &mut fs, &mut response),
        Sw::MEMORY_FAILURE
    );
    assert!(response.as_slice().is_empty());
    assert_eq!(out, [0xa5; 256]);
    assert_eq!(stored(&mut fs, key_fid(SLOT_ATTESTATION).get()), key);
    assert_eq!(stored(&mut fs, pubkey_fid(SLOT_ATTESTATION)), point);
    assert_eq!(stored(&mut fs, EF_ATTESTATION_CERT), None);
    remove.set(None);
    select(&mut app, &mut fs);
    assert_eq!(stored(&mut fs, key_fid(SLOT_ATTESTATION).get()), key);
    assert_current_chain(&mut app, &mut fs);
}

#[test]
fn a_legacy_complete_certificate_for_a_preceding_f9_is_repaired_without_replacing_its_key() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut fs = new_fs();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    select(&mut app, &mut fs);
    let old_certificate = stored(&mut fs, EF_ATTESTATION_CERT);
    let replacement = PrivKey::from_scalar(Curve::P384, &[1; 48]).unwrap();
    seal::store_ec_key(
        &identity(),
        &mut fs,
        &mut TestRng(19),
        key_fid(SLOT_ATTESTATION),
        &replacement,
    )
    .unwrap();
    let key = stored(&mut fs, key_fid(SLOT_ATTESTATION).get());
    let mut fs = Fs::new(fs.into_storage());
    fs.scan();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    select(&mut app, &mut fs);
    assert_current_chain(&mut app, &mut fs);
    assert_eq!(stored(&mut fs, key_fid(SLOT_ATTESTATION).get()), key);
    assert_ne!(stored(&mut fs, EF_ATTESTATION_CERT), old_certificate);
}

#[test]
fn a_complete_f9_certificate_survives_repair_of_only_its_legacy_public_cache() {
    let refuse = Rc::new(Cell::new(None));
    let mut fs = Fs::new(RefuseWrite {
        inner: RamStorage::new(),
        refuse: refuse.clone(),
        refuse_remove: Rc::new(Cell::new(None)),
    });
    fs.scan();
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    select(&mut app, &mut fs);
    let key = stored(&mut fs, key_fid(SLOT_ATTESTATION).get());
    let certificate = stored(&mut fs, EF_ATTESTATION_CERT);
    fs.put(pubkey_fid(SLOT_ATTESTATION), &[0x5a; 97]).unwrap();
    refuse.set(Some(pubkey_fid(SLOT_ATTESTATION)));
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    select(&mut app, &mut fs);
    assert_current_chain(&mut app, &mut fs);
    assert_eq!(stored(&mut fs, key_fid(SLOT_ATTESTATION).get()), key);
    assert_eq!(stored(&mut fs, EF_ATTESTATION_CERT), certificate);
}

#[test]
fn a_truncated_f9_certificate_is_rebuilt_under_its_existing_key() {
    for object in [&[0x70, 1, 0][..], &[0x70, 0x82, 1][..]] {
        let rng = RefCell::new(TestRng(7));
        let presence = RefCell::new(AlwaysConfirm);
        let mut fs = new_fs();
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        select(&mut app, &mut fs);
        let key = stored(&mut fs, key_fid(SLOT_ATTESTATION).get());
        fs.put(EF_ATTESTATION_CERT, object).unwrap();
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        select(&mut app, &mut fs);
        assert_current_chain(&mut app, &mut fs);
        assert_eq!(stored(&mut fs, key_fid(SLOT_ATTESTATION).get()), key);
    }
}

#[test]
fn malformed_spki_and_nonzero_unused_bits_cannot_preserve_a_broken_f9_certificate() {
    for corrupt_spki_tag in [false, true] {
        let rng = RefCell::new(TestRng(7));
        let presence = RefCell::new(AlwaysConfirm);
        let mut fs = new_fs();
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        select(&mut app, &mut fs);
        let key = stored(&mut fs, key_fid(SLOT_ATTESTATION).get());
        let mut object = stored(&mut fs, EF_ATTESTATION_CERT).unwrap();
        let der = find_tag(&object, 0x70).unwrap();
        let certificate = find_tag(der, 0x30).unwrap();
        let tbs = find_tag(certificate, 0x30).unwrap();
        let (tag, spki) = Tlv::new(tbs).nth(6).unwrap();
        assert_eq!(tag, 0x30);
        let field = if corrupt_spki_tag {
            let offset = spki.as_ptr() as usize - object.as_ptr() as usize;
            let len = u16::try_from(spki.len()).unwrap();
            offset - rsk_sdk::tlv::len_tag(tag, len) + spki.len()
        } else {
            find_tag(spki, 3).unwrap().as_ptr() as usize - object.as_ptr() as usize
        };
        object[field] = if corrupt_spki_tag { 0x31 } else { 1 };
        fs.put(EF_ATTESTATION_CERT, &object).unwrap();
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        select(&mut app, &mut fs);
        assert_current_chain(&mut app, &mut fs);
        assert_eq!(stored(&mut fs, key_fid(SLOT_ATTESTATION).get()), key);
    }
}

#[test]
fn a_faulted_public_cache_probe_refuses_without_repairing_either_public_record() {
    let (backend, medium) = ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    select(&mut app, &mut fs);
    let key = medium.value(key_fid(SLOT_ATTESTATION).get());
    let certificate = medium.value(EF_ATTESTATION_CERT);
    let cached = medium.value(pubkey_fid(SLOT_ATTESTATION));
    let generation = fs.write_gen();
    medium.stick(Some(pubkey_fid(SLOT_ATTESTATION)));
    assert_eq!(
        scan_files(&identity(), &mut fs, &mut TestRng(19)),
        Err(Sw::MEMORY_FAILURE)
    );
    medium.stick(None);
    assert_eq!(fs.write_gen(), generation);
    assert_eq!(medium.value(key_fid(SLOT_ATTESTATION).get()), key);
    assert_eq!(medium.value(EF_ATTESTATION_CERT), certificate);
    assert_eq!(medium.value(pubkey_fid(SLOT_ATTESTATION)), cached);
}

#[test]
fn a_refused_f9_root_migration_blocks_select_until_a_healthy_boot_retries_it() {
    const OTP: [u8; 32] = [0x44; 32];
    fn otp_source(out: &mut [u8; 32]) -> bool {
        *out = OTP;
        true
    }
    let refuse = Rc::new(Cell::new(None));
    let mut fs = Fs::new(RefuseWrite {
        inner: RamStorage::new(),
        refuse: refuse.clone(),
        refuse_remove: Rc::new(Cell::new(None)),
    });
    fs.scan();
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
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
    let f9 = stored(&mut fs, key_fid(SLOT_ATTESTATION).get());
    let certificate = stored(&mut fs, EF_ATTESTATION_CERT);
    let gates = [EF_PIN, EF_PUK, EF_RETRIES].map(|fid| (fid, stored(&mut fs, fid)));
    let dev = Device {
        otp_key: Some(&OTP),
        ..identity()
    };
    refuse.set(Some(key_fid(SLOT_ATTESTATION).get()));
    assert!(migrate_kbase(&dev, &mut fs, &mut TestRng(9)));
    assert!(seal::load_ec_key(&dev, &mut fs, key_fid(SLOT_AUTHENTICATION)).is_ok());
    let generation = fs.write_gen();
    let mut app = PivApplet::new(
        SERIAL,
        HASH,
        Some(FusedKey::open(otp_source)),
        &rng,
        &presence,
    );
    let mut output = [0xa5; 256];
    let mut response = ResBuf::new(&mut output);
    assert_eq!(
        Applet::select(&mut app, false, &mut fs, &mut response),
        Sw::MEMORY_FAILURE
    );
    assert!(response.as_slice().is_empty());
    assert_eq!(output, [0xa5; 256]);
    assert_eq!(fs.write_gen(), generation);
    assert_eq!(stored(&mut fs, key_fid(SLOT_ATTESTATION).get()), f9);
    assert_eq!(stored(&mut fs, EF_ATTESTATION_CERT), certificate);
    for (fid, before) in gates {
        assert_eq!(stored(&mut fs, fid), before);
    }
    refuse.set(None);
    assert!(!migrate_kbase(&dev, &mut fs, &mut TestRng(11)));
    select(&mut app, &mut fs);
    assert_eq!(stored(&mut fs, EF_ATTESTATION_CERT), certificate);
    assert_current_chain(&mut app, &mut fs);
}
