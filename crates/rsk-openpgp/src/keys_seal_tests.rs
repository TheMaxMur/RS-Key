// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn seal_and_unseal_refuse_short_windows_and_keep_legacy_widths_distinct() {
    let key = [0x11; 32];
    let nk = [0x22; IV_SIZE];
    let sh = [0x33; 32];
    let mut out = [0xa5; 64];
    assert_eq!(
        seal_with(&key, &nk, &sh, EF_PK_SIG, &[0; 33], &mut out[..60]),
        Err(Sw::WRONG_LENGTH)
    );
    assert_eq!(out, [0xa5; 64]);
    assert_eq!(
        unseal_with(&key, &nk, &sh, &[0; 16], &mut out[..15], legacy_aes_len),
        Err(Sw::WRONG_LENGTH)
    );
    assert_eq!(out, [0xa5; 64]);
    assert_eq!(
        unseal_with(&key, &nk, &sh, &[0; 61], &mut out[..32], legacy_ec_len),
        Err(Sw::SECURITY_STATUS_NOT_SATISFIED)
    );
    assert_eq!(out, [0xa5; 64]);
}

// ------------------------------------------------------------ DEK seal ---

#[test]
fn dek_seal_roundtrips_and_uses_fresh_nonces() {
    let key = [0x11u8; 32];
    let nk = [0x22u8; IV_SIZE];
    let sh = [0x33u8; 32];
    let fid = KeyFid::new(0x10d1);
    let pt_a = [0xAAu8; 33];
    let mut blob_a = [0u8; 33 + DEK_SEAL_OVERHEAD];
    let na = seal_with(&key, &nk, &sh, fid, &pt_a, &mut blob_a).unwrap();
    assert_eq!(na, 33 + DEK_SEAL_OVERHEAD);
    // Round-trips as the new (authenticated) format.
    let mut out = [0u8; 33];
    let (pn, legacy) = unseal_with(&key, &nk, &sh, &blob_a[..na], &mut out, legacy_ec_len).unwrap();
    assert_eq!((pn, legacy), (33, false));
    assert_eq!(&out[..pn], &pt_a);
    // A DIFFERENT plaintext seals under a DIFFERENT nonce — no keystream reuse
    // (the whole point of the fix; the old fixed-IV CFB seal reused it).
    let pt_b = [0xBBu8; 33];
    let mut blob_b = [0u8; 33 + DEK_SEAL_OVERHEAD];
    seal_with(&key, &nk, &sh, fid, &pt_b, &mut blob_b).unwrap();
    assert_ne!(&blob_a[..DEK_NONCE_LEN], &blob_b[..DEK_NONCE_LEN]);
    // …and a wrong-tag / tampered record is REJECTED, not silently reinterpreted.
    // Before audit run-33 this fell through to the (infallible) CFB decrypt, so a
    // tampered or wrong-DEK record came back as a "legacy" key the caller then
    // re-sealed over the original. A GCM-shaped record must fail closed instead.
    let mut bad = blob_a;
    bad[na - 1] ^= 1;
    let mut out2 = [0u8; 33];
    assert_eq!(
        unseal_with(&key, &nk, &sh, &bad[..na], &mut out2, legacy_ec_len),
        Err(Sw::SECURITY_STATUS_NOT_SATISFIED)
    );
}

#[test]
fn legacy_cfb_blob_still_unseals_and_is_flagged() {
    use rsk_crypto::aes::aes_encrypt_cfb_256;
    let key = [0x11u8; 32];
    let nk = [0x22u8; IV_SIZE];
    let sh = [0x33u8; 32];
    let pt = [0xA5u8; 33];
    // An old-format record: bare fixed-IV CFB ciphertext (IV = the nonce key),
    // no nonce/tag — exactly what the pre-fix seal wrote.
    let mut legacy = pt;
    aes_encrypt_cfb_256(&key, &nk, &mut legacy).unwrap();
    let mut out = [0u8; 33];
    let (pn, was_legacy) = unseal_with(&key, &nk, &sh, &legacy, &mut out, legacy_ec_len).unwrap();
    assert!(
        was_legacy,
        "legacy blob must be detected for forward re-sealing"
    );
    assert_eq!(&out[..pn], &pt, "legacy CFB record must still decrypt");
}

/// A key sealed under a DEK the caller holds opens with that DEK's GCM half alone,
/// under the nonce its PRF half derives: the split `load_dek_keys` makes, re-done by
/// hand rather than through the helper the seal itself calls.
#[test]
fn a_key_sealed_under_a_held_dek_opens_with_its_gcm_half() {
    use rsk_fs::storage::ram::RamStorage;
    let dek: [u8; DEK_SIZE] = core::array::from_fn(|i| i as u8);
    let dev = Device {
        serial_hash: &[0x33; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
        latched: false,
    };
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let key = PrivKey::from_scalar(Curve::P256, &[0x11; 32]).unwrap();
    store_ec_key_under(&dev, &mut fs, &dek, EF_PK_ATT, &key).unwrap();

    let mut blob = [0u8; MAX_EC_KDATA + DEK_SEAL_OVERHEAD];
    let n = fs.read_key(EF_PK_ATT, &mut blob).unwrap();
    let (nonce, rest) = blob[..n].split_at(DEK_NONCE_LEN);
    let (ct, tag) = rest.split_at(rest.len() - DEK_TAG_LEN);
    let mut pt = ct.to_vec();
    let gcm: [u8; 32] = dek[IV_SIZE..].try_into().unwrap();
    aes256gcm_decrypt(
        &gcm,
        nonce.try_into().unwrap(),
        dev.serial_hash,
        &mut pt,
        tag.try_into().unwrap(),
    )
    .unwrap();
    assert_eq!(pt, [&[Curve::P256.id()][..], &[0x11; 32]].concat());
    let prf: [u8; IV_SIZE] = dek[..IV_SIZE].try_into().unwrap();
    assert_eq!(nonce, synth_nonce(&prf, EF_PK_ATT, &pt));
}

#[test]
fn authenticated_ec_records_without_a_scalar_are_refused_without_migration() {
    struct Fill;
    impl Rng for Fill {
        fn fill(&mut self, out: &mut [u8]) {
            out.fill(7);
        }
    }
    let dev = Device {
        serial_hash: &[0xab; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
        latched: false,
    };
    let mut fs = Fs::new(rsk_fs::storage::ram::RamStorage::new());
    fs.scan();
    crate::init::scan_files(&dev, &mut fs, &mut Fill).unwrap();
    let mut sess = Session::new();
    sess.adopt_reseeded(
        &dev.pin_derive_session(PW1_DEFAULT),
        &dev.pin_derive_session(PW3_DEFAULT),
    );
    sess.has_pw3 = true;
    for plaintext in [&[][..], &[1][..]] {
        let mut blob = Secret::<[u8; DEK_SEAL_OVERHEAD + 1]>::zeroed();
        let n = dek_seal(
            &dev,
            &mut fs,
            &sess,
            EF_PK_SIG,
            plaintext,
            blob.expose_mut(),
        )
        .unwrap();
        fs.put_key(EF_PK_SIG, Sealed::wrap(&blob.expose()[..n]))
            .unwrap();
        let generation = fs.write_gen();
        assert!(matches!(
            load_ec_key(&dev, &mut fs, &sess, EF_PK_SIG),
            Err(Sw::WRONG_DATA)
        ));
        assert_eq!(fs.write_gen(), generation);
    }
}

#[test]
fn authenticated_nonstandard_rsa_width_deciphers_through_the_software_fallback() {
    struct Fill;
    impl Rng for Fill {
        fn fill(&mut self, out: &mut [u8]) {
            out.fill(7);
        }
    }
    let dev = Device {
        serial_hash: &[0xab; 32],
        serial_id: &[1; 8],
        otp_key: None,
        latched: false,
    };
    let mut fs = Fs::new(rsk_fs::storage::ram::RamStorage::new());
    crate::init::scan_files(&dev, &mut fs, &mut Fill).unwrap();
    let mut sess = Session::new();
    sess.adopt_reseeded(
        &dev.pin_derive_session(PW1_DEFAULT),
        &dev.pin_derive_session(PW3_DEFAULT),
    );
    sess.has_pw2 = true;
    let mut plain = Secret::<[u8; 80]>::zeroed();
    plain.expose_mut()[..40].copy_from_slice(&rsk_rsa::vectors::hex(rsk_rsa::vectors::P640_HEX));
    plain.expose_mut()[40..].copy_from_slice(&rsk_rsa::vectors::hex(rsk_rsa::vectors::Q640_HEX));
    let mut blob = Secret::<[u8; 80 + DEK_SEAL_OVERHEAD]>::zeroed();
    let n = dek_seal(
        &dev,
        &mut fs,
        &sess,
        EF_PK_DEC,
        plain.expose(),
        blob.expose_mut(),
    )
    .unwrap();
    fs.put_key(EF_PK_DEC, Sealed::wrap(&blob.expose()[..n]))
        .unwrap();
    let generation = fs.write_gen();
    assert!(matches!(
        load_rsa_crt(&dev, &mut fs, &sess, EF_PK_DEC),
        Err(Sw::WRONG_LENGTH)
    ));
    // Independent modular exponentiation produced this PKCS#1 v1.5 ciphertext.
    let ciphertext = rsk_rsa::vectors::hex(
        "86dd84736a7c99f13376794f689007694bd084ffe6b079ea4814acd82ad1632856ba03a27c1c15b68d603c08eb3ec20b007f6f96303ec17bc0a366d5155228e2e6cf41e64e41ef439edc56b312848a22",
    );
    let mut request = std::vec![0, INS_PSO, 0x80, 0x86, 81, 0];
    request.extend_from_slice(&ciphertext);
    let apdu = rsk_sdk::Apdu::parse(&request).unwrap();
    let mut output = [0; 80];
    let (n, sw) = crate::pso::pso(
        &dev,
        &mut fs,
        &mut sess,
        &mut Fill,
        &mut crate::AlwaysConfirm,
        &apdu,
        &mut output,
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(&output[..n], b"coverage fallback");
    assert_eq!(fs.write_gen(), generation);
}

#[test]
fn unusable_legacy_rsa_primes_refuse_without_resealing_the_record() {
    struct Fill;
    impl Rng for Fill {
        fn fill(&mut self, out: &mut [u8]) {
            out.fill(7);
        }
    }
    let dev = Device {
        serial_hash: &[0xab; 32],
        serial_id: &[1; 8],
        otp_key: None,
        latched: false,
    };
    let mut fs = Fs::new(rsk_fs::storage::ram::RamStorage::new());
    crate::init::scan_files(&dev, &mut fs, &mut Fill).unwrap();
    let mut sess = Session::new();
    sess.adopt_reseeded(
        &dev.pin_derive_session(PW1_DEFAULT),
        &dev.pin_derive_session(PW3_DEFAULT),
    );
    sess.has_pw3 = true;
    let (mut key, mut nk) = load_dek_keys(&dev, &mut fs, &sess).unwrap();
    let mut blob = Secret::<[u8; 64]>::zeroed();
    rsk_crypto::aes::aes_encrypt_cfb_256(key.expose(), nk.expose(), blob.expose_mut()).unwrap();
    key.wipe();
    nk.wipe();
    fs.put_key(EF_PK_SIG, Sealed::wrap(blob.expose())).unwrap();
    let generation = fs.write_gen();
    assert!(matches!(
        load_rsa_crt(&dev, &mut fs, &sess, EF_PK_SIG),
        Err(Sw::MEMORY_FAILURE)
    ));
    assert_eq!(fs.write_gen(), generation);
    let mut retained = Secret::<[u8; 64]>::zeroed();
    assert_eq!(fs.read_key(EF_PK_SIG, retained.expose_mut()), Some(64));
    assert_eq!(retained.expose(), blob.expose());
}
