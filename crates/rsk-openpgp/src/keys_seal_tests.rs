// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

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
