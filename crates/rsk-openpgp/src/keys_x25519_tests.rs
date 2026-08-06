// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn x25519_rfc7748_vector() {
    // RFC 7748 §6.1. Alice's scalar arrives as a big-endian OpenPGP MPI (so the
    // little-endian RFC scalar reversed); Bob's public key is the 0x40-prefixed
    // native little-endian u-coordinate. The DECIPHER result is the shared K.
    let alice_le = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let bob_pub = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let k = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    let mut alice_be = alice_le.clone();
    alice_be.reverse();
    let key = PrivKey::from_scalar(Curve::X25519, &alice_be).unwrap();

    let mut point = vec![0x40u8];
    point.extend_from_slice(&bob_pub);
    let mut out = [0u8; 32];
    let n = key.ecdh(&point, &mut out).unwrap();
    assert_eq!(&out[..n], k.as_slice());

    // The peer point is also accepted without the 0x40 native-format prefix.
    let mut out2 = [0u8; 32];
    key.ecdh(&bob_pub, &mut out2).unwrap();
    assert_eq!(out2, out);
}

#[test]
fn x25519_public_point_matches_rfc7748() {
    // Alice's public key is X25519(scalar, basepoint).
    let alice_le = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_pub = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let mut alice_be = alice_le.clone();
    alice_be.reverse();
    let key = PrivKey::from_scalar(Curve::X25519, &alice_be).unwrap();
    let mut out = [0u8; 32];
    let n = key.public_point(&mut out).unwrap();
    assert_eq!(&out[..n], alice_pub.as_slice());
}

#[test]
fn x25519_rejects_bad_peer_length() {
    let key = PrivKey::from_scalar(Curve::X25519, &[0x11u8; 32]).unwrap();
    let mut out = [0u8; 32];
    assert_eq!(key.ecdh(&[0u8; 31], &mut out), Err(Sw::DATA_INVALID));
    assert_eq!(key.ecdh(&[0u8; 40], &mut out), Err(Sw::DATA_INVALID));
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
