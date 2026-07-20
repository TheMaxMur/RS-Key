// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

// A deterministic scalar known to be in range (low value, far below n).
fn scalar(seed: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = seed;
    s[0] = seed; // keep it nonzero and varied without exceeding n
    s
}

// Both parties must agree on the same shared secret.
fn agree(proto: PinProto) {
    let a = scalar(0x11);
    let b = scalar(0x22);
    let (ax, ay) = public_xy(&a).unwrap();
    let (bx, by) = public_xy(&b).unwrap();

    let mut sa = [0u8; 64];
    let mut sb = [0u8; 64];
    let na = ecdh(proto, &a, &bx, &by, &mut sa).unwrap();
    let nb = ecdh(proto, &b, &ax, &ay, &mut sb).unwrap();
    assert_eq!(na, proto.shared_len());
    assert_eq!(sa[..na], sb[..nb]);
}

#[test]
fn ecdh_agrees_v1_and_v2() {
    agree(PinProto::One);
    agree(PinProto::Two);
}

// The KDF wiring must match the CTAP2 spec exactly.
#[test]
fn kdf_wiring_matches_spec() {
    let a = scalar(0x11);
    let b = scalar(0x22);
    let (bx, by) = public_xy(&b).unwrap();

    // Recompute Z independently to check the KDF (not the ECDH).
    let mut s1 = [0u8; 64];
    ecdh(PinProto::One, &a, &bx, &by, &mut s1).unwrap();
    let mut s2 = [0u8; 64];
    ecdh(PinProto::Two, &a, &bx, &by, &mut s2).unwrap();

    let sk = SecretKey::from_bytes(&FieldBytes::from(a)).unwrap();
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&bx);
    sec1[33..].copy_from_slice(&by);
    let ep = Sec1Point::from_bytes(&sec1).unwrap();
    let peer = Option::<PublicKey>::from(PublicKey::from_sec1_point(&ep)).unwrap();
    let z = ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    let z = z.raw_secret_bytes();

    // v1: SHA-256(Z).
    assert_eq!(&s1[..32], &sha256(z));
    // v2: HKDF(Z, "CTAP2 HMAC key") ‖ HKDF(Z, "CTAP2 AES key").
    let mut hk = [0u8; 32];
    let mut ak = [0u8; 32];
    hkdf_sha256(&[], z, b"CTAP2 HMAC key", &mut hk).unwrap();
    hkdf_sha256(&[], z, b"CTAP2 AES key", &mut ak).unwrap();
    assert_eq!(&s2[..32], &hk);
    assert_eq!(&s2[32..64], &ak);
}

fn enc_dec(proto: PinProto) {
    let shared = [0x5Au8; 64];
    let iv = [0x77u8; IV_SIZE];
    let pt = [0xABu8; 32]; // block-multiple
    let mut ct = [0u8; IV_SIZE + 32];
    let n = encrypt(proto, &shared, &iv, &pt, &mut ct).unwrap();
    assert_eq!(n, proto.iv_overhead() + 32);
    let mut back = [0u8; 32];
    let m = decrypt(proto, &shared, &ct[..n], &mut back).unwrap();
    assert_eq!(m, 32);
    assert_eq!(back, pt);
}

#[test]
fn encrypt_decrypt_roundtrip() {
    enc_dec(PinProto::One);
    enc_dec(PinProto::Two);
}

#[test]
fn v2_prepends_the_iv() {
    let shared = [0x5Au8; 64];
    let iv = [0x77u8; IV_SIZE];
    let mut ct = [0u8; IV_SIZE + 16];
    let n = encrypt(PinProto::Two, &shared, &iv, &[0u8; 16], &mut ct).unwrap();
    assert_eq!(&ct[..IV_SIZE], &iv);
    assert_eq!(n, IV_SIZE + 16);
}

#[test]
fn verify_accepts_authenticate_and_rejects_tamper() {
    for proto in [PinProto::One, PinProto::Two] {
        let shared = [0x5Au8; 64];
        let data = b"pinUvAuthToken material";
        let mut sig = [0u8; 32];
        let n = authenticate(proto, &shared, data, &mut sig).unwrap();
        assert_eq!(n, proto.mac_len());
        assert!(verify(proto, &shared, data, &sig[..n]));
        sig[0] ^= 1;
        assert!(!verify(proto, &shared, data, &sig[..n]));
        // Wrong length never verifies.
        assert!(!verify(proto, &shared, data, &sig[..n - 1]));
    }
}

#[test]
fn ecdh_rejects_off_curve_point() {
    let a = scalar(0x11);
    // (1, 1) is not on the P-256 curve.
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x[31] = 1;
    y[31] = 1;
    let mut out = [0u8; 64];
    assert_eq!(ecdh(PinProto::Two, &a, &x, &y, &mut out), Err(Error::Ecdh));
}
