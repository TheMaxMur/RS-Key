// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

// The end-to-end (applet) tests in lib.rs cover P-256 + Ed25519; these check
// the raw r‖s output and public-point round-trip for the heavier curves.
struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

fn sign_and_verify(curve: Curve, scalar: &[u8], expect_sig_len: usize) {
    let key = PrivKey::from_scalar(curve, scalar).unwrap();
    // A 64-byte (SHA-512-sized) prehash: ≥ half the field for every curve
    // here (`bits2field` rejects anything shorter than that for P-521).
    let digest = [0x42u8; 64];
    let mut sig = [0u8; MAX_EC_SIG];
    let n = key.sign(&digest, &mut SeqRng(1), &mut sig).unwrap();
    assert_eq!(n, expect_sig_len, "raw r‖s width");
    let mut pt = [0u8; MAX_EC_POINT];
    let pn = key.public_point(&mut pt).unwrap();
    let (point, sig) = (&pt[..pn], &sig[..n]);
    match curve {
        Curve::P384 => {
            use p384::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
            let vk = VerifyingKey::from_sec1_bytes(point).unwrap();
            vk.verify_prehash(&digest, &Signature::from_slice(sig).unwrap())
                .unwrap();
        }
        Curve::K256 => {
            use k256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
            let vk = VerifyingKey::from_sec1_bytes(point).unwrap();
            vk.verify_prehash(&digest, &Signature::from_slice(sig).unwrap())
                .unwrap();
        }
        Curve::P521 => {
            use p521::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
            let vk = VerifyingKey::from_sec1_bytes(point).unwrap();
            vk.verify_prehash(&digest, &Signature::from_slice(sig).unwrap())
                .unwrap();
        }
        _ => unreachable!(),
    }
}

#[test]
fn p384_raw_sign_verifies() {
    sign_and_verify(Curve::P384, &[0x11u8; 48], 96);
}

#[test]
fn k256_raw_sign_verifies() {
    sign_and_verify(Curve::K256, &[0x11u8; 32], 64);
}

#[test]
fn p521_raw_sign_verifies() {
    // Top byte 0 keeps the scalar < n (a P-521 scalar is 521 bits).
    let mut scalar = [0x11u8; 66];
    scalar[0] = 0x00;
    sign_and_verify(Curve::P521, &scalar, 132);
}

/// ECDH Diffie-Hellman symmetry: `ECDH(a, B_pub) == ECDH(b, A_pub)` proves the
/// new Weierstrass agreements (P-384/P-521/secp256k1) compute the right shared
/// x-coordinate of the field width. P-256 + X25519 have their own vectors.
fn ecdh_symmetry(curve: Curve, sa: &[u8], sb: &[u8], zlen: usize) {
    let a = PrivKey::from_scalar(curve, sa).unwrap();
    let b = PrivKey::from_scalar(curve, sb).unwrap();
    let mut pa = [0u8; MAX_EC_POINT];
    let na = a.public_point(&mut pa).unwrap();
    let mut pb = [0u8; MAX_EC_POINT];
    let nb = b.public_point(&mut pb).unwrap();
    let mut z1 = [0u8; 66];
    let n1 = a.ecdh(&pb[..nb], &mut z1).unwrap();
    let mut z2 = [0u8; 66];
    let n2 = b.ecdh(&pa[..na], &mut z2).unwrap();
    assert_eq!(n1, zlen, "shared x-coordinate width");
    assert_eq!(
        &z1[..n1],
        &z2[..n2],
        "DH shared secret must match both ways"
    );
}

#[test]
fn ecdh_weierstrass_dh_symmetry() {
    ecdh_symmetry(Curve::P384, &[0x11; 48], &[0x22; 48], 48);
    ecdh_symmetry(Curve::K256, &[0x11; 32], &[0x22; 32], 32);
    // P-521 scalars need the top byte clear to stay below n.
    let (mut a, mut b) = ([0x11u8; 66], [0x22u8; 66]);
    a[0] = 0;
    b[0] = 0;
    ecdh_symmetry(Curve::P521, &a, &b, 66);
}

#[test]
fn curve_from_attr_matches_oid_only() {
    // ECDSA- and ECDH-tagged P-256 share an OID → same curve.
    assert_eq!(
        curve_from_attr(&[0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]),
        Some(Curve::P256)
    );
    assert_eq!(
        curve_from_attr(&[0x12, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]),
        Some(Curve::P256)
    );
    // RSA / unknown OIDs are not EC curves.
    assert_eq!(curve_from_attr(&[0x01, 0x08, 0x00, 0x00, 0x20, 0x00]), None);
}
