// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

// These check the raw `r ‖ s` output and the public-point round-trip for the
// heavier Weierstrass curves; P-256 and Ed25519 are covered end-to-end by the
// two applets' own suites.
fn sign_and_verify(curve: Curve, scalar: &[u8], expect_sig_len: usize) {
    let key = PrivKey::from_scalar(curve, scalar).unwrap();
    // A 64-byte (SHA-512-sized) prehash: ≥ half the field for every curve
    // here (`bits2field` rejects anything shorter than that for P-521).
    let digest = [0x42u8; 64];
    let mut sig = [0u8; MAX_EC_SIG];
    let n = key.sign(&digest, &mut sig).unwrap();
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
fn weierstrass_ecdh_tells_undecodable_from_off_curve() {
    // A YubiKey 5.8.0's OpenPGP answers these apart on every curve it has: 6A80
    // for bytes the curve cannot decode, 6581 for a decoded point off the curve.
    let curves = [
        Curve::P256,
        Curve::P384,
        Curve::P521,
        Curve::K256,
        Curve::Bp256,
        Curve::Bp384,
    ];
    for curve in curves {
        let key = PrivKey::from_scalar(curve, &[0x11; 31]).unwrap();
        let mut point = [0u8; MAX_EC_POINT];
        let n = key.public_point(&mut point).unwrap();
        let valid = &point[..n];
        let flen = (n - 1) / 2;
        let mut off_curve = valid.to_vec();
        *off_curve.last_mut().unwrap() ^= 1;
        // x at or past p: a coordinate that decodes but is no field element.
        let mut past_p = valid.to_vec();
        past_p[1..1 + flen].fill(0xFF);
        // The same good point, compressed (`02|03 ‖ x`, y's parity in the tag) and
        // compact (`05 ‖ x`, y left to the reader).
        let mut compressed = vec![0x02 | (valid[n - 1] & 1)];
        compressed.extend_from_slice(&valid[1..1 + flen]);
        let mut compact = compressed.clone();
        compact[0] = 0x05;
        let mut out = [0u8; 66];
        assert!(key.ecdh(valid, &mut out).is_ok(), "{curve:?}: the control");
        for refused in [&off_curve, &past_p] {
            assert_eq!(
                key.ecdh(refused, &mut out),
                Err(EcError::RejectedPoint),
                "{curve:?}: {refused:02x?}"
            );
        }
        let undecodable = [
            &valid[1..],
            compressed.as_slice(),
            compact.as_slice(),
            &[0x00][..],
            &[][..],
        ];
        for bad in undecodable {
            assert_eq!(
                key.ecdh(bad, &mut out),
                Err(EcError::BadPoint),
                "{curve:?}: {bad:02x?}"
            );
        }
    }
}

#[test]
fn ecdh_over_a_stored_scalar_the_curve_refuses_is_a_failure() {
    // The peer is not at fault, so not BadPoint: the agreement fails the way
    // signing with the same key does, whatever point arrives.
    let curves = [
        Curve::P256,
        Curve::P384,
        Curve::P521,
        Curve::K256,
        Curve::Bp256,
        Curve::Bp384,
    ];
    for curve in curves {
        let peer = PrivKey::from_scalar(curve, &[0x11; 31]).unwrap();
        let mut point = [0u8; MAX_EC_POINT];
        let n = peer.public_point(&mut point).unwrap();
        let zero = PrivKey::from_scalar(curve, &[0x00]).unwrap();
        let mut out = [0u8; 66];
        assert_eq!(
            zero.ecdh(&point[..n], &mut out),
            Err(EcError::Failed),
            "{curve:?}"
        );
    }
}
