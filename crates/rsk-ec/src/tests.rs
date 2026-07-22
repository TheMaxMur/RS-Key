// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

// A fixed, in-range nonzero scalar per curve (high byte small so it is < n).
fn scalar_p256() -> p256::Scalar {
    use p256::elliptic_curve::PrimeField;
    let mut b = [0u8; 32];
    b[0] = 0x11;
    b[31] = 0x42;
    Option::from(p256::Scalar::from_repr(p256::FieldBytes::from(b))).unwrap()
}
fn scalar_p384() -> p384::Scalar {
    use p384::elliptic_curve::PrimeField;
    let mut b = [0u8; 48];
    b[0] = 0x11;
    b[47] = 0x42;
    Option::from(p384::Scalar::from_repr(p384::FieldBytes::from(b))).unwrap()
}
fn scalar_k256() -> k256::Scalar {
    use k256::elliptic_curve::PrimeField;
    let mut b = [0u8; 32];
    b[0] = 0x11;
    b[31] = 0x42;
    Option::from(k256::Scalar::from_repr(k256::FieldBytes::from(b))).unwrap()
}
fn scalar_p521() -> p521::Scalar {
    use p521::elliptic_curve::PrimeField;
    let mut b = [0u8; 66];
    b[0] = 0x00;
    b[1] = 0x11;
    b[65] = 0x42;
    Option::from(p521::Scalar::from_repr(p521::FieldBytes::from(b))).unwrap()
}

#[test]
fn comb_matches_generator_all_curves() {
    let k = scalar_p256();
    assert_eq!(
        comb_mul_p256(&k).to_affine(),
        (p256::ProjectivePoint::GENERATOR * k).to_affine()
    );
    let k = scalar_p384();
    assert_eq!(
        comb_mul_p384(&k).to_affine(),
        (p384::ProjectivePoint::GENERATOR * k).to_affine()
    );
    let k = scalar_k256();
    assert_eq!(
        comb_mul_k256(&k).to_affine(),
        (k256::ProjectivePoint::GENERATOR * k).to_affine()
    );
    let k = scalar_p521();
    assert_eq!(
        comb_mul_p521(&k).to_affine(),
        (p521::ProjectivePoint::GENERATOR * k).to_affine()
    );
}

#[test]
fn sign_p256_byte_identical_to_crate() {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::elliptic_curve::PrimeField;
    let d = scalar_p256();
    let digest = [0x5au8; 32];
    let mine = sign_p256(&d, &digest).unwrap();
    let sk = p256::ecdsa::SigningKey::from_bytes(&d.to_repr()).unwrap();
    let theirs: p256::ecdsa::Signature = sk.sign_prehash(&digest).unwrap();
    assert_eq!(mine.to_bytes(), theirs.to_bytes());
}

#[test]
fn sign_p384_byte_identical_to_crate() {
    use p384::ecdsa::signature::hazmat::PrehashSigner;
    use p384::elliptic_curve::PrimeField;
    let d = scalar_p384();
    let digest = [0x5au8; 48];
    let mine = sign_p384(&d, &digest).unwrap();
    let sk = p384::ecdsa::SigningKey::from_bytes(&d.to_repr()).unwrap();
    let theirs: p384::ecdsa::Signature = sk.sign_prehash(&digest).unwrap();
    assert_eq!(mine.to_bytes(), theirs.to_bytes());
}

#[test]
fn sign_k256_byte_identical_to_crate() {
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::elliptic_curve::PrimeField;
    let d = scalar_k256();
    let digest = [0x5au8; 32];
    let mine = sign_k256(&d, &digest).unwrap();
    let sk = k256::ecdsa::SigningKey::from_bytes(&d.to_repr()).unwrap();
    let theirs: k256::ecdsa::Signature = sk.sign_prehash(&digest).unwrap();
    assert_eq!(mine.to_bytes(), theirs.to_bytes());
}
