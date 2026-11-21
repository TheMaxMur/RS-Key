// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

std::thread_local! {
    static NONCE: std::cell::RefCell<Option<std::vec::Vec<u8>>> = const {
        std::cell::RefCell::new(None)
    };
}

pub(super) fn override_nonce(output: &mut [u8]) {
    NONCE.with(|nonce| {
        if let Some(bytes) = nonce.borrow_mut().take() {
            output.copy_from_slice(&bytes);
        }
    });
}

macro_rules! nonce_refusals {
    ($name:ident, $curve:ident, $sign:ident, $scalar:ident, $width:expr) => {
        #[test]
        fn $name() {
            use $curve::ecdsa::signature::hazmat::PrehashVerifier;
            use $curve::elliptic_curve::{PrimeField, ops::Reduce, point::AffineCoordinates};

            let mut digest = [0; $width];
            digest[$width - 1] = 1;
            let ordinary = $scalar();
            let baseline = $sign(&ordinary, &digest).unwrap();
            let r = <$curve::Scalar as Reduce<$curve::FieldBytes>>::reduce(
                &$curve::AffinePoint::GENERATOR.x(),
            );
            let zero_s = -Option::<$curve::Scalar>::from(r.invert()).unwrap();
            assert_eq!($curve::Scalar::ONE + r * zero_s, $curve::Scalar::ZERO);

            for (nonce, key, refusal) in [
                (std::vec![0xff; $width], ordinary, "out-of-range nonce"),
                (std::vec![0; $width], ordinary, "non-invertible nonce"),
                ({
                    let mut one = std::vec![0; $width];
                    one[$width - 1] = 1;
                    one
                }, zero_s, "zero signature scalar"),
            ] {
                NONCE.with(|slot| *slot.borrow_mut() = Some(nonce));
                assert!($sign(&key, &digest).is_none(), "accepted {refusal}");
                NONCE.with(|slot| assert!(slot.borrow().is_none()));
                assert_eq!($sign(&ordinary, &digest).unwrap().to_bytes(), baseline.to_bytes());
            }

            let key = $curve::ecdsa::SigningKey::from_bytes(&ordinary.to_repr()).unwrap();
            $curve::ecdsa::VerifyingKey::from(&key)
                .verify_prehash(&digest, &baseline)
                .unwrap();
        }
    };
}

nonce_refusals!(p256_nonce_refusals, p256, sign_p256, scalar_p256, 32);
nonce_refusals!(p384_nonce_refusals, p384, sign_p384, scalar_p384, 48);
nonce_refusals!(k256_nonce_refusals, k256, sign_k256, scalar_k256, 32);

macro_rules! prehash_reference {
    ($name:ident, $curve:ident, $sign:ident, $scalar:ident, $width:expr) => {
        #[test]
        fn $name() {
            use $curve::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
            use $curve::elliptic_curve::PrimeField;

            let scalar = $scalar();
            let key = $curve::ecdsa::SigningKey::from_bytes(&scalar.to_repr()).unwrap();
            for length in [$width / 2, $width - 1, $width, $width + 1, $width * 2] {
                let digest: std::vec::Vec<_> = (0..length).map(|i| (i * 37) as u8).collect();
                let actual = $sign(&scalar, &digest).unwrap();
                let expected: $curve::ecdsa::Signature = key.sign_prehash(&digest).unwrap();
                assert_eq!(
                    actual.to_bytes(),
                    expected.to_bytes(),
                    "digest length {length}"
                );
                $curve::ecdsa::VerifyingKey::from(&key)
                    .verify_prehash(&digest, &actual)
                    .unwrap();
            }
        }
    };
}

prehash_reference!(p256_prehash_widths, p256, sign_p256, scalar_p256, 32);
prehash_reference!(p384_prehash_widths, p384, sign_p384, scalar_p384, 48);
prehash_reference!(k256_prehash_widths, k256, sign_k256, scalar_k256, 32);

#[test]
fn p521_signing_rejects_non_sha512_digest_lengths() {
    let scalar = scalar_p521();
    for length in [0, 32, 63, 65, 66] {
        assert!(
            sign_p521(&scalar, &std::vec![0x5a; length], &mut |_| panic!(
                "invalid digest drew a nonce"
            ))
            .is_none()
        );
    }
    let mut draws = 0;
    assert!(
        sign_p521(&scalar, &[0x5a; 64], &mut |b| {
            draws += 1;
            assert_eq!(draws, 1, "a valid P-521 nonce was discarded");
            b.fill(1);
        })
        .is_some()
    );
}

#[test]
fn p521_signing_retries_out_of_range_zero_and_zero_signature_nonces() {
    use p521::ecdsa::signature::hazmat::PrehashVerifier;
    use p521::elliptic_curve::{PrimeField, ops::Reduce, point::AffineCoordinates};
    let r = <p521::Scalar as Reduce<p521::FieldBytes>>::reduce(&p521::AffinePoint::GENERATOR.x());
    let scalar = -Option::<p521::Scalar>::from(r.invert()).unwrap();
    let mut digest = [0; 64];
    digest[63] = 1;
    let mut draws = 0;
    let signature = sign_p521(&scalar, &digest, &mut |b| {
        draws += 1;
        b.fill(if draws == 1 { 0xff } else { 0 });
        if draws >= 3 {
            b[65] = (draws - 2) as u8;
        }
        assert!(draws <= 4, "nonce retry did not terminate");
    })
    .unwrap();
    assert_eq!(draws, 4);
    let key = p521::ecdsa::SigningKey::from_bytes(&scalar.to_repr()).unwrap();
    p521::ecdsa::VerifyingKey::from(&key)
        .verify_prehash(&digest, &signature)
        .unwrap();
}

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

macro_rules! comb_boundaries {
    ($name:ident, $curve:ident, $multiply:ident) => {
        #[test]
        fn $name() {
            use $curve::elliptic_curve::PrimeField;
            let check = |scalar| {
                assert_eq!(
                    $multiply(&scalar).to_affine(),
                    ($curve::ProjectivePoint::GENERATOR * scalar).to_affine()
                );
            };
            check($curve::Scalar::ZERO);
            check($curve::Scalar::ONE);
            for value in 1..=16u64 {
                check(-$curve::Scalar::from(value));
            }
            for bit in 0..256 {
                let mut bytes = [0; 32];
                bytes[31 - bit / 8] = 1 << (bit % 8);
                check($curve::Scalar::from_repr(bytes.into()).unwrap());
            }
            for round in [0, 63] {
                for digit in 0..16u8 {
                    let mut bytes = [0; 32];
                    for column in 0..4 {
                        let bit = column * 64 + round;
                        bytes[31 - bit / 8] |= ((digit >> column) & 1) << (bit % 8);
                    }
                    check($curve::Scalar::from_repr(bytes.into()).unwrap());
                }
            }
        }
    };
}

comb_boundaries!(p256_comb_doubling_boundaries, p256, comb_mul_p256);
comb_boundaries!(k256_comb_doubling_boundaries, k256, comb_mul_k256);

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
