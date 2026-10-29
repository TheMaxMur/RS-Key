// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use bp256::elliptic_curve::PrimeField;
use bp256::r1::ecdsa::Signature;
use ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
type SigningKey = ecdsa::SigningKey<bp256::BrainpoolP256r1>;

#[test]
fn bp256_private_sign_matches_upstream_at_scalar_and_prehash_boundaries() {
    let mut one = [0; 32];
    one[31] = 1;
    let mut high_bit = [0; 32];
    high_bit[0] = 0x80;
    let interior = [0x55; 32];
    let last: [u8; 32] = (-bp256::r1::Scalar::ONE).to_repr().into();
    let mut high_s_observed = false;
    for scalar in [one, high_bit, interior, last] {
        let key = PrivKey::Bp256(scalar);
        let reference = SigningKey::from_bytes(&scalar.into()).unwrap();
        for length in [1, 15, 16, 23, 31, 32, 33, 48, 64, 128] {
            let digest = vec![0xa5; length];
            let expected: Signature = reference.sign_prehash(&digest).unwrap();
            high_s_observed |= expected != expected.normalize_s();
            let mut out = [0x5a; MAX_EC_SIG + 4];
            let used = key.sign(&digest, &mut out).unwrap();
            assert_eq!(used, expected.to_bytes().len());
            assert_eq!(&out[..used], expected.to_bytes().as_slice());
            assert!(out[used..].iter().all(|b| *b == 0x5a));
            let actual = Signature::from_slice(&out[..used]).unwrap();
            reference
                .verifying_key()
                .verify_prehash(&digest, &actual)
                .unwrap();
            let mut changed = digest;
            changed[0] ^= 1;
            assert!(
                reference
                    .verifying_key()
                    .verify_prehash(&changed, &actual)
                    .is_err()
            );
        }
    }
    assert!(
        high_s_observed,
        "fixtures must notice unintended low-S normalization"
    );
}

#[test]
fn bp256_private_sign_rejects_zero_and_out_of_range_scalars_without_output() {
    let mut order: [u8; 32] = (-bp256::r1::Scalar::ONE).to_repr().into();
    for byte in order.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
    for scalar in [[0; 32], order, [0xff; 32]] {
        assert!(SigningKey::from_bytes(&scalar.into()).is_err());
        let key = PrivKey::Bp256(scalar);
        for length in [0, 64] {
            let mut out = [0x5a; MAX_EC_SIG];
            assert_eq!(
                key.sign(&vec![0xa5; length], &mut out),
                Err(EcError::Failed)
            );
            assert_eq!(out, [0x5a; MAX_EC_SIG]);
        }
    }
}

#[test]
fn bp256_public_points_match_upstream_and_reject_invalid_scalars() {
    let mut one = [0; 32];
    one[31] = 1;
    let mut high = [0; 32];
    high[0] = 0x80;
    let last: [u8; 32] = (-bp256::r1::Scalar::ONE).to_repr().into();
    for scalar in [one, high, last] {
        let reference = SigningKey::from_bytes(&scalar.into()).unwrap();
        let expected = reference.verifying_key().to_sec1_point(false);
        let mut out = [0x5a; MAX_EC_POINT + 4];
        let used = PrivKey::Bp256(scalar).public_point(&mut out).unwrap();
        assert_eq!(&out[..used], expected.as_bytes());
        assert!(out[used..].iter().all(|byte| *byte == 0x5a));
    }
    let mut order = last;
    for byte in order.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
    for scalar in [[0; 32], order, [0xff; 32]] {
        let mut out = [0x5a; MAX_EC_POINT];
        assert_eq!(
            PrivKey::Bp256(scalar).public_point(&mut out),
            Err(EcError::Failed)
        );
        assert_eq!(out, [0x5a; MAX_EC_POINT]);
    }
}
