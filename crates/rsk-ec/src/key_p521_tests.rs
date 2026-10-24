// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use p521::ecdsa::{
    Signature, SigningKey,
    signature::hazmat::{PrehashSigner, PrehashVerifier},
};
use p521::elliptic_curve::PrimeField;

#[test]
fn p521_private_sign_matches_upstream_at_scalar_and_prehash_boundaries() {
    let mut one = [0; 66];
    one[65] = 1;
    let mut high_bit = [0; 66];
    high_bit[0] = 1;
    let mut interior = [0x55; 66];
    interior[0] = 1;
    let last: [u8; 66] = (-p521::Scalar::ONE).to_repr().into();
    let mut high_s_observed = false;
    for scalar in [one, high_bit, interior, last] {
        let key = PrivKey::P521(scalar);
        let reference = SigningKey::from_bytes(&scalar.into()).unwrap();
        for length in [1, 31, 32, 63, 64, 65, 66, 67, 128] {
            let digest = vec![0xa5; length];
            let expected: Signature = reference.sign_prehash(&digest).unwrap();
            high_s_observed |= expected != expected.normalize_s();
            let mut out = [0x5a; MAX_EC_SIG + 4];
            let used = key.sign(&digest, &mut out).unwrap();
            assert_eq!(used, MAX_EC_SIG);
            assert_eq!(&out[..used], expected.to_bytes().as_slice());
            assert_eq!(&out[used..], &[0x5a; 4]);
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
fn p521_private_sign_rejects_zero_and_out_of_range_scalars_without_output() {
    let mut order: [u8; 66] = (-p521::Scalar::ONE).to_repr().into();
    for byte in order.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
    let mut field_max = [0xff; 66];
    field_max[0] = 1;
    for scalar in [[0; 66], order, field_max, [0xff; 66]] {
        assert!(SigningKey::from_bytes(&scalar.into()).is_err());
        let key = PrivKey::P521(scalar);
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
