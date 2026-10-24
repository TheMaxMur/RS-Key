// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use bp384::elliptic_curve::PrimeField;
use bp384::r1::ecdsa::Signature;
use ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
type SigningKey = ecdsa::SigningKey<bp384::BrainpoolP384r1>;

#[test]
fn bp384_private_sign_matches_upstream_at_scalar_and_prehash_boundaries() {
    let mut one = [0; 48];
    one[47] = 1;
    let mut high_bit = [0; 48];
    high_bit[0] = 0x80;
    let interior = [0x55; 48];
    let last: [u8; 48] = (-bp384::r1::Scalar::ONE).to_repr().into();
    let mut high_s_observed = false;
    for scalar in [one, high_bit, interior, last] {
        let key = PrivKey::Bp384(scalar);
        let reference = SigningKey::from_bytes(&scalar.into()).unwrap();
        for length in [1, 23, 24, 31, 32, 47, 48, 49, 64, 128] {
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
fn bp384_private_sign_rejects_zero_and_out_of_range_scalars_without_output() {
    let mut order: [u8; 48] = (-bp384::r1::Scalar::ONE).to_repr().into();
    for byte in order.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
    for scalar in [[0; 48], order, [0xff; 48]] {
        assert!(SigningKey::from_bytes(&scalar.into()).is_err());
        let key = PrivKey::Bp384(scalar);
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
