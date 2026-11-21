// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use elliptic_curve::scalar::IsHigh;

std::thread_local! {
    static NONCE: std::cell::RefCell<Option<[u8; SCALAR_BYTES]>> = const {
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

#[test]
fn raw_prehash_and_non_byte_aligned_boundaries_match_upstream() {
    let mut patterned = [0x53u8; SCALAR_BYTES];
    patterned[0] = 0;
    let keys = [
        Scalar::ONE,
        Option::<Scalar>::from(Scalar::from_repr(patterned.into())).unwrap(),
        -Scalar::ONE,
    ];
    let prehash: std::vec::Vec<u8> = (0..1024).map(|i| (i * 37 + 0xa5) as u8).collect();
    let mut saw_high_s = false;
    for scalar in keys {
        let key = p521::ecdsa::SigningKey::from_bytes(&scalar.to_repr()).unwrap();
        let d = NonZeroScalar::<NistP521>::new(scalar).unwrap();
        for length in [1, 31, 32, 33, 63, 64, 65, 66, 67, 129, 256, 1024] {
            let digest = &prehash[..length];
            let expected: p521::ecdsa::Signature = key.sign_prehash(digest).unwrap();
            let actual = sign(&d, digest);
            assert_eq!(actual.to_bytes(), expected.to_bytes(), "length {length}");
            key.verifying_key().verify_prehash(digest, &actual).unwrap();
            let mut changed = digest.to_vec();
            changed[0] ^= 1;
            assert!(
                key.verifying_key()
                    .verify_prehash(&changed, &actual)
                    .is_err()
            );
            saw_high_s |= bool::from(actual.s().is_high());
        }
    }
    assert!(
        saw_high_s,
        "differential set must detect accidental low-S normalization"
    );
}

#[test]
fn nonce_and_message_use_their_distinct_521_bit_conversions() {
    let d = NonZeroScalar::<NistP521>::new(Scalar::ONE).unwrap();
    let key = p521::ecdsa::SigningKey::from_bytes(&d.to_repr()).unwrap();
    let prehash = [0x53u8; SCALAR_BYTES];
    let mut high = prehash;
    high[0] ^= 0x80;
    let mut low = prehash;
    low[SCALAR_BYTES - 1] ^= 1;

    assert_eq!(bytes2scalar(&prehash), bytes2scalar(&high));
    assert_ne!(bytes2scalar(&prehash), bytes2scalar(&low));
    let actual = [prehash, high, low].map(|digest| {
        let expected: p521::ecdsa::Signature = key.sign_prehash(&digest).unwrap();
        let signature = sign(&d, &digest);
        assert_eq!(signature.to_bytes(), expected.to_bytes());
        key.verifying_key()
            .verify_prehash(&digest, &signature)
            .unwrap();
        signature
    });
    assert_ne!(actual[0].r(), actual[1].r());
    assert_eq!(actual[0].r(), actual[2].r());
    assert_ne!(actual[0].s(), actual[2].s());
}

#[test]
fn rejected_nonce_and_zero_s_continue_the_same_generator() {
    let prehash = [1u8];
    let r = bytes2scalar(&p521::AffinePoint::GENERATOR.x());
    let zero_s_key = -Option::<Scalar>::from(r.invert()).unwrap();
    assert_eq!(Scalar::ONE + r * zero_s_key, Scalar::ZERO);
    let mut one = [0u8; SCALAR_BYTES];
    one[SCALAR_BYTES - 1] = 1;
    for (forced, scalar) in [
        ([0xff; SCALAR_BYTES], Scalar::ONE),
        ([0; SCALAR_BYTES], Scalar::ONE),
        (one, zero_s_key),
    ] {
        let d = NonZeroScalar::<NistP521>::new(scalar).unwrap();
        let order = NistP521::ORDER;
        let mut generator =
            rfc6979::KGenerator::<Digest, Uint>::new(&d.to_repr(), &prehash, &[], &order);
        let mut bytes = p521::FieldBytes::default();
        generator.fill_next_k(&mut bytes);
        let expected = loop {
            generator.fill_next_k(&mut bytes);
            let k = NonZeroScalar::<NistP521>::from_repr(bytes).unwrap();
            if let Ok((signature, _)) = ecdsa::hazmat::sign_prehashed(&d, &k, &prehash) {
                break signature;
            }
        };
        NONCE.with(|nonce| *nonce.borrow_mut() = Some(forced));
        let key = crate::PrivKey::P521(scalar.to_repr().into());
        let mut output = [0xa5; crate::MAX_EC_SIG + 1];
        let length = key.sign(&prehash, &mut output).unwrap();
        NONCE.with(|nonce| assert!(nonce.borrow().is_none()));
        assert_eq!(length, crate::MAX_EC_SIG);
        assert_eq!(output[length], 0xa5);
        let actual = p521::ecdsa::Signature::from_slice(&output[..length]).unwrap();
        assert_eq!(actual.to_bytes(), expected.to_bytes());
        p521::ecdsa::SigningKey::from_bytes(&scalar.to_repr())
            .unwrap()
            .verifying_key()
            .verify_prehash(&prehash, &actual)
            .unwrap();
    }
}

#[test]
#[cfg(debug_assertions)]
fn empty_prehash_preserves_upstream_debug_contract() {
    let d = NonZeroScalar::<NistP521>::new(Scalar::ONE).unwrap();
    assert!(std::panic::catch_unwind(|| sign(&d, &[])).is_err());
    assert!(
        std::panic::catch_unwind(|| {
            ecdsa::hazmat::sign_prehashed_rfc6979::<NistP521, Digest>(&d, &[], &[])
        })
        .is_err()
    );
}

#[test]
fn private_key_route_preserves_scalar_rejection() {
    for scalar in [[0; SCALAR_BYTES], [0xff; SCALAR_BYTES]] {
        let key = crate::PrivKey::P521(scalar);
        let mut output = [0xa5; crate::MAX_EC_SIG];
        assert_eq!(key.sign(&[1], &mut output), Err(crate::EcError::Failed));
        assert_eq!(output, [0xa5; crate::MAX_EC_SIG]);
    }
}
