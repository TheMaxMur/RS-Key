// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

std::thread_local! {
    static ORDER: std::cell::Cell<Option<U384>> = const { std::cell::Cell::new(None) };
    static ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static REJECTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(super) fn candidate_order(order: U384) -> U384 {
    ORDER.with(|value| value.get().unwrap_or(order))
}

pub(super) fn accept_candidate(accepted: bool) -> bool {
    ATTEMPTS.with(|attempts| attempts.set(attempts.get() + 1));
    REJECTIONS.with(|remaining| {
        if remaining.get() == 0 || !accepted {
            accepted
        } else {
            remaining.set(remaining.get() - 1);
            false
        }
    })
}

fn compare(d: &p384::Scalar, hash: &[u8; 48], rejections: usize) {
    let order = *p384::NistP384::ORDER;
    let mut reference = rfc6979::KGenerator::<Sha384, U384>::new(&d.to_repr(), hash, &[], &order);
    let mut expected = [0; 48];
    for _ in 0..=rejections {
        reference.fill_next_k(&mut expected);
    }
    REJECTIONS.with(|remaining| remaining.set(rejections));
    let mut actual = [0; 48];
    fill_nonce(d, hash, &mut actual);
    REJECTIONS.with(|remaining| assert_eq!(remaining.get(), 0));
    assert_eq!(
        actual, expected,
        "nonce differs after {rejections} rejections"
    );
}

#[test]
fn matches_upstream_nonce_at_scalar_and_hash_boundaries() {
    let order = *p384::NistP384::ORDER;
    let last = order.wrapping_sub(&U384::ONE);
    let scalars = [U384::ONE, U384::ONE.shl_vartime(383), last];
    let hashes = [U384::ZERO, U384::ONE, last, order, U384::MAX];
    for scalar in scalars {
        let d = Option::<p384::Scalar>::from(p384::Scalar::from_repr(scalar.to_be_bytes().into()))
            .unwrap();
        for hash in hashes {
            for rejections in 0..=2 {
                compare(&d, &hash.to_be_bytes().into(), rejections);
            }
        }
    }
}

#[test]
fn matches_upstream_for_dense_private_keys_and_hashes() {
    let mut state = 0x7985_41df_296b_a03cu64;
    for _ in 0..128 {
        let mut bytes = [[0u8; 48]; 2];
        for value in &mut bytes {
            for chunk in value.as_chunks_mut::<8>().0 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *chunk = state.to_be_bytes();
            }
        }
        let d = <p384::Scalar as Reduce<U384>>::reduce(&U384::from_be_slice(&bytes[0]));
        compare(&d, &bytes[1], 0);
    }
}

#[test]
fn refuses_zero_and_out_of_range_candidates_without_reduction() {
    let order = *p384::NistP384::ORDER;
    for value in [U384::ZERO, order, order.wrapping_add(&U384::ONE), U384::MAX] {
        assert!(
            !acceptable(&value.to_be_bytes().into()),
            "invalid nonce accepted"
        );
    }
    for value in [U384::ONE, order.wrapping_sub(&U384::ONE)] {
        assert!(
            acceptable(&value.to_be_bytes().into()),
            "valid nonce refused"
        );
    }
}

#[test]
fn retries_actual_out_of_range_draws_through_the_nonce_entry_point() {
    // A 384-bit test order makes rejection common; d and h remain below both orders.
    let order = U384::ONE.shl_vartime(383).wrapping_add(&U384::ONE);
    let private = p384::Scalar::ONE;
    let hash: [u8; 48] = U384::from(13u32).to_be_bytes().into();
    let mut reference =
        rfc6979::KGenerator::<Sha384, U384>::new(&private.to_repr(), &hash, &[], &order);
    let mut expected = [0; 48];
    reference.fill_next_k(&mut expected);
    ORDER.with(|value| value.set(Some(order)));
    ATTEMPTS.with(|attempts| attempts.set(0));
    let mut actual = [0; 48];
    fill_nonce(&private, &hash, &mut actual);
    ORDER.with(|value| value.set(None));
    ATTEMPTS.with(|attempts| assert_eq!(attempts.get(), 3, "range check or retry bypassed"));
    assert_eq!(actual, expected);
    assert_eq!(
        U384::from_be_slice(&actual),
        U384::from_be_hex(
            "4b40e5e32f057c49b13c2a6583a68555ac9d0c003fc3f340f2170bf2cc317f193edac8abecb71fa623f9c7dae2ad5140"
        ),
    );
}
