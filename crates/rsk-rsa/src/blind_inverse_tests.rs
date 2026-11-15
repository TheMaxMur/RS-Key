// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use num_bigint_dig::ModInverse;

use super::*;
use crate::Rng;
use crate::fixtures::{SeqRng, modulus, test_key};

fn compare(candidate: &BigUint, modulus: &BigUint) {
    let expected = candidate.mod_inverse(modulus).and_then(|v| v.to_biguint());
    let actual = inverse_2048(candidate, modulus);
    assert_eq!(actual.as_ref().map(Secret::expose), expected.as_ref());
}

#[test]
fn inverse_matches_biguint_across_fresh_rsa_width_blinds() {
    let n = modulus();
    let mut rng = SeqRng(19);
    for _ in 0..128 {
        let mut bytes = [0; RSA_2048_BYTES];
        rng.fill(&mut bytes);
        compare(&(BigUint::from_bytes_le(&bytes) % &n), &n);
    }
}

#[test]
fn inverse_handles_large_quotients_and_non_units() {
    let n = modulus();
    let one = BigUint::from(1u8);
    compare(&one, &BigUint::from(u32::MAX));
    compare(&one, &n);
    compare(&(&n - &one), &n);
    compare(&BigUint::from(0u8), &n);
    compare(&BigUint::from(0u8), &one);
    let factor = BigUint::from(0x1_0000_0001u64);
    compare(&factor, &(&factor * BigUint::from(3u8)));
    let key = test_key();
    compare(key.p(), &n);
    compare(key.q(), &n);

    // The leading words suggest quotient 2 even though the exact quotient is 1.
    let sparse = (&one << 2047usize) + BigUint::from(3u8);
    compare(&((&sparse + &one) >> 1usize), &sparse);

    let middle = (&n - &one) >> 1usize;
    compare(&middle, &n);
    compare(&(&middle + &one), &n);
}

#[test]
fn approximate_batches_match_exact_steps_for_both_parities() {
    let mut left = [0; WORDS];
    decode(&BigUint::from(0x5d9f_e971_9000_0003u64), &mut left);
    assert_eq!(top_word(&left, 2, 1), 0xbb3f_d2e3);

    // Exact remainders after eight and nine Euclidean steps respectively.
    for (input, head, expected_odd, expected_left, expected_right) in [
        (
            0x32a0_5c77_a000_0035u64,
            0x6540_b8ef,
            false,
            0x0008_ce4c_afff_e4e8u64,
            0x0007_d0b9_d002_0a35u64,
        ),
        (
            0x315e_e861_e000_004fu64,
            0x62bd_d0c3,
            true,
            0x0021_3d50_b000_6eafu64,
            0x0004_0088_6fff_3344u64,
        ),
    ] {
        let mut right = [0; WORDS];
        decode(&BigUint::from(input), &mut right);
        assert_eq!(top_word(&right, 2, 1), head);

        let mut matrix = [[0; 2]; 2];
        let odd = quotients(&left, &right, 2, &mut matrix);
        assert_eq!(odd, expected_odd);
        let mut next_left = [0; WORDS];
        let mut next_right = [0; WORDS];
        assert!(residues(
            &left,
            &right,
            &mut next_left,
            &mut next_right,
            &matrix,
            odd,
            2,
        ));
        assert_eq!(*encode(&next_left).expose(), BigUint::from(expected_left));
        assert_eq!(*encode(&next_right).expose(), BigUint::from(expected_right));
    }
}

#[test]
fn invalid_euclidean_batches_are_rejected() {
    for (left, right, matrix, odd) in [
        (8, 3, [[0, 1], [1, 1]], true),
        (4_000_000_000, 3_000_000_000, [[0, 1], [1, 2]], true),
        (3_000_000_000, 2_000_000_000, [[1, 2], [1, 3]], false),
    ] {
        let mut r = [0; WORDS];
        let mut s = [0; WORDS];
        r[0] = left;
        s[0] = right;
        assert!(!residues(
            &r,
            &s,
            &mut [0; WORDS],
            &mut [0; WORDS],
            &matrix,
            odd,
            1,
        ));
    }
}
