// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use num_bigint_dig::BigUint;

fn big(words: &[u32]) -> BigUint {
    let bytes: alloc::vec::Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    BigUint::from_bytes_le(&bytes)
}

#[test]
fn inverse_cancels_a_word() {
    for n in [1u32, 3, u32::MAX, 21, 0x8000_0001] {
        assert_eq!(n.wrapping_mul(negative_inverse(&[n])), u32::MAX);
    }
}

#[test]
fn wide_arithmetic_matches_biguint() {
    let mut state = 0x3979_b3f5u32;
    let mut random = || {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state
    };
    for w in [1, 2, 3, 4, 5, 8, 32, 48, 64, 128] {
        for (a, b) in [
            (alloc::vec![0; w], alloc::vec![u32::MAX; w]),
            (alloc::vec![u32::MAX; w], alloc::vec![u32::MAX; w]),
            (
                (0..w).map(|_| random()).collect(),
                (0..w).map(|_| random()).collect(),
            ),
        ] {
            let a_big = big(&a);
            let b_big = big(&b);
            let mut product = alloc::vec![u32::MAX; 2 * w];
            let radix = BigUint::from(1u8) << (32 * w);
            mul_acc(&mut product, &a, &b);
            assert_eq!(big(&product), &a_big * &b_big + &radix - 1u8);
            square(&mut product, &a);
            assert_eq!(big(&product), &a_big * &a_big);
            for n in [alloc::vec![u32::MAX; w], {
                let mut small = alloc::vec![0; w];
                small[0] = 3;
                small
            }] {
                let value = &radix * big(&n) - 1u8;
                let mut bytes = value.to_bytes_le();
                bytes.resize(8 * w, 0);
                crate::bytes_to_words_le(&bytes, &mut product);
                reduce(&mut product, &n, negative_inverse(&n));
                let n = big(&n);
                let out = big(&product[w..]);
                assert!(out < n);
                assert_eq!(out * &radix % &n, value % &n);
                assert!(product[..w].iter().all(|word| *word == 0));
            }
        }
    }
}

#[test]
fn subtraction_handles_borrow_and_final_reduction() {
    let n = [1, 2];
    let mut a = [0, 1];
    sub_mod(&mut a, &[1, 1], &n);
    assert_eq!(a, [0, 2]);

    let mut a = [0, 3];
    sub_mod(&mut a, &n, &n);
    assert_eq!(a, [u32::MAX, 0]);

    let mut a = n;
    sub_mod(&mut a, &n, &n);
    assert_eq!(a, [0; 2]);
}

#[test]
fn conversion_preserves_the_padded_radix() {
    let mut state = 0x9e37_79b9u32;
    let mut word = || {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state
    };
    for w in [1usize, 2, 8, 32, 64, 128] {
        let mut n = [0; 128];
        let mut a = [0; 128];
        let mut out = [u32::MAX; 128];
        let mut scratch = [u32::MAX; 128];
        for significant in [1, w.div_ceil(2), w] {
            for shift in [0, 1, 17, 31] {
                for b in &mut n[..significant] {
                    *b = word();
                }
                n[0] |= 1;
                n[significant - 1] >>= shift;
                n[significant - 1] |= 1 << (31 - shift);
                a[..significant].copy_from_slice(&n[..significant]);
                a[0] -= 1;
                to_mont(&mut out[..w], &a[..w], &n[..w], &mut scratch);
                assert_eq!(big(&out[..w]), (big(&a[..w]) << (w * 32)) % big(&n[..w]));
            }
        }
    }
}

#[test]
fn conversion_corrects_a_quotient_two_too_high() {
    let n = [0xf80b_0845, 0x8e0f_9c65];
    let a = [0x1a90_f87b, 0x7ab5_7e29];
    let mut out = [0; 2];
    to_mont(&mut out, &a, &n, &mut [0; 2]);
    assert_eq!(out, [0xd013_ec76, 0x317d_81ac]);
}
