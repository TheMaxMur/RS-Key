// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use num_bigint_dig::BigUint;

fn big(words: &[u32]) -> BigUint {
    let bytes: alloc::vec::Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    BigUint::from_bytes_le(&bytes)
}

#[test]
fn inverse_cancels_four_words() {
    for n in [
        [1, 0, 0, 0],
        [3, 0, 0, 0],
        [u32::MAX; 4],
        [21, 7, 0, u32::MAX],
    ] {
        assert_eq!(
            (big(&n) * big(&negative_inverse(&n)) + 1u8) % (BigUint::from(1u8) << 128),
            BigUint::default()
        );
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
