// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Modular inverse of a fresh RSA blinding factor under a public modulus.

use num_bigint_dig::BigUint;
use num_integer::Integer;
use rsk_secret::Secret;

use crate::{RSA_2048_BYTES, bytes_to_words_le, words_to_bytes_le};

const WORDS: usize = RSA_2048_BYTES / size_of::<u32>();
const MIN_DIVISOR: u32 = 1 << 20;
type Words = [u32; WORDS];
type QuotientMatrix = [[u32; 2]; 2];

fn decode(big: &BigUint, out: &mut Words) {
    let encoded = Secret::new(big.to_bytes_le());
    let mut bytes = Secret::<[u8; RSA_2048_BYTES]>::zeroed();
    bytes.expose_mut()[..encoded.expose().len()].copy_from_slice(encoded.expose());
    bytes_to_words_le(bytes.expose(), out);
}

fn encode(words: &Words) -> Secret<BigUint> {
    let mut bytes = Secret::<[u8; RSA_2048_BYTES]>::zeroed();
    words_to_bytes_le(words, bytes.expose_mut());
    Secret::new(BigUint::from_bytes_le(bytes.expose()))
}

fn top_word(words: &Words, len: usize, shift: u32) -> u32 {
    let low = len.checked_sub(2).map_or(0, |i| words[i]);
    let high = words[len - 1];
    ((u64::from(low) << shift) >> 32) as u32 | (high << shift)
}

fn significant_words(words: &Words) -> usize {
    words
        .iter()
        .rposition(|&word| word != 0)
        .map_or(0, |i| i + 1)
}

// Accumulate the magnitudes of the matrix rows. Their signs alternate with each step.
fn quotients(r: &Words, s: &Words, words: usize, matrix: &mut QuotientMatrix) -> bool {
    let shift = r[words - 1].leading_zeros();
    let mut x = top_word(r, words, shift);
    let mut y = top_word(s, words, shift);
    *matrix = [[1, 0], [0, 1]];
    let mut odd = false;
    // The leading remainder after the step is at least MIN_DIVISOR.
    // Reconstructing the original u32 heads bounds each coefficient below 4096.
    while y >= MIN_DIVISOR {
        let q = x / y;
        (x, y) = (y, x % y);
        let [[a, b], [c, d]] = *matrix;
        *matrix = [[c, d], [a + c * q, b + d * q]];
        odd = !odd;
    }
    odd
}

fn residues(
    r: &Words,
    s: &Words,
    next_r: &mut Words,
    next_s: &mut Words,
    matrix: &QuotientMatrix,
    odd: bool,
    words: usize,
) -> bool {
    let &[[a, b], [c, d]] = matrix;
    let (r, s, a, b, c, d) = if odd {
        (s, r, b, a, d, c)
    } else {
        (r, s, a, b, c, d)
    };
    let (a, b, c, d) = (i64::from(a), i64::from(b), i64::from(c), i64::from(d));
    let (mut h0, mut h1) = (0, 0);
    for i in 0..words {
        let ri = i64::from(r[i]);
        let si = i64::from(s[i]);
        let v0 = ri * a - si * b + h0;
        let v1 = si * d - ri * c + h1;
        next_r[i] = v0 as u32;
        next_s[i] = v1 as u32;
        h0 = v0 >> 32;
        h1 = v1 >> 32;
    }
    h0 == 0
        && h1 == 0
        && next_r[..words]
            .iter()
            .rev()
            .cmp(next_s[..words].iter().rev())
            .is_gt()
}

// The two Bezout coefficients have opposite signs, so both sums use magnitudes.
fn coefficients(x: &mut Words, y: &mut Words, matrix: &QuotientMatrix) {
    let &[[a, b], [c, d]] = matrix;
    let (a, b, c, d) = (u64::from(a), u64::from(b), u64::from(c), u64::from(d));
    let (mut h0, mut h1) = (0, 0);
    for (x, y) in x.iter_mut().zip(y.iter_mut()) {
        let xi = u64::from(*x);
        let yi = u64::from(*y);
        let v0 = xi * a + yi * b + h0;
        let v1 = xi * c + yi * d + h1;
        *x = v0 as u32;
        *y = v1 as u32;
        h0 = v0 >> 32;
        h1 = v1 >> 32;
    }
}

fn exact_step(r: &mut Words, s: &mut Words, x: &mut Words, y: &mut Words) {
    let a = encode(r);
    let b = encode(s);
    let (quotient, remainder) = a.expose().div_rem(b.expose());
    let quotient = Secret::new(quotient);
    let remainder = Secret::new(remainder);
    r.copy_from_slice(s);
    decode(remainder.expose(), s);
    let a = encode(x);
    let b = encode(y);
    let scaled = Secret::new(b.expose() * quotient.expose());
    let c = Secret::new(a.expose() + scaled.expose());
    x.copy_from_slice(y);
    decode(c.expose(), y);
}

/// Variable-time Lehmer inversion for a freshly drawn value below the public modulus.
/// Both inputs fit in an RSA-2048 modulus width.
#[inline(never)]
pub(super) fn inverse_2048(value: &BigUint, n: &BigUint) -> Option<Secret<BigUint>> {
    let mut r = Secret::new([0; WORDS]);
    let mut s = Secret::new([0; WORDS]);
    let mut next_r = Secret::new([0; WORDS]);
    let mut next_s = Secret::new([0; WORDS]);
    let mut x = Secret::new([0; WORDS]);
    let mut y = Secret::new([0; WORDS]);
    let mut matrix = Secret::new([[1u32, 0], [0, 1]]);
    decode(n, r.expose_mut());
    decode(value, s.expose_mut());
    y.expose_mut()[0] = 1;
    let mut negative = true;
    let mut words = significant_words(r.expose());
    while s.expose()[..words].iter().any(|&v| v != 0) {
        if words == 1 {
            let (a, b) = (r.expose()[0], s.expose()[0]);
            r.expose_mut()[0] = b;
            s.expose_mut()[0] = a % b;
            *matrix.expose_mut() = [[0, 1], [1, a / b]];
            coefficients(x.expose_mut(), y.expose_mut(), matrix.expose());
            negative = !negative;
            continue;
        }

        let odd = quotients(r.expose(), s.expose(), words, matrix.expose_mut());
        let changed = matrix.expose()[0][1] != 0;
        // A sorted nonnegative result validates the whole quotient sequence:
        // run Euclid backwards, using that every simulated quotient was positive.
        if changed
            && residues(
                r.expose(),
                s.expose(),
                next_r.expose_mut(),
                next_s.expose_mut(),
                matrix.expose(),
                odd,
                words,
            )
        {
            r.expose_mut()[..words].copy_from_slice(&next_r.expose()[..words]);
            s.expose_mut()[..words].copy_from_slice(&next_s.expose()[..words]);
            coefficients(x.expose_mut(), y.expose_mut(), matrix.expose());
            negative ^= odd;
        } else {
            exact_step(
                r.expose_mut(),
                s.expose_mut(),
                x.expose_mut(),
                y.expose_mut(),
            );
            negative = !negative;
        }
        words = significant_words(r.expose());
    }
    if r.expose()[0] != 1 || significant_words(r.expose()) != 1 {
        return None;
    }
    let result = encode(x.expose());
    if negative && result.expose().bits() != 0 {
        return Some(Secret::new(n - result.expose()));
    }
    Some(result)
}

#[cfg(test)]
#[path = "blind_inverse_tests.rs"]
mod tests;
