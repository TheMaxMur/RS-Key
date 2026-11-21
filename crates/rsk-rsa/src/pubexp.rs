// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Fixed public exponent for CRT blinding and the result check.

use crate::RSA_E;

/// Fixed-width little-endian inputs and output. Failure leaves `out` untouched.
pub(crate) fn modexp_pub(base: &[u8], modulus: &[u8], out: &mut [u8]) -> bool {
    let len = modulus.len();
    if len == 0 || len > crate::MAX_RSA_BYTES || !len.is_multiple_of(32) {
        return false;
    }
    if base.len() != len || out.len() != len || modulus[0] & 1 == 0 {
        return false;
    }
    let low = u32::from_le_bytes([modulus[0], modulus[1], modulus[2], modulus[3]]);
    if low <= RSA_E && modulus[4..].iter().all(|&b| b == 0) {
        return false;
    }
    // The base can be secret. Subtract across the full width to test base < n.
    let borrow = base.iter().zip(modulus).fold(0u16, |borrow, (&a, &b)| {
        (u16::from(a).wrapping_sub(u16::from(b) + borrow)) >> 15
    });
    if borrow == 0 {
        return false;
    }
    backend::pow(base, modulus, out);
    true
}

fn square_for_65537(mut square: impl FnMut()) {
    const SQUARES: u32 = (RSA_E - 1).trailing_zeros();
    const { assert!(RSA_E == (1 << SQUARES) + 1) };
    for _ in 0..SQUARES {
        square();
    }
}

mod backend {
    use crate::montgomery::*;
    use crate::{MAX_RSA_BYTES, bytes_to_words_le, words_to_bytes_le};
    use rsk_secret::Secret;

    #[inline(never)]
    pub(super) fn pow(base: &[u8], modulus: &[u8], out: &mut [u8]) {
        const MAX_WORDS: usize = MAX_RSA_BYTES / 4;
        let words = modulus.len() / 4;
        let mut n = [0u32; MAX_WORDS];
        let mut base_words = Secret::new([0u32; MAX_WORDS]);
        let mut value = Secret::new([0u32; MAX_WORDS]);
        let mut product = Secret::new([0u32; 2 * MAX_WORDS]);
        let n = &mut n[..words];
        let base_words = &mut base_words.expose_mut()[..words];
        let value = &mut value.expose_mut()[..words];
        let product = &mut product.expose_mut()[..2 * words];
        bytes_to_words_le(modulus, n);
        bytes_to_words_le(base, base_words);
        to_mont(value, base_words, n, product);
        let inverse = negative_inverse(n);

        super::square_for_65537(|| {
            square(product, value);
            reduce(product, n, inverse);
            value.copy_from_slice(&product[words..]);
        });
        // Multiplication by the original base cancels the Montgomery factor.
        mul(product, value, base_words);
        reduce(product, n, inverse);
        words_to_bytes_le(&product[words..], out);
    }
}

#[cfg(test)]
#[path = "pubexp_tests.rs"]
mod tests;
