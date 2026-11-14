// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Fixed public exponent for CRT blinding and the result check. The ARM
//! Montgomery operations are from rsa-armv7 (see `csrc/LICENSE.txt`).

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

fn pow_65537<T>(power: &mut T, mut square: impl FnMut(&mut T), multiply_base: impl FnOnce(&mut T)) {
    const SQUARES: u32 = (RSA_E - 1).trailing_zeros();
    const { assert!(RSA_E == (1 << SQUARES) + 1) };
    for _ in 0..SQUARES {
        square(power);
    }
    multiply_base(power);
}

#[cfg(not(target_os = "none"))]
mod backend {
    use num_bigint_dig::BigUint;
    use rsk_secret::Secret;

    pub(super) fn pow(base: &[u8], modulus: &[u8], out: &mut [u8]) {
        let modulus = BigUint::from_bytes_le(modulus);
        let base = Secret::new(BigUint::from_bytes_le(base));
        let mut power = Secret::new(base.expose().clone());
        super::pow_65537(
            &mut power,
            |power| {
                let square = Secret::new(power.expose() * power.expose());
                *power = Secret::new(square.expose() % &modulus);
            },
            |power| {
                let product = Secret::new(power.expose() * base.expose());
                let reduced = Secret::new(product.expose() % &modulus);
                let bytes = Secret::new(reduced.expose().to_bytes_le());
                out.fill(0);
                out[..bytes.expose().len()].copy_from_slice(bytes.expose());
            },
        );
    }
}

#[cfg(target_os = "none")]
mod backend {
    use crate::{MAX_RSA_BYTES, bytes_to_words_le, words_to_bytes_le};
    use rsk_secret::Secret;

    unsafe extern "C" {
        fn bignum_to_mont(value: *mut u32, n: *const u32, len: usize, scratch: *mut u32);
        fn bignum_modular_inverse(inverse: *mut u32, n: *const u32);
        fn bignum_sqracc(product: *mut u32, value: *const u32, len: usize);
        fn bignum_mulacc(product: *mut u32, a: *const u32, b: *const u32, len: usize);
        fn bignum_mont_redc(
            product: *mut u32,
            len: usize,
            n: *const u32,
            inverse: *const u32,
            not_n: *const u32,
            out: *mut u32,
        );
        fn bignum_submod(
            out: *mut u32,
            not_n: *const u32,
            n: *const u32,
            a: *const u32,
            len: usize,
        ) -> i32;
    }

    #[inline(never)]
    pub(super) fn pow(base: &[u8], modulus: &[u8], out: &mut [u8]) {
        const MAX_WORDS: usize = MAX_RSA_BYTES / 4;
        let len = modulus.len();
        let words = len / 4;
        let mut n = [0u32; MAX_WORDS];
        let mut not_n = [0u32; MAX_WORDS];
        let mut inverse = [0u32; 4];
        bytes_to_words_le(modulus, &mut n[..words]);
        for (dst, &word) in not_n.iter_mut().zip(&n[..words]) {
            *dst = !word;
        }
        let mut base_words = Secret::new([0u32; MAX_WORDS]);
        bytes_to_words_le(base, &mut base_words.expose_mut()[..words]);
        let mut value = Secret::new([0u32; 2 * MAX_WORDS]);
        value.expose_mut()[words..2 * words].copy_from_slice(&base_words.expose()[..words]);
        let mut product = Secret::new([0u32; 2 * MAX_WORDS]);

        let n = n.as_ptr();
        let not_n = not_n.as_ptr();
        let mut buffers = (value.expose_mut(), product.expose_mut());
        // SAFETY: modexp_pub checks len (32..=512, multiple of 32), odd n and
        // base < n. The disjoint aligned arrays hold n/~n, a four-word inverse,
        // and two double-width buffers; only submod aliases its input/output.
        unsafe {
            bignum_to_mont(buffers.0.as_mut_ptr(), n, len, buffers.1.as_mut_ptr());
            bignum_modular_inverse(inverse.as_mut_ptr(), n);
            let inverse = inverse.as_ptr();
            buffers.1[..words].fill(0);
            super::pow_65537(
                &mut buffers,
                |(value, product)| {
                    let (value, product) = (value.as_mut_ptr(), product.as_mut_ptr());
                    bignum_sqracc(product, value, len);
                    bignum_mont_redc(product, len, n, inverse, not_n, value);
                },
                |(value, product)| {
                    let (value, product) = (value.as_mut_ptr(), product.as_mut_ptr());
                    // Multiplication by the original base cancels the Montgomery factor.
                    bignum_mulacc(product, value, base_words.expose().as_ptr(), len);
                    bignum_mont_redc(product, len, n, inverse, not_n, value);
                    bignum_submod(value, not_n, n, value, len);
                },
            );
        }
        words_to_bytes_le(&value.expose()[..words], out);
    }
}

#[cfg(test)]
#[path = "pubexp_tests.rs"]
mod tests;
