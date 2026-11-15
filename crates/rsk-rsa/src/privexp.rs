// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Four-bit private exponentiation and CRT recombination.
//! Based on Emil Lenngren's rsa-armv7, copyright 2025, BSD-2-Clause (`LICENSE-rsa-armv7.txt`).

use crate::MAX_MOD;

fn valid_width(len: usize) -> bool {
    len != 0 && len <= MAX_MOD && len.is_multiple_of(32)
}

fn odd_above_one(low: u8, high: &[u8]) -> bool {
    let upper = high.iter().fold(low & !1, |bits, &byte| bits | byte);
    (low & 1 != 0) & (upper != 0)
}

pub(crate) fn modexp_priv(base: &[u8], exponent: &[u8], modulus: &[u8], out: &mut [u8]) -> bool {
    let len = modulus.len();
    if !valid_width(len)
        || out.len() != len
        || base.len() > len
        || !odd_above_one(modulus[0], &modulus[1..])
    {
        return false;
    }
    let mut borrow = 0u16;
    for (i, &b) in modulus.iter().enumerate() {
        let a = base.get(i).copied().unwrap_or(0);
        borrow = (u16::from(a).wrapping_sub(u16::from(b) + borrow)) >> 15;
    }
    if borrow == 0 {
        return false;
    }
    backend::modexp(base, exponent, modulus, out);
    true
}

/// `base` is little-endian and below p*q. The CRT fields are big-endian.
pub(crate) fn sign_crt(
    base: &[u8],
    dp: &[u8],
    dq: &[u8],
    p: &[u8],
    q: &[u8],
    qinv: &[u8],
    out: &mut [u8],
) -> bool {
    let half = p.len();
    if !valid_width(half)
        || q.len() != half
        || qinv.len() != half
        || base.len() != 2 * half
        || out.len() != base.len()
        || !odd_above_one(p[half - 1], &p[..half - 1])
        || !odd_above_one(q[half - 1], &q[..half - 1])
    {
        return false;
    }
    backend::crt(base, dp, dq, p, q, qinv, out);
    true
}

const WINDOW_ENTRIES: usize = 16;

#[inline(always)]
fn windows(exponent: &[u8], mut step: impl FnMut(usize, bool)) {
    for (i, &byte) in exponent.iter().enumerate() {
        step(usize::from(byte >> 4), i != 0);
        step(usize::from(byte & 0xf), true);
    }
}

mod backend {
    use crate::montgomery::*;
    use crate::{MAX_MOD, be_bytes_to_words_le, bytes_to_words_le, words_to_bytes_le};
    use rsk_secret::Secret;

    const WORDS: usize = MAX_MOD / 4;
    const TABLE: usize = super::WINDOW_ENTRIES;

    // Keep the window loop and its calls in SRAM while both cores test primes.
    #[cfg_attr(target_os = "none", unsafe(link_section = ".data.bignum_hl"))]
    #[inline(never)]
    fn pow(
        exponent: &[u8],
        n: &[u32],
        inverse: u32,
        base: &[u32],
        scratch: &mut [u32; (TABLE + 2) * WORDS],
        out: &mut [u32],
    ) {
        let w = n.len();
        let (table, product) = scratch[..(TABLE + 2) * w].split_at_mut(TABLE * w);
        let (one, rest) = table.split_at_mut(w);
        let (base_mont, tmp) = rest.split_at_mut(w);
        // The second CRT half reuses the first half's populated table.
        tmp[..w].fill(0);
        tmp[0] = 1;
        to_mont(one, &tmp[..w], n, product);
        to_mont(base_mont, base, n, product);

        for i in 2..TABLE {
            let (previous, remaining) = table.split_at_mut(i * w);
            mul(product, &previous[w..2 * w], &previous[(i - 1) * w..]);
            reduce(product, n, inverse);
            remaining[..w].copy_from_slice(&product[w..]);
        }
        out.copy_from_slice(&table[..w]);
        super::windows(exponent, |index, square_first| {
            if square_first {
                for _ in 0..4 {
                    square(product, out);
                    reduce(product, n, inverse);
                    out.copy_from_slice(&product[w..]);
                }
            }
            mul(product, &table[index * w..][..w], out);
            reduce(product, n, inverse);
            out.copy_from_slice(&product[w..]);
        });
        let (low, high) = product.split_at_mut(w);
        low.copy_from_slice(out);
        high.fill(0);
        reduce(product, n, inverse);
        out.copy_from_slice(&product[w..]);
    }

    pub(super) fn modexp(base: &[u8], exponent: &[u8], n: &[u8], out: &mut [u8]) {
        let w = n.len() / 4;
        let mut modulus = Secret::new([0u32; WORDS]);
        let mut padded = Secret::<[u8; MAX_MOD]>::zeroed();
        padded.expose_mut()[..base.len()].copy_from_slice(base);
        let mut base_words = Secret::new([0u32; WORDS]);
        let mut result = Secret::new([0u32; WORDS]);
        let mut scratch = Secret::new([0u32; (TABLE + 2) * WORDS]);
        bytes_to_words_le(
            &padded.expose()[..n.len()],
            &mut base_words.expose_mut()[..w],
        );
        bytes_to_words_le(n, &mut modulus.expose_mut()[..w]);
        let n = &modulus.expose()[..w];
        let inverse = Secret::new(negative_inverse(n));
        pow(
            exponent,
            n,
            *inverse.expose(),
            &base_words.expose()[..w],
            scratch.expose_mut(),
            &mut result.expose_mut()[..w],
        );
        words_to_bytes_le(&result.expose()[..w], out);
    }

    // For x < R*n, REDC followed by conversion to Montgomery form gives x mod n.
    fn reduce_wide(value: &mut [u32], n: &[u32], inverse: u32, scratch: &mut [u32]) {
        reduce(value, n, inverse);
        let (low, high) = value.split_at_mut(n.len());
        to_mont(low, high, n, scratch);
    }

    pub(super) fn crt(
        base: &[u8],
        dp: &[u8],
        dq: &[u8],
        p: &[u8],
        q: &[u8],
        qinv: &[u8],
        out: &mut [u8],
    ) {
        let len = p.len();
        let w = len / 4;
        let mut p_words = Secret::new([0u32; WORDS]);
        let mut q_words = Secret::new([0u32; WORDS]);
        let mut qinv_words = Secret::new([0u32; WORDS]);
        be_bytes_to_words_le(p, &mut p_words.expose_mut()[..w]);
        be_bytes_to_words_le(q, &mut q_words.expose_mut()[..w]);
        be_bytes_to_words_le(qinv, &mut qinv_words.expose_mut()[..w]);
        let p = &p_words.expose()[..w];
        let q = &q_words.expose()[..w];
        let mut value = Secret::new([0u32; 2 * WORDS]);
        let value = &mut value.expose_mut()[..2 * w];
        let mut m2 = Secret::new([0u32; WORDS]);
        let inverse_p = Secret::new(negative_inverse(p));
        let inverse_q = Secret::new(negative_inverse(q));
        let mut result = Secret::new([0u32; 2 * WORDS]);
        let result = &mut result.expose_mut()[..2 * w];
        let mut scratch = Secret::new([0u32; (TABLE + 2) * WORDS]);
        let scratch = scratch.expose_mut();

        for (n, inverse, d, residue) in [
            (q, *inverse_q.expose(), dq, &mut m2.expose_mut()[..w]),
            (p, *inverse_p.expose(), dp, &mut result[..w]),
        ] {
            bytes_to_words_le(base, value);
            reduce_wide(value, n, inverse, scratch);
            pow(d, n, inverse, &value[..w], scratch, residue);
        }

        // Garner recombination: m2 + q * ((m1 - m2) * qInv mod p).
        value[..w].copy_from_slice(&m2.expose()[..w]);
        value[w..].fill(0);
        reduce_wide(value, p, *inverse_p.expose(), scratch);
        sub_mod(&mut result[..w], &value[..w], p);
        mul(value, &result[..w], &qinv_words.expose()[..w]);
        reduce_wide(value, p, *inverse_p.expose(), scratch);
        result[..w].copy_from_slice(&m2.expose()[..w]);
        mul_acc(result, q, &value[..w]);
        words_to_bytes_le(result, out);
    }
}
