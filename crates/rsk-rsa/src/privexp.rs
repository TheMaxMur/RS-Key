// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Four-bit private exponentiation and CRT recombination over rsa-armv7's
//! Thumb-2 arithmetic (see csrc/LICENSE.txt).
//! Based on Emil Lenngren's rsa-armv7, copyright 2025, BSD-2-Clause.

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

#[cfg(not(target_os = "none"))]
mod backend {
    use crate::key::from_secret_be;
    use num_bigint_dig::BigUint;
    use rsk_secret::Secret;

    fn pow(base: &BigUint, exponent: &[u8], n: &BigUint) -> Secret<BigUint> {
        let mut table: [Secret<BigUint>; super::WINDOW_ENTRIES] =
            core::array::from_fn(|_| Secret::new(BigUint::default()));
        table[0] = Secret::new(BigUint::from(1u8));
        table[1] = Secret::new(base % n);
        for i in 2..table.len() {
            let product = Secret::new(table[i - 1].expose() * table[1].expose());
            table[i] = Secret::new(product.expose() % n);
        }
        let mut value = Secret::new(BigUint::from(1u8));
        super::windows(exponent, |index, square| {
            if square {
                for _ in 0..4 {
                    let product = Secret::new(value.expose() * value.expose());
                    value = Secret::new(product.expose() % n);
                }
            }
            let product = Secret::new(value.expose() * table[index].expose());
            value = Secret::new(product.expose() % n);
        });
        value
    }

    fn write_le(value: &Secret<BigUint>, out: &mut [u8]) {
        let le = Secret::new(value.expose().to_bytes_le());
        out.fill(0);
        out[..le.expose().len()].copy_from_slice(le.expose());
    }

    pub(super) fn modexp(base: &[u8], exponent: &[u8], n: &[u8], out: &mut [u8]) {
        let base = Secret::new(BigUint::from_bytes_le(base));
        let n = Secret::new(BigUint::from_bytes_le(n));
        write_le(&pow(base.expose(), exponent, n.expose()), out);
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
        let base = Secret::new(BigUint::from_bytes_le(base));
        let p = Secret::new(from_secret_be(p));
        let q = Secret::new(from_secret_be(q));
        let qinv = Secret::new(from_secret_be(qinv));
        let m2 = pow(base.expose(), dq, q.expose());
        let m1 = pow(base.expose(), dp, p.expose());
        let m2p = Secret::new(m2.expose() % p.expose());
        let sum = Secret::new(m1.expose() + p.expose());
        let diff = Secret::new(sum.expose() - m2p.expose());
        let product = Secret::new(diff.expose() * qinv.expose());
        let h = Secret::new(product.expose() % p.expose());
        let qh = Secret::new(q.expose() * h.expose());
        let result = Secret::new(m2.expose() + qh.expose());
        write_le(&result, out);
    }
}

#[cfg(target_os = "none")]
mod backend {
    use crate::montgomery::*;
    use crate::{MAX_MOD, be_bytes_to_words_le, bytes_to_words_le, words_to_bytes_le};
    use rsk_secret::Secret;

    const WORDS: usize = MAX_MOD / 4;
    const TABLE: usize = super::WINDOW_ENTRIES;

    // Keep the window loop and its calls in SRAM while both cores test primes.
    #[unsafe(link_section = ".data.bignum_hl")]
    #[inline(never)]
    fn pow(
        exponent: &[u8],
        n: &[u32],
        complement: &[u32],
        inverse: &[u32; 4],
        base: &[u32],
        scratch: &mut [u32; (TABLE + 2) * WORDS],
        out: &mut [u32],
    ) {
        let w = n.len();
        let len = core::mem::size_of_val(n);
        let (table, product) = scratch[..(TABLE + 2) * w].split_at_mut(TABLE * w);
        // The second CRT half reuses the first half's populated table.
        table[w..2 * w].fill(0);
        table[w] = 1;
        let t = table.as_mut_ptr();
        let product = product.as_mut_ptr();
        let result = out.as_mut_ptr();
        let modulus = n.as_ptr();
        let complement = complement.as_ptr();
        let inverse = inverse.as_ptr();
        // SAFETY: callers provide w words in every operand, with nonzero w
        // aligned to eight words. Table entries and the double-width product
        // are disjoint. Each conversion uses two adjacent table entries.
        unsafe {
            bignum_to_mont(t, modulus, len, product);
            core::ptr::copy_nonoverlapping(base.as_ptr(), t.add(2 * w), w);
            bignum_to_mont(t.add(w), modulus, len, product);
            for i in 0..w {
                product.add(i).write(0);
            }
            for i in 2..TABLE {
                bignum_mulacc(product, t.add(w), t.add((i - 1) * w), len);
                bignum_mont_redc(product, len, modulus, inverse, complement, t.add(i * w));
            }
            core::ptr::copy_nonoverlapping(t, result, w);
            super::windows(exponent, |index, square| {
                if square {
                    for _ in 0..4 {
                        bignum_sqracc(product, result, len);
                        bignum_mont_redc(product, len, modulus, inverse, complement, result);
                    }
                }
                bignum_mulacc(product, t.add(index * w), result, len);
                bignum_mont_redc(product, len, modulus, inverse, complement, result);
            });
            for i in 0..w {
                product.add(i).write(result.add(i).read());
                product.add(w + i).write(0);
            }
            bignum_mont_redc(product, len, modulus, inverse, complement, result);
            bignum_submod(result, complement, modulus, result, len);
        }
    }

    fn parameters(n: &[u32], complement: &mut [u32], inverse: &mut [u32; 4]) {
        for (dst, &value) in complement.iter_mut().zip(n) {
            *dst = !value;
        }
        // SAFETY: both validated moduli have at least eight words and are odd;
        // the disjoint output holds the four words written by the routine.
        unsafe { bignum_modular_inverse(inverse.as_mut_ptr(), n.as_ptr()) };
    }

    pub(super) fn modexp(base: &[u8], exponent: &[u8], n: &[u8], out: &mut [u8]) {
        let w = n.len() / 4;
        let mut modulus = Secret::new([0u32; WORDS]);
        let mut complement = Secret::new([0u32; WORDS]);
        let mut inverse = Secret::new([0u32; 4]);
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
        let complement = &mut complement.expose_mut()[..w];
        parameters(n, complement, inverse.expose_mut());
        pow(
            exponent,
            n,
            complement,
            inverse.expose(),
            &base_words.expose()[..w],
            scratch.expose_mut(),
            &mut result.expose_mut()[..w],
        );
        words_to_bytes_le(&result.expose()[..w], out);
    }

    // For x < R*n, REDC followed by conversion to Montgomery form gives x mod n.
    fn reduce_wide(
        value: &mut [u32],
        n: &[u32],
        complement: &[u32],
        inverse: &[u32; 4],
        scratch: &mut [u32],
    ) {
        let w = n.len();
        let len = core::mem::size_of_val(n);
        let v = value.as_mut_ptr();
        let n = n.as_ptr();
        let complement = complement.as_ptr();
        // SAFETY: value and scratch each hold 2*w words and are disjoint.
        // REDC may write to the upper half of its input; submod may alias a.
        unsafe {
            let high = v.add(w);
            bignum_mont_redc(v, len, n, inverse.as_ptr(), complement, high);
            bignum_submod(high, complement, n, high, len);
            bignum_to_mont(v, n, len, scratch.as_mut_ptr());
        }
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
        let mut complement = Secret::new([0u32; WORDS]);
        let complement = &mut complement.expose_mut()[..w];
        let mut inverse = Secret::new([0u32; 4]);
        let inverse = inverse.expose_mut();
        let mut value = Secret::new([0u32; 2 * WORDS]);
        let value = &mut value.expose_mut()[..2 * w];
        let mut m2 = Secret::new([0u32; WORDS]);
        let mut result = Secret::new([0u32; 2 * WORDS]);
        let result = &mut result.expose_mut()[..2 * w];
        let mut scratch = Secret::new([0u32; (TABLE + 2) * WORDS]);
        let scratch = scratch.expose_mut();

        for (n, d, residue) in [
            (q, dq, &mut m2.expose_mut()[..w]),
            (p, dp, &mut result[..w]),
        ] {
            parameters(n, complement, inverse);
            bytes_to_words_le(base, value);
            reduce_wide(value, n, complement, inverse, scratch);
            pow(d, n, complement, inverse, &value[..w], scratch, residue);
        }

        // Garner recombination: m2 + q * ((m1 - m2) * qInv mod p).
        value[..w].copy_from_slice(&m2.expose()[..w]);
        value[w..].fill(0);
        reduce_wide(value, p, complement, inverse, scratch);
        for v in &mut value[..w] {
            *v = !*v;
        }
        // SAFETY: value and result are double width; p, q and qInv each hold
        // w words. Submod aliases only a, and mulacc outputs are disjoint.
        unsafe {
            let r = result.as_mut_ptr();
            bignum_submod(r, value.as_ptr(), p.as_ptr(), r, len);
            value[..w].fill(0);
            bignum_mulacc(value.as_mut_ptr(), r, qinv_words.expose().as_ptr(), len);
        }
        reduce_wide(value, p, complement, inverse, scratch);
        result[..w].copy_from_slice(&m2.expose()[..w]);
        // SAFETY: result is double width and disjoint from q and the factor.
        unsafe { bignum_mulacc(result.as_mut_ptr(), q.as_ptr(), value.as_ptr(), len) };
        words_to_bytes_le(result, out);
    }
}
