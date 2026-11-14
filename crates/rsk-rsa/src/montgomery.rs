// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Montgomery setup and the three rsa-armv7 Thumb-2 arithmetic kernels.

#[cfg(target_os = "none")]
unsafe extern "C" {
    pub(crate) fn bignum_sqracc(product: *mut u32, value: *const u32, len: usize);
    pub(crate) fn bignum_mulacc(product: *mut u32, a: *const u32, b: *const u32, len: usize);
    pub(crate) fn bignum_mont_redc(
        product: *mut u32,
        len: usize,
        n: *const u32,
        inverse: *const u32,
        not_n: *const u32,
        out: *mut u32,
    );
}

/// The Thumb-2 reducer cancels four words per iteration, so it needs −n⁻¹ mod 2¹²⁸.
/// Newton doubling starts at −n, which is correct modulo 8 for odd n.
pub(crate) fn negative_inverse(n: &[u32]) -> [u32; 4] {
    let a = n[0];
    let mut x = a.wrapping_neg();
    for _ in 0..4 {
        x = x.wrapping_mul(2u32.wrapping_add(a.wrapping_mul(x)));
    }
    let a = u64::from(a) | (u64::from(n[1]) << 32);
    let x = u64::from(x);
    let x = x.wrapping_mul(2u64.wrapping_add(a.wrapping_mul(x)));
    let a = u128::from(a) | (u128::from(n[2]) << 64) | (u128::from(n[3]) << 96);
    let x = u128::from(x);
    let x = x.wrapping_mul(2u128.wrapping_add(a.wrapping_mul(x)));
    [
        x as u32,
        (x >> 32) as u32,
        (x >> 64) as u32,
        (x >> 96) as u32,
    ]
}

#[inline(always)]
fn add_masked(value: &mut [u32], n: &[u32], mask: u32) -> u64 {
    let mut carry = 0;
    for (a, &b) in value.iter_mut().zip(n) {
        let sum = u64::from(*a) + u64::from(b & mask) + carry;
        *a = sum as u32;
        carry = sum >> 32;
    }
    carry
}

/// Subtract b in place, adding n on borrow. The caller guarantees −n ≤ a−b < n.
#[inline(always)]
pub(crate) fn sub_mod(a: &mut [u32], b: &[u32], n: &[u32]) {
    let mut borrow = 0;
    for (a, &b) in a.iter_mut().zip(b) {
        let difference = u64::from(*a).wrapping_sub(u64::from(b) + borrow);
        *a = difference as u32;
        borrow = difference >> 63;
    }
    add_masked(a, n, (borrow as u32).wrapping_neg());
}

/// Divide the top two words by a normalized word, with `high <= divisor`.
/// When the top words are equal, the quotient saturates at `u32::MAX`.
/// Use a fixed number of steps because the dividend can be secret.
#[inline(always)]
fn quotient(high: u32, low: u32, divisor: u32) -> u32 {
    let mut rem = u64::from(high);
    let mut q = 0;
    for bit in (0..32).rev() {
        rem = (rem << 1) | u64::from((low >> bit) & 1);
        let diff = rem.wrapping_sub(u64::from(divisor));
        let keep = diff >> 63;
        rem = diff.wrapping_add(u64::from(divisor) & keep.wrapping_neg());
        q = (q << 1) | (1 - keep as u32);
    }
    q
}

#[inline(always)]
fn append_zero(value: &mut [u32], n: &[u32], top: u32) {
    let w = value.len();
    let next = if w > 1 { value[w - 2] } else { 0 };
    let high = u64::from(value[w - 1]);
    let q = u64::from(quotient(high as u32, next, top));
    let mut previous = 0;
    let mut carry = 0;
    for (a, &b) in value.iter_mut().zip(n) {
        let product = q * u64::from(b) + carry;
        let diff = u64::from(previous).wrapping_sub(u64::from(product as u32));
        previous = *a;
        *a = diff as u32;
        carry = (product >> 32) + (diff >> 63);
    }
    // With the divisor's top bit set, the estimate is high by at most two.
    let high = high.wrapping_sub(carry);
    let high = high.wrapping_add(add_masked(value, n, ((high >> 63) as u32).wrapping_neg()));
    add_masked(value, n, ((high >> 63) as u32).wrapping_neg());
}

/// Compute value·R mod n, with R determined by the padded width and value < n.
/// All word slices are little-endian and scratch holds at least n.len() words.
#[cfg_attr(target_os = "none", unsafe(link_section = ".data.bignum_hl"))]
#[inline(never)]
pub(crate) fn to_mont(out: &mut [u32], value: &[u32], n: &[u32], scratch: &mut [u32]) {
    let w = n.len();
    // The exponentiation radix still includes leading zero words.
    let significant = n.iter().rposition(|&word| word != 0).unwrap() + 1;
    let shift = n[significant - 1].leading_zeros();
    let divisor = &mut scratch[..significant];
    let (out, padding) = out.split_at_mut(significant);
    let mut divisor_carry = 0;
    let mut value_carry = 0;
    for (((dst, d), &a), &b) in out.iter_mut().zip(divisor.iter_mut()).zip(value).zip(n) {
        let norm_d = (u64::from(b) << shift) | divisor_carry;
        let norm_a = (u64::from(a) << shift) | value_carry;
        *d = norm_d as u32;
        *dst = norm_a as u32;
        divisor_carry = norm_d >> 32;
        value_carry = norm_a >> 32;
    }
    let top = divisor[significant - 1];
    for _ in 0..w {
        append_zero(out, divisor, top);
    }
    let mut high = 0;
    for word in out.iter_mut().rev() {
        let pair = (u64::from(high) << 32) | u64::from(*word);
        high = *word;
        *word = (pair >> shift) as u32;
    }
    padding.fill(0);
}

#[cfg(test)]
#[path = "montgomery_tests.rs"]
mod tests;
