// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Fixed-width Montgomery arithmetic over little-endian 32-bit limbs.
//! The doubling strategy for squaring follows Emil Lenngren's rsa-armv7
//! (copyright 2025, BSD-2-Clause, `LICENSE-rsa-armv7.txt`).

// Array arguments let LLVM specialize the hot loops for RSA-2048 prime widths.
const RSA_2048_PRIME_WORDS: usize = crate::RSA_2048_BYTES / (2 * size_of::<u32>());

/// The reducer derives its cancellation factors from −n⁻¹ mod 2³².
/// Newton doubling starts at −n, which is correct modulo 8 for odd n.
pub(crate) fn negative_inverse(n: &[u32]) -> u32 {
    let a = n[0];
    let mut x = a.wrapping_neg();
    for _ in 0..4 {
        x = x.wrapping_mul(2u32.wrapping_add(a.wrapping_mul(x)));
    }
    x
}

#[inline(always)]
fn add_product(row: &mut [u32], a: &[u32], b: u32) -> u32 {
    let b = u64::from(b);
    let mut carry = 0;
    for (dst, &word) in row.iter_mut().zip(a) {
        let acc = u64::from(word) * b + u64::from(*dst) + carry;
        *dst = acc as u32;
        carry = acc >> 32;
    }
    carry as u32
}

#[inline(always)]
fn mac(a: u32, b: u32, x: u32, y: u32) -> (u32, u32) {
    // The maximum is (2^32 - 1)^2 + 2(2^32 - 1) = 2^64 - 1.
    let v = u64::from(a) * u64::from(b) + u64::from(x) + u64::from(y);
    (v as u32, (v >> 32) as u32)
}

/// Accumulate four rows with pending limbs left in carry.
#[inline(always)]
fn block4(dst: &mut [u32], a: &[u32; 4], b: &[u32], mut carry: [u32; 4]) -> [u32; 4] {
    let [a0, a1, a2, a3] = *a;
    let column = |dst: &mut u32, word: u32, [c0, c1, c2, c3]: [u32; 4]| {
        let (p, h0) = mac(a0, word, *dst, c0);
        let (p1, h1) = mac(a1, word, h0, c1);
        let (p2, h2) = mac(a2, word, h1, c2);
        let (p3, h3) = mac(a3, word, h2, c3);
        *dst = p;
        [p1, p2, p3, h3]
    };
    // Rotate through four columns so LLVM can keep carries in registers.
    for (dst, b) in dst
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(b.as_chunks::<4>().0)
    {
        carry = column(&mut dst[0], b[0], carry);
        carry = column(&mut dst[1], b[1], carry);
        carry = column(&mut dst[2], b[2], carry);
        carry = column(&mut dst[3], b[3], carry);
    }
    carry
}

// For each limb, the doubled lower prefix lacks the carry into that limb.
// Adding carry times the limb restores its contribution to the diagonal.
#[inline(always)]
fn square_block(row: &mut [u32], a: &[u32], prev: u32) -> [u32; 4] {
    let [a0, a1, a2, a3] = *a.first_chunk::<4>().unwrap();
    let d0 = (a0 << 1) | prev;
    let d1 = (a1 << 1) | (a0 >> 31);
    let d2 = (a2 << 1) | (a1 >> 31);
    let d3 = (a3 << 1) | (a2 >> 31);
    let correction = |a: u32, c: u32| a & c.wrapping_neg();

    let (lo, h0) = mac(a0, a0, row[0], correction(a0, prev));
    row[0] = lo;
    let (lo, h0) = mac(d0, a1, row[1], h0);
    let (p1, h1) = mac(a1, a1, h0, correction(a1, a0 >> 31));
    row[1] = lo;
    let (lo, h0) = mac(d0, a2, row[2], p1);
    let (p1, h1) = mac(d1, a2, h0, h1);
    let (p2, h2) = mac(a2, a2, h1, correction(a2, a1 >> 31));
    row[2] = lo;
    let (lo, h0) = mac(d0, a3, row[3], p1);
    let (p1, h1) = mac(d1, a3, h0, p2);
    let (p2, h2) = mac(d2, a3, h1, h2);
    let (p3, h3) = mac(a3, a3, h2, correction(a3, a2 >> 31));
    row[3] = lo;
    block4(&mut row[4..], &[d0, d1, d2, d3], &a[4..], [p1, p2, p3, h3])
}

#[inline(always)]
fn factor4(t: &[u32; 4], n: &[u32; 4], inverse: u32) -> [u32; 4] {
    // Compute the next four factors without streaming over the whole modulus
    // for each one. The low four words suffice to make t + m*n vanish there.
    let [t0, t1, t2, t3] = *t;
    let [n0, n1, n2, n3] = *n;
    let m0 = t0.wrapping_mul(inverse);
    let (_, c) = mac(n0, m0, t0, 0);
    let (t1, c) = mac(n1, m0, t1, c);
    let (t2, c) = mac(n2, m0, t2, c);
    let (t3, _) = mac(n3, m0, t3, c);
    let m1 = t1.wrapping_mul(inverse);
    let (_, c) = mac(n0, m1, t1, 0);
    let (t2, c) = mac(n1, m1, t2, c);
    let (t3, _) = mac(n2, m1, t3, c);
    let m2 = t2.wrapping_mul(inverse);
    let (_, c) = mac(n0, m2, t2, 0);
    let (t3, _) = mac(n1, m2, t3, c);
    let m3 = t3.wrapping_mul(inverse);
    [m0, m1, m2, m3]
}

/// Add a×b to the initial low half; the high half is overwritten.
#[cfg_attr(target_os = "none", unsafe(link_section = ".data.bignum_mul"))]
#[inline(never)]
pub(crate) fn mul_acc(product: &mut [u32], a: &[u32], b: &[u32]) {
    if let (Ok(product), Ok(a), Ok(b)) = (
        <&mut [u32; 2 * RSA_2048_PRIME_WORDS]>::try_from(&mut *product),
        <&[u32; RSA_2048_PRIME_WORDS]>::try_from(a),
        <&[u32; RSA_2048_PRIME_WORDS]>::try_from(b),
    ) {
        mul_acc_width(product, a, b);
        return;
    }
    mul_acc_width(product, a, b);
}

#[inline(always)]
fn mul_acc_width(product: &mut [u32], a: &[u32], b: &[u32]) {
    let w = a.len();
    if w.is_multiple_of(4) {
        for (k, block) in a.as_chunks::<4>().0.iter().enumerate() {
            let (row, high) = product[4 * k..][..w + 4].split_at_mut(w);
            let carry = block4(row, block, b, [0; 4]);
            high.copy_from_slice(&carry);
        }
        return;
    }

    for (i, &word) in b.iter().enumerate() {
        let (row, high) = product[i..][..=w].split_at_mut(w);
        high[0] = add_product(row, a, word);
    }
}

#[inline(always)]
pub(crate) fn mul(product: &mut [u32], a: &[u32], b: &[u32]) {
    product[..a.len()].fill(0);
    mul_acc(product, a, b);
}

/// Square with one multiplication per pair of limbs.
#[cfg_attr(target_os = "none", unsafe(link_section = ".data.bignum_sqr"))]
#[inline(never)]
pub(crate) fn square(product: &mut [u32], a: &[u32]) {
    if let (Ok(product), Ok(a)) = (
        <&mut [u32; 2 * RSA_2048_PRIME_WORDS]>::try_from(&mut *product),
        <&[u32; RSA_2048_PRIME_WORDS]>::try_from(a),
    ) {
        square_width(product, a);
        return;
    }
    square_width(product, a);
}

#[inline(always)]
fn square_width(product: &mut [u32], a: &[u32]) {
    let w = a.len();
    product.fill(0);
    if w.is_multiple_of(4) {
        let mut prev = 0;
        for i in (0..w).step_by(4) {
            let (row, high) = product[2 * i..][..w - i + 4].split_at_mut(w - i);
            let carry = square_block(row, &a[i..], prev);
            high.copy_from_slice(&carry);
            prev = a[i + 3] >> 31;
        }
        return;
    }
    for (i, &word) in a.iter().enumerate() {
        let (row, high) = product[2 * i + 1..i + w + 1].split_at_mut(w - i - 1);
        high[0] = add_product(row, &a[i + 1..], word);
    }
    let mut carry = 0;
    for (pair, &word) in product.as_chunks_mut::<2>().0.iter_mut().zip(a) {
        let diagonal = u64::from(word) * u64::from(word);
        let low = 2 * u64::from(pair[0]) + u64::from(diagonal as u32) + carry;
        let high = 2 * u64::from(pair[1]) + (diagonal >> 32) + (low >> 32);
        pair[0] = low as u32;
        pair[1] = high as u32;
        carry = high >> 32;
    }
}

/// Reduce T < R*n in place. The low half becomes zero and the high half holds T/R mod n.
#[cfg_attr(target_os = "none", unsafe(link_section = ".data.bignum_redc"))]
#[inline(never)]
pub(crate) fn reduce(product: &mut [u32], n: &[u32], inverse: u32) {
    if let (Ok(product), Ok(n)) = (
        <&mut [u32; 2 * RSA_2048_PRIME_WORDS]>::try_from(&mut *product),
        <&[u32; RSA_2048_PRIME_WORDS]>::try_from(n),
    ) {
        reduce_width(product, n, inverse);
        return;
    }
    reduce_width(product, n, inverse);
}

#[inline(always)]
fn reduce_width(product: &mut [u32], n: &[u32], inverse: u32) {
    let w = n.len();
    let mut carry = 0u32;
    if w >= 4 && w.is_multiple_of(4) {
        let n_low = n.first_chunk::<4>().unwrap();
        for i in (0..w).step_by(4) {
            let (row, high) = product[i..][..w + 4].split_at_mut(w);
            let factor = factor4(row.first_chunk::<4>().unwrap(), n_low, inverse);
            let c = block4(row, &factor, n, [0; 4]);
            // The incoming carry starts at the first limb beyond this row.
            let [c0, c1, c2, c3] = c;
            let (p0, h0) = mac(c0, 1, high[0], carry);
            let (p1, h1) = mac(c1, 1, high[1], h0);
            let (p2, h2) = mac(c2, 1, high[2], h1);
            let (p3, h3) = mac(c3, 1, high[3], h2);
            high.copy_from_slice(&[p0, p1, p2, p3]);
            carry = h3;
        }
    } else {
        for i in 0..w {
            let (row, high) = product[i..][..=w].split_at_mut(w);
            let m = row[0].wrapping_mul(inverse);
            (high[0], carry) = mac(add_product(row, n, m), 1, high[0], carry);
        }
    }

    // The result is below 2*n. A carry above R pays for a borrow in the subtraction.
    let high = &mut product[w..];
    let borrow = subtract(high, n);
    add_masked(high, n, (borrow as u32 & !carry).wrapping_neg());
}

#[inline(always)]
fn add_masked(value: &mut [u32], n: &[u32], mask: u32) -> u64 {
    // Callers pass either zero or an all-ones mask.
    let bit = mask & 1;
    let mut carry = 0;
    for (a, &b) in value.iter_mut().zip(n) {
        (*a, carry) = mac(b, bit, *a, carry);
    }
    u64::from(carry)
}

#[inline(always)]
fn subtract(a: &mut [u32], b: &[u32]) -> u64 {
    // a + !b + 1 leaves a carry exactly when there was no borrow.
    let mut carry = 1;
    for (a, &b) in a.iter_mut().zip(b) {
        (*a, carry) = mac(!b, 1, *a, carry);
    }
    u64::from(1 - carry)
}

/// Subtract b in place, adding n on borrow. The caller guarantees −n ≤ a−b < n.
#[inline(always)]
pub(crate) fn sub_mod(a: &mut [u32], b: &[u32], n: &[u32]) {
    let borrow = subtract(a, b);
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
