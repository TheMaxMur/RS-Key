// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Modular reduction over q, ported faithfully from the reference (FIPS 204 §7.5
//! helpers). All routines are branch-free straight-line arithmetic — the
//! conditional subtractions are masked (`x >> 31 & Q`), never `if x < 0`, so they
//! stay constant-time on secret coefficients.

use crate::params::Q;
use crate::poly::Poly;

/// Montgomery reduction (FIPS 204 Alg 49): returns `a·2^-32 mod q` in (−q, q).
/// Input must satisfy `−2^31·q ≤ a ≤ 2^31·q`.
pub(crate) const fn mont_reduce(a: i64) -> i32 {
    const QINV: i32 = 58_728_449; // q·QINV ≡ 1 (mod 2^32)
    let t = (a as i32).wrapping_mul(QINV);
    let res = (a - (t as i64).wrapping_mul(Q as i64)) >> 32;
    debug_assert!(
        res < Q as i64 && res > -(Q as i64),
        "mont_reduce out of range"
    );
    res as i32
}

/// Partial reduction of a signed 32-bit value: result within (−q, q).
pub(crate) const fn partial_reduce32(a: i32) -> i32 {
    let x = (a + (1 << 22)) >> 23;
    a - x * Q
}

/// Full reduction to the canonical range [0, q).
pub(crate) const fn full_reduce32(a: i32) -> i32 {
    let x = partial_reduce32(a); // within (−q, q)
    x + ((x >> 31) & Q) // add q iff negative
}

/// Partial Barrett reduction of a 64-bit product to (−2q, 2q); used by `to_mont`.
pub(crate) const fn partial_reduce64(a: i64) -> i32 {
    const M: i64 = (1 << 48) / (Q as i64);
    let x = a >> 23;
    let a = a - x * (Q as i64);
    let x = a >> 23;
    let a = a - x * (Q as i64);
    let q = (a * M) >> 48;
    (a - q * (Q as i64)) as i32
}

/// Centered reduction mod± q into (−q/2, q/2] (used to serialize z).
pub(crate) fn center_mod(m: i32) -> i32 {
    let t = full_reduce32(m); // [0, q)
    let over2 = (Q / 2) - t;
    t - ((over2 >> 31) & Q) // subtract q iff t > q/2
}

/// Lift a polynomial into the Montgomery domain: `out[n] = a[n]·2^32 mod q`.
pub(crate) fn to_mont(a: &Poly) -> Poly {
    let mut out = Poly::zero();
    for n in 0..crate::params::N {
        out.0[n] = partial_reduce64(i64::from(a.0[n]) << 32);
    }
    out
}

/// [`to_mont`] in place, for a polynomial that already sits where it is kept.
pub(crate) fn to_mont_inplace(a: &mut Poly) {
    for c in a.0.iter_mut() {
        *c = partial_reduce64(i64::from(*c) << 32);
    }
}

#[cfg(test)]
#[path = "reduce_tests.rs"]
mod tests;
