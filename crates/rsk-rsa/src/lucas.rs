// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The num-bigint-dig 0.8.6 extra-strong Lucas test with cancellation boundaries.
//! Adapted from its MIT-licensed prime.rs; attribution and license are in NOTICE.

use num_bigint_dig::{BigInt, BigUint, Sign, algorithms::jacobi};
use num_integer::Integer;
use rsk_secret::Secret;

const MAX_PARAMETER: u64 = 10_000;

pub(crate) fn passes_lucas(n: &BigUint, cancelled: &mut dyn FnMut() -> bool) -> bool {
    let two = BigUint::from(2u8);
    if n <= &two || n.is_even() {
        return false;
    }
    let modulus = Secret::new(BigInt::from_biguint(Sign::Plus, n.clone()));
    let mut p = 3u64;
    loop {
        if cancelled() || p > MAX_PARAMETER {
            return false;
        }
        match jacobi(&BigInt::from(p * p - 4), modulus.expose()) {
            -1 => break,
            0 => return !cancelled() && n == &BigUint::from(p + 2),
            _ => {}
        }
        if p == 40 {
            let root = Secret::new(n.sqrt());
            let square = Secret::new(root.expose() * root.expose());
            if square.expose() == n {
                return false;
            }
        }
        p += 1;
    }

    let mut s = Secret::new(n + BigUint::from(1u8));
    let Some(r) = s.expose().trailing_zeros() else {
        return false;
    };
    *s.expose_mut() >>= r;
    let nm2 = Secret::new(n - &two);
    let mut vk = Secret::new(two.clone());
    let mut vk1 = Secret::new(BigUint::from(p));
    let limb_bits = core::mem::size_of_val(&s.expose().get_limb(0)) * 8;
    for i in (0..s.expose().bits()).rev() {
        if cancelled() {
            return false;
        }
        let bit = s.expose().get_limb(i / limb_bits) >> (i % limb_bits) & 1;
        // V(2k) = V(k)^2 - 2; V(2k+1) = V(k)V(k+1) - P, with Q = 1.
        let (square, product) = if bit == 1 {
            (&mut vk1, &mut vk)
        } else {
            (&mut vk, &mut vk1)
        };
        let mut term = Secret::new(square.expose() * product.expose() + n - p);
        product.wipe();
        *product.expose_mut() = term.expose() % n;
        term.wipe();
        *term.expose_mut() = square.expose() * square.expose() + nm2.expose();
        square.wipe();
        *square.expose_mut() = term.expose() % n;
        #[cfg(test)]
        tests::observe_residues(vk.expose(), vk1.expose(), n);
    }
    if cancelled() {
        return false;
    }
    if vk.expose() == &two || vk.expose() == nm2.expose() {
        // U(s) = 0 iff P V(s) = 2 V(s+1) mod n; no inversion is needed.
        let mut left = Secret::new(vk.expose() * p);
        let mut right = Secret::new(vk1.expose() << 1usize);
        if left.expose() < right.expose() {
            core::mem::swap(left.expose_mut(), right.expose_mut());
        }
        *left.expose_mut() -= right.expose();
        let remainder = Secret::new(left.expose() % n);
        if remainder.expose() == &BigUint::from(0u8) {
            return !cancelled();
        }
    }
    for _ in 0..r - 1 {
        if cancelled() {
            return false;
        }
        if vk.expose() == &BigUint::from(0u8) {
            return true;
        }
        if vk.expose() == &two {
            return false;
        }
        let term = Secret::new(vk.expose() * vk.expose() - &two);
        vk.wipe();
        *vk.expose_mut() = term.expose() % n;
        #[cfg(test)]
        tests::observe_residues(vk.expose(), vk1.expose(), n);
    }
    false
}

#[cfg(test)]
#[path = "lucas_tests.rs"]
mod tests;
