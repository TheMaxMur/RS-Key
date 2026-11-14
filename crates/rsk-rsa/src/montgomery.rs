// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! AAPCS declarations for the rsa-armv7 Thumb-2 primitives.

unsafe extern "C" {
    pub(crate) fn bignum_to_mont(value: *mut u32, n: *const u32, len: usize, scratch: *mut u32);
    pub(crate) fn bignum_modular_inverse(inverse: *mut u32, n: *const u32);
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
    pub(crate) fn bignum_submod(
        out: *mut u32,
        not_n: *const u32,
        n: *const u32,
        a: *const u32,
        len: usize,
    ) -> i32;
}
