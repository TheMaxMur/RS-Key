// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Feature-gated timing entrypoints for the on-device latency harness.
//!
//! NEVER shipped: the `bench` feature gates a vendor `INS_BENCH` that is a timing
//! oracle over the crypto primitives (like `keygen-bench`). Each
//! [`crate::bench::run`] drives the REAL hot path with fixed, public inputs and
//! returns a checksum of the result so the compiler cannot fold the call away.
//! Inputs are constants (a public on-curve point, a fixed scalar/seed/path/message)
//! — no device secret is involved, so exposing the primitive is a timing leak of
//! already-public code, not of any key.
//!
//! Selectors:
//! - `0` — variable-base P-256 ECDH ([`rsk_crypto::pinproto::ecdh_raw`]): the
//!   clientPIN key-agreement path, whose crate scalar-mul is the ~34 KB working
//!   set that overflows the XIP cache (the ±30 ms layout-sensitive one).
//! - `1` — P-256 fixed-base comb sign (`crate::ec::sign_p256_comb`): the
//!   getAssertion signing hot path.
//! - `2` — the HKDF-SHA512 key-derivation ratchet (`crate::keyderiv::ratchet`).

use core::hint::black_box;

/// P-256 generator `G`, the deterministic ECDH peer point (public, on-curve).
const G_X: [u8; 32] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
];
const G_Y: [u8; 32] = [
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];
/// A fixed nonzero scalar `< n`, well below the group order.
const FIXED_SCALAR: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];
const FIXED_SEED: [u8; 32] = [0xa5; 32];
const FIXED_PATH: [u8; crate::keyderiv::KEY_PATH_LEN] = [0x5a; crate::keyderiv::KEY_PATH_LEN];
const FIXED_MSG: [u8; 32] = [0x3c; 32];

/// Run one primitive once and return a checksum of its output. The inputs are
/// `black_box`ed so the compiler can't see they're compile-time constants: the
/// operands become loop-invariant-opaque, which stops LICM from hoisting the pure
/// crypto out of the caller's timing loop (the timed region must recompute every
/// iteration). The caller `black_box`es the returned checksum to defeat DCE — the
/// two ends form the `black_box(f(black_box(input)))` idiom, matching keygen-bench.
/// Unknown selectors return 0.
pub fn run(sel: u8) -> u32 {
    match sel {
        0 => {
            let z = rsk_crypto::pinproto::ecdh_raw(
                black_box(&FIXED_SCALAR),
                black_box(&G_X),
                black_box(&G_Y),
            )
            .unwrap_or([0u8; 32]);
            checksum(&z)
        }
        1 => {
            use p256::elliptic_curve::PrimeField;
            let d = Option::<p256::Scalar>::from(p256::Scalar::from_repr(p256::FieldBytes::from(
                black_box(FIXED_SCALAR),
            )))
            .expect("FIXED_SCALAR is a valid nonzero P-256 scalar");
            let mut out = [0u8; crate::ec::MAX_DER_SIG];
            let n = crate::ec::sign_p256_comb(&d, black_box(&FIXED_MSG), &mut out);
            checksum(&out[..n])
        }
        2 => {
            let r = crate::keyderiv::ratchet(black_box(&FIXED_SEED), black_box(&FIXED_PATH));
            checksum(&r)
        }
        _ => 0,
    }
}

/// XOR-fold `bytes` into a `u32`, wrapped in `black_box` so the whole [`run`] call
/// can't be optimized away as unused.
fn checksum(bytes: &[u8]) -> u32 {
    let mut acc = 0u32;
    for (i, &b) in bytes.iter().enumerate() {
        acc ^= (b as u32) << ((i % 4) * 8);
    }
    black_box(acc)
}

#[cfg(test)]
#[path = "bench_tests.rs"]
mod tests;
