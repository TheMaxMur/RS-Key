// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The EC public-key data object `7F49 { 86 <point> }`.
//!
//! Both card applets answer key generation and import with these exact bytes —
//! OpenPGP from `keypair_gen` / IMPORT, PIV from GENERATE — so the encoder lives
//! once, below both, exactly as the RSA half does in `rsk_rsa::pubdo`. It is
//! pure byte-building: no status word, no key state, nothing an applet has to
//! own.

use crate::MAX_EC_POINT;

/// A buffer [`make_ec_pubkey_do`] can be called with for any curve. The widest
/// DO is 7 bytes of framing (both lengths long-form, which only P-521 reaches)
/// plus the point = 140; the eighth byte is slack, kept because it is the width
/// the OpenPGP applet already sized these buffers to.
pub const MAX_EC_PUBDO: usize = 8 + MAX_EC_POINT;

/// Wrap a public point as the public-key DO `7F49 { 86 <point> }`, with
/// long-form lengths when the point ≥ 128 bytes (P-521). Returns the DO length;
/// `out` must be at least [`MAX_EC_PUBDO`] wide.
pub fn make_ec_pubkey_do(point: &[u8], out: &mut [u8]) -> usize {
    let plen = point.len();
    let long = plen >= 128;
    let mut p = 0;
    out[p] = 0x7f;
    p += 1;
    out[p] = 0x49;
    p += 1;
    if long {
        out[p] = 0x81;
        p += 1;
    }
    out[p] = (plen + if long { 3 } else { 2 }) as u8;
    p += 1;
    out[p] = 0x86;
    p += 1;
    if long {
        out[p] = 0x81;
        p += 1;
    }
    out[p] = plen as u8;
    p += 1;
    out[p..p + plen].copy_from_slice(point);
    p + plen
}

#[cfg(test)]
#[path = "pubdo_tests.rs"]
mod tests;
