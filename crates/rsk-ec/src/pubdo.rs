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
/// long-form lengths where they are needed (P-521 reaches both). Returns the DO
/// length; `point` must be at most [`MAX_EC_POINT`] and `out` at least
/// [`MAX_EC_PUBDO`] wide.
pub fn make_ec_pubkey_do(point: &[u8], out: &mut [u8]) -> usize {
    let plen = point.len();
    // Each length takes the long form when the value *it* encodes reaches 128:
    // the inner one measures the point, the outer one the whole `86` object
    // around it. Deciding both from `plen` wrote 0x80 / 0x81 into the outer
    // short-form slot at a 126- or 127-byte point. Same rule as
    // `rsk_sdk::tlv::format_len`, which is two tiers up and cannot be called here.
    let point_long = plen >= 128;
    let body = plen + if point_long { 3 } else { 2 };
    let body_long = body >= 128;
    let mut p = 0;
    out[p] = 0x7f;
    p += 1;
    out[p] = 0x49;
    p += 1;
    if body_long {
        out[p] = 0x81;
        p += 1;
    }
    out[p] = body as u8;
    p += 1;
    out[p] = 0x86;
    p += 1;
    if point_long {
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
