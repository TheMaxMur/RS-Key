// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The RSA public-key data object `7F49 82 LL { 81 82 <N> · 82 <Elen> <E> }`.
//!
//! Both card applets answer key generation and import with these exact bytes —
//! OpenPGP from `keypair_gen` / IMPORT, PIV from GENERATE and GET METADATA — so
//! the encoder lives once, below both. It is pure byte-building: no status word,
//! no key state, nothing an applet has to own.

use rsa::RsaPrivateKey;
use rsa::traits::PublicKeyParts;

use crate::MAX_RSA_BYTES;

/// Largest RSA public-key DO `7F49 82 LL { 81 82 <N> · 82 <Elen> <E> }`.
pub const MAX_RSA_PUBDO: usize = 5 + 4 + MAX_RSA_BYTES + 2 + 8;

/// The inner RSA public-key body `81 82 <nlen:u16-be> N 82 <elen:u8> E` (no `7F49`
/// wrapper), from the modulus and exponent bytes. Returns its length
/// (`4 + n.len() + 2 + e.len()`). Shared by [`make_rsa_response`] and the PIV
/// GET METADATA path, which has `N` and `e` directly and must not rebuild the key.
pub fn make_rsa_pub_body(n: &[u8], e: &[u8], out: &mut [u8]) -> usize {
    out[0] = 0x81;
    out[1] = 0x82;
    out[2..4].copy_from_slice(&(n.len() as u16).to_be_bytes());
    let mut p = 4;
    out[p..p + n.len()].copy_from_slice(n);
    p += n.len();
    out[p] = 0x82;
    out[p + 1] = e.len() as u8;
    p += 2;
    out[p..p + e.len()].copy_from_slice(e);
    p + e.len()
}

/// Build the whole public-key DO `7F49 82 LL { 81 82 <N> · 82 <Elen> <E> }`
/// (modulus tag 0x81 with a 2-byte length, exponent tag 0x82 with a 1-byte one).
pub fn make_rsa_response(key: &RsaPrivateKey, out: &mut [u8]) -> usize {
    out[0] = 0x7f;
    out[1] = 0x49;
    out[2] = 0x82; // 2-byte inner length, back-patched below
    // e stays sourced from the key: an imported OpenPGP key may carry a non-65537
    // exponent, so only the PIV metadata caller is allowed to hardcode 65537.
    let body = make_rsa_pub_body(
        &key.n().to_bytes_be(),
        &key.e().to_bytes_be(),
        &mut out[5..],
    );
    out[3..5].copy_from_slice(&(body as u16).to_be_bytes());
    5 + body
}

#[cfg(test)]
#[path = "pubdo_tests.rs"]
mod tests;
