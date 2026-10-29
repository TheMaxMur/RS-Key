// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! HMAC and HKDF over SHA-1, SHA-256 and SHA-512. SHA-256 backs the PIN KDF;
//! SHA-512 backs the FIDO key-derivation ratchet and the credential key chains;
//! SHA-1 exists only for the YKOATH applet, where HMAC-SHA1 is the
//! protocol-mandated default OTP algorithm (RFC 4226/6238).

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rsk_sha256::Sha256;
use sha1::Sha1;
// SHA-512 (HMAC + the FIDO HKDF ratchet) uses the Cortex-M33-fast core; the
// generic HMAC/HKDF constructions above it are unchanged, so the output stays
// byte-identical to sha2::Sha512.
use rsk_sha512::Sha512;

use crate::{Error, Result};

/// HMAC-SHA1 — the RFC 4226 HOTP/TOTP PRF. Any key length is accepted.
pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&tag);
    out
}

/// HMAC-SHA256. Any key length is accepted.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// A command-local HMAC template; keep it in returned frames covered by the
/// Secure stack sweep, never in a mounted store or between backend operations.
pub struct HmacSha256(Hmac<Sha256>);

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        Self(Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length"))
    }

    pub fn tag(&self, msg: &[u8]) -> [u8; 32] {
        let mut mac = self.0.clone();
        mac.update(msg);
        mac.finalize().into_bytes().into()
    }
}

/// HMAC-SHA256 from the unpadded chaining states of two public key-pad blocks.
/// Only public, fixed keys may use this path; secret keys use `HmacSha256`.
pub fn hmac_sha256_public_pads(inner: [u32; 8], outer: [u32; 8], msg: &[u8]) -> [u8; 32] {
    let digest = rsk_secret::Secret::new(rsk_sha256::digest_after_public_block(inner, msg));
    rsk_sha256::digest_after_public_block(outer, digest.expose())
}

/// HMAC-SHA512. Any key length is accepted.
pub fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&tag);
    out
}

/// Constant-time byte-slice equality, for MAC verification — an early-exit
/// compare of a freshly computed (secret) tag against an attacker-controlled
/// value is a timing oracle. Lengths are public, so mismatched lengths may
/// return early.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    // Barrier so a future compiler can't fold the OR-accumulate into an
    // early-exit branch (CT is verified in disassembly today; this pins it).
    core::hint::black_box(diff) == 0
}

/// HKDF-SHA256 extract-then-expand into `okm`.
/// `okm.len()` must be ≤ 255·32 = 8160.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, okm).map_err(|_| Error::BadLength)
}

/// HKDF-SHA512 extract-then-expand into `okm`.
/// `okm.len()` must be ≤ 255·64 = 16320.
pub fn hkdf_sha512(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()> {
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    hk.expand(info, okm).map_err(|_| Error::BadLength)
}

#[cfg(test)]
#[path = "mac_tests.rs"]
mod tests;
