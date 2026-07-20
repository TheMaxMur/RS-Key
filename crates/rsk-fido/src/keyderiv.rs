// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! FIDO key derivation. A key handle is a 32-byte path plus a 32-byte HMAC tag:
//! the private scalar is an HKDF-SHA512 ratchet over the device seed, salted per
//! 4-byte path entry, and the tag binds the handle to an app id (rpIdHash).

use zeroize::Zeroize;

use rsk_crypto::{ct_eq, hkdf_sha512, hmac_sha256};

use crate::Rng;
use crate::ec::RATCHET_LEN;

/// The path portion of a key handle.
pub const KEY_PATH_LEN: usize = 32;
const KEY_PATH_ENTRIES: usize = KEY_PATH_LEN / 4; // 8
/// Key-handle length: 32-byte path + 32-byte HMAC tag.
pub const KEY_HANDLE_LEN: usize = KEY_PATH_LEN + 32;

/// First path element for CTAP2 credentials: `0x80000000 | 10022`.
const RESIDENT_PATH_FIRST: u32 = 0x8000_0000 | 10022;

/// The HKDF-SHA512 ratchet: derive the raw key material from `seed` and `path`.
///
/// Each iteration re-keys with HKDF(salt = 4 path bytes, ikm = bytes[..32],
/// info = bytes[32..64]); only the first 64 bytes feed forward. The output is
/// expanded to [`RATCHET_LEN`] (66 — a P-521 scalar); by HKDF's prefix property
/// the expansion width never changes the leading bytes, so each curve's scalar
/// is just its length sliced off the front.
pub(crate) fn ratchet(seed: &[u8; 32], path: &[u8; KEY_PATH_LEN]) -> [u8; RATCHET_LEN] {
    let mut outk = [0u8; RATCHET_LEN]; // [ikm(32) | info(32) | extra]; info starts zero
    outk[..32].copy_from_slice(seed);
    for i in 0..KEY_PATH_ENTRIES {
        let salt = &path[i * 4..i * 4 + 4];
        let mut tmp = [0u8; RATCHET_LEN];
        hkdf_sha512(salt, &outk[..32], &outk[32..64], &mut tmp).expect("HKDF output");
        outk.copy_from_slice(&tmp);
        tmp.zeroize();
    }
    outk
}

/// The first 32 bytes of the ratchet — the P-256 scalar and the HMAC-tag key.
fn ratchet_scalar32(seed: &[u8; 32], path: &[u8; KEY_PATH_LEN]) -> [u8; 32] {
    let mut full = ratchet(seed, path);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&full[..32]);
    full.zeroize();
    scalar
}

/// HMAC-SHA256(scalar, app_id ‖ path) — the key-handle tag.
fn handle_tag(scalar: &[u8; 32], app_id: &[u8; 32], path: &[u8; KEY_PATH_LEN]) -> [u8; 32] {
    let mut base = [0u8; 64];
    base[..32].copy_from_slice(app_id);
    base[32..].copy_from_slice(path);
    hmac_sha256(scalar, &base)
}

/// Derive a fresh credential: random path → ratchet → tag.
/// Returns `(key_handle = path ‖ tag, scalar)`.
pub fn derive_new(
    seed: &[u8; 32],
    app_id: &[u8; 32],
    rng: &mut impl Rng,
) -> ([u8; KEY_HANDLE_LEN], [u8; 32]) {
    let mut path = [0u8; KEY_PATH_LEN];
    for i in 0..KEY_PATH_ENTRIES {
        let mut e = [0u8; 4];
        rng.fill(&mut e);
        e[3] |= 0x80; // set 0x80000000 in the little-endian u32
        path[i * 4..i * 4 + 4].copy_from_slice(&e);
    }
    let scalar = ratchet_scalar32(seed, &path);
    let mut kh = [0u8; KEY_HANDLE_LEN];
    kh[..32].copy_from_slice(&path);
    kh[32..].copy_from_slice(&handle_tag(&scalar, app_id, &path));
    (kh, scalar)
}

/// Re-derive from the handle's path and check its tag binds it to `app_id`;
/// returns the scalar on success. (Constant-time compare — the handle is
/// attacker-chosen, but the recomputed tag is secret; an early-exit compare
/// would leak how many leading tag bytes matched, letting an attacker forge
/// a valid handle for an rpId byte by byte.)
pub fn verify_key(
    seed: &[u8; 32],
    app_id: &[u8; 32],
    key_handle: &[u8; KEY_HANDLE_LEN],
) -> Option<[u8; 32]> {
    // Every path entry must have its high bit set.
    for i in 0..KEY_PATH_ENTRIES {
        if key_handle[i * 4 + 3] & 0x80 == 0 {
            return None;
        }
    }
    let mut path = [0u8; KEY_PATH_LEN];
    path.copy_from_slice(&key_handle[..KEY_PATH_LEN]);
    let scalar = ratchet_scalar32(seed, &path);
    if ct_eq(
        &handle_tag(&scalar, app_id, &path),
        &key_handle[KEY_PATH_LEN..],
    ) {
        Some(scalar)
    } else {
        None
    }
}

/// The raw signing key material for a CTAP2 credential. The path is the
/// cred_id's first 32 bytes with entry 0 forced to `0x80000000 | 10022` and
/// every entry's high bit set. Returns the full [`RATCHET_LEN`]-byte ratchet
/// output; the caller builds a [`crate::ec::CredKey`] for the credential's
/// curve, which reads the curve's scalar length off the front.
pub fn fido_load_key(seed: &[u8; 32], cred_id: &[u8]) -> Option<[u8; RATCHET_LEN]> {
    if cred_id.len() < KEY_PATH_LEN {
        return None;
    }
    let mut path = [0u8; KEY_PATH_LEN];
    path.copy_from_slice(&cred_id[..KEY_PATH_LEN]);
    path[0..4].copy_from_slice(&RESIDENT_PATH_FIRST.to_le_bytes());
    for i in 0..KEY_PATH_ENTRIES {
        path[i * 4 + 3] |= 0x80;
    }
    Some(ratchet(seed, &path))
}

#[cfg(test)]
#[path = "keyderiv_tests.rs"]
mod tests;
