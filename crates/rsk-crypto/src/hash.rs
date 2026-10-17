// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! SHA-1 / SHA-256 / SHA-384 / SHA-512 helpers.

use sha2::{Digest, Sha256};
// SHA-384/512 use the Cortex-M33-fast core (byte-identical to sha2::Sha384/512).
use rsk_sha512::{Sha384, Sha512};

/// Streaming SHA-256 for public metadata larger than a command's scratch buffer.
pub struct Sha256State(Sha256);

impl Default for Sha256State {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256State {
    pub fn new() -> Self {
        Self(Sha256::new())
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    pub fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

/// One-shot SHA-1 — only for X.509 key identifiers (SKI/AKI, RFC 5280 method 1),
/// never for new signatures.
pub fn sha1(input: &[u8]) -> [u8; 20] {
    let digest = sha1::Sha1::digest(input);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest);
    out
}

/// One-shot SHA-256.
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// One-shot SHA-384.
pub fn sha384(input: &[u8]) -> [u8; 48] {
    let digest = Sha384::digest(input);
    let mut out = [0u8; 48];
    out.copy_from_slice(&digest);
    out
}

/// One-shot SHA-512.
pub fn sha512(input: &[u8]) -> [u8; 64] {
    let digest = Sha512::digest(input);
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
#[path = "hash_tests.rs"]
mod tests;
