// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Why an RSA operation refused.
//!
//! This crate cannot name `rsk_sdk::Sw`: the status word is the *applets'* wire
//! surface and `rsk-sdk` sits two tiers above an algorithm crate. So each
//! variant below names the status word its callers must answer with, and
//! `rsk-openpgp` (`keys::rsa_sw`) and `rsk-piv` (`rsa_sw`) each reproduce that
//! table at their APDU boundary, pinned by a test. The two copies are forced,
//! not chosen: `RsaError` and `Sw` are both foreign to those crates, so no
//! shared `From` impl exists that does not point a dependency upward.

/// Why an RSA operation refused. The variants are exhaustive on purpose — a new
/// one must break both applets' mappings rather than fall into a `_` arm and
/// answer some other status word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaError {
    /// A width does not fit: an output buffer too small for the result, a field
    /// wider than its slot, or a prime width the asm CRT core cannot take.
    /// Applets answer `Sw::WRONG_LENGTH`.
    BadWidth,
    /// The caller's block is not a valid input for this modulus — the wrong
    /// length, or padding that does not decode. Applets answer `Sw::WRONG_DATA`.
    BadBlock,
    /// A stored key blob matches no known layout, or its primes do not form a
    /// key. Applets answer `Sw::MEMORY_FAILURE`.
    BadBlob,
    /// The operation itself failed: the Bellcore fault check, absent CRT
    /// parameters, or a keygen that cannot run. Applets answer `Sw::EXEC_ERROR`.
    Failed,
}
