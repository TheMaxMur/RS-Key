// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Why an EC private-key operation refused.
//!
//! This crate cannot name `rsk_sdk::Sw`: the status word is the *applets'* wire
//! surface and `rsk-sdk` sits two tiers above an algorithm crate. So each
//! variant below names the status word its callers must answer with, and
//! `rsk-openpgp` (`keys::ec_sw`) and `rsk-piv` (`ec_sw`) each reproduce that
//! table at their APDU boundary, pinned arm by arm by a test — the same shape,
//! and for the same reason, as the RSA sibling `rsk_rsa::RsaError`, whose
//! `error.rs` carries the long argument for why `rsk-sdk` must not host it.
//!
//! The split between [`EcError::Failed`] and [`EcError::BadPoint`] is not
//! cosmetic: it is what keeps a signature failure answering `6400` while a
//! malformed ECDH peer point keeps answering `6984`. One shared "it failed"
//! variant would have to pick one of the two and silently change the other.

/// Why an EC private-key operation refused. The variants are exhaustive on
/// purpose — a new one must break both applets' mappings rather than fall into
/// a `_` arm and answer some other status word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcError {
    /// The operation itself failed: a scalar that is not a field element, a
    /// zero scalar, or a signer that could not produce `r ‖ s`. Applets answer
    /// `Sw::EXEC_ERROR`.
    Failed,
    /// The caller's bytes are not a usable point or scalar for this curve — a
    /// peer point that does not parse, or one of the wrong width. Applets
    /// answer `Sw::DATA_INVALID`.
    BadPoint,
    /// The curve does not offer this operation at all: X25519 never signs,
    /// Ed25519 never agrees. Applets answer `Sw::FUNC_NOT_SUPPORTED`.
    Unsupported,
}
