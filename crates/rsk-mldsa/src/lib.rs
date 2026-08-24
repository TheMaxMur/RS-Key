// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg_attr(not(test), no_std)]

//! `rsk-mldsa` — stack-optimized ML-DSA (FIPS 204, Dilithium) signatures for the
//! RP2350. The reference arithmetic (reduction, NTT, sampling, packing,
//! encodings) is ported faithfully; the top-level keygen/sign/verify are
//! restructured to **stream the public matrix A** on the fly (one polynomial
//! resident instead of the full k×l) and transform **in place**, so ML-DSA-65
//! fits the ~222 KiB main stack where the by-value `fips204` crate overflows it.
//!
//! `no_std`, no alloc, no `unsafe`. Byte-for-byte compatible with FIPS 204: host
//! tests check both parameter sets against NIST ACVP KATs (keygen/sign/verify),
//! with Kani proofs over the reductions, rounding, and bit-packing.

mod encode;
mod ntt;
mod pack;
mod params;
mod poly;
mod reduce;
mod round;
mod sample;
mod sign;

#[cfg(test)]
mod testutil;
#[cfg(test)]
mod testvectors;

use params::{ML_DSA_44, ML_DSA_65, ML_DSA_87};
use sign::{ExpandedKey, verify};

/// Length of the key-generation seed ξ (both parameter sets).
pub const SEED_LEN: usize = 32;

/// ML-DSA-44 serialized public-key length.
pub const MLDSA44_PK_LEN: usize = 1312;
/// ML-DSA-44 signature length.
pub const MLDSA44_SIG_LEN: usize = 2420;
/// ML-DSA-65 serialized public-key length.
pub const MLDSA65_PK_LEN: usize = 1952;
/// ML-DSA-65 signature length.
pub const MLDSA65_SIG_LEN: usize = 3309;
/// ML-DSA-87 serialized public-key length.
pub const MLDSA87_PK_LEN: usize = 2592;
/// ML-DSA-87 signature length.
pub const MLDSA87_SIG_LEN: usize = 4627;

/// Errors from the fallible operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The signature output buffer was shorter than the parameter set's
    /// signature length.
    BufferTooSmall,
}

/// An ML-DSA-44 keypair expanded from a 32-byte seed. Holds the NTT-domain
/// precomputes (~13 KB); derive, use and drop within one request. Zeroizes on
/// drop. Signs with an empty FIPS 204 context (the COSE/WebAuthn profile).
pub struct MlDsa44(ExpandedKey<4, 4>);

impl MlDsa44 {
    /// Deterministically expand the keypair from ξ.
    pub fn from_seed(xi: &[u8; SEED_LEN]) -> Self {
        Self(ExpandedKey::from_seed(&ML_DSA_44, xi))
    }

    /// The serialized public key (the COSE `pub` parameter).
    pub fn public_key(&self) -> [u8; MLDSA44_PK_LEN] {
        let mut pk = [0u8; MLDSA44_PK_LEN];
        self.0.write_public_key(&ML_DSA_44, &mut pk);
        pk
    }

    /// Sign `msg` (empty context) into `out`; returns the signature length. `rnd`
    /// is the hedge randomness — fresh RNG bytes in firmware; all-zero is the
    /// spec's deterministic variant.
    pub fn sign(&self, msg: &[u8], rnd: &[u8; 32], out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < MLDSA44_SIG_LEN {
            return Err(Error::BufferTooSmall);
        }
        self.0
            .sign(&ML_DSA_44, msg, &[], rnd, &mut out[..MLDSA44_SIG_LEN]);
        Ok(MLDSA44_SIG_LEN)
    }
}

/// An ML-DSA-65 keypair expanded from a 32-byte seed. Holds the NTT-domain
/// precomputes (~23 KB); derive, use and drop within one request. Zeroizes on
/// drop. Signs with an empty FIPS 204 context (the COSE/WebAuthn profile).
pub struct MlDsa65(ExpandedKey<6, 5>);

impl MlDsa65 {
    /// Deterministically expand the keypair from ξ.
    pub fn from_seed(xi: &[u8; SEED_LEN]) -> Self {
        Self(ExpandedKey::from_seed(&ML_DSA_65, xi))
    }

    /// The serialized public key (the COSE `pub` parameter).
    pub fn public_key(&self) -> [u8; MLDSA65_PK_LEN] {
        let mut pk = [0u8; MLDSA65_PK_LEN];
        self.0.write_public_key(&ML_DSA_65, &mut pk);
        pk
    }

    /// Sign `msg` (empty context) into `out`; returns the signature length.
    pub fn sign(&self, msg: &[u8], rnd: &[u8; 32], out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < MLDSA65_SIG_LEN {
            return Err(Error::BufferTooSmall);
        }
        self.0
            .sign(&ML_DSA_65, msg, &[], rnd, &mut out[..MLDSA65_SIG_LEN]);
        Ok(MLDSA65_SIG_LEN)
    }
}

/// An ML-DSA-87 keypair expanded from a 32-byte seed. Holds the NTT-domain
/// precomputes (~31 KB); derive, use and drop within one request. Zeroizes on
/// drop. Signs with an empty FIPS 204 context (the COSE/WebAuthn profile).
pub struct MlDsa87(ExpandedKey<8, 7>);

impl MlDsa87 {
    /// Deterministically expand the keypair from ξ.
    pub fn from_seed(xi: &[u8; SEED_LEN]) -> Self {
        Self(ExpandedKey::from_seed(&ML_DSA_87, xi))
    }

    /// The serialized public key (the COSE `pub` parameter).
    pub fn public_key(&self) -> [u8; MLDSA87_PK_LEN] {
        let mut pk = [0u8; MLDSA87_PK_LEN];
        self.0.write_public_key(&ML_DSA_87, &mut pk);
        pk
    }

    /// Sign `msg` (empty context) into `out`; returns the signature length.
    pub fn sign(&self, msg: &[u8], rnd: &[u8; 32], out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < MLDSA87_SIG_LEN {
            return Err(Error::BufferTooSmall);
        }
        self.0
            .sign(&ML_DSA_87, msg, &[], rnd, &mut out[..MLDSA87_SIG_LEN]);
        Ok(MLDSA87_SIG_LEN)
    }
}

/// Verify an ML-DSA-44 signature (empty context) against a serialized public
/// key. Malformed keys or signatures verify as `false`.
pub fn mldsa44_verify(pk: &[u8; MLDSA44_PK_LEN], msg: &[u8], sig: &[u8; MLDSA44_SIG_LEN]) -> bool {
    verify::<4, 4>(&ML_DSA_44, pk, msg, &[], sig)
}

/// Verify an ML-DSA-65 signature (empty context) against a serialized public
/// key. Malformed keys or signatures verify as `false`.
pub fn mldsa65_verify(pk: &[u8; MLDSA65_PK_LEN], msg: &[u8], sig: &[u8; MLDSA65_SIG_LEN]) -> bool {
    verify::<6, 5>(&ML_DSA_65, pk, msg, &[], sig)
}

/// Verify an ML-DSA-87 signature (empty context) against a serialized public
/// key. Malformed keys or signatures verify as `false`.
pub fn mldsa87_verify(pk: &[u8; MLDSA87_PK_LEN], msg: &[u8], sig: &[u8; MLDSA87_SIG_LEN]) -> bool {
    verify::<8, 7>(&ML_DSA_87, pk, msg, &[], sig)
}
