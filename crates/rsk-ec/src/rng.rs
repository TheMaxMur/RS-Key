// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The randomness seam key generation needs.
//!
//! Declared here rather than borrowed from `rsk-sdk`, for the reason spelled out
//! in `rsk_rsa::rng`: that crate sits two tiers up and an algorithm crate
//! reaching for it would invert the dependency. The applets bridge the two
//! (`rsk_openpgp::keys::EcRng`, `rsk_piv::EcRng`), exactly as they already do
//! for the RSA half.
//!
//! Only [`crate::PrivKey::generate`] takes one. Signing and public-point
//! derivation are deterministic and take no randomness at all; P-521's random
//! nonce is the one exception, and it stays on [`crate::sign_p521`]'s own `fill`
//! closure rather than widening this seam.

/// Random-byte source. `firmware` backs this with the RP2350 TRNG; tests use a
/// deterministic counter.
pub trait Rng {
    fn fill(&mut self, buf: &mut [u8]);
}
