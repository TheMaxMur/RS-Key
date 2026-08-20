// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The randomness seam the private-key paths need.
//!
//! Declared here rather than borrowed from `rsk-sdk`: that crate sits two tiers
//! up and an algorithm crate reaching for it would invert the dependency. The
//! applets re-export this trait as their own `Rng`, so the tree still has one
//! declaration of it, not two.

/// Random-byte source. `firmware` backs this with the RP2350 TRNG; tests use a
/// deterministic counter.
pub trait Rng {
    fn fill(&mut self, buf: &mut [u8]);
}
