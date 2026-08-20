// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The randomness seam the private-key paths need, plus the bridge to the `rsa`
//! crate's `rand_core`.
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

/// Adapts [`Rng`] to the `rsa` crate's `rand_core` (still 0.6, distinct from the
/// EC stack's 0.10) for RSA blinding, signing and key construction. Public
/// because `rsk-openpgp`'s legacy DECIPHER arm drives the same crate APIs.
pub struct RngAdapter<'a>(pub &'a mut dyn Rng);

impl rsa::rand_core::RngCore for RngAdapter<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.0.fill(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.0.fill(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.0.fill(dst);
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.0.fill(dst);
        Ok(())
    }
}
impl rsa::rand_core::CryptoRng for RngAdapter<'_> {}
