// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The randomness seam every applet is handed by its composition root.

/// A source of random bytes — the device TRNG in `firmware`, a deterministic
/// stream in tests. Decouples the applets from any specific `rand_core` version.
///
/// `rsk-rsa` declares its own, identical trait: it is an algorithm crate two
/// tiers below this one, and reaching up for this would invert the dependency.
/// The applets that call into it bridge the two at the call (`keys::RsaRng`).
pub trait Rng {
    fn fill(&mut self, buf: &mut [u8]);
}
