// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! HMAC-DRBG (NIST SP 800-90A) over HMAC-SHA256 — the firmware's whitening
//! CSPRNG. The firmware seeds and periodically reseeds it from the hardware TRNG
//! at sample-chain length 0; per-operation TRNG draws are avoided because the
//! TRNG's autocorrelation health test stalls at longer chain settings. Per-draw
//! cost is a few HMAC-SHA256 ops — microseconds, uniform.

use hmac::{Hmac, Mac};
use rsk_secret::Secret;
use sha2::Sha256;

/// HMAC-SHA256 output / DRBG state size.
const SEEDLEN: usize = 32;

/// HMAC-DRBG over HMAC-SHA256. Instantiate with [`HmacDrbg::new`], draw with
/// [`HmacDrbg::fill`], refresh entropy with [`HmacDrbg::reseed`].
pub struct HmacDrbg {
    k: Secret<[u8; SEEDLEN]>,
    v: Secret<[u8; SEEDLEN]>,
}

impl HmacDrbg {
    /// Instantiate from `seed` — the caller concatenates entropy ‖ nonce ‖
    /// personalization (SP 800-90A 10.1.2.3).
    pub fn new(seed: &[u8]) -> Self {
        let mut d = Self {
            k: Secret::new([0x00; SEEDLEN]),
            v: Secret::new([0x01; SEEDLEN]),
        };
        d.update(seed);
        d
    }

    /// `HMAC(key, a ‖ b ‖ c)` — parts fed without concatenating (no alloc).
    fn hmac(key: &[u8; SEEDLEN], a: &[u8], b: &[u8], c: &[u8]) -> [u8; SEEDLEN] {
        let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
        m.update(a);
        m.update(b);
        m.update(c);
        let mut out = [0u8; SEEDLEN];
        out.copy_from_slice(&m.finalize().into_bytes());
        out
    }

    /// SP 800-90A 10.1.2.2 Update; an empty `provided` is the no-data form.
    fn update(&mut self, provided: &[u8]) {
        // K = HMAC(K, V ‖ 0x00 ‖ provided); V = HMAC(K, V)
        *self.k.expose_mut() = Self::hmac(self.k.expose(), self.v.expose(), &[0x00], provided);
        *self.v.expose_mut() = Self::hmac(self.k.expose(), self.v.expose(), &[], &[]);
        if !provided.is_empty() {
            // K = HMAC(K, V ‖ 0x01 ‖ provided); V = HMAC(K, V)
            *self.k.expose_mut() = Self::hmac(self.k.expose(), self.v.expose(), &[0x01], provided);
            *self.v.expose_mut() = Self::hmac(self.k.expose(), self.v.expose(), &[], &[]);
        }
    }

    /// Fill `out` with DRBG output (SP 800-90A 10.1.2.5, no additional input). Each
    /// call is one Generate: the state ratchets afterwards, so two `fill`s yield a
    /// different stream than one `fill` of the combined length (by design).
    pub fn fill(&mut self, out: &mut [u8]) {
        let mut i = 0;
        while i < out.len() {
            *self.v.expose_mut() = Self::hmac(self.k.expose(), self.v.expose(), &[], &[]);
            let n = (out.len() - i).min(SEEDLEN);
            out[i..i + n].copy_from_slice(&self.v.expose()[..n]);
            i += n;
        }
        self.update(&[]);
    }

    /// Mix fresh entropy into the state (SP 800-90A 10.1.2.4 reseed).
    pub fn reseed(&mut self, entropy: &[u8]) {
        self.update(entropy);
    }

    /// Wipe the internal state — for a secure reboot, destroy the live keystream
    /// before handing control to the bootloader. Unusable until re-seeded.
    pub fn scrub(&mut self) {
        // Assigning drops the old state, which wipes it; the fresh one is zeros.
        let Self { k, v } = self;
        *k = Secret::zeroed();
        *v = Secret::zeroed();
    }
}

/// How many draws [`draw_entropy`] takes before it gives up. A working source answers
/// an all-zero block with probability 2^-(8·len), so each one is a fault, and a fault
/// that outlasts three draws is not a passing one.
pub const ENTROPY_TRIES: usize = 3;

/// An entropy source that answered only draws with an all-zero block.
#[derive(Debug, PartialEq, Eq)]
pub struct EntropyFault;

/// Fill `buf` from `source`, refusing a draw with an all-zero `block`-byte block (the
/// last may be shorter): a DRBG seeded from one is seeded from a constant. At most
/// [`ENTROPY_TRIES`] draws; then [`EntropyFault`], `buf` holding the last, to wipe.
pub fn draw_entropy(
    buf: &mut [u8],
    block: usize,
    mut source: impl FnMut(&mut [u8]),
) -> Result<(), EntropyFault> {
    for _ in 0..ENTROPY_TRIES {
        source(buf);
        // Folded, not searched: these bytes are the seed.
        if buf
            .chunks(block.max(1))
            .all(|c| c.iter().fold(0, |acc, &b| acc | b) != 0)
        {
            return Ok(());
        }
    }
    Err(EntropyFault)
}

#[cfg(test)]
#[path = "drbg_tests.rs"]
mod tests;
