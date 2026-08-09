// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The emulator's randomness: the same [`HmacDrbg`] the firmware runs, seeded
//! from `/dev/urandom` instead of the RP2350 TRNG — or from a fixed `--seed` so
//! a test run is reproducible.
//!
//! A `--seed` run makes every key the emulator mints predictable. That is the
//! point for tests, and the reason the banner says so out loud.

use std::fs::File;
use std::io::{self, Read};

use rsk_crypto::HmacDrbg;

pub struct EmuRng {
    drbg: HmacDrbg,
}

impl EmuRng {
    /// Seed from 48 bytes of OS entropy — 32 B of security strength plus a 16 B
    /// nonce, the split SP 800-90A 10.1.2.3 asks for and the firmware uses.
    pub fn from_os() -> io::Result<Self> {
        let mut seed = [0u8; 48];
        File::open("/dev/urandom")?.read_exact(&mut seed)?;
        Ok(Self {
            drbg: HmacDrbg::new(&seed),
        })
    }

    /// Seed from a caller-supplied value: same input, same keys, every run.
    pub fn from_seed(seed: &[u8]) -> Self {
        Self {
            drbg: HmacDrbg::new(seed),
        }
    }

    fn draw(&mut self, buf: &mut [u8]) {
        self.drbg.fill(buf);
    }
}

// One backend behind each applet crate's own `Rng`, exactly as `firmware`'s
// `FidoRng` does — the crates deliberately don't share a trait.
impl rsk_fido::Rng for EmuRng {
    fn fill(&mut self, buf: &mut [u8]) {
        self.draw(buf);
    }
}

impl rsk_openpgp::Rng for EmuRng {
    fn fill(&mut self, buf: &mut [u8]) {
        self.draw(buf);
    }
}

impl rsk_oath::Rng for EmuRng {
    fn fill(&mut self, buf: &mut [u8]) {
        self.draw(buf);
    }
}

impl rsk_otp::Rng for EmuRng {
    fn fill(&mut self, buf: &mut [u8]) {
        self.draw(buf);
    }
}

impl rsk_rescue::Rng for EmuRng {
    fn fill(&mut self, buf: &mut [u8]) {
        self.draw(buf);
    }
}
