// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! On-card RSA key generation: the stepped prime search both RP2350 cores run,
//! its blocking single-core driver, and the import path that rebuilds a key from
//! host-supplied `e`/`p`/`q`.

use alloc::boxed::Box;
use num_bigint_dig::prime::probably_prime_lucas;
use rsa::{BigUint, RsaPrivateKey};
use zeroize::Zeroize;

use crate::{
    IncrementalSieve, MAX_RSA_BYTES, RSA_E, Rng, RsaError, mod_small, passes_strong_mr_base2,
    self_test,
};

/// Build the RSA key from the imported exponent / primes (OpenPGP tags
/// 0x91/0x92/0x93, PIV's `01`/`02` import template).
pub fn rsa_from_pqe(e: &[u8], p: &[u8], q: &[u8]) -> Option<RsaPrivateKey> {
    let p = BigUint::from_bytes_be(p);
    let q = BigUint::from_bytes_be(q);
    // from_p_q derives the totient via (p-1)(q-1); a zero prime MPI underflows
    // num-bigint's unsigned subtraction (a panic, not an Err) and halts the device
    // on import, so reject it here and let the caller's ok_or(EXEC_ERROR) do its job.
    if p < BigUint::from(2u8) || q < BigUint::from(2u8) {
        return None;
    }
    RsaPrivateKey::from_p_q(p, q, BigUint::from_bytes_be(e)).ok()
}

/// The RSA prime search as a *stepper*, so the CCID transport can yield — and
/// send time-extension keepalives — between candidates. Each
/// [`step`](RsaKeygen::step) tests ONE random candidate (a bounded chunk: one
/// `probably_prime`, ~tens of ms on-device), matching the `rsa` crate's keygen:
/// two `nbits/2`-bit primes with the top two bits set and `gcd(e, prime − 1) = 1`,
/// assembled with `RsaPrivateKey::from_p_q`. The primality decision is
/// Baillie-PSW split across backends: the strong Miller-Rabin base-2 half on
/// the KAT-gated asm modexp (ours, differentially tested against the library),
/// the strong Lucas half and key assembly the vetted library routines.
///
/// `step` decomposes into [`try_candidate`](RsaKeygen::try_candidate) (one
/// draw + test, stateless) and [`offer`](RsaKeygen::offer) (the two-prime
/// pool): the firmware runs `try_candidate` on BOTH RP2350 cores — each with
/// its own RNG stream — and funnels every find through one `offer` pool, so
/// the cores race for `p` and `q` and the expected search time roughly halves.
pub struct RsaKeygen {
    half_bytes: usize,
    e: BigUint,
    p: Option<BigUint>,
    /// Result of the asm modexp known-answer test, checked once up front: if the
    /// fast modexp is wrong on this build/silicon, refuse to generate (rather than
    /// emit a weak key). Always true on the host (num-bigint backend).
    asm_ok: bool,
}

// A keygen abandoned between steps still holds the first found prime.
impl Drop for RsaKeygen {
    fn drop(&mut self) {
        if let Some(p) = &mut self.p {
            p.zeroize();
        }
    }
}

/// The outcome of one [`RsaKeygen::step`]. The `Done` key is boxed so the enum
/// stays pointer-sized (it is returned up the call stack each step).
pub enum RsaStep {
    /// Candidate rejected, or the first prime was just found — call `step` again.
    More,
    /// Both primes found and the private key assembled.
    Done(Box<RsaPrivateKey>),
    /// Unusable parameters (unsupported modulus size) or a key-assembly failure.
    Failed,
}

impl RsaKeygen {
    /// Prepare to generate an `nbits`-bit modulus (only byte-aligned half-sizes —
    /// every real OpenPGP size, 2048/3072/4096, qualifies).
    pub fn new(nbits: usize) -> Self {
        RsaKeygen {
            half_bytes: nbits / 16,
            e: BigUint::from(RSA_E),
            p: None,
            asm_ok: self_test(),
        }
    }

    /// Whether this keygen can run at all: the modulus size is supported (the
    /// asm modexp needs the prime length to be a multiple of 32 bytes — every
    /// standard RSA size qualifies) and the modexp known-answer test passed
    /// (a broken fast modexp must never yield a key).
    pub fn usable(&self) -> bool {
        let half = self.half_bytes;
        self.asm_ok && half != 0 && half <= MAX_RSA_BYTES / 2 && half.is_multiple_of(32)
    }

    /// One prime's size in bytes (half the modulus).
    pub fn half_bytes(&self) -> usize {
        self.half_bytes
    }

    /// Draw and test ONE prime candidate of `half_bytes` — the bounded unit of
    /// search work. Stateless (an associated fn), so a second core can run it
    /// concurrently with its own RNG stream. The pipeline is Baillie-PSW split
    /// across backends: the cheap rejections (the small-prime sieve, the
    /// `gcd(e, n−1)` check), then the strong Miller-Rabin base-2 gate on the
    /// KAT-gated asm modexp, then the vetted software strong Lucas test for
    /// the final accept. Admitting a composite would take a simultaneous
    /// failure of both halves — the same combined guarantee
    /// `probably_prime(_, 0)` gives, with the modexp-heavy half on the fast
    /// path. The caller is responsible for the
    /// [`usable`](RsaKeygen::usable) gate.
    ///
    /// `sieve` is a running [`IncrementalSieve`] owned by the caller (one per
    /// core in the dual-core search): each call advances it by one candidate.
    /// A call that lands on a composite, or that reseeds an exhausted window,
    /// returns `None` cheaply; only a sieve survivor pays the modexp + Lucas.
    pub fn try_candidate(
        sieve: &mut IncrementalSieve,
        rng: &mut dyn Rng,
        half_bytes: usize,
    ) -> Option<BigUint> {
        match sieve.step() {
            None => {
                // Window exhausted (or never seeded) — draw a fresh random odd
                // top-two-bits start; this call yields no candidate.
                let mut seed = [0u8; MAX_RSA_BYTES / 2];
                rng.fill(&mut seed[..half_bytes]);
                sieve.reseed(half_bytes, &seed[..half_bytes]);
                seed.zeroize();
                return None;
            }
            Some(false) => return None, // composite by a small prime — cheap
            Some(true) => {}            // sieve survivor — run the dear tests
        }
        let n = sieve.candidate();
        // gcd(e, n − 1) == 1  ⇔  n ≢ 1 (mod e), since e is prime.
        if mod_small(n, RSA_E) == 1 {
            return None;
        }
        // The strong Miller-Rabin half of Baillie-PSW, on the asm modexp.
        if !passes_strong_mr_base2(n) {
            return None;
        }
        let cand = BigUint::from_bytes_le(n);
        // The strong Lucas half (vetted library code). Together with the MR
        // gate above this is exactly `probably_prime(_, 0)` — see the
        // `keygen_bpsw_split_matches_library` test.
        if !probably_prime_lucas(&cand) {
            return None;
        }
        Some(cand)
    }

    /// Feed a found prime into the two-prime pool: the first is held, a second
    /// *distinct* one completes the key (a duplicate is rejected and the held
    /// prime kept — the search just continues). Accepts primes found by any
    /// core, in any order.
    pub fn offer(&mut self, mut cand: BigUint) -> RsaStep {
        match self.p.take() {
            None => {
                self.p = Some(cand);
                RsaStep::More
            }
            Some(p) if p == cand => {
                self.p = Some(p);
                cand.zeroize();
                RsaStep::More
            }
            Some(p) => match RsaPrivateKey::from_p_q(p, cand, self.e.clone()) {
                Ok(k) => RsaStep::Done(Box::new(k)),
                Err(_) => RsaStep::Failed,
            },
        }
    }

    /// [`try_candidate`](RsaKeygen::try_candidate), returning the prime as
    /// little-endian bytes in `out` — the inter-core transport format (the
    /// second core ships raw bytes, not bignums, so the zeroize discipline
    /// stays in this crate). `out` must hold `half_bytes`; the candidate's top
    /// bits are set, so a find is always exactly `half_bytes` long.
    pub fn try_candidate_le(
        sieve: &mut IncrementalSieve,
        rng: &mut dyn Rng,
        half_bytes: usize,
        out: &mut [u8],
    ) -> Option<usize> {
        let mut p = Self::try_candidate(sieve, rng, half_bytes)?;
        let mut v = p.to_bytes_le();
        p.zeroize();
        let n = v.len();
        out[..n].copy_from_slice(&v);
        v.zeroize();
        Some(n)
    }

    /// [`offer`](RsaKeygen::offer) from little-endian bytes (the inter-core
    /// transport format); scrubs `bytes` after the conversion.
    pub fn offer_le(&mut self, bytes: &mut [u8]) -> RsaStep {
        // Belt-and-suspenders: a byte-transport find must be exactly this key's
        // half size — a wrong length is a stale prime from a prior different-size
        // job (mailbox scrubbed on engage, so never fires today); pooling corrupts n.
        if bytes.len() != self.half_bytes {
            bytes.zeroize();
            return RsaStep::More;
        }
        let cand = BigUint::from_bytes_le(bytes);
        bytes.zeroize();
        self.offer(cand)
    }

    /// Draw and test one prime candidate, feeding any find into the pool — the
    /// single-core step: [`try_candidate`](RsaKeygen::try_candidate) then
    /// [`offer`](RsaKeygen::offer). `sieve` is the caller's running window.
    pub fn step(&mut self, sieve: &mut IncrementalSieve, rng: &mut dyn Rng) -> RsaStep {
        if !self.usable() {
            return RsaStep::Failed;
        }
        match Self::try_candidate(sieve, rng, self.half_bytes) {
            None => RsaStep::More,
            Some(cand) => self.offer(cand),
        }
    }
}

/// Blocking RSA keygen — drives [`RsaKeygen`] to completion on one core. Used
/// by the synchronous `keypair_gen` (host tests, the non-CCID path); on the
/// device the firmware races `try_candidate` on both cores instead.
pub fn generate_rsa(rng: &mut dyn Rng, nbits: usize) -> Result<RsaPrivateKey, RsaError> {
    let mut kg = RsaKeygen::new(nbits);
    let mut sieve = IncrementalSieve::new();
    loop {
        match kg.step(&mut sieve, rng) {
            RsaStep::Done(k) => return Ok(*k),
            RsaStep::Failed => return Err(RsaError::Failed),
            RsaStep::More => {}
        }
    }
}

#[cfg(test)]
#[path = "keygen_tests.rs"]
mod tests;
