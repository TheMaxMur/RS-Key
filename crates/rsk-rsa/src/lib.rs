// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg_attr(not(test), no_std)]
// On-device arithmetic runs from SRAM while both cores search for primes.
#![cfg_attr(
    target_os = "none",
    expect(
        unsafe_code,
        reason = "the .data placement of the RSA kernels; docs/unsafe.md"
    )
)]

//! The RSA algorithm family: key generation, the CRT parameter layout and its
//! blinded private operation, PKCS#1 v1.5, and the public-key DO both card
//! applets answer with. Both host and device use the same fixed-width
//! Montgomery arithmetic. All multi-byte values in this file are **little-endian**
//! except the modexp exponent (big-endian).
//!
//! Nothing here names a status word or a filesystem: `rsk-openpgp` and `rsk-piv`
//! own the APDU framing and the seal I/O, and map [`RsaError`] at their edge.

extern crate alloc;

use privexp::modexp_priv;
use rsk_secret::Secret;

pub mod crt;
pub mod keygen;
pub mod pkcs1v15;
pub mod pubdo;

mod blind_inverse;
mod error;
mod key;
mod lucas;
mod montgomery;
mod privexp;
mod pubexp;
mod rng;

/// Known-answer vectors and the public-key verifier the host tests check this
/// crate against. Dev-only — `rsk-openpgp` and `rsk-piv` turn `test-util` on
/// from their `[dev-dependencies]`, so none of it reaches the firmware image.
#[cfg(any(test, feature = "test-util"))]
pub mod vectors;
#[cfg(any(test, feature = "test-util"))]
pub mod verify;

pub use crt::{MAX_CRT_PLAIN, RsaCrt};
pub use error::RsaError;
pub use key::{RsaKey, modulus_be};
pub use keygen::{RsaKeygen, RsaStep, generate_rsa, rsa_from_pqe};
pub use pubdo::{MAX_RSA_PUBDO, make_rsa_pub_body, make_rsa_response};
pub use rng::Rng;

const RSA_2048_BYTES: usize = 256;

/// Largest modulus this handles: an RSA-4096 prime is 2048 bits = 256 bytes. The
/// routines retain a 32-byte width requirement — every standard
/// RSA prime size (512/1024/1536/2048-bit) qualifies.
pub const MAX_MOD: usize = 256;

/// Largest RSA modulus in bytes (RSA-4096 = 512) — a signature, a challenge and
/// a DECIPHER cryptogram are all exactly this wide. Two primes, by definition, so
/// it is derived from [`MAX_MOD`] rather than written out again.
pub const MAX_RSA_BYTES: usize = 2 * MAX_MOD;

/// The RSA public exponent, fixed at 65537 for every key this generates and every
/// key the CRT signer / DECIPHER assume.
pub const RSA_E: u32 = 65_537;

/// [`RSA_E`] big-endian, so a caller that already has the modulus (PIV GET
/// METADATA) can build the public-key DO without a `BigUint` or a magic literal.
/// `rsa_pub_exp_be_is_65537` pins the two spellings together.
pub const RSA_PUB_EXP_BE: &[u8] = &[0x01, 0x00, 0x01];

// ----------------------------------------------------------- small primes ----

const N_SMALL: usize = 1280;

/// The first [`N_SMALL`] odd primes (3, 5, 7, …), computed at compile time. Trial
/// division by these rejects the vast majority of composite candidates cheaply,
/// before the (relatively) expensive strong-MR modexp. How many of them a given
/// candidate is actually divided by is [`sieve_count`] of its length — the
/// larger the prime, the dearer that modexp, so the deeper it pays to sieve.
///
/// In SRAM on the device — see [`IncrementalSieve::step`] for why. `.data` costs
/// the RAM but not the flash (the image still carries the initializer).
#[cfg_attr(target_os = "none", unsafe(link_section = ".data.small_primes"))]
static SMALL_PRIMES: [u32; N_SMALL] = build_small_primes();

/// How many small primes to trial-divide a candidate of `cand_len` bytes by.
///
/// Each division that rejects a composite saves one strong-MR modexp, and the
/// modexp cost grows far faster with key size than a trial division does:
/// measured on the RP2350 (the `keygen-bench` vendor command), one strong MR
/// is ~35 ms at a 1024-bit prime and ~239 ms at 2048-bit, while one trial
/// division is ~11 µs and ~23 µs. The break-even prime bound (sieve while
/// `p < c_modexp / c_div`) is therefore ~3.1k and ~10.5k respectively — far
/// past the flat 256-prime (≤1619) sieve we used to run. The optimum scales
/// ~quadratically with prime length (modexp ~k³, division ~k), so step the
/// count by candidate size:
const fn sieve_count(cand_len: usize) -> usize {
    match cand_len {
        0..=64 => 256,    // ≤ RSA-1024 half (rare; fips blocks 1024 gen anyway)
        65..=128 => 448,  // RSA-2048 half (1024-bit) → primes ≲ 3.1k
        129..=192 => 832, // RSA-3072 half (1536-bit)
        _ => N_SMALL,     // RSA-4096 half (2048-bit) → primes ≲ 10.5k
    }
}

const fn build_small_primes() -> [u32; N_SMALL] {
    let mut primes = [0u32; N_SMALL];
    let mut count = 0;
    let mut cand = 3u32;
    while count < N_SMALL {
        let mut is_prime = true;
        let mut d = 3u32;
        while d * d <= cand {
            if cand.is_multiple_of(d) {
                is_prime = false;
                break;
            }
            d += 2;
        }
        if is_prime {
            primes[count] = cand;
            count += 1;
        }
        cand += 2;
    }
    // Every residue plus one sieve stride must fit before reduction.
    assert!(primes[N_SMALL - 1] <= u16::MAX as u32 - 2);
    primes
}

/// `n mod m`, with `n` little-endian — Horner's method over the bytes from the
/// most significant down. `m` must be non-zero and `< 2^23` (so the intermediate
/// `(r << 8) | b` stays within `u32`, keeping this on the M33's hardware 32-bit
/// divide rather than the much slower 64-bit software path).
pub fn mod_small(n_le: &[u8], m: u32) -> u32 {
    debug_assert!(m != 0 && m < (1 << 23));
    let mut r: u32 = 0;
    for &b in n_le.iter().rev() {
        r = ((r << 8) | b as u32) % m;
    }
    r
}

/// Does `n` (little-endian) have a small prime factor among the first
/// `sieve_count` primes for its length? Trial division only ever *rejects*,
/// so it can never misclassify a composite as prime — at worst a too-shallow
/// sieve just lets more composites through to the (vetted) strong-MR test.
pub fn has_small_factor(n_le: &[u8]) -> bool {
    SMALL_PRIMES[..sieve_count(n_le.len())]
        .iter()
        .any(|&p| mod_small(n_le, p) == 0)
}

// ------------------------------------------------------ incremental sieve -----

/// Force a fresh window after this many steps even if no overflow — a cap, not
/// a correctness bound (the residues never drift). Keeps the candidate stream
/// from wandering arbitrarily far from a fresh random draw.
const SIEVE_WINDOW: u32 = 1 << 14;

/// A running small-prime sieve over consecutive candidates `n, n+2, n+4, …`.
///
/// The flat [`has_small_factor`] re-derives every residue `n mod pᵢ` from
/// scratch (a Horner pass per prime) on every candidate. But consecutive odd
/// candidates differ by 2, so each residue just steps `r ← (r + 2) mod pᵢ` —
/// one add and a compare, no division, no Horner. One full `mod_small` set is
/// paid once when a window is (re)seeded, then amortized over thousands of
/// near-free steps. The compositeness verdict is identical to
/// [`has_small_factor`] (proved by the `incremental_matches_flat` test); only
/// the candidate *stream* changes from independent draws to "scan up from a
/// random odd start", which is exactly how OpenSSL/GMP generate RSA primes.
/// The primality decision (strong MR + Lucas) is untouched, so this cannot
/// affect key strength — only search speed.
pub struct IncrementalSieve {
    half: usize,
    cnt: usize,
    // `MAX_MOD` is already a single prime's width (an RSA-4096 prime = 256 B).
    cand: [u8; MAX_MOD],
    res: [u16; N_SMALL],
    steps: u32,
    seeded: bool,
}

impl Default for IncrementalSieve {
    fn default() -> Self {
        Self::new()
    }
}

impl IncrementalSieve {
    /// An unseeded sieve; `const` so it can initialize a `static`.
    pub const fn new() -> Self {
        Self {
            half: 0,
            cnt: 0,
            cand: [0; MAX_MOD],
            res: [0; N_SMALL],
            steps: 0,
            seeded: false,
        }
    }

    /// True until the first [`reseed`](Self::reseed), and again once a window is
    /// exhausted — the caller must reseed before the next [`step`](Self::step).
    pub fn needs_seed(&self) -> bool {
        !self.seeded
    }

    /// Begin a fresh window from `seed_le` (caller-supplied random bytes, length
    /// `half`): apply the odd + top-two-bits mask (so the product of two such
    /// primes keeps `2·half·8` bits) and compute every residue once.
    pub fn reseed(&mut self, half: usize, seed_le: &[u8]) {
        debug_assert!((2..=MAX_MOD).contains(&half));
        self.half = half;
        self.cnt = sieve_count(half);
        self.cand[..half].copy_from_slice(&seed_le[..half]);
        self.cand[half - 1] |= 0xC0;
        self.cand[0] |= 0x01;
        for (r, &p) in self.res[..self.cnt]
            .iter_mut()
            .zip(&SMALL_PRIMES[..self.cnt])
        {
            *r = mod_small(&self.cand[..half], p) as u16;
        }
        self.steps = 0;
        self.seeded = true;
    }

    /// Advance to the next candidate (`n += 2`) and update every residue.
    /// `Some(true)` — passes the small-prime sieve (no factor); `Some(false)` —
    /// composite; `None` — the window ended (top bits would overflow, or the
    /// step cap was hit): reseed before stepping again.
    ///
    /// **Code and table both live in SRAM on the device.** This runs for every
    /// candidate the search draws — hundreds to thousands per prime — and walks
    /// `sieve_count` table entries each time (1.8 KB at RSA-2048, 5 KB at
    /// RSA-4096). Left in XIP flash the loop and its table compete with each
    /// other and with whatever else the image put nearby for the small XIP
    /// cache, which makes keygen time a function of unrelated commits: v0.4.5
    /// and 0x0864 differ by 1.36× on RSA-2048 (medians 9.7 s vs 13.2 s, three
    /// and four batches of 12, no overlap) with this search byte-identical
    /// between them. The modexp was moved to SRAM for the same reason; the
    /// sieve was the half left behind.
    #[cfg_attr(target_os = "none", unsafe(link_section = ".data.sieve_step"))]
    #[inline(never)]
    pub fn step(&mut self) -> Option<bool> {
        if !self.seeded {
            return None;
        }
        // n += 2, little-endian carry.
        let mut carry = 2u16;
        let mut i = 0;
        while carry != 0 && i < self.half {
            let s = self.cand[i] as u16 + carry;
            self.cand[i] = s as u8;
            carry = s >> 8;
            i += 1;
        }
        self.steps += 1;
        // The top two bits must stay set (else the modulus could be short) and
        // the window is capped; either way, end the window.
        if self.cand[self.half - 1] & 0xC0 != 0xC0 || self.steps >= SIEVE_WINDOW {
            self.seeded = false;
            return None;
        }
        // Every residue steps by 2; one conditional subtract keeps it in range.
        // All are updated even after a zero is seen, so the next step stays
        // correct.
        let mut composite = false;
        for (r, &p) in self.res[..self.cnt]
            .iter_mut()
            .zip(&SMALL_PRIMES[..self.cnt])
        {
            let p = p as u16;
            *r += 2;
            if *r >= p {
                *r -= p;
            }
            composite |= *r == 0;
        }
        Some(!composite)
    }

    /// The current candidate (little-endian, `half` bytes).
    pub fn candidate(&self) -> &[u8] {
        &self.cand[..self.half]
    }

    /// Wipe the candidate window (a found prime may still sit in it).
    #[expect(
        clippy::disallowed_methods,
        reason = "the sieve lives in a static: `scrub` is its wipe point"
    )]
    pub fn scrub(&mut self) {
        use zeroize::Zeroize;
        let Self {
            half: _,
            cnt: _,
            cand,
            res,
            steps: _,
            seeded,
        } = self;
        cand.zeroize();
        res.zeroize();
        *seeded = false;
    }
}

// -------------------------------------------------------- modexp backend -----

fn bytes_to_words_le(src: &[u8], dst: &mut [u32]) {
    for (i, w) in dst.iter_mut().enumerate() {
        let b = i * 4;
        *w = u32::from_le_bytes([src[b], src[b + 1], src[b + 2], src[b + 3]]);
    }
}

fn words_to_bytes_le(src: &[u32], dst: &mut [u8]) {
    for (i, w) in src.iter().enumerate() {
        dst[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
}

/// The i-th least-significant 32-bit limb of a big-endian value: fill `dst`
/// (length = `be.len() / 4`) with `be` re-read as little-endian u32 words.
fn be_bytes_to_words_le(be: &[u8], dst: &mut [u32]) {
    for (i, w) in dst.iter_mut().enumerate() {
        let hi = be.len() - 4 * i;
        *w = u32::from_be_bytes([be[hi - 4], be[hi - 3], be[hi - 2], be[hi - 1]]);
    }
}

/// Fermat primality pre-filter to base 2: `2^(n-1) mod n == 1`. `n` is the
/// little-endian candidate, which must be **odd** and a multiple of 32 bytes. A
/// composite almost always fails (only rare Fermat pseudoprimes slip through, to
/// be caught by the vetted final primality test), and a prime always passes — so
/// this never rejects a real prime.
pub fn passes_fermat_base2(n_le: &[u8]) -> bool {
    #[cfg(test)]
    if let Some(verdict) = tests::inject_primality_fault(tests::PrimalityGate::Fermat, n_le) {
        return verdict;
    }
    let mod_len = n_le.len();
    // exponent = n − 1 in big-endian. n is odd, so n − 1 just clears bit 0.
    let mut exp_be = Secret::<[u8; MAX_MOD]>::zeroed();
    let exp = exp_be.expose_mut();
    for i in 0..mod_len {
        exp[mod_len - 1 - i] = n_le[i];
    }
    exp[mod_len - 1] &= 0xFE;

    let mut out = Secret::<[u8; MAX_MOD]>::zeroed();
    if !modexp_priv(
        &[2u8],
        &exp_be.expose()[..mod_len],
        n_le,
        &mut out.expose_mut()[..mod_len],
    ) {
        return false;
    }
    let prime = out.expose()[0] == 1 && out.expose()[1..mod_len].iter().all(|&b| b == 0);
    // `exp_be` is candidate − 1; for the accepted candidate that is p − 1.
    exp_be.wipe();
    out.wipe();
    prime
}

// ------------------------------------------------------- strong Miller-Rabin --

/// Trailing zero bits of a non-zero little-endian value.
fn trailing_zeros_le(v: &[u8]) -> usize {
    for (i, &b) in v.iter().enumerate() {
        if b != 0 {
            return i * 8 + b.trailing_zeros() as usize;
        }
    }
    v.len() * 8
}

/// `out_be = v_le >> s`, emitted big-endian (the modexp exponent format);
/// `out_be.len() == v_le.len()`, high bytes zero-padded.
fn shr_into_be(v_le: &[u8], s: usize, out_be: &mut [u8]) {
    let len = v_le.len();
    let (bytes, bits) = (s / 8, (s % 8) as u32);
    for i in 0..len {
        let lo = v_le.get(i + bytes).copied().unwrap_or(0) as u16;
        let hi = v_le.get(i + bytes + 1).copied().unwrap_or(0) as u16;
        let b = if bits == 0 {
            lo
        } else {
            (lo >> bits) | (hi << (8 - bits))
        };
        out_be[len - 1 - i] = b as u8;
    }
}

/// Little-endian value == 1.
fn is_one_le(v: &[u8]) -> bool {
    v[0] == 1 && v[1..].iter().all(|&b| b == 0)
}

/// Strong Miller-Rabin probable-prime test to base 2 — the Miller-Rabin half
/// of Baillie-PSW — on the SRAM-resident modexp. `n_le` is the odd
/// little-endian candidate, length a multiple of 32 bytes, like
/// [`passes_fermat_base2`] but strictly stronger: write n − 1 = d·2^s (d odd);
/// n passes iff 2^d ≡ ±1 (mod n) or one of the s − 1 successive squarings
/// hits n − 1. A chain that reaches 1 any other way has exhibited a
/// nontrivial square root of 1, i.e. a factor. Mirrors num-bigint-dig's
/// `probably_prime_miller_rabin(n, 1, force2 = true)` exactly — the host
/// tests hold the two implementations equal over random candidates and the
/// canonical pseudoprime families.
pub fn passes_strong_mr_base2(n_le: &[u8]) -> bool {
    #[cfg(test)]
    if let Some(verdict) = tests::inject_primality_fault(tests::PrimalityGate::StrongMr, n_le) {
        return verdict;
    }
    let len = n_le.len();
    debug_assert!(len >= 2 && n_le[0] & 1 == 1);

    // n − 1: n is odd, so clearing bit 0 is the whole subtraction.
    let mut nm1 = Secret::<[u8; MAX_MOD]>::zeroed();
    nm1.expose_mut()[..len].copy_from_slice(n_le);
    nm1.expose_mut()[0] &= 0xFE;

    // n − 1 = d · 2^s, d odd; the exponent rides big-endian.
    let s = trailing_zeros_le(&nm1.expose()[..len]);
    let mut d_be = Secret::<[u8; MAX_MOD]>::zeroed();
    shr_into_be(&nm1.expose()[..len], s, &mut d_be.expose_mut()[..len]);

    let mut x = Secret::<[u8; MAX_MOD]>::zeroed();
    if !modexp_priv(
        &[2u8],
        &d_be.expose()[..len],
        n_le,
        &mut x.expose_mut()[..len],
    ) {
        return false;
    }

    let mut verdict = is_one_le(&x.expose()[..len]) || x.expose()[..len] == nm1.expose()[..len];
    if !verdict {
        for _ in 1..s {
            // One modular squaring: exponent 2 costs ~two multiplications.
            let mut sq = Secret::<[u8; MAX_MOD]>::zeroed();
            if !modexp_priv(
                &x.expose()[..len],
                &[2u8],
                n_le,
                &mut sq.expose_mut()[..len],
            ) {
                return false;
            }
            x.expose_mut()[..len].copy_from_slice(&sq.expose()[..len]);
            sq.wipe();
            if x.expose()[..len] == nm1.expose()[..len] {
                verdict = true;
                break;
            }
            if is_one_le(&x.expose()[..len]) {
                break; // nontrivial √1 — certainly composite
            }
        }
    }
    // For the accepted candidate these hold p − 1 and its power residues.
    nm1.wipe();
    d_be.wipe();
    x.wipe();
    verdict
}

// ------------------------------------------------------------- self-test -----

/// A 256-bit prime and a 256-bit odd composite (little-endian), for an on-device
/// correctness check of the modexp/Fermat path.
const KAT_PRIME_LE: [u8; 32] = [
    0x73, 0x7b, 0xb1, 0xa3, 0x7f, 0x31, 0x80, 0x1c, 0xd1, 0x1a, 0x67, 0x06, 0xfb, 0x40, 0xd6, 0xbd,
    0x57, 0x52, 0x68, 0x46, 0x90, 0x3b, 0xb1, 0x3e, 0xde, 0x56, 0x24, 0x39, 0xf4, 0x60, 0xdc, 0x91,
];
const KAT_COMPOSITE_LE: [u8; 32] = [
    0xb9, 0x22, 0x68, 0x48, 0x3a, 0x7a, 0xde, 0xb9, 0xff, 0x27, 0x6e, 0x4c, 0x64, 0xd2, 0x64, 0xd6,
    0xed, 0x8c, 0x41, 0x96, 0xc9, 0xdb, 0x75, 0x94, 0x2d, 0x10, 0xb8, 0xff, 0x48, 0xf0, 0x78, 0xd4,
];

/// Known-answer test of the modexp path: a known prime must pass and a known
/// composite must fail BOTH the base-2 Fermat test and the strong Miller-Rabin
/// gate the keygen uses. Catches a wrong modexp result before it can weaken
/// the primality decision.
pub fn self_test() -> bool {
    passes_fermat_base2(&KAT_PRIME_LE)
        && !passes_fermat_base2(&KAT_COMPOSITE_LE)
        && passes_strong_mr_base2(&KAT_PRIME_LE)
        && !passes_strong_mr_base2(&KAT_COMPOSITE_LE)
}

/// Kani proof harnesses (`cargo kani -p rsk-rsa`): exhaustive over every
/// input up to the stated bound, where `incremental_matches_flat` below only
/// samples random seeds.
#[cfg(kani)]
#[path = "kani.rs"]
mod proofs;

#[cfg(test)]
mod fixtures;

#[cfg(test)]
mod tests;

/// Wycheproof's RSA cases, dev-only like [`vectors`].
#[cfg(any(test, feature = "test-util"))]
pub mod wycheproof;
