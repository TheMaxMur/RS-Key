// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The RSA private key — the two primes, the private exponent derived from
//! them, the cached CRT parameters, and the blinded, Bellcore-fault-checked
//! private operation over the pair.
//!
//! This is what the `rsa` crate's `RsaPrivateKey` was here until 0.4.12. That
//! crate carries RUSTSEC-2023-0071 with no fixed release, and its key type was
//! its last foothold: it crossed out of this tier into both card applets,
//! `rsk-device` and `firmware`. [`RsaKey`]'s own surface is bytes — nothing
//! above names a bignum — and the derivations below reproduce the crate's
//! `from_p_q` / `validate` / `precompute` arm for arm, so an IMPORT that used to
//! be refused is still refused, with the same status word.

use alloc::vec::Vec;
use num_bigint_dig::{BigUint, ModInverse};
use num_integer::Integer;
use rsk_secret::Secret;
use zeroize::Zeroize;

use crate::{MAX_RSA_BYTES, Rng, RsaError};

/// Accepted public exponents, `rsa`'s `MIN_PUB_EXPONENT`/`MAX_PUB_EXPONENT`. The
/// ceiling is what makes an exponent's width bounded at all, so it is policy and
/// belongs under a name rather than inline at the one place that enforces it.
const PUB_EXP_RANGE: core::ops::RangeInclusive<u64> = 2..=(1 << 33) - 1;

/// `dP`, `dQ` and `qInv` — what a CRT private operation needs beyond the primes.
/// Optional because `q⁻¹ mod p` does not exist for two "primes" sharing a
/// factor, which only an authenticated IMPORT can offer; the `rsa` crate left
/// exactly this hole (its `from_components` discards `precompute`'s error), and
/// which of the two arms refuses decides the applet's status word.
struct CrtParams {
    dp: BigUint,
    dq: BigUint,
    qinv: BigUint,
}

impl Drop for CrtParams {
    #[expect(clippy::disallowed_methods, reason = "a CrtParams's drop is its wipe")]
    fn drop(&mut self) {
        self.dp.zeroize();
        self.dq.zeroize();
        self.qinv.zeroize();
    }
}

/// An RSA private key: modulus `n = p·q`, public exponent `e`, private exponent
/// `d`, and the CRT parameters cached alongside the primes. The secret fields
/// are zeroized on drop — num-bigint has no scrubbing `Drop` of its own, so the
/// limbs would otherwise be freed intact; `n` and `e` are public values.
pub struct RsaKey {
    n: BigUint,
    e: BigUint,
    d: BigUint,
    p: BigUint,
    q: BigUint,
    crt: Option<CrtParams>,
}

impl Drop for RsaKey {
    #[expect(clippy::disallowed_methods, reason = "a RsaKey's drop is its wipe")]
    fn drop(&mut self) {
        self.d.zeroize();
        self.p.zeroize();
        self.q.zeroize();
    }
}

impl RsaKey {
    /// Assemble a key from its two primes and public exponent: `n = p·q`,
    /// `d = e⁻¹ mod lcm(p−1, q−1)` (NIST SP 800-56B §6.2.1 — FIPS 186-4 wants
    /// `d < λ(n)`, which Euler's totient does not give), then the CRT
    /// parameters. `None` for any triple that is not a usable key.
    pub(crate) fn from_p_q(p: BigUint, q: BigUint, e: BigUint) -> Option<Self> {
        let one = BigUint::from(1u8);
        // Every derivation below subtracts one from a prime, and num-bigint's
        // unsigned subtraction underflows into a panic rather than an error.
        if p <= one || q <= one || p == q {
            return None;
        }
        let n = &p * &q;
        let p1 = Secret::new(&p - &one);
        let q1 = Secret::new(&q - &one);
        let lam = Secret::new(p1.expose().lcm(q1.expose()));
        // num-bigint's `mod_inverse` hands back a signed intermediate with no
        // scrubbing `Drop` of its own, and this one is `d`.
        let d = Secret::new((&e).mod_inverse(lam.expose())?)
            .expose()
            .to_biguint()?;
        // The `rsa` crate's `check_public` and `validate`, both of which every
        // key it built had passed: an exponent in range, odd and below an odd
        // modulus, and `d·e ≡ 1` modulo each prime less one.
        if e < BigUint::from(*PUB_EXP_RANGE.start()) || e > BigUint::from(*PUB_EXP_RANGE.end()) {
            return None;
        }
        if e >= n || n.is_even() || e.is_even() {
            return None;
        }
        let de = Secret::new(&d * &e);
        if de.expose() % p1.expose() != one || de.expose() % q1.expose() != one {
            return None;
        }
        let crt = (&q)
            .mod_inverse(&p)
            .map(Secret::new)
            .and_then(|i| i.expose().to_biguint())
            .map(|qinv| CrtParams {
                dp: &d % p1.expose(),
                dq: &d % q1.expose(),
                qinv,
            });
        Some(RsaKey { n, e, d, p, q, crt })
    }

    /// Modulus width in bytes — the width of a signature, a DECIPHER cryptogram
    /// and a GENERAL AUTHENTICATE challenge alike.
    pub fn size(&self) -> usize {
        self.n.bits().div_ceil(8)
    }

    /// The public modulus, big-endian, minimal width (no leading zero byte).
    pub fn n_be(&self) -> Vec<u8> {
        self.n.to_bytes_be()
    }

    /// The public exponent, big-endian, minimal width. Sourced from the key
    /// rather than assumed: an imported OpenPGP key may carry a non-65537 one.
    pub fn e_be(&self) -> Vec<u8> {
        self.e.to_bytes_be()
    }

    pub(crate) fn p(&self) -> &BigUint {
        &self.p
    }

    pub(crate) fn q(&self) -> &BigUint {
        &self.q
    }

    /// `(dP, dQ, qInv)`, or `None` for a key whose primes admit no CRT form.
    pub(crate) fn crt(&self) -> Option<(&BigUint, &BigUint, &BigUint)> {
        self.crt.as_ref().map(|c| (&c.dp, &c.dq, &c.qinv))
    }

    /// The private-key operation `m = cᵈ mod n` over the big-endian block `c`,
    /// base-blinded `(c·rᵉ)ᵈ·r⁻¹ mod n` with a fresh random `r` so the
    /// variable-time exponentiation cannot become a Marvin-style timing oracle,
    /// then Bellcore fault-checked (`mᵉ ≡ c mod n`). Writes `size()` big-endian
    /// bytes to `out`. The asm CRT core is the fast path for a key of a width it
    /// can take ([`crate::crt::private_op`]); this is the software one every
    /// other key still needs.
    pub(crate) fn private_op(
        &self,
        c: &[u8],
        rng: &mut dyn Rng,
        out: &mut [u8],
    ) -> Result<usize, RsaError> {
        let k = self.size();
        if k > MAX_RSA_BYTES || out.len() < k {
            return Err(RsaError::BadWidth);
        }
        let c = BigUint::from_bytes_be(c);
        if c >= self.n {
            return Err(RsaError::BadBlock);
        }
        let (r, r_inv) = blind_pair(&self.n, k, rng);
        let re = Secret::new(r.expose().modpow(&self.e, &self.n));
        let cre = Secret::new(&c * re.expose());
        let blinded = Secret::new(cre.expose() % &self.n);
        let m = match &self.crt {
            Some(crt) => {
                let m1 = Secret::new(blinded.expose().modpow(&crt.dp, &self.p));
                let m2 = Secret::new(blinded.expose().modpow(&crt.dq, &self.q));
                // Garner, unsigned where the `rsa` crate was signed: `m1 < p` and
                // `m2 % p < p`, so `m1 + p - m2 % p` cannot underflow for any `p`, `q`.
                // Each step is a CRT half or follows from one, so each is a `Secret`.
                let m2p = Secret::new(m2.expose() % &self.p);
                let sum = Secret::new(m1.expose() + &self.p);
                let dif = Secret::new(sum.expose() - m2p.expose());
                let diff = Secret::new(dif.expose() % &self.p);
                let hq = Secret::new(&crt.qinv * diff.expose());
                let h = Secret::new(hq.expose() % &self.p);
                let hqq = Secret::new(h.expose() * &self.q);
                Secret::new(m2.expose() + hqq.expose())
            }
            None => Secret::new(blinded.expose().modpow(&self.d, &self.n)),
        };
        let prod = Secret::new(m.expose() * r_inv.expose());
        let m = Secret::new(prod.expose() % &self.n);
        if m.expose().modpow(&self.e, &self.n) != c {
            return Err(RsaError::Failed);
        }
        let mb = Secret::new(m.expose().to_bytes_be());
        if mb.expose().len() > k {
            return Err(RsaError::Failed);
        }
        let off = k - mb.expose().len();
        out[..off].fill(0);
        out[off..k].copy_from_slice(mb.expose());
        Ok(k)
    }
}

/// `BigUint::from_bytes_be` for a secret: that one reverses its input in a `Vec`
/// it frees unwiped. This reverses it in a `Secret` and reads it little-endian,
/// which copies nothing more.
pub(crate) fn from_secret_be(be: &[u8]) -> BigUint {
    let mut le = Secret::new(be.to_vec());
    le.expose_mut().reverse();
    BigUint::from_bytes_le(le.expose())
}

/// A fresh blinding pair `(r, r⁻¹ mod n)`, `width` random bytes drawn per
/// attempt. A candidate with no inverse shares a factor with `n` — so it is a
/// multiple of a prime factor — and is wiped rather than freed intact.
pub(crate) fn blind_pair(
    n: &BigUint,
    width: usize,
    rng: &mut dyn Rng,
) -> (Secret<BigUint>, Secret<BigUint>) {
    loop {
        let mut rb = Secret::<[u8; MAX_RSA_BYTES]>::zeroed();
        rng.fill(&mut rb.expose_mut()[..width]);
        let raw = Secret::new(from_secret_be(&rb.expose()[..width]));
        let mut cand = Secret::new(raw.expose() % n);
        rb.wipe();
        match cand
            .expose()
            .mod_inverse(n)
            .map(Secret::new)
            .and_then(|i| i.expose().to_biguint())
        {
            Some(inv) => return (cand, Secret::new(inv)),
            None => cand.wipe(),
        }
    }
}

/// The public modulus `N = p·q` from the two primes alone, big-endian into
/// `out`. PIV GET METADATA needs only `N` and the fixed exponent, so this skips
/// the key assembly — `dP`/`dQ`/`qInv` are two modular inversions, ~50 ms on
/// RSA-4096 — and is byte-identical to `rsa_from_pqe(..)?.n_be()`.
pub fn modulus_be(p: &[u8], q: &[u8], out: &mut [u8]) -> Result<usize, RsaError> {
    let p = Secret::new(from_secret_be(p));
    let q = Secret::new(from_secret_be(q));
    let nb = (p.expose() * q.expose()).to_bytes_be();
    if nb.len() > out.len() {
        return Err(RsaError::BadWidth);
    }
    out[..nb.len()].copy_from_slice(&nb);
    Ok(nb.len())
}

#[cfg(test)]
#[path = "key_tests.rs"]
mod tests;
