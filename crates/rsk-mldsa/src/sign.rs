// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Key generation, signing and verification (FIPS 204 §6/7, Alg 6/7/8),
//! restructured for a small stack: the matrix Â is streamed via
//! [`matrix_mul_streaming`] (never materialized), every NTT runs in place, and
//! the rejection loop reuses its k-/l-sized scratch across iterations.
//!
//! The message representative follows the pure (non-prehash) profile,
//! `mu = H(tr || 0x00 || |ctx| || ctx || M)` — the FIPS 204 hedged pure-signing
//! profile (`ExternalMu=false`). The firmware always passes an empty `ctx`
//! (the COSE/WebAuthn profile); a non-empty `ctx` exists for the ACVP KATs.

use sha3::digest::XofReader;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::encode::{pk_decode, pk_encode, sig_decode, sig_encode, w1_encode};
use crate::ntt::{inv_ntt_inplace, ntt_inplace};
use crate::params::{D, Params, Q, SEED_LEN};
use crate::poly::{Poly, pointwise_mont, zero_vec};
use crate::reduce::{center_mod, full_reduce32, mont_reduce, partial_reduce32, to_mont};
use crate::round::{high_bits, low_bits, make_hint, power2round, use_hint};
use crate::sample::{expand_mask, expand_s, matrix_mul_streaming, sample_in_ball, shake256};

/// The largest `pk_len` across the supported parameter sets (ML-DSA-87 = 2592),
/// used for the transient pk buffer that feeds `tr = H(pk)` during keygen.
const MAX_PK_LEN: usize = 2592;
/// The largest `w1_len` (ML-DSA-87 = 32·8·4) and `lambda_div4` (ML-DSA-87 = 64).
/// These are fixed-size buffers, so widening them for -87 costs every set the
/// same ~900 B — the alternative is const-generic buffers, which the callers
/// cannot size without threading `Params` into the type system.
const MAX_W1_LEN: usize = 1024;
const MAX_LAMBDA_DIV4: usize = 64;

/// An expanded ML-DSA key: the NTT/Montgomery precomputes needed to sign, plus
/// `t1` to re-emit the public key. Derived from the 32-byte seed and held for
/// one request (the firmware boxes it off-stack). Zeroizes on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ExpandedKey<const K: usize, const L: usize> {
    rho: [u8; 32],
    cap_k: [u8; 32],
    tr: [u8; 64],
    t1: [Poly; K],
    s1_hat_mont: [Poly; L],
    s2_hat_mont: [Poly; K],
    t0_hat_mont: [Poly; K],
}

/// NTT each element of a vector (out of place — the inputs are needed later).
fn ntt_vec<const M: usize>(v: &[Poly; M]) -> [Poly; M] {
    core::array::from_fn(|i| {
        let mut p = v[i].clone();
        ntt_inplace(&mut p);
        p
    })
}

/// Lift each element of a vector into the Montgomery domain.
fn to_mont_vec<const M: usize>(v: &[Poly; M]) -> [Poly; M] {
    core::array::from_fn(|i| to_mont(&v[i]))
}

/// The ∞-norm (max centered magnitude) over a vector of polynomials.
fn infinity_norm<const M: usize>(v: &[Poly; M]) -> i32 {
    v.iter()
        .flat_map(|p| p.0)
        .map(|e| center_mod(e).abs())
        .max()
        .unwrap_or(0)
}

/// Total number of 1s in the hint vector.
fn hint_weight<const K: usize>(h: &[Poly; K]) -> i32 {
    h.iter().map(|p| p.0.iter().sum::<i32>()).sum()
}

/// Reduce every coefficient of a matrix-vector product into (−q, q) before the
/// inverse NTT — the reference's `polyveck_reduce` (FIPS 204 §7.5). Â∘NTT sums L
/// Montgomery products, so a raw lane reaches ~L·q; the inv-NTT's sum lane then
/// grows past i32 unless the input is first brought below q. Byte-exact: invNTT
/// is linear mod q and the tail reduces to [0, q).
fn reduce_vec<const M: usize>(v: &mut [Poly; M]) {
    for p in v {
        for c in &mut p.0 {
            *c = partial_reduce32(*c);
        }
    }
}

impl<const K: usize, const L: usize> ExpandedKey<K, L> {
    /// Deterministically expand the keypair from the 32-byte seed ξ (Alg 6).
    pub fn from_seed(p: &Params, xi: &[u8; SEED_LEN]) -> Self {
        debug_assert!(K == p.k && L == p.l, "params/dimension mismatch");

        // (ρ, ρ′, K) ← H(ξ || IntegerToBytes(k,1) || IntegerToBytes(l,1))
        let mut h = shake256(&[xi, &[K as u8], &[L as u8]]);
        let mut rho = [0u8; 32];
        let mut rho_prime = [0u8; 64];
        let mut cap_k = [0u8; 32];
        h.read(&mut rho);
        h.read(&mut rho_prime);
        h.read(&mut cap_k);

        // (s1, s2) ← ExpandS(ρ′); t ← invNTT(Â ∘ NTT(s1)) + s2
        let (s1, s2) = expand_s::<K, L>(p.eta, &rho_prime);
        rho_prime.zeroize(); // ExpandS seed → whole SK; not held past this point
        let s1_hat = ntt_vec(&s1);
        let mut t = matrix_mul_streaming::<K, L>(&rho, &s1_hat);
        reduce_vec(&mut t);
        for k in 0..K {
            inv_ntt_inplace(&mut t[k]);
            for n in 0..256 {
                t[k].0[n] = full_reduce32(t[k].0[n] + s2[k].0[n]);
            }
        }

        // (t1, t0) ← Power2Round(t)
        let mut t1: [Poly; K] = zero_vec();
        let mut t0: [Poly; K] = zero_vec();
        for k in 0..K {
            let (hi, lo) = power2round(&t[k]);
            t1[k] = hi;
            t0[k] = lo;
        }

        // tr ← H(pkEncode(ρ, t1))
        let pk_len = 32 + 32 * K * 10;
        let mut pk = [0u8; MAX_PK_LEN];
        pk_encode::<K>(&rho, &t1, &mut pk[..pk_len]);
        let mut tr = [0u8; 64];
        shake256(&[&pk[..pk_len]]).read(&mut tr);

        // Montgomery-domain NTT precomputes for signing.
        let s1_hat_mont = to_mont_vec(&s1_hat);
        let s2_hat_mont = to_mont_vec(&ntt_vec(&s2));
        let t0_hat_mont = to_mont_vec(&ntt_vec(&t0));

        ExpandedKey {
            rho,
            cap_k,
            tr,
            t1,
            s1_hat_mont,
            s2_hat_mont,
            t0_hat_mont,
        }
    }

    /// Reconstruct an expanded key from encoded `sk` bytes (Alg 25 + the sign
    /// precomputes). Test-only — drives the ACVP sigGen KAT; the firmware only
    /// ever expands from the seed. `t1` is left zero (unused for signing).
    #[cfg(test)]
    pub(crate) fn from_sk_bytes(p: &Params, sk: &[u8]) -> Self {
        let (rho, cap_k, tr, s1, s2, t0) = crate::encode::sk_decode::<K, L>(p.eta, sk);
        let s1_hat_mont = to_mont_vec(&ntt_vec(&s1));
        let s2_hat_mont = to_mont_vec(&ntt_vec(&s2));
        let t0_hat_mont = to_mont_vec(&ntt_vec(&t0));
        ExpandedKey {
            rho,
            cap_k,
            tr,
            t1: zero_vec(),
            s1_hat_mont,
            s2_hat_mont,
            t0_hat_mont,
        }
    }

    /// A byte derived from the key, so the stack probe's keygen phase is not
    /// optimized away. Test-only.
    #[cfg(test)]
    pub(crate) fn probe_byte(&self) -> u8 {
        self.tr[0]
    }

    /// Serialize the public key (Alg 22) into `out` (`out.len() == p.pk_len`).
    pub fn write_public_key(&self, p: &Params, out: &mut [u8]) {
        debug_assert_eq!(out.len(), p.pk_len);
        pk_encode::<K>(&self.rho, &self.t1, out);
    }

    /// Sign `msg` under context `ctx` with hedge randomness `rnd` (Alg 7),
    /// writing the signature into `out` (`out.len() == p.sig_len`).
    pub fn sign(&self, p: &Params, msg: &[u8], ctx: &[u8], rnd: &[u8; 32], out: &mut [u8]) {
        debug_assert_eq!(out.len(), p.sig_len);
        debug_assert!(ctx.len() <= 255);

        // µ ← H(tr || 0x00 || |ctx| || ctx || M)
        let mut mu = [0u8; 64];
        shake256(&[&self.tr, &[0u8], &[ctx.len() as u8], ctx, msg]).read(&mut mu);

        // ρ′′ ← H(K || rnd || µ). ExpandMask seed → wiped on every exit path
        // (Zeroizing) since it lives across the rejection loop's mid-body return.
        let mut rho_pp = Zeroizing::new([0u8; 64]);
        shake256(&[&self.cap_k, rnd, &mu]).read(&mut rho_pp[..]);

        let ld4 = p.lambda_div4;
        let mut c_tilde = [0u8; MAX_LAMBDA_DIV4];
        let mut kappa = 0u16;

        loop {
            // y ← ExpandMask(ρ′′, κ); w ← invNTT(Â ∘ NTT(y))
            let y = expand_mask::<L>(p.gamma1, &rho_pp, kappa);
            let mut w = matrix_mul_streaming::<K, L>(&self.rho, &ntt_vec(&y));
            reduce_vec(&mut w);
            for wk in &mut w {
                inv_ntt_inplace(wk);
            }

            // c̃ ← H(µ || w1Encode(HighBits(w))). w1 is scoped so its k
            // polynomials free before the c·s / c·t products are allocated.
            let mut w1_bytes = [0u8; MAX_W1_LEN];
            {
                let mut w1: [Poly; K] = zero_vec();
                for k in 0..K {
                    for n in 0..256 {
                        w1[k].0[n] = high_bits(p.gamma2, w[k].0[n]);
                    }
                }
                w1_encode::<K>(p.gamma2, &w1, &mut w1_bytes[..p.w1_len]);
            }
            shake256(&[&mu, &w1_bytes[..p.w1_len]]).read(&mut c_tilde[..ld4]);

            // c ← SampleInBall(c̃); ĉ ← NTT(c)
            let mut c_hat = sample_in_ball(p.tau, &c_tilde[..ld4]);
            ntt_inplace(&mut c_hat);

            // ⟨⟨c·s1⟩⟩ and ⟨⟨c·s2⟩⟩
            let c_s1: [Poly; L] = core::array::from_fn(|l| {
                let mut r = pointwise_mont(&c_hat, &self.s1_hat_mont[l]);
                inv_ntt_inplace(&mut r);
                r
            });
            let c_s2: [Poly; K] = core::array::from_fn(|k| {
                let mut r = pointwise_mont(&c_hat, &self.s2_hat_mont[k]);
                inv_ntt_inplace(&mut r);
                r
            });

            // z ← y + ⟨⟨c·s1⟩⟩; r0 ← LowBits(w − ⟨⟨c·s2⟩⟩)
            let mut z: [Poly; L] = zero_vec();
            for l in 0..L {
                for n in 0..256 {
                    z[l].0[n] = partial_reduce32(y[l].0[n] + c_s1[l].0[n]);
                }
            }
            let mut r0: [Poly; K] = zero_vec();
            for k in 0..K {
                for n in 0..256 {
                    r0[k].0[n] = low_bits(p.gamma2, partial_reduce32(w[k].0[n] - c_s2[k].0[n]));
                }
            }

            // Validity: reject on ||z||∞ ≥ γ1−β or ||r0||∞ ≥ γ2−β.
            if infinity_norm(&z) >= (p.gamma1 - p.beta) || infinity_norm(&r0) >= (p.gamma2 - p.beta)
            {
                kappa += L as u16;
                continue;
            }

            // ⟨⟨c·t0⟩⟩; h ← MakeHint(−⟨⟨c·t0⟩⟩, w − ⟨⟨c·s2⟩⟩ + ⟨⟨c·t0⟩⟩)
            let c_t0: [Poly; K] = core::array::from_fn(|k| {
                let mut r = pointwise_mont(&c_hat, &self.t0_hat_mont[k]);
                inv_ntt_inplace(&mut r);
                r
            });
            let mut h: [Poly; K] = zero_vec();
            for k in 0..K {
                for n in 0..256 {
                    h[k].0[n] = i32::from(make_hint(
                        p.gamma2,
                        Q - c_t0[k].0[n],
                        partial_reduce32(w[k].0[n] - c_s2[k].0[n] + c_t0[k].0[n]),
                    ));
                }
            }

            // Reject on ||⟨⟨c·t0⟩⟩||∞ ≥ γ2 or hint weight > ω.
            if infinity_norm(&c_t0) >= p.gamma2 || hint_weight(&h) > p.omega {
                kappa += L as u16;
                continue;
            }

            // σ ← sigEncode(c̃, z mod± q, h). Centre z in place — it is dead
            // afterwards, so no separate buffer is needed.
            for zl in &mut z {
                for n in 0..256 {
                    zl.0[n] = center_mod(zl.0[n]);
                }
            }
            sig_encode::<K, L>(p.gamma1, p.omega, ld4, &c_tilde, &z, &h, out);
            return;
        }
    }
}

/// Verify signature `sig` on `msg` under context `ctx` against public key `pk`
/// (Alg 8). Malformed keys or signatures verify as `false`.
pub fn verify<const K: usize, const L: usize>(
    p: &Params,
    pk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> bool {
    debug_assert!(K == p.k && L == p.l);
    if ctx.len() > 255 || pk.len() != p.pk_len || sig.len() != p.sig_len {
        return false;
    }
    let Ok((rho, t1)) = pk_decode::<K>(pk) else {
        return false;
    };
    let Ok((c_tilde, z, h)) = sig_decode::<K, L>(p.gamma1, p.omega, p.lambda_div4, sig) else {
        return false;
    };

    // tr ← H(pk); µ ← H(tr || 0x00 || |ctx| || ctx || M)
    let mut tr = [0u8; 64];
    shake256(&[pk]).read(&mut tr);
    let mut mu = [0u8; 64];
    shake256(&[&tr, &[0u8], &[ctx.len() as u8], ctx, msg]).read(&mut mu);

    // t1·2^d in Montgomery/NTT form (Alg 8 step 9's last term).
    let t1_hat_mont = to_mont_vec(&ntt_vec(&t1));
    let t1_d2_hat_mont: [Poly; K] = core::array::from_fn(|k| {
        let mut tmp = Poly::zero();
        for n in 0..256 {
            tmp.0[n] = mont_reduce(i64::from(t1_hat_mont[k].0[n]) << D);
        }
        to_mont(&tmp)
    });

    // w'Approx ← invNTT(Â ∘ NTT(z) − ĉ ∘ NTT(t1·2^d))
    let az = matrix_mul_streaming::<K, L>(&rho, &ntt_vec(&z));
    let mut c_hat = sample_in_ball(p.tau, &c_tilde[..p.lambda_div4]);
    ntt_inplace(&mut c_hat);
    let mut wp: [Poly; K] = core::array::from_fn(|k| {
        let mut r = Poly::zero();
        for n in 0..256 {
            r.0[n] =
                az[k].0[n] - mont_reduce(i64::from(c_hat.0[n]) * i64::from(t1_d2_hat_mont[k].0[n]));
        }
        r
    });
    reduce_vec(&mut wp);
    for wpk in &mut wp {
        inv_ntt_inplace(wpk);
    }

    // w'1 ← UseHint(h, w'Approx); c̃′ ← H(µ || w1Encode(w'1))
    let mut wp1: [Poly; K] = zero_vec();
    for k in 0..K {
        for n in 0..256 {
            wp1[k].0[n] = use_hint(p.gamma2, h[k].0[n], wp[k].0[n]);
        }
    }
    let mut w1_bytes = [0u8; MAX_W1_LEN];
    w1_encode::<K>(p.gamma2, &wp1, &mut w1_bytes[..p.w1_len]);
    let mut c_tilde_p = [0u8; MAX_LAMBDA_DIV4];
    shake256(&[&mu, &w1_bytes[..p.w1_len]]).read(&mut c_tilde_p[..p.lambda_div4]);

    // Accept iff ||z||∞ < γ1−β and c̃ == c̃′.
    infinity_norm(&z) < (p.gamma1 - p.beta)
        && c_tilde[..p.lambda_div4] == c_tilde_p[..p.lambda_div4]
}

#[cfg(test)]
#[path = "sign_tests.rs"]
mod tests;
