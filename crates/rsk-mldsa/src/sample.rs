// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Pseudorandom sampling from SHAKE (FIPS 204 §7.3, Alg 29–34) plus the
//! streaming matrix-vector product that is the crate's whole reason to exist.
//!
//! Constant-time notes, matching the pq-crystals reference implementation:
//! - `coeff_from_half_byte`'s `mod 5` uses a Barrett multiply, never a hardware
//!   divide — the Cortex-M33 `UDIV` is variable-latency, and this value is
//!   secret-derived (this is the class of bug behind RUSTSEC-2025-0144).
//! - the rejection loops (`rej_ntt_poly`, `rej_bounded_poly`, `sample_in_ball`)
//!   are variable-time by construction; their iteration counts depend only on
//!   uniform hash output, not on the resulting secret, per the Dilithium model.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

use crate::pack::{bit_length, bit_unpack};
use crate::params::{N, Q};
use crate::poly::{Poly, zero_vec};
use crate::reduce::{mont_reduce, to_mont};

// The readers own their Keccak state (the inputs are absorbed by `update`), so
// `use<>` opts the returned `impl XofReader` out of edition-2024's default
// capture of the `parts` lifetime — otherwise the caller's temporary seed
// fragments would be seen as borrowed for the reader's whole life.

/// H — a SHAKE256 XOF over the concatenated inputs (FIPS 204 §3.7).
pub(crate) fn shake256(parts: &[&[u8]]) -> impl XofReader + use<> {
    let mut h = Shake256::default();
    for p in parts {
        h.update(p);
    }
    h.finalize_xof()
}

/// G — a SHAKE128 XOF over the concatenated inputs (FIPS 204 §3.7).
fn shake128(parts: &[&[u8]]) -> impl XofReader + use<> {
    let mut h = Shake128::default();
    for p in parts {
        h.update(p);
    }
    h.finalize_xof()
}

/// CoeffFromThreeBytes (Alg 14): a value in [0, q) or ⊥ (`None`), for rejection.
fn coeff_from_three_bytes(b: [u8; 3]) -> Option<i32> {
    let b2 = i32::from(b[2] & 0x7F); // clear the top bit
    let z = (b2 << 16) | (i32::from(b[1]) << 8) | i32::from(b[0]);
    (z < Q).then_some(z)
}

/// CoeffFromHalfByte (Alg 15): a value in [−η, η] or ⊥. The `mod 5` for η=2 is a
/// Barrett multiply (see the module CT note).
fn coeff_from_half_byte(eta: i32, b: u8) -> Option<i32> {
    const M5: i32 = (1 << 24) / 5 + 1;
    let b = i32::from(b);
    if eta == 2 && b < 15 {
        let quot = (b * M5) >> 24;
        Some(2 - (b - quot * 5))
    } else if eta == 4 && b < 9 {
        Some(4 - b)
    } else {
        None
    }
}

/// SampleInBall (Alg 29): a challenge polynomial with coefficients in {−1,0,1}
/// and Hamming weight τ, from the (public) commitment hash `c_tilde`.
pub(crate) fn sample_in_ball(tau: i32, c_tilde: &[u8]) -> Poly {
    let tau = tau as usize;
    let mut c = Poly::zero();
    let mut xof = shake256(&[c_tilde]);
    let mut signs = [0u8; 8];
    xof.read(&mut signs);
    let mut sign_bits = u64::from_le_bytes(signs);
    for i in (256 - tau)..=255 {
        let mut j = [0u8; 1];
        loop {
            xof.read(&mut j);
            if usize::from(j[0]) <= i {
                break;
            }
        }
        let jj = usize::from(j[0]);
        c.0[i] = c.0[jj];
        c.0[jj] = 1 - 2 * (sign_bits & 1) as i32;
        sign_bits >>= 1;
    }
    c
}

/// RejNTTPoly (Alg 30): one matrix entry `Â[r][s]` in the NTT domain, seeded by
/// `rho || s || r`. Regenerated on demand by the streaming matrix product.
pub(crate) fn rej_ntt_poly(rho: &[u8; 32], s: u8, r: u8) -> Poly {
    let mut a = Poly::zero();
    let mut xof = shake128(&[rho, &[s], &[r]]);
    let mut j = 0;
    while j < 256 {
        let mut buf = [0u8; 3];
        xof.read(&mut buf);
        if let Some(v) = coeff_from_three_bytes(buf) {
            a.0[j] = v;
            j += 1;
        }
    }
    a
}

/// RejBoundedPoly (Alg 31): a polynomial with coefficients in [−η, η].
fn rej_bounded_poly(eta: i32, parts: &[&[u8]]) -> Poly {
    let mut a = Poly::zero();
    let mut xof = shake256(parts);
    let mut j = 0;
    while j < 256 {
        let mut z = [0u8; 1];
        xof.read(&mut z);
        for half in [z[0] & 0x0f, z[0] >> 4] {
            if j >= 256 {
                break;
            }
            if let Some(v) = coeff_from_half_byte(eta, half) {
                a.0[j] = v;
                j += 1;
            }
        }
    }
    a
}

/// ExpandS (Alg 33): the short secret vectors s1 ∈ R^l, s2 ∈ R^k in [−η, η].
pub(crate) fn expand_s<const K: usize, const L: usize>(
    eta: i32,
    rho: &[u8; 64],
) -> ([Poly; L], [Poly; K]) {
    // IntegerToBytes(r, 2) little-endian; r and r+L are both < 256.
    let s1 = core::array::from_fn(|r| rej_bounded_poly(eta, &[rho, &[r as u8], &[0]]));
    let s2 = core::array::from_fn(|r| rej_bounded_poly(eta, &[rho, &[(r + L) as u8], &[0]]));
    (s1, s2)
}

/// ExpandMask (Alg 34): the masking vector y ∈ R^l with coefficients in
/// (−γ1, γ1], for signing-loop iteration counter `mu`.
pub(crate) fn expand_mask<const L: usize>(gamma1: i32, rho: &[u8; 64], mu: u16) -> [Poly; L] {
    let c = 1 + bit_length(gamma1 - 1); // 18 (γ1=2^17) or 20 (γ1=2^19)
    core::array::from_fn(|r| {
        let mut v = [0u8; 32 * 20];
        let n = mu + r as u16;
        let mut xof = shake256(&[rho, &n.to_le_bytes()]);
        xof.read(&mut v[..32 * c]);
        // a+b+1 = 2γ1 is a power of two, so every decode is in range — never Err.
        bit_unpack(&v[..32 * c], gamma1 - 1, gamma1).expect("ExpandMask decode in range")
    })
}

/// Streaming matrix-vector product `w = Â·û` in the NTT domain (the pointwise
/// products of `mat_vec_mul`, Alg 44/helpers). Instead of materializing the full
/// k×l matrix Â, each `Â[i][j]` is regenerated on the fly via [`rej_ntt_poly`] —
/// one A-polynomial plus the SHAKE128 state resident, not k·l. This is the core
/// stack saving over the by-value reference. `û` need not be in Montgomery form;
/// it is lifted here (exactly one operand carries the 2^32 factor).
#[allow(clippy::needless_range_loop)] // i, j index different arrays and seed Â[i][j]
pub(crate) fn matrix_mul_streaming<const K: usize, const L: usize>(
    rho: &[u8; 32],
    u_hat: &[Poly; L],
) -> [Poly; K] {
    let u_mont: [Poly; L] = core::array::from_fn(|j| to_mont(&u_hat[j]));
    let mut w: [Poly; K] = zero_vec();
    for i in 0..K {
        for j in 0..L {
            let a_ij = rej_ntt_poly(rho, j as u8, i as u8); // Â[i][j] on the fly
            for n in 0..N {
                w[i].0[n] += mont_reduce(i64::from(a_ij.0[n]) * i64::from(u_mont[j].0[n]));
            }
        }
    }
    w
}

#[cfg(test)]
#[path = "sample_tests.rs"]
mod tests;
