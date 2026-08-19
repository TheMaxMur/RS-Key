// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! FIPS 204 domain constants and the per-parameter-set scalars for ML-DSA-44 and
//! ML-DSA-65. `Q`, `ZETA`, `D`, `N` are shared across all sets; the differing
//! scalars live in [`Params`], selected once per scheme and threaded through the
//! const-generic core (the array dimensions `k`/`l` are the generics; these are
//! the runtime scalars plus the byte lengths the wrappers marshal).

/// Modulus q = 2^23 − 2^13 + 1 (FIPS 204 Table 1).
pub const Q: i32 = 8_380_417;
/// The 512th root of unity used to build the NTT twiddle table (§2.5).
pub const ZETA: i32 = 1753;
/// Number of low bits of t dropped by `Power2Round` (Table 1).
pub const D: u32 = 13;
/// Coefficients per polynomial (ring `R_q = Z_q[X]/(X^256+1)`).
pub const N: usize = 256;
/// Length of the key-generation seed ξ and of the per-signature hedge value `rnd`.
pub const SEED_LEN: usize = 32;

/// The scalar parameters distinguishing the ML-DSA parameter sets. The array
/// dimensions `k`, `l` are const generics on the core functions; everything here
/// is threaded at runtime.
#[derive(Clone, Copy)]
pub struct Params {
    /// Rows of A / length of the t, s2 vectors.
    pub k: usize,
    /// Columns of A / length of the s1, y, z vectors.
    pub l: usize,
    /// Secret-coefficient bound η ∈ {2, 4}.
    pub eta: i32,
    /// Mask bound γ1 (a power of two).
    pub gamma1: i32,
    /// Low-order rounding range γ2.
    pub gamma2: i32,
    /// Hamming weight τ of the challenge polynomial c.
    pub tau: i32,
    /// Maximum number of 1s in the hint h.
    pub omega: i32,
    /// Validity margin β = τ·η.
    pub beta: i32,
    /// λ/4 — the commitment-hash (c̃) byte length.
    pub lambda_div4: usize,
    /// Encoded public-key length.
    pub pk_len: usize,
    /// Encoded signature length.
    pub sig_len: usize,
    /// w1Encode buffer length = 32·k·bitlen((q−1)/(2γ2)−1).
    pub w1_len: usize,
}

/// ML-DSA-44 (COSE −48), NIST category 2. k=4, l=4.
pub const ML_DSA_44: Params = Params {
    k: 4,
    l: 4,
    eta: 2,
    gamma1: 1 << 17,
    gamma2: (Q - 1) / 88,
    tau: 39,
    omega: 80,
    beta: 39 * 2,
    lambda_div4: 128 / 4,
    pk_len: 1312,
    sig_len: 2420,
    w1_len: 32 * 4 * 6,
};

/// ML-DSA-65 (COSE −49), NIST category 3. k=6, l=5.
pub const ML_DSA_65: Params = Params {
    k: 6,
    l: 5,
    eta: 4,
    gamma1: 1 << 19,
    gamma2: (Q - 1) / 32,
    tau: 49,
    omega: 55,
    beta: 49 * 4,
    lambda_div4: 192 / 4,
    pk_len: 1952,
    sig_len: 3309,
    w1_len: 32 * 6 * 4,
};

/// ML-DSA-87 (COSE −50), NIST category 5. k=8, l=7.
///
/// λ = 256 ⇒ c̃ is 64 bytes; γ2 matches ML-DSA-65 so w1Encode still packs 4 bits
/// per coefficient. Fitting this on the RP2350 is the open question — see the
/// stack measurements in the branch that introduced it.
pub const ML_DSA_87: Params = Params {
    k: 8,
    l: 7,
    eta: 2,
    gamma1: 1 << 19,
    gamma2: (Q - 1) / 32,
    tau: 60,
    omega: 75,
    beta: 60 * 2,
    lambda_div4: 256 / 4,
    pk_len: 2592,
    sig_len: 4627,
    w1_len: 32 * 8 * 4,
};
