// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::params::Q;

/// SplitMix64 — a deterministic PRNG for test vectors (avoids a `rand` dependency).
fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn rand_poly(state: &mut u64) -> Poly {
    let mut p = Poly::zero();
    for c in &mut p.0 {
        *c = (splitmix(state) % (Q as u64)) as i32; // canonical [0, q)
    }
    p
}

#[test]
fn ntt_roundtrip_identity() {
    let mut st = 0x1234_5678_9abc_def0u64;
    for _ in 0..64 {
        let orig = rand_poly(&mut st);
        let mut w = orig.clone();
        ntt_inplace(&mut w);
        inv_ntt_inplace(&mut w);
        assert_eq!(w.0, orig.0, "inv_ntt(ntt(x)) must equal x for x in [0,q)");
    }
}

#[test]
fn ntt_zero_stays_zero() {
    let mut w = Poly::default();
    ntt_inplace(&mut w);
    assert_eq!(w.0, [0i32; 256]);
    inv_ntt_inplace(&mut w);
    assert_eq!(w.0, [0i32; 256]);
}

#[test]
fn runtime_twiddles_match_independent_modular_exponentiation() {
    let table = core::hint::black_box(gen_zeta_table_mont());
    for (index, actual) in table.iter().enumerate() {
        let mut exponent = (index as u8).reverse_bits();
        let mut base = i64::from(ZETA);
        let mut power = 1_i64;
        while exponent != 0 {
            if exponent & 1 != 0 {
                power = power * base % i64::from(Q);
            }
            base = base * base % i64::from(Q);
            exponent >>= 1;
        }
        assert_eq!(i64::from(*actual), power * (1_i64 << 32) % i64::from(Q));
    }
}

#[test]
fn ntt_is_linear() {
    // NTT(a) + NTT(b) == NTT(a+b) coefficientwise, mod q.
    let mut st = 0xdead_beefu64;
    let a = rand_poly(&mut st);
    let b = rand_poly(&mut st);
    let mut sum = Poly::zero();
    for n in 0..256 {
        sum.0[n] = (a.0[n] + b.0[n]) % Q;
    }
    let (mut na, mut nb, mut nsum) = (a.clone(), b.clone(), sum);
    ntt_inplace(&mut na);
    ntt_inplace(&mut nb);
    ntt_inplace(&mut nsum);
    for n in 0..256 {
        let lhs = (na.0[n] + nb.0[n]).rem_euclid(Q);
        assert_eq!(lhs, nsum.0[n].rem_euclid(Q), "linearity at {n}");
    }
}
