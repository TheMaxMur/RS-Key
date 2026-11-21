// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::params::{ML_DSA_44, ML_DSA_65};
use crate::testutil::{Rng, rand_poly_q};

#[test]
#[should_panic(expected = "power2round input not in [0,q)")]
fn power2round_refuses_an_unreduced_coefficient() {
    let mut r = Poly([0; 256]);
    r.0[0] = Q;
    power2round(&r);
}

#[test]
fn power2round_reconstructs() {
    let mut rng = Rng::new(1);
    for _ in 0..40 {
        let r = rand_poly_q(&mut rng);
        let (r1, r0) = power2round(&r);
        for n in 0..256 {
            assert_eq!(r.0[n], (r1.0[n] << D) + r0.0[n], "reconstruct at {n}");
            assert!(
                r0.0[n] > -(1 << (D - 1)) && r0.0[n] <= (1 << (D - 1)),
                "r0 centered"
            );
        }
    }
}

#[test]
fn decompose_reconstructs_both_sets() {
    for p in [ML_DSA_44, ML_DSA_65] {
        let mut rng = Rng::new(p.gamma2 as u64);
        for _ in 0..2000 {
            let r = (rng.next_u64() % (Q as u64)) as i32;
            let (r1, r0) = decompose(p.gamma2, r);
            assert_eq!(
                (r1 * 2 * p.gamma2 + r0).rem_euclid(Q),
                r.rem_euclid(Q),
                "reconstruct"
            );
            assert!(r0.abs() <= p.gamma2, "r0 within +/- gamma2");
        }
    }
}

#[test]
fn make_hint_zero_never_fires() {
    for p in [ML_DSA_44, ML_DSA_65] {
        let mut rng = Rng::new(7);
        for _ in 0..1000 {
            let r = (rng.next_u64() % (Q as u64)) as i32;
            assert!(!make_hint(p.gamma2, 0, r));
            assert_eq!(use_hint(p.gamma2, 0, r), high_bits(p.gamma2, r));
        }
    }
}

#[test]
fn make_use_hint_roundtrip() {
    // FIPS 204 guarantees UseHint(MakeHint(z, r), r) == HighBits(r + z) for |z| <= gamma2.
    for p in [ML_DSA_44, ML_DSA_65] {
        let mut rng = Rng::new(99);
        for _ in 0..4000 {
            let r = (rng.next_u64() % (Q as u64)) as i32;
            let z = ((rng.next_u64() % (2 * p.gamma2 as u64 + 1)) as i32) - p.gamma2;
            let h = i32::from(make_hint(p.gamma2, z, r));
            assert_eq!(
                use_hint(p.gamma2, h, r),
                high_bits(p.gamma2, (r + z).rem_euclid(Q))
            );
        }
    }
}

#[test]
fn use_hint_matches_the_spec_at_zero_low_bits_and_both_wraps() {
    for (p, modulus) in [(ML_DSA_44, 44), (ML_DSA_65, 16)] {
        for high in 0..modulus {
            for low in [-1, 0, 1] {
                let r = (high * 2 * p.gamma2 + low).rem_euclid(Q);
                assert_eq!(decompose(p.gamma2, r), (high, low));
                assert_eq!(use_hint(p.gamma2, 0, r), high);
                let expected = (high + if low > 0 { 1 } else { -1 }).rem_euclid(modulus);
                assert_eq!(use_hint(p.gamma2, 1, r), expected, "high={high} low={low}");
            }
        }
    }
}
