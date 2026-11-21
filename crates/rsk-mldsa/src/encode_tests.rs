// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::params::{ML_DSA_44, ML_DSA_65, Params};
use crate::testutil::{Rng, rand_poly_range};

#[test]
fn pk_encode_decode_roundtrip() {
    fn check<const K: usize>(p: &Params) {
        let mut rng = Rng::new(p.k as u64);
        let mut rho = [0u8; 32];
        rng.fill(&mut rho);
        let t1: [Poly; K] = core::array::from_fn(|_| rand_poly_range(&mut rng, 0, (1 << 10) - 1));
        let mut pk = vec![0u8; p.pk_len];
        pk_encode::<K>(&rho, &t1, &mut pk);
        let (rho2, t12) = pk_decode::<K>(&pk).unwrap();
        assert_eq!(rho, rho2);
        for i in 0..K {
            assert_eq!(t1[i].0, t12[i].0);
        }
    }
    check::<4>(&ML_DSA_44);
    check::<6>(&ML_DSA_65);
}

#[test]
fn sig_encode_decode_roundtrip() {
    fn check<const K: usize, const L: usize>(p: &Params) {
        let mut rng = Rng::new(p.sig_len as u64);
        let mut c = [0u8; 64];
        rng.fill(&mut c[..p.lambda_div4]);
        let z: [Poly; L] =
            core::array::from_fn(|_| rand_poly_range(&mut rng, -(p.gamma1 - 1), p.gamma1));
        let mut h = crate::poly::zero_vec::<K>();
        h[0].0[3] = 1;
        h[0].0[100] = 1;
        h[K - 1].0[200] = 1;
        let mut sig = vec![0u8; p.sig_len];
        sig_encode::<K, L>(p.gamma1, p.omega, p.lambda_div4, &c, &z, &h, &mut sig);
        let (c2, z2, h2) = sig_decode::<K, L>(p.gamma1, p.omega, p.lambda_div4, &sig).unwrap();
        assert_eq!(c[..p.lambda_div4], c2[..p.lambda_div4]);
        for i in 0..L {
            assert_eq!(z[i].0, z2[i].0);
        }
        for i in 0..K {
            assert_eq!(h[i].0, h2[i].0);
        }
    }
    check::<4, 4>(&ML_DSA_44);
    check::<6, 5>(&ML_DSA_65);
}

#[test]
fn a_complete_public_key_encoding_accepts_the_full_coefficient_range() {
    for (byte, coefficient) in [(0, 0), (0xff, 1023)] {
        let (rho, coefficients) = pk_decode::<4>(&[byte; crate::MLDSA44_PK_LEN]).unwrap();
        assert_eq!(rho, [byte; 32]);
        assert!(
            coefficients
                .iter()
                .all(|poly| poly.0.iter().all(|&value| value == coefficient))
        );
    }
}
