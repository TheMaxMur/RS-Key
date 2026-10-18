// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn check(scalar: p384::Scalar) {
    assert_eq!(
        comb_mul_p384(&scalar).to_affine(),
        (p384::ProjectivePoint::GENERATOR * scalar).to_affine(),
    );
}

#[test]
fn every_scalar_bit_matches_the_generator() {
    for bit in 0..384 {
        let mut bytes = [0; 48];
        bytes[47 - bit / 8] = 1 << (bit % 8);
        check(Option::from(p384::Scalar::from_repr(bytes.into())).unwrap());
    }
}

#[test]
fn zero_one_order_edge_and_mixed_group_boundaries_match_the_generator() {
    check(p384::Scalar::ZERO);
    check(p384::Scalar::ONE);
    check(-p384::Scalar::ONE);
    for offset in [0, 1, 23, 24, 46, 47] {
        let mut bytes = [0; 48];
        for group in 0..8 {
            let bit = group * HALF + offset;
            bytes[47 - bit / 8] |= 1 << (bit % 8);
        }
        check(Option::from(p384::Scalar::from_repr(bytes.into())).unwrap());
    }
}
