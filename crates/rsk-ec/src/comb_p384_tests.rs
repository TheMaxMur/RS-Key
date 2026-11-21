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
    for offset in [0, 1, ROUNDS / 2, ROUNDS - 2, ROUNDS - 1] {
        let mut bytes = [0; 48];
        for column in 0..WIDTH {
            for group in 0..GROUPS {
                let bit = column * STRIDE + group * ROUNDS + offset;
                bytes[47 - bit / 8] |= 1 << (bit % 8);
            }
        }
        check(Option::from(p384::Scalar::from_repr(bytes.into())).unwrap());
    }
}

#[test]
fn every_digit_in_every_group_matches_the_generator() {
    for group in 0..GROUPS {
        for offset in [0, ROUNDS - 1] {
            for digit in 0..(1 << WIDTH) {
                let mut bytes = [0; 48];
                for column in 0..WIDTH {
                    let bit = column * STRIDE + group * ROUNDS + offset;
                    bytes[47 - bit / 8] |= ((digit >> column) & 1) << (bit % 8);
                }
                check(Option::from(p384::Scalar::from_repr(bytes.into())).unwrap());
            }
        }
    }
}

#[test]
fn dense_scalars_match_the_generator() {
    for byte in [0x11, 0x33, 0x55, 0x77, 0x88, 0xaa, 0xcc, 0xee] {
        check(Option::from(p384::Scalar::from_repr([byte; 48].into())).unwrap());
    }
}
