// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn check(scalar: p521::Scalar) {
    assert_eq!(
        comb_mul_p521(&scalar).to_affine(),
        (p521::ProjectivePoint::GENERATOR * scalar).to_affine(),
    );
}

#[test]
fn every_scalar_bit_matches_the_generator() {
    for bit in 0..BITS {
        let mut bytes = [0; 66];
        bytes[65 - bit / 8] = 1 << (bit % 8);
        check(p521::Scalar::from_repr(bytes.into()).unwrap());
    }
}

#[test]
fn zero_one_order_edge_and_group_boundaries_match_the_generator() {
    check(p521::Scalar::ZERO);
    check(p521::Scalar::ONE);
    check(-p521::Scalar::ONE);
    for offset in [
        0,
        1,
        ROUNDS / 2,
        (BITS - 1) % ROUNDS,
        BITS % ROUNDS,
        ROUNDS - 2,
        ROUNDS - 1,
    ] {
        let mut bytes = [0; 66];
        for column in 0..WIDTH {
            for group in 0..GROUPS {
                let bit = column * STRIDE + group * ROUNDS + offset;
                if bit < BITS {
                    bytes[65 - bit / 8] |= 1 << (bit % 8);
                }
            }
        }
        check(p521::Scalar::from_repr(bytes.into()).unwrap());
    }
}

#[test]
fn every_digit_in_every_group_matches_the_generator() {
    for group in 0..GROUPS {
        for offset in [0, (BITS - 1) % ROUNDS, BITS % ROUNDS, ROUNDS - 1] {
            for digit in 0..(1 << WIDTH) {
                let mut bytes = [0; 66];
                for column in 0..WIDTH {
                    let bit = column * STRIDE + group * ROUNDS + offset;
                    if bit < BITS {
                        bytes[65 - bit / 8] |= ((digit >> column) & 1) << (bit % 8);
                    }
                }
                check(p521::Scalar::from_repr(bytes.into()).unwrap());
            }
        }
    }
}

#[test]
fn dense_scalars_match_the_generator() {
    let mut state = 0x5b0175e1f3a97c21u64;
    for _ in 0..128 {
        let mut bytes = [0; 66];
        for part in bytes.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            part.copy_from_slice(&state.to_be_bytes()[..part.len()]);
        }
        bytes[0] &= 1;
        check(p521::Scalar::from_repr(bytes.into()).unwrap());
    }
}
