// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::comb_p521_params::{BITS, ENTRIES, GROUPS, ROUNDS, STRIDE, WIDTH};
use p521::elliptic_curve::{
    PrimeField,
    ops::Double,
    point::AffineCoordinates,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq},
};
use rsk_secret::Secret;

include!(concat!(env!("OUT_DIR"), "/gen_signed_p521.rs"));

fn decode((x, y): &([u8; 66], [u8; 66])) -> p521::AffinePoint {
    Option::from(p521::AffinePoint::from_coordinates(
        &(*x).into(),
        &(*y).into(),
    ))
    .expect("valid comb point")
}

/// Fixed-base P-521 multiplication with four signed width-four groups.
pub fn comb_mul_p521(k: &p521::Scalar) -> p521::ProjectivePoint {
    let mut tables = [[p521::AffinePoint::IDENTITY; ENTRIES]; GROUPS];
    for (table, bytes) in tables.iter_mut().zip(&SIGNED_P521) {
        for (point, coordinates) in table.iter_mut().zip(bytes) {
            *point = decode(coordinates);
        }
    }
    let repr = Secret::new(k.to_repr());
    let bit = |n: usize| {
        if n >= BITS {
            0
        } else {
            (repr.expose()[65 - n / 8] >> (n % 8)) & 1
        }
    };
    let mut q = Secret::new(p521::ProjectivePoint::IDENTITY);
    for t in (0..ROUNDS).rev() {
        q.expose_mut().double_in_place();
        for (group, table) in tables.iter().enumerate() {
            let mut index = 0u8;
            for j in 0..WIDTH {
                index |= bit(j * STRIDE + group * ROUNDS + t) << j;
            }
            // Complementary digits are opposite points around the public center.
            let sign = index >> (WIDTH - 1);
            index = (index ^ 0u8.wrapping_sub(sign)) & (ENTRIES as u8 - 1);
            let mut selected = Secret::new(p521::AffinePoint::IDENTITY);
            for (i, point) in table.iter().enumerate() {
                selected
                    .expose_mut()
                    .conditional_assign(point, (i as u8).ct_eq(&index));
            }
            let negative = Secret::new(-*selected.expose());
            selected
                .expose_mut()
                .conditional_assign(negative.expose(), Choice::from(sign));
            *q.expose_mut() += *selected.expose();
        }
    }
    // Undo the centers accumulated by the fixed double-and-add schedule.
    *q.expose_mut() += decode(&P521_CORRECTION);
    *q.expose()
}

#[cfg(test)]
#[path = "comb_p521_tests.rs"]
mod tests;
