// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::comb_p384_params::{ENTRIES, GROUPS, ROUNDS, STRIDE, WIDTH};
use super::{P384_CORRECTION, SIGNED_P384};
use p384::elliptic_curve::PrimeField;
use p384::elliptic_curve::ops::Double;
use p384::elliptic_curve::point::AffineCoordinates;
use p384::elliptic_curve::subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use rsk_secret::Secret;

fn decode((x, y): &([u8; 48], [u8; 48])) -> p384::AffinePoint {
    Option::from(p384::AffinePoint::from_coordinates(
        &(*x).into(),
        &(*y).into(),
    ))
    .expect("valid comb point")
}

/// Fixed-base P-384 multiplication with four signed width-four groups.
pub fn comb_mul_p384(k: &p384::Scalar) -> p384::ProjectivePoint {
    let mut tables = [[p384::AffinePoint::IDENTITY; ENTRIES]; GROUPS];
    for (table, bytes) in tables.iter_mut().zip(&SIGNED_P384) {
        for (point, coordinates) in table.iter_mut().zip(bytes) {
            *point = decode(coordinates);
        }
    }
    let repr = Secret::new(k.to_repr());
    let bit = |n: usize| (repr.expose()[47 - n / 8] >> (n % 8)) & 1;
    let mut q = p384::ProjectivePoint::IDENTITY;
    for t in (0..ROUNDS).rev() {
        q.double_in_place();
        for (group, table) in tables.iter().enumerate() {
            let mut index = 0u8;
            for j in 0..WIDTH {
                index |= bit(j * STRIDE + group * ROUNDS + t) << j;
            }
            // Complementary digits are opposite points around the public center.
            let sign = index >> (WIDTH - 1);
            index = (index ^ 0u8.wrapping_sub(sign)) & (ENTRIES as u8 - 1);
            let mut selected = p384::AffinePoint::IDENTITY;
            for (i, point) in table.iter().enumerate() {
                selected.conditional_assign(point, (i as u8).ct_eq(&index));
            }
            selected.conditional_assign(&-selected, Choice::from(sign));
            q += selected;
        }
    }
    // Undo the centers accumulated by the fixed double-and-add schedule.
    q += decode(&P384_CORRECTION);
    q
}

#[cfg(test)]
#[path = "comb_p384_tests.rs"]
mod tests;
