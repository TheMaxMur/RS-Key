// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use p384::elliptic_curve::PrimeField;
use p384::elliptic_curve::ops::Double;
use p384::elliptic_curve::point::AffineCoordinates;
use p384::elliptic_curve::subtle::{ConditionallySelectable, ConstantTimeEq};
use rsk_secret::Secret;

use super::{COMB_D_P384, COMB_W, GEN_COMB_P384, GEN_COMB_P384_HI};

const HALF: usize = COMB_D_P384 / 2;
const ENTRIES: usize = 1 << COMB_W;

fn decode(bytes: &[([u8; 48], [u8; 48]); ENTRIES]) -> [p384::AffinePoint; ENTRIES] {
    let mut table = [p384::AffinePoint::IDENTITY; ENTRIES];
    for (point, (x, y)) in table.iter_mut().zip(bytes).skip(1) {
        *point = Option::from(p384::AffinePoint::from_coordinates(
            &p384::FieldBytes::from(*x),
            &p384::FieldBytes::from(*y),
        ))
        .expect("valid comb point");
    }
    table
}

/// Fixed-base P-384 multiplication with two width-four comb groups.
pub fn comb_mul_p384(k: &p384::Scalar) -> p384::ProjectivePoint {
    const { assert!(COMB_D_P384.is_multiple_of(2)) }
    // T1 = 2^HALF · T0 gives two additions per round and halves the doublings.
    let tables = [decode(&GEN_COMB_P384), decode(&GEN_COMB_P384_HI)];
    let repr = Secret::new(k.to_repr());
    let bit = |n: usize| (repr.expose()[47 - n / 8] >> (n % 8)) & 1;
    let mut q = p384::ProjectivePoint::IDENTITY;
    for t in (0..HALF).rev() {
        q.double_in_place();
        for (group, table) in tables.iter().enumerate() {
            let mut index = 0u8;
            for j in 0..COMB_W {
                index |= bit(j * COMB_D_P384 + group * HALF + t) << j;
            }
            let mut selected = p384::AffinePoint::IDENTITY;
            for (i, point) in table.iter().enumerate() {
                selected.conditional_assign(point, (i as u8).ct_eq(&index));
            }
            q += selected;
        }
    }
    q
}

#[cfg(test)]
#[path = "comb_p384_tests.rs"]
mod tests;
