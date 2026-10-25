// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use crate::comb_p521_params::{ENTRIES, GROUPS, ROUNDS, STRIDE, WIDTH};
use p521::elliptic_curve::sec1::ToSec1Point;
use p521::{ProjectivePoint, Scalar};
use std::{env, fs, path::Path};

pub fn generate() {
    let inv_two = Scalar::from(2u32).invert().unwrap();
    let mut body = String::new();
    let mut bias = ProjectivePoint::IDENTITY;
    // Centering makes complementary width-WIDTH digits opposite points.
    for group in 0..GROUPS {
        let mut base = [ProjectivePoint::GENERATOR; WIDTH];
        for (j, point) in base.iter_mut().enumerate() {
            for _ in 0..(group * ROUNDS + j * STRIDE) {
                *point += *point;
            }
        }
        let center = base.iter().copied().sum::<ProjectivePoint>() * inv_two;
        bias += center;
        body.push_str("[\n");
        for i in 0..ENTRIES {
            let mut point = -center;
            for (j, term) in base.iter().enumerate() {
                if i & (1 << j) != 0 {
                    point += term;
                }
            }
            let ep = point.to_affine().to_sec1_point(false);
            let x: [u8; 66] = ep.x().unwrap().as_slice().try_into().unwrap();
            let y: [u8; 66] = ep.y().unwrap().as_slice().try_into().unwrap();
            body.push_str(&format!("({x:?}, {y:?}),\n"));
        }
        body.push_str("],\n");
    }
    let mut correction = bias;
    for _ in 0..ROUNDS {
        correction += correction;
    }
    correction -= bias;
    let ep = correction.to_affine().to_sec1_point(false);
    let x: [u8; 66] = ep.x().unwrap().as_slice().try_into().unwrap();
    let y: [u8; 66] = ep.y().unwrap().as_slice().try_into().unwrap();
    let src = format!(
        "pub(crate) const SIGNED_P521: [[([u8;66],[u8;66]);{ENTRIES}];{GROUPS}] = [\n{body}];\npub(crate) const P521_CORRECTION: ([u8;66],[u8;66]) = ({x:?},{y:?});\n"
    );
    fs::write(
        Path::new(&env::var("OUT_DIR").unwrap()).join("gen_signed_p521.rs"),
        src,
    )
    .unwrap();
}
