// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn palette_quantization_keeps_the_native_panel_high_bits() {
    let convert = std::hint::black_box(rgb as fn(u8, u8, u8) -> Rgb565);
    for ((red, green, blue), expected) in [
        ((0, 0, 0), Rgb565::new(0, 0, 0)),
        ((7, 3, 7), Rgb565::new(0, 0, 0)),
        ((8, 4, 8), Rgb565::new(1, 1, 1)),
        ((127, 127, 127), Rgb565::new(15, 31, 15)),
        ((128, 128, 128), Rgb565::new(16, 32, 16)),
        ((247, 251, 247), Rgb565::new(30, 62, 30)),
        ((248, 252, 248), Rgb565::new(31, 63, 31)),
        ((255, 255, 255), Rgb565::new(31, 63, 31)),
    ] {
        assert_eq!(convert(red, green, blue), expected);
    }
}
