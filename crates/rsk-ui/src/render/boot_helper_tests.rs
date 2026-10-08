// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use embedded_graphics::prelude::RgbColor;

#[test]
fn runtime_breathe_rgb_conversion_preserves_the_high_component_bits() {
    for channels in [(0, 0, 0), (255, 255, 255), (154, 163, 173), (75, 80, 87)] {
        let (red, green, blue) = std::hint::black_box(channels);
        let color = rgb(red, green, blue);
        assert_eq!(color.r(), red / 8);
        assert_eq!(color.g(), green / 4);
        assert_eq!(color.b(), blue / 8);
    }
}
