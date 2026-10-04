// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use embedded_graphics::pixelcolor::IntoStorage;

use super::*;

#[test]
fn flash_rows_match_the_public_theme_colors() {
    for color in [
        crate::theme::PANEL_BG,
        crate::theme::SURFACE,
        crate::theme::KEY_BG,
        crate::theme::NAV_BG,
    ] {
        let row = row(color.into_storage()).unwrap();
        let expected = color.into_storage().to_be_bytes();
        assert!(row.chunks_exact(2).all(|pixel| pixel == expected));
    }
}

#[test]
fn dynamic_colors_do_not_alias_a_template() {
    assert!(row(crate::theme::ACCENT.into_storage()).is_none());
}

#[test]
fn runtime_template_building_matches_panel_quantization_and_wire_byte_order() {
    let convert = std::hint::black_box(rgb565 as fn(u8, u8, u8) -> u16);
    let build = std::hint::black_box(solid_row as fn(u16) -> [u8; ROW_BYTES]);
    for ((red, green, blue), expected) in [
        ((0, 0, 0), 0x0000_u16),
        ((255, 0, 0), 0xf800),
        ((0, 255, 0), 0x07e0),
        ((0, 0, 255), 0x001f),
        ((7, 3, 7), 0x0000),
        ((8, 4, 8), 0x0821),
        ((10, 13, 17), 0x0862),
        ((128, 128, 128), 0x8410),
        ((255, 255, 255), 0xffff),
    ] {
        let color = convert(red, green, blue);
        assert_eq!(color, expected);
        assert!(
            build(color)
                .chunks_exact(2)
                .all(|pixel| pixel == expected.to_be_bytes())
        );
    }
}
