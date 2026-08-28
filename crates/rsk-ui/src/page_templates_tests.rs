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
