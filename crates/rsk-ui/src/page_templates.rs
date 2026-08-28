// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Exact raster rows for fixed page surfaces, stored in XIP flash.

use crate::PANEL_W;

const ROW_BYTES: usize = PANEL_W as usize * 2;

const fn rgb565(r: u8, g: u8, b: u8) -> u16 {
    ((r as u16 >> 3) << 11) | ((g as u16 >> 2) << 5) | (b as u16 >> 3)
}

const fn solid_row(color: u16) -> [u8; ROW_BYTES] {
    let mut row = [0; ROW_BYTES];
    let bytes = color.to_be_bytes();
    let mut offset = 0;
    while offset < ROW_BYTES {
        row[offset] = bytes[0];
        row[offset + 1] = bytes[1];
        offset += 2;
    }
    row
}

const PANEL_BG: u16 = rgb565(0x0a, 0x0d, 0x11);
const SURFACE: u16 = rgb565(0x13, 0x17, 0x1d);
const KEY_BG: u16 = rgb565(0x15, 0x19, 0x1f);
const NAV_BG: u16 = rgb565(0x10, 0x13, 0x17);

static PANEL_BG_ROW: [u8; ROW_BYTES] = solid_row(PANEL_BG);
static SURFACE_ROW: [u8; ROW_BYTES] = solid_row(SURFACE);
static KEY_BG_ROW: [u8; ROW_BYTES] = solid_row(KEY_BG);
static NAV_BG_ROW: [u8; ROW_BYTES] = solid_row(NAV_BG);

/// Return the exact pre-rasterized row for a fixed page surface.
pub(crate) fn row(color: u16) -> Option<&'static [u8; ROW_BYTES]> {
    match color {
        PANEL_BG => Some(&PANEL_BG_ROW),
        SURFACE => Some(&SURFACE_ROW),
        KEY_BG => Some(&KEY_BG_ROW),
        NAV_BG => Some(&NAV_BG_ROW),
        _ => None,
    }
}

#[cfg(test)]
#[path = "page_templates_tests.rs"]
mod tests;
