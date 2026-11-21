// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn send(panel: &mut Panel, data: bool, bytes: &[u8]) {
    let pins = RESET | if data { DC } else { 0 };
    panel.sample(pins);
    for byte in bytes {
        for bit in (0..8).rev() {
            let pins = pins | if byte & (1 << bit) != 0 { MOSI } else { 0 };
            panel.sample(pins);
            panel.sample(pins | CLK);
        }
    }
    panel.sample(pins | CS);
}

#[test]
fn address_order_sleep_and_inversion_do_not_change_gram_color_bytes() {
    for madctl in [0, MV, MX, MY, MV | MX | MY] {
        let mut panel = Panel::default();
        command(&mut panel, MADCTL, &[madctl]);
        command(&mut panel, COLMOD, &[RGB565]);
        command(&mut panel, CASET, &[0, 3, 0, 3]);
        command(&mut panel, RASET, &[0, 7, 0, 7]);
        command(&mut panel, RAMWR, &[0xF8, 0]);
        let (mut x, mut y) = if madctl & MV != 0 { (7, 3) } else { (3, 7) };
        if madctl & MX != 0 {
            x = WIDTH - 1 - x;
        }
        if madctl & MY != 0 {
            y = HEIGHT - 1 - y;
        }
        assert_eq!(panel.pixels[y * WIDTH + x], 0xF800);
        command(&mut panel, SLPOUT, &[]);
        command(&mut panel, DISPON, &[]);
        command(&mut panel, INVON, &[]);
        assert!(panel.inverted && !panel.sleeping && panel.enabled);
        command(&mut panel, SLPIN, &[]);
        command(&mut panel, DISPOFF, &[]);
        command(&mut panel, INVOFF, &[]);
        assert!(!panel.inverted && panel.sleeping && !panel.enabled);
        assert_eq!(panel.pixels[y * WIDTH + x], 0xF800);
        assert_eq!(panel.error, None);
    }
}

#[test]
fn chip_select_discards_a_partial_byte_and_clock_levels_do_not_repeat_bits() {
    let mut panel = Panel::default();
    panel.sample(RESET);
    panel.sample(RESET | CLK);
    panel.sample(RESET | CLK);
    panel.sample(RESET | CS);
    assert_eq!(panel.bytes, 0);
    command(&mut panel, SLPOUT, &[]);
    assert!(!panel.sleeping);
    assert_eq!(panel.bytes, 1);
    assert_eq!(panel.error, None);
}

#[test]
fn malformed_parameters_fail_before_the_next_command_can_hide_them() {
    for (cmd, params) in [
        (CASET, &[0, 3][..]),
        (COLMOD, &[RGB565, RGB565][..]),
        (MADCTL, &[8][..]),
        (RAMWR, &[0xF8][..]),
    ] {
        let mut panel = Panel::default();
        command(&mut panel, COLMOD, &[RGB565]);
        command(&mut panel, cmd, params);
        command(&mut panel, DISPON, &[]);
        assert!(panel.error.is_some(), "command {cmd:#x}");
        assert_eq!(panel.writes, 0);
    }
}

fn command(panel: &mut Panel, command: u8, params: &[u8]) {
    send(panel, false, &[command]);
    send(panel, true, params);
}

#[test]
fn serial_commands_and_split_pixel_bands_reach_the_named_window() {
    let mut panel = Panel::default();
    command(&mut panel, 0x11, &[]);
    command(&mut panel, 0x29, &[]);
    command(&mut panel, 0x3A, &[0x55]);
    command(&mut panel, 0x2A, &[0, 3, 0, 4]);
    command(&mut panel, 0x2B, &[0, 7, 0, 7]);
    command(&mut panel, 0x2C, &[0xF8]);
    send(&mut panel, true, &[0, 0x07, 0xE0]);
    assert!(!panel.sleeping && panel.enabled);
    assert_eq!(
        &panel.pixels[7 * WIDTH + 3..7 * WIDTH + 5],
        &[0xF800, 0x07E0]
    );
    assert_eq!(panel.pixels.iter().filter(|p| **p != 0).count(), 2);
    assert_eq!(panel.writes, 2);
    assert_eq!(panel.error, None);
    panel.sample(0);
    assert!(panel.sleeping && !panel.enabled);
    assert!(panel.pixels.iter().all(|p| *p == 0));
}

#[test]
fn an_invalid_window_or_pixel_format_is_an_explicit_model_error() {
    for format in [0, 0x55] {
        let mut panel = Panel::default();
        command(&mut panel, 0x3A, &[format]);
        command(&mut panel, 0x2A, &[0, 240, 0, 240]);
        command(&mut panel, 0x2C, &[0, 1]);
        assert!(panel.error.is_some());
        assert_eq!(panel.writes, 0);
    }
}
