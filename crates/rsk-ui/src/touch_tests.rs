// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn reconstructs_finger_coordinate() {
    // x=100 (0x064): X high 8 = 0x06, X low 4 = 0x4. y=200 (0x0C8): Y high 8 =
    // 0x0C, Y low 4 = 0x8 — so the packed low-nibble byte is 0x48.
    let r = [FINGER_DOWN, 0x06, 0x0C, 0x48, 0, 0, 0];
    assert_eq!(parse_cst328(&r), Some(Point::new(100, 200)));
}

#[test]
fn no_finger_down_is_none() {
    assert_eq!(parse_cst328(&[0x00, 0x06, 0x0C, 0x48]), None);
}

#[test]
fn short_report_is_none() {
    assert_eq!(parse_cst328(&[FINGER_DOWN, 0x06]), None);
    assert_eq!(parse_cst328(&[]), None);
}

#[test]
fn full_scale_is_twelve_bits_each() {
    let r = [FINGER_DOWN, 0xFF, 0xFF, 0xFF];
    assert_eq!(parse_cst328(&r), Some(Point::new(0xFFF, 0xFFF)));
}

#[test]
fn cst3530_reconstructs_finger_coordinate() {
    // x=100 (0x064): low byte 0x64, high nibble 0. y=200 (0x0C8): low byte 0xC8,
    // high nibble 0 — so the packed nibble byte is 0x00, and 0x12 is finger 2
    // reporting a press.
    let r = [0, 0, 0, 0x01, 0x64, 0xC8, 0x40, 0x00, 0x12];
    assert_eq!(parse_cst3530(&r), Some(Point::new(100, 200)));
}

#[test]
fn cst3530_high_nibbles_are_the_upper_four_bits() {
    // x=0x123, y=0x2C8: the packed byte is X high nibble (1) | Y high nibble (2)
    // in its upper half, so 0x21.
    let r = [0, 0, 0, 0x01, 0x23, 0xC8, 0x40, 0x21, 0x11];
    assert_eq!(parse_cst3530(&r), Some(Point::new(0x123, 0x2C8)));
}

#[test]
fn cst3530_lift_frame_is_none() {
    // The frame that ends a touch still carries its coordinate; the event nibble is
    // 0, so it must not become a tap.
    let r = [0, 0, 0, 0x01, 0x64, 0xC8, 0x40, 0xC0, 0x02];
    assert_eq!(parse_cst3530(&r), None);
}

#[test]
fn cst3530_no_points_is_none() {
    let r = [0, 0, 0, 0x00, 0x64, 0xC8, 0x40, 0xC0, 0x12];
    assert_eq!(parse_cst3530(&r), None);
}

#[test]
fn cst3530_short_report_is_none() {
    assert_eq!(parse_cst3530(&[0, 0, 0, 0x01, 0x64]), None);
    assert_eq!(parse_cst3530(&[]), None);
}
