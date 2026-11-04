// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Parsing a capacitive-touch report into a panel coordinate. Two controllers
//! appear on the reference board — a CST328 on V1 and a CST3530 on the V2 revision
//! of 2026-10-14 — with different register maps and different report layouts. Pure
//! and host-tested: the firmware's `display.rs` does the I2C transfer (read the
//! report block and hand the raw bytes here), so the bit-twiddling that turns a
//! report into the point [`crate::hit_confirm`] will judge sits under test rather
//! than buried in the driver — a wrong reconstruction maps a tap to the wrong
//! button.

use crate::Point;

/// Finger-1 status nibble (CST328 register 0xD000, low 4 bits) meaning a finger
/// is down.
const FINGER_DOWN: u8 = 0x06;

/// Parse a CST328 report block read starting at register 0xD000, returning the
/// first active finger's coordinate or `None` (no finger down, or a short block).
///
/// Byte layout returned by the controller from 0xD000: `[0]` finger-1 status,
/// `[1]` X high 8 bits, `[2]` Y high 8 bits, `[3]` X low 4 bits (upper nibble) |
/// Y low 4 bits (lower nibble). Both axes are 12-bit. The controller is configured
/// at the panel resolution and reports the panel's own axes, so `display.rs` hands
/// this straight on — there is no rotation or flip step anywhere.
pub fn parse_cst328(report: &[u8]) -> Option<Point> {
    if report.len() < 4 || report[0] & 0x0F != FINGER_DOWN {
        return None;
    }
    let x = ((report[1] as u16) << 4) | ((report[3] as u16) >> 4);
    let y = ((report[2] as u16) << 4) | ((report[3] as u16) & 0x0F);
    Some(Point::new(x, y))
}

/// Finger-event nibble of a CST3530 report (`[8]` high 4 bits) for a lift: the
/// frame that ends a touch still carries the last coordinate, so a lift sample
/// must not be read as a tap.
const CST3530_LIFT: u8 = 0x00;

/// Parse a CST3530 report block read starting at register `0xD0070000` — the touch
/// controller Waveshare put on the **V2** revision of the reference board (the V1
/// carries a CST328). Returns the first finger's coordinate, or `None`.
///
/// Byte layout as read (nine bytes, no register prefix): `[3]` low nibble is the
/// number of points, `[4]` X low 8 bits, `[5]` Y low 8 bits, `[6]` strength,
/// `[7]` X high 4 bits in the low nibble | Y high 4 bits in the high nibble,
/// `[8]` finger id in the low nibble | finger event in the high nibble (1 press,
/// 2 hold, 0 lift). Both axes are 12-bit and already in the panel's own axes — as
/// with the CST328, no rotation or flip step follows.
pub fn parse_cst3530(report: &[u8]) -> Option<Point> {
    if report.len() < 9 || report[3] & 0x0F == 0 || report[8] & 0xF0 == CST3530_LIFT {
        return None;
    }
    let x = (report[4] as u16) | (((report[7] & 0x0F) as u16) << 8);
    let y = (report[5] as u16) | (((report[7] & 0xF0) as u16) << 4);
    Some(Point::new(x, y))
}

#[cfg(test)]
#[path = "touch_tests.rs"]
mod tests;
