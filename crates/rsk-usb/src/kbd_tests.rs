// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// The characters a Yubico OTP ticket is made of. If any of these typed nothing,
/// a ticket would arrive at the host silently short — and modhex is the whole
/// alphabet a ticket uses.
#[test]
fn every_modhex_character_types_something() {
    for c in b"cbdefghijklnrtuv" {
        assert!(keystroke(*c, true).is_some(), "{}", *c as char);
    }
}

/// A ticket ends in Enter, which is what submits the login form it was typed
/// into.
#[test]
fn a_ticket_terminator_types_enter() {
    assert_eq!(keystroke(b'\n', true), Some([0, 0, 0x28, 0, 0, 0, 0, 0]));
    assert_eq!(keystroke(b'\r', true), keystroke(b'\n', true));
}

/// Upper case is the shift modifier plus the *same* keycode as lower case, not a
/// second table — a host maps the pair, and disagreeing on the keycode types a
/// different letter.
#[test]
fn upper_case_is_the_lower_case_key_with_shift() {
    let lower = keystroke(b'k', true).unwrap();
    let upper = keystroke(b'K', true).unwrap();
    assert_eq!(lower[0], 0);
    assert_eq!(upper[0], KEYBOARD_MODIFIER_LEFTSHIFT);
    assert_eq!(lower[2], upper[2]);
}

/// The digit row is not contiguous with `0`: HID puts `1`..`9` at 0x1E..0x26 and
/// `0` at 0x27, so an off-by-one here types the wrong digit for every ticket
/// carrying a zero.
#[test]
fn the_digit_row_wraps_zero_to_the_end() {
    assert_eq!(keystroke(b'1', true).unwrap()[2], 0x1E);
    assert_eq!(keystroke(b'9', true).unwrap()[2], 0x26);
    assert_eq!(keystroke(b'0', true).unwrap()[2], 0x27);
}

/// A static password is stored as scancodes, so it must be passed through
/// untouched — mapping it as ASCII would let a keyboard layout rewrite the
/// password.
#[test]
fn a_raw_scancode_is_passed_through_with_its_shift_bit() {
    assert_eq!(keystroke(0x04, false), Some([0, 0, 0x04, 0, 0, 0, 0, 0]));
    assert_eq!(
        keystroke(0x80 | 0x04, false),
        Some([KEYBOARD_MODIFIER_LEFTSHIFT, 0, 0x04, 0, 0, 0, 0, 0])
    );
}

/// An unmapped byte types nothing rather than typing keycode 0, which a host
/// reads as "no key" in a report that claims a press.
#[test]
fn an_unmapped_byte_types_nothing() {
    assert_eq!(keystroke(0x01, true), None);
    assert_eq!(keystroke(0x00, false), None);
}
