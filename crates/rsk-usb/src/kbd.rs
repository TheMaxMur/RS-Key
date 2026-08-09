// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The emulated-keyboard (Yubico-OTP) HID interface's report descriptor.
//!
//! Interface 0 on every build that has it, because the libusb backend
//! `ykpers`/`ykcore` ships claims interface 0 and sends OTP frame reports there
//! blind — the reorder that fixed issue #55. It lives here rather than in the
//! firmware because the emulator declares the same interface, in the same place,
//! and an interface order described twice is an interface order that drifts.

/// HID keyboard report descriptor: a standard boot keyboard (8-byte input report,
/// LED output) with an 8-byte vendor FEATURE report appended for the OTP frame
/// protocol. The top-level usage is Generic-Desktop / Keyboard `(0x01, 0x06)`,
/// which is what `ykman` matches to find the OTP HID interface.
pub const KEYBOARD_REPORT_DESCRIPTOR: &[u8] = &[
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x06, // Usage (Keyboard)
    0xA1, 0x01, // Collection (Application)
    0x05, 0x07, //   Usage Page (Keyboard/Keypad)
    0x19, 0xE0, //   Usage Minimum (224, Left Control)
    0x29, 0xE7, //   Usage Maximum (231, Right GUI)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x01, //   Logical Maximum (1)
    0x75, 0x01, //   Report Size (1)
    0x95, 0x08, //   Report Count (8)
    0x81, 0x02, //   Input (Data,Var,Abs)  — modifier byte
    0x95, 0x01, //   Report Count (1)
    0x75, 0x08, //   Report Size (8)
    0x81, 0x01, //   Input (Const)         — reserved byte
    0x05, 0x08, //   Usage Page (LEDs)
    0x19, 0x01, //   Usage Minimum (1)
    0x29, 0x05, //   Usage Maximum (5)
    0x95, 0x05, //   Report Count (5)
    0x75, 0x01, //   Report Size (1)
    0x91, 0x02, //   Output (Data,Var,Abs) — LED report
    0x95, 0x01, //   Report Count (1)
    0x75, 0x03, //   Report Size (3)
    0x91, 0x01, //   Output (Const)        — LED padding
    0x05, 0x07, //   Usage Page (Keyboard/Keypad)
    0x19, 0x00, //   Usage Minimum (0)
    0x29, 0xFF, //   Usage Maximum (255)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, // Logical Maximum (255)
    0x95, 0x06, //   Report Count (6)
    0x75, 0x08, //   Report Size (8)
    0x81, 0x00, //   Input (Data,Array)    — 6 keycodes
    0x06, 0x00, 0xFF, // Usage Page (Vendor 0xFF00)
    0x09, 0x01, //   Usage (1)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, // Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x08, //   Report Count (8)
    0xB1, 0x02, //   Feature (Data,Var,Abs) — the 8-byte OTP frame report
    0xC0, //       End Collection
];

/// Left-Shift in the report's modifier byte — the keystroke builder's half of
/// the descriptor above.
pub const KEYBOARD_MODIFIER_LEFTSHIFT: u8 = 0x02;

/// The boot-keyboard input report: `[modifier, reserved, keycode, 0, 0, 0, 0, 0]`.
pub const KEYBOARD_REPORT_SIZE: usize = 8;

/// Raw-scancode marker: a static-password slot stores scancodes, and the high bit
/// means "with shift".
const SCANCODE_SHIFT: u8 = 0x80;

/// ASCII → (left-shift?, HID keycode) for the characters a typed ticket can
/// contain (modhex letters, digits, CR) plus the rest of the printable set for
/// completeness; unmapped bytes type nothing.
fn ascii_to_keycode(c: u8) -> (bool, u8) {
    match c {
        b'a'..=b'z' => (false, 0x04 + (c - b'a')),
        b'A'..=b'Z' => (true, 0x04 + (c - b'A')),
        b'1'..=b'9' => (false, 0x1E + (c - b'1')),
        b'0' => (false, 0x27),
        b'\n' | b'\r' => (false, 0x28), // Enter
        0x1B => (false, 0x29),          // Esc
        0x08 => (false, 0x2A),          // Backspace
        b'\t' => (false, 0x2B),
        b' ' => (false, 0x2C),
        b'-' => (false, 0x2D),
        b'=' => (false, 0x2E),
        b'[' => (false, 0x2F),
        b']' => (false, 0x30),
        b'\\' => (false, 0x31),
        b';' => (false, 0x33),
        b'\'' => (false, 0x34),
        b'`' => (false, 0x35),
        b',' => (false, 0x36),
        b'.' => (false, 0x37),
        b'/' => (false, 0x38),
        b'!' => (true, 0x1E),
        b'@' => (true, 0x1F),
        b'#' => (true, 0x20),
        b'$' => (true, 0x21),
        b'%' => (true, 0x22),
        b'^' => (true, 0x23),
        b'&' => (true, 0x24),
        b'*' => (true, 0x25),
        b'(' => (true, 0x26),
        b')' => (true, 0x27),
        b'_' => (true, 0x2D),
        b'+' => (true, 0x2E),
        b'{' => (true, 0x2F),
        b'}' => (true, 0x30),
        b'|' => (true, 0x31),
        b':' => (true, 0x33),
        b'"' => (true, 0x34),
        b'~' => (true, 0x35),
        b'<' => (true, 0x36),
        b'>' => (true, 0x37),
        b'?' => (true, 0x38),
        _ => (false, 0),
    }
}

/// The key-press report for `byte`, or `None` if it maps to no key.
///
/// `encode` true → `byte` is ASCII, mapped through the table above (a typed
/// ticket); false → `byte` is already a HID scancode with [`SCANCODE_SHIFT`] for
/// the modifier (a static password, which is stored as scancodes precisely so a
/// keyboard layout cannot rewrite it).
///
/// The release report is `[0; 8]`, which every caller sends next — it is not
/// returned here because there is nothing to compute about it.
pub fn keystroke(byte: u8, encode: bool) -> Option<[u8; KEYBOARD_REPORT_SIZE]> {
    let (shift, keycode) = if encode {
        ascii_to_keycode(byte)
    } else {
        (byte & SCANCODE_SHIFT != 0, byte & !SCANCODE_SHIFT)
    };
    if keycode == 0 {
        return None;
    }
    let mut report = [0u8; KEYBOARD_REPORT_SIZE];
    report[0] = if shift {
        KEYBOARD_MODIFIER_LEFTSHIFT
    } else {
        0
    };
    report[2] = keycode;
    Some(report)
}

#[cfg(test)]
#[path = "kbd_tests.rs"]
mod tests;
