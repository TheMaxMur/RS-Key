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
