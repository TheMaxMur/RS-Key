// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn control_flags_preserve_the_selector_and_endpoint_address_fields() {
    assert!(FIRST > u32::from(u16::MAX));
    assert!(LAST > u32::from(u16::MAX));
    assert_eq!(FIRST & LAST, 0);
    let operation = CTRL_IN | (0x81 << ADDRESS_SHIFT) | FIRST | LAST;
    assert_eq!(operation & 0xff, CTRL_IN);
    assert_eq!((operation >> ADDRESS_SHIFT) & 0xff, 0x81);
}

#[test]
fn keyboard_reply_flags_distinguish_an_absent_key_and_preserve_every_byte() {
    use crate::worker_abi::{KEY_ENCODE, KEY_PRESENT};

    assert_ne!(KEY_PRESENT, 0);
    assert_ne!(KEY_ENCODE, 0);
    assert_eq!(KEY_PRESENT & KEY_ENCODE, 0);
    for byte in 0..=u8::MAX {
        for encode in [false, true] {
            let reply = u32::from(byte) | KEY_PRESENT | if encode { KEY_ENCODE } else { 0 };
            assert_ne!(reply & KEY_PRESENT, 0);
            assert_eq!(reply & KEY_ENCODE != 0, encode);
            assert_eq!(reply & 0xff, u32::from(byte));
        }
    }
}

#[test]
fn status_codes_reserve_only_the_top_values_of_the_ticket_space() {
    let codes = [
        crate::worker_abi::INVALID,
        crate::worker_abi::PENDING,
        crate::worker_abi::ABANDONED,
        DISABLED,
        OVERFLOW,
    ];
    assert_eq!(codes[0], u32::MAX);
    for pair in codes.windows(2) {
        assert_eq!(pair[0].checked_sub(1), Some(pair[1]));
    }
}
