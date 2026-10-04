// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn the_build_aaguid_parser_preserves_every_nibble() {
    let text = "0123456789abcdef0123456789abcdef";
    assert_eq!(
        parse_aaguid(std::hint::black_box(text)),
        [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef
        ]
    );
    for byte in 0..=u8::MAX {
        let expected = b"0123456789abcdef"
            .iter()
            .position(|&digit| digit == byte)
            .unwrap_or(0);
        assert_eq!(
            usize::from(hex_nibble(std::hint::black_box(byte))),
            expected
        );
    }
}
