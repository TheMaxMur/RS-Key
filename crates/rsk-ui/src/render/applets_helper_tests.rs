// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn direct_numeric_formatters_refuse_short_windows_without_partial_text() {
    let mut output = [0xa5; 32];
    for room in 0..="sig 4294967295".len() {
        output.fill(0xa5);
        let formatted = fmt_labeled("sig", u32::MAX, &mut output[..room]);
        assert_eq!(
            formatted,
            if room < "sig 4294967295".len() {
                ""
            } else {
                "sig 4294967295"
            }
        );
        if room < "sig 4294967295".len() {
            assert_eq!(output, [0xa5; 32]);
        }
        assert_eq!(&output[room..], &[0xa5; 32][room..]);
    }
    for room in 0..="PIN 255/255".len() {
        output.fill(0xa5);
        let formatted = fmt_pair("PIN", 255, 255, &mut output[..room]);
        assert_eq!(
            formatted,
            if room < "PIN 255/255".len() {
                ""
            } else {
                "PIN 255/255"
            }
        );
        if room < "PIN 255/255".len() {
            assert_eq!(output, [0xa5; 32]);
        }
        assert_eq!(&output[room..], &[0xa5; 32][room..]);
    }
}

#[test]
fn grouped_hex_never_writes_outside_a_direct_short_window() {
    for (room, expected) in [(0, ""), (4, "1234"), (9, "1234 ABCD")] {
        let mut output = [0xa5; 16];
        assert_eq!(
            fmt_hex_grouped(&[0x12, 0x34, 0xab, 0xcd], &mut output[..room]),
            expected
        );
        assert_eq!(&output[room..], &[0xa5; 16][room..]);
    }
    let mut output = [0xa5; 1];
    assert_eq!(fmt_hex_grouped(&[0x12], &mut output), "");
    assert_eq!(output, [0xa5; 1]);
}
