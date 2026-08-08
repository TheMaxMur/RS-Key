// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// `63Cx` carries the remaining attempts in SW2's low nibble, so a count that does
/// not fit must saturate rather than overflow into SW1's neighbours: unclamped,
/// 0x10 reports "0 left" and 0x40 IS `63C0`, which every host reads as blocked —
/// the device would claim a PIN is dead while it still has 64 attempts.
#[test]
fn retries_saturate_at_the_nibble() {
    assert_eq!(Sw::retries(0), Sw::new(0x63, 0xC0));
    assert_eq!(Sw::retries(3), Sw::new(0x63, 0xC3));
    assert_eq!(Sw::retries(RETRIES_REPORTED_MAX), Sw::new(0x63, 0xCF));
    // Past the nibble every count reports the ceiling, never a lower one.
    for left in RETRIES_REPORTED_MAX + 1..=u8::MAX {
        assert_eq!(
            Sw::retries(left),
            Sw::new(0x63, 0xCF),
            "retries({left}) escaped the nibble"
        );
    }
}
