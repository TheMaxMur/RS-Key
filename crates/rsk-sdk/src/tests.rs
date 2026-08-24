// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn default_firmware_version_is_5_7_4() {
    // The default build must keep masquerading as a current YubiKey 5; an
    // override (FW_VERSION=…) is the only thing that changes this.
    assert_eq!(FIRMWARE_VERSION, (5, 7, 4));
    assert_eq!(FIRMWARE_VERSION_U32, 0x05_07_04);
}

#[test]
fn serial4_masks_the_chip_id_to_eight_digits() {
    // The top 6 bits of byte 0 are cleared, so the serial never exceeds
    // 0x03FF_FFFF — ykman prints it as decimal and a wider value would not fit
    // the 8 digits every one of the four reporters is expected to show.
    assert_eq!(serial4([0xFF; 8]), [0x03, 0xFF, 0xFF, 0xFF]);
    assert_eq!(
        serial4([0x12, 0x34, 0x56, 0x78, 0xAA, 0xBB, 0xCC, 0xDD]),
        [0x02, 0x34, 0x56, 0x78]
    );
    assert!(u32::from_be_bytes(serial4([0xFF; 8])) <= 0x03FF_FFFF);
}
