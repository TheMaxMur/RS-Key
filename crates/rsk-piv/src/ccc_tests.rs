// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn wire_bytes_are_the_spec_shape() {
    // The exact nine bytes, pinned as a literal so the constant cannot move the
    // test with it: F0/F1/F2 zero-length (the spec defines no PIV values), F5
    // the data model number — the one element §3.1.1 requires to carry a value.
    assert_eq!(CCC, [0xF0, 0x00, 0xF1, 0x00, 0xF2, 0x00, 0xF5, 0x01, 0x10]);
}

#[test]
fn is_wellformed_tlv_in_table_order() {
    // Table 8 order, mandatory elements only; unused optional elements absent.
    let mut i = 0;
    for (tag, len) in [(0xF0u8, 0usize), (0xF1, 0), (0xF2, 0), (0xF5, 1)] {
        assert_eq!(CCC[i], tag, "tag at {i}");
        assert_eq!(CCC[i + 1] as usize, len, "len at {i}");
        i += 2 + len;
    }
    assert_eq!(i, CCC.len(), "TLVs must cover the whole object exactly");
}
