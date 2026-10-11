// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn direct_unsigned_large_blob_lookup_skips_unknown_fields_and_refuses_bad_values() {
    for body in [
        &b"\xa0"[..],
        &b"\xa1\x06\x00"[..],
        &b"\xa1\x06\xa1\x00\x00"[..],
        &b"\xa1\x06\xa1\x66future\x81"[..],
        &b"\xa1\x06\xa1\x66future\xf6"[..],
    ] {
        assert_eq!(unsigned_large_blob(body, 6), None);
    }
    let body = b"\xa1\x06\xa2\x66future\xf6\x69largeBlob\xa1\x69supported\xf5";
    assert_eq!(
        unsigned_large_blob(body, 6),
        Some(b"\xa1\x69supported\xf5".to_vec())
    );
}
