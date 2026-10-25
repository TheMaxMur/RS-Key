// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[path = "../../fuzz_targets/sha256_oracle.rs"]
mod oracle;

#[test]
fn miri_sha256_diff() {
    let patterned: Vec<_> = (0..512)
        .map(|i| u8::try_from(i % 256).unwrap().wrapping_mul(37))
        .collect();
    for data in [
        &b""[..],
        b"abc",
        &[0xa5; 55],
        &[0x5a; 56],
        &[0xa5; 64],
        &[0x5a; 257],
        patterned.as_slice(),
    ] {
        oracle::check(data, sha256(data));
    }
}
