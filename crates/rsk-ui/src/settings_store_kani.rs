// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// `apply_block(encode()) == id` for every config: the round-trip never loses
/// or corrupts a field.
#[kani::proof]
fn encode_apply_block_roundtrip() {
    let cfg = DisplayConfig {
        brightness: kani::any(),
        sleep_secs: kani::any(),
        pin_declined: kani::any(),
        scramble_pin: kani::any(),
    };
    let mut got = DisplayConfig::default();
    got.apply_block(&cfg.encode());
    assert_eq!(got, cfg);
}
