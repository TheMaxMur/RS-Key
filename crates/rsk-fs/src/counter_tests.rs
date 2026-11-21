// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// Each value is where a provisioned device already keeps that counter, so a
/// changed one reads absent on the next build: a rollback on the counter.
#[test]
fn a_counter_fid_is_where_a_device_already_keeps_it() {
    assert_eq!(
        COUNTER_FIDS.map(CounterFid::get),
        [0xC000, 0xC001, 0x0093, 0xCC01]
    );
}
