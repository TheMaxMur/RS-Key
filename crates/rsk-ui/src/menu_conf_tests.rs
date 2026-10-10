// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn a_record_round_trips() {
    let conf = MenuConf {
        delay_idx: 1,
        flip: true,
    };
    let rec = conf.encode();
    assert_eq!(MenuConf::decode(&rec, rec.len()), conf);
    assert_eq!(conf.delay_ms(), 5_000);
}

#[test]
fn a_missing_record_keeps_the_defaults() {
    let rec = [0u8; 2];
    assert_eq!(MenuConf::decode(&rec, 0), MenuConf::default());
    assert_eq!(MenuConf::default().delay_ms(), 30_000);
}

#[test]
fn a_one_byte_record_from_an_older_build_still_loads() {
    // The flip byte did not exist yet: the delay is read, the flip stays off.
    let rec = [1u8, 1];
    let conf = MenuConf::decode(&rec, 1);
    assert_eq!(conf.delay_idx, 1);
    assert!(!conf.flip, "a byte the record does not carry is not a flip");
}

#[test]
fn an_index_this_build_does_not_list_falls_back_per_field() {
    // A newer build wrote a longer delay table: the delay falls back, the flip
    // (which is a flag, not an index) is still honoured.
    let rec = [9u8, 1];
    let conf = MenuConf::decode(&rec, 2);
    assert_eq!(conf.delay_idx, DEFAULT_DELAY_IDX as u8);
    assert!(conf.flip);
    assert_eq!(conf.delay_ms(), 30_000);
}

#[test]
fn delay_ms_is_total_on_a_hand_built_index() {
    let conf = MenuConf {
        delay_idx: 200,
        flip: false,
    };
    assert_eq!(conf.delay_ms(), 30_000);
}
