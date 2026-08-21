// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the phy TLV codec directly (`PhyData::parse` / `serialize`) — the
//! attacker-controlled config record behind rescue WRITE 0x1C P1=0x01. The
//! parse must never panic or overread, and a parsed record must re-serialize
//! into a buffer it round-trips from (parse ∘ serialize = identity on the
//! parsed value).

use libfuzzer_sys::fuzz_target;
use rsk_phy::{PHY_MAX_SIZE, PhyData};

fuzz_target!(|data: &[u8]| {
    let phy = PhyData::parse(data);
    let mut buf = [0u8; PHY_MAX_SIZE];
    let n = phy.serialize(&mut buf).expect("PHY_MAX_SIZE always fits");
    assert_eq!(PhyData::parse(&buf[..n]), phy);
});
