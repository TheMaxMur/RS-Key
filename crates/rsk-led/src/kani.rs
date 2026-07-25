// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// An arbitrary config (color is the only constrained field: it is a 3-bit
/// palette index by construction).
fn any_config() -> LedConfig {
    let any_status = || StatusCfg {
        effect: kani::any(),
        color: kani::any::<u8>() & 0x7,
        brightness: kani::any(),
        speed: kani::any(),
    };
    LedConfig {
        steady: kani::any(),
        status: [any_status(), any_status(), any_status(), any_status()],
    }
}

/// `apply_block(encode()) == id` for every config the codec can emit — i.e. one
/// whose touch invariants already hold, since `apply_block` enforces them.
#[kani::proof]
fn encode_apply_block_roundtrip() {
    let mut cfg = any_config();
    cfg.enforce_touch_invariants();
    let mut got = LedConfig::default();
    got.apply_block(&cfg.encode());
    assert_eq!(got, cfg);
}

/// The consent indicator stays lit, above the floor, non-degenerate, and the
/// only status in its colour — no brightness or speed nudge buys an alias.
fn assert_touch_invariant(cfg: &LedConfig) {
    let t = cfg.status[STATUS_TOUCH as usize];
    assert!(t.color != 0);
    assert!(t.brightness >= TOUCH_MIN_BRIGHTNESS);
    assert!(t.speed == SPEED_DEFAULT || t.speed >= TOUCH_MIN_SPEED);
    for (i, s) in cfg.status.iter().enumerate() {
        assert!(i == STATUS_TOUCH as usize || s.color != t.color);
    }
}

/// Whatever a host writes, the invariant holds.
#[kani::proof]
fn touch_stays_visible_and_unique() {
    let mut cfg = any_config();
    cfg.enforce_touch_invariants();
    assert_touch_invariant(&cfg);
}

/// And it holds for every accepted record length, so an older firmware's block
/// still in flash cannot decode into an aliased indicator on the upgrade boot.
#[kani::proof]
fn every_block_length_holds_the_invariant() {
    let block: [u8; CONF_LEN] = kani::any();
    for len in [0, 1, 2, 3, 9, 13, CONF_LEN] {
        let mut cfg = any_config();
        cfg.apply_block(&block[..len]);
        assert_touch_invariant(&cfg);
    }
}

/// Enforcement is a fixpoint — the round-trip proof rests on it.
#[kani::proof]
fn enforce_touch_invariants_is_idempotent() {
    let mut once = any_config();
    once.enforce_touch_invariants();
    let mut twice = once;
    twice.enforce_touch_invariants();
    assert_eq!(twice, once);
}
