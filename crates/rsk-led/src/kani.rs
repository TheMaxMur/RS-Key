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

/// And it holds for **every** accepted record length, so no block left in flash
/// by another firmware — older or newer — can decode into an aliased indicator
/// on the upgrade boot.
///
/// Every length, not the seven this used to name. That list was not the set of
/// behaviours: the pre-effect arm computes `n = (len - 1) / 2` and updates only
/// `n.min(N_STATUS)` statuses, so a 7- or 8-byte record leaves the last status
/// holding whatever the live config had — the one shape where an old record and
/// a running config mix, and the one the list skipped. 10, 11, 12, 14, 15 and 16
/// went unvisited too, and `CONF_LEN + 1`, a longer record from a future format,
/// was not reachable at all.
///
/// The lengths are concrete and swept rather than symbolic. A symbolic `len`
/// makes `&block[..len]` a symbolic-length slice and every index into it
/// symbolic with it: measured at over 4 minutes without converging, against
/// well under a second for the whole sweep. The domain is 19 values; enumerating
/// it is exhaustive over exactly the same set.
#[kani::proof]
fn every_block_length_holds_the_invariant() {
    // Two past CONF_LEN: a record a later format made longer still takes the
    // first arm, and must still land on a lawful config.
    let block: [u8; CONF_LEN + 2] = kani::any();
    for len in 0..=CONF_LEN + 2 {
        let mut cfg = any_config();
        cfg.apply_block(&block[..len]);
        assert_touch_invariant(&cfg);
    }
}

/// `CTAPHID_WINK` is ungated, so the bound on a burst is the only thing between a
/// flooding host and the reserved touch colour held solid. Prove the arm cannot
/// extend a live burst over every (deadline, now) pair — the wrapping millisecond
/// counter is exactly where a loop test stops covering.
#[kani::proof]
fn wink_arm_never_extends_a_running_burst() {
    let end: u32 = kani::any();
    let now: u32 = kani::any();
    if wink_running(end, now) {
        assert_eq!(wink_arm(end, now), end);
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
