// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[kani::proof]
fn clearing_force_preserves_complexity_and_floor() {
    let policy = Policy {
        min: kani::any(),
        force: kani::any(),
        complexity: kani::any(),
    };
    let flags = policy.flags() & !FORCE_CHANGE;
    let after = Policy::decode(&[policy.min, flags]);
    assert_eq!(after.min, policy.min);
    assert!(!after.force);
    assert_eq!(after.complexity, policy.complexity || PIN_COMPLEXITY_POLICY);
}

#[kani::proof]
fn legacy_flags_do_not_enable_complexity() {
    let min: u8 = kani::any();
    let force: bool = kani::any();
    let policy = Policy::decode(&[min, u8::from(force)]);
    assert_eq!(policy.min, min);
    assert_eq!(policy.force, force);
    assert_eq!(policy.complexity, PIN_COMPLEXITY_POLICY);
}
