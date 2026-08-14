// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn the_press_bump_stops_below_the_reserved_high_bit() {
    // Only the wrapping press touches the counter.
    assert_eq!(next_use_counter(5, 0), (5, 1, false));
    assert_eq!(next_use_counter(5, 254), (5, 255, false));
    assert_eq!(next_use_counter(5, 255), (6, 0, true));
    // At the ceiling it declines rather than storing 0x8000.
    assert_eq!(
        next_use_counter(USE_COUNTER_MAX - 1, 255),
        (USE_COUNTER_MAX, 0, true)
    );
    assert_eq!(
        next_use_counter(USE_COUNTER_MAX, 255),
        (USE_COUNTER_MAX, 0, false)
    );
}

#[test]
fn both_writers_stop_at_the_same_value() {
    // The defect this pins: the press bump guarded the counter it already had
    // and the boot bump the one it was about to store, so they disagreed by one
    // and the press bump could store a value the boot bump then never advanced.
    for stored in [0u16, 1, 5, USE_COUNTER_MAX - 1, USE_COUNTER_MAX] {
        let (pressed, session, persist) = next_use_counter(stored, 255);
        assert_eq!(session, 0);
        let booted = boot_use_counter(stored);
        assert_eq!(persist, booted.is_some(), "stored {stored:#06X}");
        assert_eq!(pressed, booted.unwrap_or(stored), "stored {stored:#06X}");
    }
}
