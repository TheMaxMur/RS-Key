// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The click gesture, and the one rule that shares the button with a ceremony.

use super::*;

/// The firmware's idle cadence (`BTN_POLL_MS`), so a tick count reads as time.
const POLL_MS: u64 = 16;

/// Drive `n` polls at `pressed`, returning any slot the gesture fired.
fn run(c: &mut Clicks, now: &mut u64, n: usize, pressed: bool) -> Option<u8> {
    let mut fired = None;
    for _ in 0..n {
        *now += POLL_MS;
        if let Some(slot) = c.tick(*now, pressed) {
            fired = Some(slot);
        }
    }
    fired
}

/// One click types slot 1, and only after the window closes.
#[test]
fn one_click_fires_slot_one_when_the_window_closes() {
    let mut c = Clicks::new();
    let mut now = 0;
    assert_eq!(
        run(&mut c, &mut now, 3, true),
        None,
        "a held button is no click"
    );
    assert_eq!(
        run(&mut c, &mut now, 3, false),
        None,
        "fired inside the window"
    );
    assert_eq!(
        run(
            &mut c,
            &mut now,
            CLICK_WINDOW_MS as usize / POLL_MS as usize,
            false
        ),
        Some(1)
    );
}

/// Two clicks inside the window are slot 2.
#[test]
fn two_clicks_inside_the_window_are_slot_two() {
    let mut c = Clicks::new();
    let mut now = 0;
    run(&mut c, &mut now, 2, true);
    run(&mut c, &mut now, 2, false);
    run(&mut c, &mut now, 2, true);
    run(&mut c, &mut now, 2, false);
    assert_eq!(run(&mut c, &mut now, 70, false), Some(2));
}

/// The rule this module exists for: a touch wait can return with the finger still
/// down, and the release that press produces is the ceremony's, not a gesture. The
/// firmware used to clear the accumulated counters here, which cannot suppress an
/// edge that has not happened yet — so a consent press typed slot 1's one-time
/// password into whatever had focus.
#[test]
fn the_release_of_a_press_a_ceremony_consumed_is_not_a_click() {
    let mut c = Clicks::new();
    let mut now = 0;
    // A dispatch ran while the operator held the button and ended with it down.
    c.consumed_by_ceremony(true);
    // Idle again: the finger is still down for a while, then lifts.
    assert_eq!(run(&mut c, &mut now, 4, true), None);
    assert_eq!(
        run(&mut c, &mut now, 200, false),
        None,
        "the consent press typed a ticket"
    );
}

/// …and the button still works afterwards: the mark is one-shot.
#[test]
fn the_next_press_after_a_consumed_one_is_a_click_again() {
    let mut c = Clicks::new();
    let mut now = 0;
    c.consumed_by_ceremony(true);
    run(&mut c, &mut now, 2, true);
    run(&mut c, &mut now, 2, false); // the ceremony's release, swallowed
    run(&mut c, &mut now, 2, true); // a fresh press
    run(&mut c, &mut now, 2, false);
    assert_eq!(run(&mut c, &mut now, 70, false), Some(1));
}

/// A dispatch that ends with the button already up marks nothing — otherwise the
/// operator's next real click would be swallowed instead.
#[test]
fn a_dispatch_that_ends_with_the_button_up_swallows_nothing() {
    let mut c = Clicks::new();
    let mut now = 0;
    c.consumed_by_ceremony(false);
    run(&mut c, &mut now, 2, true);
    run(&mut c, &mut now, 2, false);
    assert_eq!(run(&mut c, &mut now, 70, false), Some(1));
}

/// A gesture in progress when a dispatch arrives is dropped, not carried across it.
#[test]
fn a_dispatch_drops_a_gesture_it_interrupted() {
    let mut c = Clicks::new();
    let mut now = 0;
    run(&mut c, &mut now, 2, true);
    run(&mut c, &mut now, 2, false);
    c.consumed_by_ceremony(false);
    assert_eq!(run(&mut c, &mut now, 200, false), None);
}
