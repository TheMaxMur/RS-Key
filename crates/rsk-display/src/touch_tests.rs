// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{DeadlinePad, Pad, center};

#[test]
fn a_release_wait_stops_at_the_first_untouched_sample() {
    let p = center(rsk_ui::ALLOW_RECT);
    let mut pad = Pad::script(&[Some(p), Some(p), None, Some(p)]);
    pad.wait_release(Instant::now(), Duration::from_secs(30));
    assert_eq!(pad.reads, 3, "one tap must map to one key press");
}

#[test]
fn a_release_wait_is_bounded_by_its_deadline() {
    // A finger resting on the glass must not hold the UI for ever.
    let mut pad = Pad::held(center(rsk_ui::ALLOW_RECT));
    let start = Instant::now();
    pad.wait_release(start, Duration::from_millis(50));
    assert!(start.elapsed() < RELEASE_FLOOR_MS);
    assert!(pad.reads > 0);
}

#[test]
fn a_menu_release_wait_takes_the_deadline_it_is_given() {
    // Only the consent ceremonies take the floor: a menu's deadline is the UI's own
    // idle limit, and stalling it on a resting finger would be a UI bug.
    let mut pad = DeadlinePad::default();
    let start = Instant::now();
    let timeout = Duration::from_millis(100);
    pad.wait_release(start, timeout);
    assert_eq!(pad.deadline, Some(start + timeout));
}

#[test]
fn a_ceremony_release_wait_never_falls_below_the_floor() {
    // A host can shorten the presence timeout to nothing. The debounce a consent
    // ceremony leans on must not shrink with it — an expiry that returns with the
    // finger still down degrades it into a no-op for a level-triggered caller.
    let mut pad = DeadlinePad::default();
    let start = Instant::now();
    pad.wait_release_ceremony(start, Duration::from_millis(1));
    let deadline = pad
        .deadline
        .expect("a ceremony always waits for the release");
    assert!(deadline >= start + RELEASE_FLOOR_MS);
}

#[test]
fn a_generous_ceremony_timeout_is_its_own_deadline() {
    // The floor is a minimum, not a replacement: a long presence timeout still
    // bounds the wait, or a ceremony would outlive the deadline it was given.
    let mut pad = DeadlinePad::default();
    let start = Instant::now();
    let timeout = Duration::from_secs(30);
    pad.wait_release_ceremony(start, timeout);
    assert_eq!(pad.deadline, Some(start + timeout));
}
