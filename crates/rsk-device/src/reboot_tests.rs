// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn an_empty_slot_has_nothing_to_take() {
    let slot = RebootSlot::new();
    assert_eq!((slot.pending(), slot.take()), (false, None));
}

/// The worker takes a request once; the reset it began keeps the slot pending, and a second
/// take has nothing to run.
#[test]
fn a_taken_request_stays_pending_until_the_reset() {
    let slot = RebootSlot::new();
    slot.queue(true);
    let taken = slot.take();
    assert_eq!(
        (taken, slot.pending(), slot.take()),
        (Some(2), true, None),
        "taking the reboot must not clear the slot the panel parks on"
    );
}

/// The TRNG fault's request: a warm reboot on an idle slot, and nothing over a queued BOOTSEL
/// drop (the panel's firmware install) or a reset under way, both of which scrub and reset.
#[test]
fn a_warm_request_unless_pending_keeps_what_is_queued() {
    let idle = RebootSlot::new();
    idle.queue_warm_unless_pending();
    assert_eq!(
        idle.take(),
        Some(1),
        "an idle slot must queue the warm reboot"
    );

    let bootsel = RebootSlot::new();
    bootsel.queue(true);
    bootsel.queue_warm_unless_pending();
    assert_eq!(
        bootsel.take(),
        Some(2),
        "a queued BOOTSEL drop must keep its mode"
    );

    let resetting = RebootSlot::new();
    resetting.begin_reset();
    resetting.queue_warm_unless_pending();
    assert_eq!(
        (resetting.pending(), resetting.take()),
        (true, None),
        "a reset under way must not be queued again"
    );
}

/// A reset the worker begins with no request queued still reads pending: the panel parks on
/// the reset under way, not on the request.
#[test]
fn a_reset_begun_without_a_request_reads_pending() {
    let slot = RebootSlot::new();
    slot.begin_reset();
    assert_eq!(
        (slot.pending(), slot.take()),
        (true, None),
        "a begun reset must read pending and give the worker nothing to take"
    );
}
