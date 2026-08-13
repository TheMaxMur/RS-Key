// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The characterisation table for the presence arbitration, row by row.
//!
//! These were written against `firmware/src/presence.rs` as it stood before the
//! lift (read, not run — `firmware` does not build on the host), so they are the
//! specification the moved code is held to rather than a description of it.

use super::*;

extern crate std;
use std::vec;
use std::vec::Vec;

/// A transport event, fired between two poll iterations — the point where the
/// real device's high-priority executor runs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ev {
    None,
    FidoCancel,
    OtpCancel,
    Scope(u8),
}

/// A scripted board. `presses` is consumed one entry per [`Board::pressed`] call
/// and its last entry repeats forever; the clock only advances inside
/// [`Board::block_for_ms`], which is also where `events[n]` fires.
struct TestBoard<'a> {
    arb: &'a Arbiter,
    presses: Vec<bool>,
    samples: usize,
    events: Vec<Ev>,
    delays: usize,
    now_us: u64,
    /// `pending_for(scope)` as seen by a transport between iterations.
    saw_pending: [bool; 4],
}

impl<'a> TestBoard<'a> {
    fn new(arb: &'a Arbiter, presses: Vec<bool>) -> Self {
        Self {
            arb,
            presses,
            samples: 0,
            events: Vec::new(),
            delays: 0,
            now_us: 0,
            saw_pending: [false; 4],
        }
    }

    fn with_events(mut self, events: Vec<Ev>) -> Self {
        self.events = events;
        self
    }

    /// What a transport would read if it ran right now.
    fn observe(&mut self) {
        for (s, seen) in self.saw_pending.iter_mut().enumerate() {
            *seen |= self.arb.pending_for(s as u8);
        }
    }
}

impl Board for TestBoard<'_> {
    fn pressed(&mut self) -> bool {
        let i = self.samples.min(self.presses.len().saturating_sub(1));
        self.samples += 1;
        self.presses.get(i).copied().unwrap_or(false)
    }

    fn now_us(&self) -> u64 {
        self.now_us
    }

    fn block_for_ms(&mut self, ms: u64) {
        self.observe();
        match self.events.get(self.delays).copied().unwrap_or(Ev::None) {
            Ev::None => {}
            Ev::FidoCancel => self.arb.request_cancel(),
            Ev::OtpCancel => self.arb.cancel_otp_wait(),
            Ev::Scope(s) => self.arb.set_wait_scope(s),
        }
        self.observe();
        self.delays += 1;
        self.now_us += ms * US_PER_MS;
    }
}

/// An arbiter scoped to `scope` with a short budget: `polls` iterations of
/// [`POLL_MS`] before the deadline.
fn armed(scope: u8, polls: u32) -> Arbiter {
    let arb = Arbiter::new();
    arb.set_wait_scope(scope);
    arb.set_timeout_ms(polls * POLL_MS as u32);
    arb
}

const SCOPES: [u8; 4] = [SCOPE_NONE, SCOPE_FIDO, SCOPE_CCID, SCOPE_OTP];

// ---------------------------------------------------------------- A1, A2

#[test]
fn a2_nothing_is_pending_on_a_fresh_arbiter() {
    let arb = Arbiter::new();
    for s in SCOPES {
        assert!(!arb.pending_for(s), "scope {s} pending on a fresh arbiter");
    }
}

#[test]
fn a2_pending_is_true_only_for_the_scope_that_owns_the_wait() {
    for owner in SCOPES {
        let arb = Arbiter::new();
        arb.set_wait_scope(owner);
        arb.set_up_pending(true);
        for s in SCOPES {
            assert_eq!(
                arb.pending_for(s),
                s == owner,
                "scope {s} asked about a wait owned by {owner}"
            );
        }
    }
}

#[test]
fn a2_the_scope_alone_never_advertises_a_wait() {
    for owner in SCOPES {
        let arb = Arbiter::new();
        arb.set_wait_scope(owner);
        assert!(
            !arb.pending_for(owner),
            "scope {owner} pending with no wait"
        );
    }
}

// ---------------------------------------------------------------- A5..A8

#[test]
fn a5_a6_request_cancel_only_bites_under_the_fido_scope() {
    for s in SCOPES {
        let arb = Arbiter::new();
        arb.set_wait_scope(s);
        arb.set_up_pending(true);
        arb.request_cancel();
        assert_eq!(
            arb.cancel_requested(),
            s == SCOPE_FIDO,
            "CTAPHID_CANCEL reached a wait scoped to {s}"
        );
        // Only `cancel_otp_wait` retracts the advertisement.
        assert!(arb.pending_for(s), "request_cancel cleared up_pending");
    }
}

#[test]
fn a7_a8_cancel_otp_wait_only_bites_under_the_otp_scope() {
    for s in SCOPES {
        let arb = Arbiter::new();
        arb.set_wait_scope(s);
        arb.set_up_pending(true);
        arb.cancel_otp_wait();
        assert_eq!(
            arb.cancel_requested(),
            s == SCOPE_OTP,
            "an OTP abort reached a wait scoped to {s}"
        );
        assert_eq!(
            arb.pending_for(s),
            s != SCOPE_OTP,
            "up_pending after an OTP abort under scope {s}"
        );
    }
}

// ---------------------------------------------------------------- A9, A10

#[test]
fn a9_a10_the_timeout_floor() {
    for (secs, want_ms) in [
        (0u8, DEFAULT_TIMEOUT_MS),
        (1, 10_000),
        (9, 10_000),
        (10, 10_000),
        (11, 11_000),
        (30, 30_000),
        (255, 255_000),
    ] {
        let arb = Arbiter::new();
        arb.set_timeout_secs(secs);
        assert_eq!(arb.timeout_ms(), want_ms, "set_timeout_secs({secs})");
    }
}

// ---------------------------------------------------------------- W1, W8

#[test]
fn w1_a_cancel_left_from_an_earlier_request_is_dropped_at_entry() {
    let arb = armed(SCOPE_FIDO, 2);
    arb.request_cancel();
    assert!(arb.cancel_requested());
    let mut board = TestBoard::new(&arb, vec![false]);
    // No cancel fires during the wait, so the stale one must not end it.
    assert_eq!(ButtonWait::new().wait(&arb, &mut board), Outcome::Timeout);
}

#[test]
fn w8_a_cancel_that_raced_in_does_not_leak_into_the_next_wait() {
    let arb = armed(SCOPE_FIDO, 4);
    let mut latch = ButtonWait::new();
    // Confirm on the first sample; the hold survives one debounce poll, which is
    // where the cancel lands — after the outcome was decided, so it can only
    // affect what the *next* wait sees.
    let mut board = TestBoard::new(&arb, vec![true, true, false]).with_events(vec![Ev::FidoCancel]);
    assert_eq!(latch.wait(&arb, &mut board), Outcome::Confirmed);
    assert_eq!(
        board.delays, 1,
        "the debounce gave the cancel no slice to land in"
    );
    assert!(!arb.cancel_requested(), "the cancel survived the wait");
}

// ---------------------------------------------------------------- W2, W7

#[test]
fn w2_w7_the_wait_advertises_itself_to_its_own_scope_and_stops_after() {
    for owner in SCOPES {
        let arb = armed(owner, 2);
        let mut board = TestBoard::new(&arb, vec![false]);
        assert_eq!(ButtonWait::new().wait(&arb, &mut board), Outcome::Timeout);
        for s in SCOPES {
            assert_eq!(
                board.saw_pending[s as usize],
                s == owner,
                "scope {s} saw a wait owned by {owner}"
            );
            assert!(!arb.pending_for(s), "still advertising after the wait");
        }
    }
}

// ---------------------------------------------------------------- W4a..W4d

#[test]
fn w4a_a_press_on_the_first_sample_confirms() {
    let arb = armed(SCOPE_FIDO, 4);
    let mut board = TestBoard::new(&arb, vec![true, false]);
    assert_eq!(ButtonWait::new().wait(&arb, &mut board), Outcome::Confirmed);
}

#[test]
fn w4a_a_press_beats_a_cancel_and_a_deadline_in_the_same_iteration() {
    let arb = armed(SCOPE_FIDO, 1);
    // The cancel fires in the only delay, so iteration 2 has both a press and a
    // live cancel, and the deadline has passed.
    let mut board =
        TestBoard::new(&arb, vec![false, true, false]).with_events(vec![Ev::FidoCancel]);
    assert_eq!(ButtonWait::new().wait(&arb, &mut board), Outcome::Confirmed);
}

#[test]
fn w4c_a_cancel_from_the_owning_transport_ends_the_wait() {
    for (owner, ev) in [(SCOPE_FIDO, Ev::FidoCancel), (SCOPE_OTP, Ev::OtpCancel)] {
        let arb = armed(owner, 8);
        let mut board = TestBoard::new(&arb, vec![false]).with_events(vec![ev]);
        assert_eq!(
            ButtonWait::new().wait(&arb, &mut board),
            Outcome::Cancelled,
            "{owner} could not cancel its own wait"
        );
    }
}

#[test]
fn w4c_no_cancel_crosses_a_transport_boundary() {
    // Every (owner, canceller) pair the two host-reachable cancels can form.
    for owner in SCOPES {
        for ev in [Ev::FidoCancel, Ev::OtpCancel] {
            let owns = (owner == SCOPE_FIDO && ev == Ev::FidoCancel)
                || (owner == SCOPE_OTP && ev == Ev::OtpCancel);
            if owns {
                continue;
            }
            let arb = armed(owner, 2);
            let mut board = TestBoard::new(&arb, vec![false]).with_events(vec![ev, ev, ev]);
            assert_eq!(
                ButtonWait::new().wait(&arb, &mut board),
                Outcome::Timeout,
                "{ev:?} ended a wait owned by {owner}"
            );
        }
    }
}

#[test]
fn w4d_no_press_and_no_cancel_times_out_on_the_budget() {
    let arb = armed(SCOPE_CCID, 3);
    let mut board = TestBoard::new(&arb, vec![false]);
    assert_eq!(ButtonWait::new().wait(&arb, &mut board), Outcome::Timeout);
    assert_eq!(board.delays, 3, "the budget was not spent exactly");
}

// ---------------------------------------------------------------- the latch

#[test]
fn w4a_a_spent_hold_confirms_nothing_until_the_finger_lifts() {
    let arb = armed(SCOPE_FIDO, 6);
    let mut latch = ButtonWait::new();

    // Ceremony 1: press, and the finger never lifts — the debounce gives up.
    let mut b1 = TestBoard::new(&arb, vec![true]);
    assert_eq!(latch.wait(&arb, &mut b1), Outcome::Confirmed);

    // Ceremony 2, same hold: it is spent, so this one can only time out.
    let mut b2 = TestBoard::new(&arb, vec![true]);
    assert_eq!(latch.wait(&arb, &mut b2), Outcome::Timeout);
}

#[test]
fn w4b_the_latch_clears_on_the_release_and_the_next_iteration_confirms() {
    let arb = armed(SCOPE_FIDO, 8);
    let mut latch = ButtonWait::new();
    let mut b1 = TestBoard::new(&arb, vec![true]);
    assert_eq!(latch.wait(&arb, &mut b1), Outcome::Confirmed);

    // Held for one more sample, then released, then pressed again.
    let mut b2 = TestBoard::new(&arb, vec![true, false, true, false]);
    assert_eq!(latch.wait(&arb, &mut b2), Outcome::Confirmed);
}

#[test]
fn w4b_the_release_iteration_cannot_itself_confirm() {
    let arb = armed(SCOPE_FIDO, 8);
    let mut latch = ButtonWait::new();
    let mut b1 = TestBoard::new(&arb, vec![true]);
    assert_eq!(latch.wait(&arb, &mut b1), Outcome::Confirmed);

    // Sample 1 observes the release and clears the latch; sample 2, a poll later,
    // is the earliest that may confirm. A re-check inside the same iteration would
    // land this at zero delays.
    let mut b2 = TestBoard::new(&arb, vec![false, true, false]);
    assert_eq!(latch.wait(&arb, &mut b2), Outcome::Confirmed);
    assert_eq!(b2.delays, 1, "the release iteration confirmed by itself");
}

#[test]
fn w6_a_release_before_the_wait_ends_leaves_the_next_ceremony_free() {
    let arb = armed(SCOPE_FIDO, 8);
    let mut latch = ButtonWait::new();
    // Press, then the finger lifts during the debounce.
    let mut b1 = TestBoard::new(&arb, vec![true, false]);
    assert_eq!(latch.wait(&arb, &mut b1), Outcome::Confirmed);
    // A fresh press is a fresh consent.
    let mut b2 = TestBoard::new(&arb, vec![true, false]);
    assert_eq!(latch.wait(&arb, &mut b2), Outcome::Confirmed);
}

#[test]
fn w6_a_timeout_with_the_finger_down_still_spends_the_hold() {
    let arb = armed(SCOPE_FIDO, 3);
    let mut latch = ButtonWait::new();
    // Ceremony 1 confirms and the hold is never released → spent.
    let mut b1 = TestBoard::new(&arb, vec![true]);
    assert_eq!(latch.wait(&arb, &mut b1), Outcome::Confirmed);
    // Ceremony 2 times out with the finger still down.
    let mut b2 = TestBoard::new(&arb, vec![true]);
    assert_eq!(latch.wait(&arb, &mut b2), Outcome::Timeout);
    // Ceremony 3 must still find it spent.
    let mut b3 = TestBoard::new(&arb, vec![true]);
    assert_eq!(latch.wait(&arb, &mut b3), Outcome::Timeout);
}

#[test]
fn w6_a_cancel_with_the_finger_down_still_spends_the_hold() {
    let arb = armed(SCOPE_FIDO, 8);
    let mut latch = ButtonWait::new();
    let mut b1 = TestBoard::new(&arb, vec![true]);
    assert_eq!(latch.wait(&arb, &mut b1), Outcome::Confirmed);
    // Cancelled while the finger is still down.
    let mut b2 = TestBoard::new(&arb, vec![true]).with_events(vec![Ev::FidoCancel]);
    assert_eq!(latch.wait(&arb, &mut b2), Outcome::Cancelled);
    // Still spent: the hold that was never lifted is nobody's new consent.
    let mut b3 = TestBoard::new(&arb, vec![true]);
    assert_eq!(latch.wait(&arb, &mut b3), Outcome::Timeout);
}

/// The confirm clause of `NoCrossTransportTouchConsumption`: one hold, two
/// transports, and the second must not be served by it.
#[test]
fn one_hold_never_serves_two_transports() {
    for first in SCOPES {
        for second in SCOPES {
            let arb = armed(first, 6);
            let mut latch = ButtonWait::new();
            let mut b1 = TestBoard::new(&arb, vec![true]);
            assert_eq!(latch.wait(&arb, &mut b1), Outcome::Confirmed);

            arb.set_wait_scope(second);
            let mut b2 = TestBoard::new(&arb, vec![true]);
            assert_eq!(
                latch.wait(&arb, &mut b2),
                Outcome::Timeout,
                "a hold consumed by {first} confirmed for {second}"
            );
        }
    }
}

// ---------------------------------------------------------------- W5

#[test]
fn w5_the_debounce_waits_for_the_release() {
    let arb = armed(SCOPE_FIDO, 10);
    // Press on sample 1, held for three more samples, then released.
    let mut board = TestBoard::new(&arb, vec![true, true, true, true, false]);
    assert_eq!(ButtonWait::new().wait(&arb, &mut board), Outcome::Confirmed);
    // One delay per held sample in the debounce; the loop itself used none.
    assert_eq!(board.delays, 3);
}

/// The bound the debounce must not break: wherever the press lands — first sample,
/// mid-window, or the iteration the deadline would have fired on (W4a precedes W4d)
/// — a finger that never lifts carries the wait to the ceremony's own deadline and
/// no further. A debounce with a *fresh* budget took the last of those to 2× the
/// configured window, and the worker is held for all of it.
///
/// `at == 0` passes under either shape (nothing has elapsed, so the two budgets are
/// the same); rows 1..=`polls` are the ones that discriminate. The row past the end
/// closes the boundary from the other side.
#[test]
fn w5_a_ceremony_never_outlasts_the_window_it_was_given() {
    let polls = 4u32;
    let budget_us = polls as u64 * POLL_MS * US_PER_MS;

    for at in 0..=polls as usize {
        let arb = armed(SCOPE_FIDO, polls);
        // The last entry repeats, so the finger is down from `at` onwards.
        let mut presses = vec![false; at];
        presses.push(true);
        let mut board = TestBoard::new(&arb, presses);
        assert_eq!(
            ButtonWait::new().wait(&arb, &mut board),
            Outcome::Confirmed,
            "press at sample {at}"
        );
        assert_eq!(
            board.now_us, budget_us,
            "press at sample {at}: the ceremony did not end on its own deadline"
        );
    }

    // One sample later is past the deadline, so there is nothing left to confirm.
    let arb = armed(SCOPE_FIDO, polls);
    let mut presses = vec![false; polls as usize + 1];
    presses.push(true);
    let mut board = TestBoard::new(&arb, presses);
    assert_eq!(ButtonWait::new().wait(&arb, &mut board), Outcome::Timeout);
    assert_eq!(board.now_us, budget_us);
}

// ---------------------------------------------------------------- the scope moving mid-wait

#[test]
fn a_scope_change_mid_wait_moves_the_advertisement_and_the_cancel_right() {
    // The worker sets the scope, so this cannot happen on the device; it is here
    // because the property must not depend on that being true.
    let arb = armed(SCOPE_FIDO, 6);
    let mut board = TestBoard::new(&arb, vec![false]).with_events(vec![
        Ev::Scope(SCOPE_CCID),
        Ev::FidoCancel,
        Ev::OtpCancel,
    ]);
    assert_eq!(ButtonWait::new().wait(&arb, &mut board), Outcome::Timeout);
    assert!(board.saw_pending[SCOPE_FIDO as usize]);
    assert!(board.saw_pending[SCOPE_CCID as usize]);
}
