// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Bounded proofs of `NoCrossTransportTouchConsumption` — the maintainer's fourth
//! security invariant, modelled in `formal/RSKeySecurityState.tla` and, until the
//! arbitration was lifted here, the one with no harness: its whole mechanism sat
//! in `firmware/src/presence.rs`, and no `cargo kani -p` can build a thumbv8m
//! embassy-rp binary.
//!
//! Every premise is asserted rather than assumed. Measured on kani 0.67.0: an
//! **unsatisfiable `kani::cover!` does not fail the harness** — it prints
//! "N of M cover properties satisfied" and still reports SUCCESSFUL. `kani.sh`'s
//! cover row reads those verdicts back, so a `cover!` guards at the tier; an
//! asserted premise guards here, where the counterexample is.

use super::*;

/// The wait's budget, in polls. Small on purpose: it bounds both the press loop
/// and the debounce, so it is the harness's unwind bound and its cost.
const BUDGET_POLLS: u32 = 3;

// `#[kani::unwind]` takes a literal, so the two cannot be tied by expression.
// Either loop runs at most `BUDGET_POLLS + 1` iterations; the bound is that plus
// slack. Too small is loud, not silent — Kani fails the unwinding assertion.
const _: () = assert!(BUDGET_POLLS + 3 == 6);

/// A board driven by symbolic input. The transport executor gets its slice inside
/// [`Board::block_for_ms`], which is where it gets one on the device: `block_for`
/// keeps interrupts enabled, so the high-priority executor runs between polls.
struct SymBoard<'a> {
    arb: &'a Arbiter,
    /// The scope the wait this board is driving belongs to.
    owner: u8,
    now_us: u64,
    /// `true` → the finger is down for every sample (one unbroken hold).
    held: bool,
    /// What the last [`Board::pressed`] call answered — the sample the `spent`
    /// latch is set from.
    last_pressed: bool,
    /// Which transports *attempted* a cancel during this wait, indexed by the
    /// scope the attempt came from. Recorded from the call site, never read back
    /// out of the arbiter — reading it back would weaken the property to a
    /// tautology.
    attempted: [bool; 4],
    /// Which scopes ever saw `pending_for` true while the wait ran.
    saw_pending: [bool; 4],
    slices: u32,
}

impl<'a> SymBoard<'a> {
    fn new(arb: &'a Arbiter, owner: u8) -> Self {
        Self {
            arb,
            owner,
            now_us: 0,
            held: false,
            last_pressed: false,
            attempted: [false; 4],
            saw_pending: [false; 4],
            slices: 0,
        }
    }

    fn held(arb: &'a Arbiter, owner: u8) -> Self {
        let mut b = Self::new(arb, owner);
        b.held = true;
        b
    }

    /// What each transport would read if it ran right now.
    fn observe(&mut self) {
        let mut s = 0u8;
        while s <= SCOPE_OTP {
            self.saw_pending[s as usize] |= self.arb.pending_for(s);
            s += 1;
        }
    }
}

impl Board for SymBoard<'_> {
    fn pressed(&mut self) -> bool {
        let p = self.held || kani::any();
        self.last_pressed = p;
        p
    }

    fn now_us(&self) -> u64 {
        self.now_us
    }

    fn block_for_ms(&mut self, ms: u64) {
        if self.slices == 0 {
            // Nothing has run yet in this wait but the wait itself, so it must be
            // advertising to its owner. Positive and unconditional: it is what
            // makes the "…and to nobody else" assertions non-vacuous.
            assert!(
                self.arb.pending_for(self.owner),
                "the wait never advertised itself to the transport that owns it"
            );
        }
        self.slices += 1;
        self.observe();
        // Either host transport may raise its cancel in this slice, or neither.
        if kani::any() {
            self.attempted[SCOPE_FIDO as usize] = true;
            self.arb.request_cancel();
        }
        if kani::any() {
            self.attempted[SCOPE_OTP as usize] = true;
            self.arb.cancel_otp_wait();
        }
        self.observe();
        self.now_us = self.now_us.saturating_add(ms * US_PER_MS);
    }
}

fn any_scope() -> u8 {
    let s: u8 = kani::any();
    kani::assume(s <= SCOPE_OTP);
    s
}

fn armed(scope: u8) -> Arbiter {
    let arb = Arbiter::new();
    arb.set_wait_scope(scope);
    arb.set_timeout_ms(BUDGET_POLLS * POLL_MS as u32);
    arb
}

/// `NoCrossTransportTouchConsumption`, cancel clause — the code-level instance of
/// the TLA+ `TouchCancel` action, whose violation is `cancelBy != scope`.
///
/// Over a symbolic interleaving of button samples and host cancels, a wait that
/// ends `Cancelled` must have been cancelled by the transport that owns it. A
/// `SCOPE_CCID` or `SCOPE_NONE` wait therefore cannot be cancelled at all: no API
/// can originate a cancel from either, so `attempted` at that index stays false
/// and the assertion admits no `Cancelled`. The stale cancel armed before the
/// wait is part of the clause — one raised before this ceremony started owns no
/// ceremony either, whoever raised it. It also carries the invariant's
/// advertisement half: the wait is pending for its owner and for nobody else,
/// and stops being pending when it ends.
///
/// What this does **not** prove: the scope is set by the worker around a
/// dispatch, and that sequencing is `firmware/src/worker.rs`'s, not modelled
/// here; the button samples are independent, so a physically impossible flicker
/// is admitted (an over-approximation, sound for a safety property); the
/// advertisement half is only asserted on paths that reach a poll delay, so a
/// wait that confirms on its first sample is `w2_w7_…`'s to cover; and of the
/// two stale-cancel drops only the one at entry is pinned here — the one at exit
/// needs a second wait to observe, which is the unit test `w8_…`.
#[kani::proof]
#[kani::unwind(6)]
fn no_cross_transport_touch_consumption_cancel() {
    let scope = any_scope();
    let arb = armed(scope);
    // A cancel left over from an earlier, already-finished request.
    if kani::any() {
        arb.set_cancel_requested(true);
    }

    let mut board = SymBoard::new(&arb, scope);
    let mut latch = ButtonWait { spent: kani::any() };
    let outcome = latch.wait(&arb, &mut board);

    if outcome == Outcome::Cancelled {
        assert!(
            board.attempted[scope as usize],
            "a touch wait was cancelled by a transport that does not own it"
        );
    }

    let mut s = 0u8;
    while s <= SCOPE_OTP {
        assert!(!arb.pending_for(s), "still advertising after the wait");
        assert!(
            s == scope || !board.saw_pending[s as usize],
            "a wait was advertised to a transport that does not own it"
        );
        s += 1;
    }
}

/// One unbroken hold satisfies at most one ceremony, and it is spent by the
/// first — the premise the confirm clause below reasons from, proved rather
/// than assumed so that clause cannot be vacuous.
#[kani::proof]
#[kani::unwind(6)]
fn a_hold_that_satisfied_a_ceremony_is_spent_by_it() {
    let scope = any_scope();
    let arb = armed(scope);
    let mut latch = ButtonWait::new();
    let mut hold = SymBoard::held(&arb, scope);

    // The press is there from the first sample and W4a precedes both the cancel
    // and the deadline, so no interleaving can produce anything else.
    assert_eq!(latch.wait(&arb, &mut hold), Outcome::Confirmed);
    assert!(latch.spent, "a hold that was never released was not spent");
}

/// A board that never presses and raises `by`'s cancel in every slice.
struct CancellingBoard<'a> {
    arb: &'a Arbiter,
    by: u8,
    now_us: u64,
}

impl Board for CancellingBoard<'_> {
    fn pressed(&mut self) -> bool {
        false
    }

    fn now_us(&self) -> u64 {
        self.now_us
    }

    fn block_for_ms(&mut self, ms: u64) {
        if self.by == SCOPE_FIDO {
            self.arb.request_cancel();
        } else {
            self.arb.cancel_otp_wait();
        }
        self.now_us = self.now_us.saturating_add(ms * US_PER_MS);
    }
}

/// A cancel from the owning transport *does* end the wait, for each of the two
/// transports that can raise one. The cancel clause above is an implication, and
/// this is its antecedent: without it, deleting the cancel check outright would
/// leave that harness green and vacuous, and a `cover!` would not have said so.
#[kani::proof]
#[kani::unwind(6)]
fn a_cancel_from_the_owning_transport_ends_the_wait() {
    for by in [SCOPE_FIDO, SCOPE_OTP] {
        let arb = armed(by);
        let mut board = CancellingBoard {
            arb: &arb,
            by,
            now_us: 0,
        };
        assert_eq!(ButtonWait::new().wait(&arb, &mut board), Outcome::Cancelled);
    }
}

/// `NoCrossTransportTouchConsumption`, confirm clause — the TLA+ `TouchConfirm`
/// action, whose violation is a hold already consumed by one transport's ceremony
/// satisfying another's.
///
/// Two ceremonies under symbolic scopes, with the second running on a finger that
/// never lifted: it cannot confirm if the first did. Stated as one implication
/// rather than an `assume`, so no premise can silently go unreachable. The Rust is
/// stronger than the model needs — `spent` carries no owner, so a still-held press
/// confirms for nobody, including the same transport again.
#[kani::proof]
#[kani::unwind(6)]
fn no_cross_transport_touch_consumption_confirm() {
    let owner = any_scope();
    let arb = armed(owner);

    let mut latch = ButtonWait::new();
    let mut first = SymBoard::new(&arb, owner);
    let one = latch.wait(&arb, &mut first);

    let next = any_scope();
    arb.set_wait_scope(next);
    let mut second = SymBoard::held(&arb, next);
    let two = latch.wait(&arb, &mut second);

    assert!(
        !(one == Outcome::Confirmed && first.last_pressed && two == Outcome::Confirmed),
        "one physical hold satisfied two ceremonies"
    );
}

/// The same invariant's third mechanism, over the arbiter alone: the "a touch is
/// pending" advertisement. An unscoped one told a parked FIDO request that a human
/// was about to touch the key for somebody else's operation, and armed the frame
/// reader that turns a cancel into a cross-transport abort.
#[kani::proof]
fn up_pending_never_advertises_another_transports_wait() {
    let arb = Arbiter::new();
    let owner = any_scope();
    let asker = any_scope();
    let pending: bool = kani::any();

    arb.set_wait_scope(owner);
    arb.set_up_pending(pending);

    assert_eq!(arb.pending_for(asker), pending && asker == owner);
}

/// One ceremony never outlasts the window it was given, over every interleaving
/// of button samples and host cancels rather than the four schedules the unit
/// test scripts. The debounce used to take a *fresh* copy of the budget, so a
/// press landing on the deadline ran the wait — and the single-threaded worker
/// behind it — to twice the operator's configured window.
#[kani::proof]
#[kani::unwind(6)]
fn a_ceremony_never_outlasts_its_window() {
    let scope = any_scope();
    let arb = armed(scope);
    let mut board = SymBoard::new(&arb, scope);
    let mut latch = ButtonWait { spent: kani::any() };
    let _ = latch.wait(&arb, &mut board);

    assert!(board.now_us <= BUDGET_POLLS as u64 * POLL_MS * US_PER_MS);
}

/// The consent window a phy record may impose never undercuts [`MIN_TIMEOUT_SECS`].
/// The record is host-writable through the ungated `CONFIG_WRITE`, and a window
/// short enough to expire mid-press turns a single hold into two grants.
#[kani::proof]
fn a_stored_timeout_never_undercuts_the_floor() {
    let arb = Arbiter::new();
    let secs: u8 = kani::any();
    arb.set_timeout_secs(secs);

    assert!(arb.timeout_ms() >= MIN_TIMEOUT_SECS as u32 * 1000);
    if secs == 0 {
        assert_eq!(arb.timeout_ms(), DEFAULT_TIMEOUT_MS);
    }
}
