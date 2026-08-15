// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Presence-scope arbitration: one physical button, four transports, and the
//! rules deciding whose ceremony a press satisfies and whose cancel may end it.
//!
//! [`Arbiter`] holds the three cross-executor flags — is a touch pending, has a
//! cancel been raised, and which transport the wait belongs to — and every
//! transport hook is the *conjunction* of a flag with the scope, never the bare
//! flag. Without that, an unprivileged FIDO-HID process could `CTAPHID_CANCEL` a
//! CCID (OpenPGP/PIV/OATH) or keyboard-frame (Yubico-OTP) ceremony, and an
//! unscoped `UPNEEDED` would tell a parked FIDO request that a human is about to
//! touch the key for somebody else's operation. CTAP 2.1 §11.2.9.1.4 scopes a
//! cancel to its own channel.
//!
//! [`ButtonWait`] is the level-triggered press wait and the `spent` latch that
//! stops one hold from satisfying two ceremonies. The board half it runs on —
//! the button sample, the clock, the blocking delay — is [`Board`], so the
//! embassy/RP2350 pieces stay in `firmware/src/presence.rs` and the arbitration
//! is host-testable and Kani-provable here. The invariant it carries is
//! `NoCrossTransportTouchConsumption` (`formal/RSKeySecurityState.tla`).

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

/// No host request in flight: an on-panel (local) flow owns the button.
pub const SCOPE_NONE: u8 = 0;
/// CTAPHID — CTAP2 (CBOR), U2F (MSG) and the Management vendor commands.
pub const SCOPE_FIDO: u8 = 1;
/// CCID — every applet APDU, including the pinpad VERIFY.
pub const SCOPE_CCID: u8 = 2;
/// The keyboard interface's Yubico-OTP frame protocol.
pub const SCOPE_OTP: u8 = 3;

/// Built-in touch-wait timeout (ms) used when the phy record carries none.
const DEFAULT_TIMEOUT_MS: u32 = 30_000;

/// Shortest touch-wait window a stored timeout may impose, matching the
/// on-device settings menu's own floor (`rsk_ui::TIMEOUT_CHOICES`). The phy
/// record is host-writable through the ungated `CONFIG_WRITE`, and a consent
/// window short enough to expire mid-press turns a single hold into two grants.
pub const MIN_TIMEOUT_SECS: u8 = 10;

/// Poll cadence for the press wait, in milliseconds.
const POLL_MS: u64 = 16;

const US_PER_MS: u64 = 1_000;

/// Neutral wait result, mapped to each applet's own `Presence` enum by the
/// backend. The button has no "declined" gesture; `Cancelled` comes from a
/// transport-scoped cancel observed mid-wait.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    Confirmed,
    Timeout,
    Cancelled,
}

/// The board underneath a press wait: the button, the clock, and the delay that
/// lets the higher-priority transport code run. No defaults — a board that can
/// neither sample a button nor tell the time cannot run a wait at all.
pub trait Board {
    /// One non-blocking sample of the presence source; `true` = pressed.
    fn pressed(&mut self) -> bool;

    /// A monotonic microsecond counter. Only differences are used.
    fn now_us(&self) -> u64;

    /// Block for `ms`, leaving whatever else the board runs free to run.
    fn block_for_ms(&mut self, ms: u64);
}

/// The three cross-executor presence flags plus the runtime touch-wait timeout.
///
/// One instance per device — the firmware keeps it in a `static`, because the
/// transport (interrupt) and worker (thread) executors both reach it. Every
/// method takes `&self` for that reason.
pub struct Arbiter {
    up_pending: AtomicBool,
    cancel_requested: AtomicBool,
    wait_scope: AtomicU8,
    timeout_ms: AtomicU32,
}

impl Default for Arbiter {
    fn default() -> Self {
        Self::new()
    }
}

impl Arbiter {
    pub const fn new() -> Self {
        Self {
            up_pending: AtomicBool::new(false),
            cancel_requested: AtomicBool::new(false),
            wait_scope: AtomicU8::new(SCOPE_NONE),
            timeout_ms: AtomicU32::new(DEFAULT_TIMEOUT_MS),
        }
    }

    /// Mark which transport the worker is dispatching for. Set around every
    /// dispatch, `SCOPE_NONE` between them so an on-panel ceremony is nobody's
    /// to cancel.
    pub fn set_wait_scope(&self, scope: u8) {
        self.wait_scope.store(scope, Ordering::Release);
    }

    /// Is a touch pending *for `scope`*? Every transport hook needs the
    /// conjunction, never the bare flag.
    /// Refines `RSKeySecurityState!NoCrossTransportTouchConsumption` — SEC-FIDO-002.
    pub fn pending_for(&self, scope: u8) -> bool {
        self.up_pending.load(Ordering::Acquire) && self.wait_scope.load(Ordering::Acquire) == scope
    }

    /// The CTAPHID cancel hook: request that an in-flight touch wait be
    /// abandoned. Only ever ends a FIDO ceremony — the wait it aborts must be
    /// the one the cancelling channel owns.
    /// Refines `RSKeySecurityState!NoCrossTransportTouchConsumption` — SEC-FIDO-002.
    pub fn request_cancel(&self) {
        if self.wait_scope.load(Ordering::Acquire) == SCOPE_FIDO {
            self.cancel_requested.store(true, Ordering::Release);
        }
    }

    /// End an OTP touch wait because the host moved on: it sent the dummy write
    /// that aborts (`0x8f`), or a new frame — a YubiKey lets either supersede
    /// the wait, and without that every later command reads "would block" until
    /// the wait times out.
    /// Refines `RSKeySecurityState!NoCrossTransportTouchConsumption` — SEC-FIDO-002.
    pub fn cancel_otp_wait(&self) {
        if self.wait_scope.load(Ordering::Acquire) == SCOPE_OTP {
            self.cancel_requested.store(true, Ordering::Relaxed);
            // The wait is over as of this decision; stop advertising it right
            // away so the host's next status poll cannot read a stale
            // "waiting for touch".
            self.up_pending.store(false, Ordering::Relaxed);
        }
    }

    /// Override the touch-wait timeout from the phy record — value in
    /// **seconds**, matching PicoForge's tag `0x08`. `0` (or an absent tag)
    /// keeps the built-in 30 s default; anything below [`MIN_TIMEOUT_SECS`] is
    /// raised to it. Call once at boot, before any applet runs.
    pub fn set_timeout_secs(&self, secs: u8) {
        if secs != 0 {
            let secs = secs.max(MIN_TIMEOUT_SECS);
            self.timeout_ms.store(secs as u32 * 1000, Ordering::Relaxed);
        }
    }

    pub fn timeout_ms(&self) -> u32 {
        self.timeout_ms.load(Ordering::Relaxed)
    }

    pub fn set_timeout_ms(&self, ms: u32) {
        self.timeout_ms.store(ms, Ordering::Relaxed);
    }

    pub fn set_up_pending(&self, pending: bool) {
        self.up_pending.store(pending, Ordering::Release);
    }

    pub fn set_cancel_requested(&self, requested: bool) {
        self.cancel_requested.store(requested, Ordering::Relaxed);
    }

    pub fn cancel_requested(&self) -> bool {
        self.cancel_requested.load(Ordering::Acquire)
    }
}

/// The level-triggered press wait and its `spent` latch.
///
/// `spent` says the button was still down when the last wait returned, so that
/// press is used up: consent is per-operation, and a level-triggered wait would
/// otherwise hand the same hold to the next queued request — including one from
/// a different transport, which is what
/// `NoCrossTransportTouchConsumption`'s confirm clause forbids.
#[derive(Default)]
pub struct ButtonWait {
    spent: bool,
}

impl ButtonWait {
    pub const fn new() -> Self {
        Self { spent: false }
    }

    /// Block until the button is pressed, a cancel scoped to this wait's
    /// transport arrives, or the timeout expires.
    ///
    /// The caller owns the touch indicator: the LED is switched before this and
    /// restored after, so nothing here needs to know a board has one.
    pub fn wait<B: Board>(&mut self, arb: &Arbiter, board: &mut B) -> Outcome {
        // Drop any cancel left from an earlier (already-finished) request so
        // this wait starts clean.
        arb.set_cancel_requested(false);
        arb.set_up_pending(true);
        let start = board.now_us();
        let timeout_us = arb.timeout_ms() as u64 * US_PER_MS;
        // Wait for a press; a scoped cancel aborts it, and with neither before
        // the timeout it times out.
        let result = loop {
            if board.pressed() {
                // A press the previous ceremony already consumed is not consent
                // for this one; it stays spent until the finger actually lifts.
                if !self.spent {
                    break Outcome::Confirmed;
                }
            } else {
                self.spent = false;
            }
            if arb.cancel_requested() {
                break Outcome::Cancelled;
            }
            if board.now_us().wrapping_sub(start) >= timeout_us {
                break Outcome::Timeout;
            }
            board.block_for_ms(POLL_MS);
        };
        if result == Outcome::Confirmed {
            // The debounce runs inside what is LEFT of this ceremony's budget, not a
            // fresh copy of it: the window the operator configured is the whole
            // wait's, and a press landing on the deadline used to double it.
            let elapsed = board.now_us().wrapping_sub(start);
            self.await_release(board, timeout_us.saturating_sub(elapsed));
        }
        // The debounce is bounded, so it can give up with the finger still down;
        // whatever the outcome, a button that never released carries no new consent.
        self.spent = board.pressed();
        arb.set_up_pending(false);
        // Clear any cancel that raced in (e.g. just after a confirm) so it can't
        // leak into the next request's wait.
        arb.set_cancel_requested(false);
        result
    }

    /// Debounce: wait for release, within `budget_us`, so a held button doesn't
    /// immediately satisfy the next operation.
    ///
    /// Giving up with the finger still down costs nothing the `spent` latch does not
    /// already carry: it is set from the sample either way. That is why this takes no
    /// floor where `rsk_display`'s `wait_release_ceremony` does — that one debounces
    /// at ceremony *entry*, with no latch behind it. The release *edge* it leaves is
    /// the idle click watcher's to discount ([`crate::click`]).
    fn await_release<B: Board>(&mut self, board: &mut B, budget_us: u64) {
        let release = board.now_us();
        while board.pressed() {
            if board.now_us().wrapping_sub(release) >= budget_us {
                break;
            }
            board.block_for_ms(POLL_MS);
        }
    }
}

#[cfg(test)]
#[path = "presence_tests.rs"]
mod tests;

#[cfg(kani)]
#[path = "presence_kani.rs"]
mod proofs;
