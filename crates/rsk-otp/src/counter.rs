// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The Yubico-OTP use-counter rule, in one place. Both writers of the
//! non-volatile counter — the per-press bump in [`crate::ticket::build`] and the
//! boot-time bump in [`crate::power_up_bump`] — take their step from here, so
//! the 15-bit ceiling cannot be enforced two different ways.

use crate::USE_COUNTER_MAX;

/// The step a button press owes the counter. The RAM session counter rolls on
/// every press and the non-volatile use counter advances only when it wraps —
/// that `(use, session)` pair is the ordering a Yubico validation server uses to
/// reject a replay. Returns `(counter, session, persist)`; `persist` is `true`
/// exactly when `counter` moved and therefore has to reach flash.
/// Refines `RSKeyAppletPolicies!OtpCounterNeverRepeats` — SEC-POL-006.
pub(crate) fn next_use_counter(counter: u16, session: u8) -> (u16, u8, bool) {
    let new_session = session.wrapping_add(1);
    // Guard the value about to be stored, not the one already stored: at the
    // ceiling `counter + 1` is 0x8000, which sets the reserved high bit and
    // which `boot_use_counter` would then refuse to advance ever again.
    if new_session == 0 && counter < USE_COUNTER_MAX {
        (counter + 1, new_session, true)
    } else {
        (counter, new_session, false)
    }
}

/// The step a power-up owes a stored counter, so a counter never repeats across
/// reboots — the RAM session restarts at 0. `None` means leave the stored value
/// alone: at the ceiling there is no next value, and a counter is never lowered,
/// because going backwards is the replay it exists to prevent.
pub(crate) fn boot_use_counter(stored: u16) -> Option<u16> {
    let next = stored.wrapping_add(1);
    (next <= USE_COUNTER_MAX).then_some(next)
}

#[cfg(test)]
#[path = "counter_tests.rs"]
mod tests;

#[cfg(kani)]
#[path = "counter_kani.rs"]
mod proofs;
