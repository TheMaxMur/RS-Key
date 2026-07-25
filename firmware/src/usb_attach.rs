// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! How long the authenticator has been *reachable*, which is not how long it has
//! been powered.
//!
//! `Instant::now()` counts from `embassy_rp::init`, and boot spends seconds there
//! before the bus pull-up goes up: the TRNG seed (~1.5 s), the seal migrations, the
//! seed/attestation provisioning, and the one-shot at-rest hardening lap (a
//! multi-second GC). CTAP 2.1 §6.6's `authenticatorReset` power-up window can only
//! mean "since the authenticator could answer" — a host cannot send anything before
//! enumeration — so charging that window against boot time would let a slow boot
//! close it before the first command lands, which is the reset unreachable on
//! exactly the devices (hardening boot, many resident credentials) whose owners
//! most need it.
//!
//! Stamped once on the boot path and never again: a host cannot re-open the window
//! by re-enumerating, and a warm reset — the one reboot a host *can* request —
//! closes it outright ([`crate::pin_lock`]).

use core::sync::atomic::{AtomicU32, Ordering};

use embassy_time::Instant;

/// Uptime at the attach, in ms (u32 is ~49 days; the attach is seconds into boot).
/// `0` until [`mark`] runs, which is before any host command can exist.
static ATTACH_MS: AtomicU32 = AtomicU32::new(0);

/// Stamp the origin. Call once, immediately before the USB pull-up is asserted.
pub fn mark() {
    ATTACH_MS.store(Instant::now().as_millis() as u32, Ordering::Relaxed);
}

/// Milliseconds since the attach — the clock the FIDO layer gets as `Ctx::now_ms`,
/// so every window it measures counts time a host could actually use.
pub fn elapsed_ms() -> u64 {
    Instant::now()
        .as_millis()
        .saturating_sub(ATTACH_MS.load(Ordering::Relaxed) as u64)
}
