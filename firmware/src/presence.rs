// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Physical user presence over either the BOOTSEL button (default) or a dedicated
//! GPIO button (`PRESENCE_PIN`). BOOTSEL samples use the QSPI-CS-to-Hi-Z trick in a
//! RAM function; a GPIO button is polled active-low with an internal pull-up by
//! default, or active-high with a pull-down when `PRESENCE_ACTIVE_HIGH` is set. The
//! wait blocks the worker while the high-priority transports stream keepalives
//! reporting `UPNEEDED` ([`up_pending`]). One `ButtonPresence` serves every
//! applet's `UserPresence` trait; a touch is required by default, and the opt-in
//! `no-touch` feature makes `request` confirm instantly (for the automated suites,
//! which cannot press a button). The `display` build takes presence from the
//! touchscreen (`crate::display::TouchPresence`) instead, so the button backend
//! below is compiled out there.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

#[cfg(not(feature = "display"))]
use embassy_rp::Peri;
#[cfg(not(feature = "display"))]
use embassy_rp::gpio::{AnyPin, Input, Pull};
#[cfg(not(feature = "display"))]
use embassy_rp::peripherals::BOOTSEL;

#[cfg(all(not(feature = "no-touch"), not(feature = "display")))]
use embassy_rp::bootsel::is_bootsel_pressed;
#[cfg(all(not(feature = "no-touch"), not(feature = "display")))]
use embassy_time::{Duration, Instant, block_for};

/// Set while the worker is blocked in a presence wait — read by the CTAPHID
/// keepalive to report `UPNEEDED` (0x02) instead of `PROCESSING` (0x01). Shared
/// with the `display` build's `TouchPresence`.
pub(crate) static UP_PENDING: AtomicBool = AtomicBool::new(false);

/// Set by the CTAPHID transport (high-priority executor) when a `CTAPHID_CANCEL`
/// arrives for the request the worker is processing. The button wait — running on
/// the worker executor — polls it each iteration and abandons with `Cancelled`, so
/// the in-flight CTAP2 command answers `CTAP2_ERR_KEEPALIVE_CANCEL`. Cross-executor
/// (transport sets, worker reads), mirroring `UP_PENDING` in the other direction.
pub(crate) static CANCEL_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Which transport owns the presence wait the worker is running. Every cancel and
/// every "a touch is pending" advertisement is scoped to it, because one button
/// serves all of them: without this an unprivileged FIDO-HID process could
/// `CTAPHID_CANCEL` a CCID (OpenPGP/PIV/OATH) or keyboard-frame (Yubico-OTP)
/// ceremony — and on a button build inherit the user's descending finger onto its
/// own request, since a fresh wait starts with `spent == false`. CTAP 2.1 §11.2.9.1.4
/// scopes a cancel to its own channel.
static WAIT_SCOPE: AtomicU8 = AtomicU8::new(SCOPE_NONE);

/// No host request in flight: an on-panel (local) flow owns the button.
pub const SCOPE_NONE: u8 = 0;
/// CTAPHID — CTAP2 (CBOR), U2F (MSG) and the Management vendor commands.
pub const SCOPE_FIDO: u8 = 1;
/// CCID — every applet APDU, including the pinpad VERIFY.
pub const SCOPE_CCID: u8 = 2;
/// The keyboard interface's Yubico-OTP frame protocol.
pub const SCOPE_OTP: u8 = 3;

/// Mark which transport the worker is dispatching for. Set around every dispatch,
/// `SCOPE_NONE` between them so an on-panel ceremony is nobody's to cancel.
pub fn set_wait_scope(scope: u8) {
    WAIT_SCOPE.store(scope, Ordering::Release);
}

/// Is a touch pending *for `scope`*? Both hooks below need the conjunction, never
/// the bare flag.
fn pending_for(scope: u8) -> bool {
    UP_PENDING.load(Ordering::Acquire) && WAIT_SCOPE.load(Ordering::Acquire) == scope
}

/// The CTAPHID keepalive hook passed to `CtapHid::new`: is a touch being awaited
/// *for this transport*? Always `false` on the `no-touch` build, so the status
/// stays `PROCESSING`. Scoping it also closes a cross-transport oracle — an
/// unscoped `UPNEEDED` told a parked FIDO request that a human was about to touch
/// the key for somebody else's operation — and keeps the transport from arming the
/// frame reader that turns a cancel into a cross-transport abort.
pub fn up_pending() -> bool {
    pending_for(SCOPE_FIDO)
}

/// The keyboard-interface status-frame hook: is *its* touch pending? Reported in
/// the OTP status byte so a host polling for a touch-gated challenge-response sees
/// the wait (issue #55).
pub fn otp_up_pending() -> bool {
    pending_for(SCOPE_OTP)
}

/// The CTAPHID cancel hook passed to `CtapHid::new`: request that an in-flight
/// touch wait be abandoned. Only ever ends a FIDO ceremony — the wait it aborts
/// must be the one the cancelling channel owns.
pub fn request_cancel() {
    if WAIT_SCOPE.load(Ordering::Acquire) == SCOPE_FIDO {
        CANCEL_REQUESTED.store(true, Ordering::Release);
    }
}

/// End an OTP touch wait because the host moved on: it sent the dummy write that
/// aborts (`0x8f`), or a new frame — a YubiKey lets either supersede the wait, and
/// without that every later command reads "would block" until the wait times out.
pub fn cancel_otp_wait() {
    if WAIT_SCOPE.load(Ordering::Acquire) == SCOPE_OTP {
        CANCEL_REQUESTED.store(true, Ordering::Relaxed);
        // The wait is over as of this decision; stop advertising it right away so
        // the host's next status poll cannot read a stale "waiting for touch".
        UP_PENDING.store(false, Ordering::Relaxed);
    }
}

/// Built-in touch-wait timeout (ms) used when the phy record carries none.
const DEFAULT_TIMEOUT_MS: u32 = 30_000;
/// Touch-wait timeout in ms, seeded at boot from the phy record's
/// `PRESENCE_TIMEOUT` tag (PicoForge `0x08`, seconds). Read live by the wait.
pub(crate) static PRESENCE_TIMEOUT_MS: AtomicU32 = AtomicU32::new(DEFAULT_TIMEOUT_MS);

/// Shortest touch-wait window a stored timeout may impose, matching the on-device
/// settings menu's own floor (`rsk_ui::TIMEOUT_CHOICES`). The phy record is
/// host-writable through the ungated `CONFIG_WRITE`, and a consent window short
/// enough to expire mid-press turns a single hold into two grants.
pub(crate) const MIN_TIMEOUT_SECS: u8 = 10;
#[cfg(feature = "display")]
const _: () = assert!(MIN_TIMEOUT_SECS as u16 == rsk_ui::TIMEOUT_CHOICES[0]);

/// Override the touch-wait timeout from the phy record — value in **seconds**,
/// matching PicoForge's tag `0x08`. `0` (or an absent tag) keeps the
/// built-in 30 s default; anything below [`MIN_TIMEOUT_SECS`] is raised to it.
/// Call once at boot, before any applet runs.
pub fn set_timeout_secs(secs: u8) {
    if secs != 0 {
        let secs = secs.max(MIN_TIMEOUT_SECS);
        PRESENCE_TIMEOUT_MS.store(secs as u32 * 1000, Ordering::Relaxed);
    }
}

// Poll cadence for the press wait. `block_for` keeps interrupts enabled, so the
// high-priority executor (USB + keepalives) runs between polls; only the ~4000-cycle
// `is_bootsel_pressed` read briefly masks interrupts. The timeout is runtime
// (`PRESENCE_TIMEOUT_MS`).
#[cfg(all(not(feature = "no-touch"), not(feature = "display")))]
const POLL_MS: u64 = 16;

/// Neutral wait result, mapped to each applet's own `Presence` enum. The button
/// has no "declined" gesture; `Cancelled` comes from a `CTAPHID_CANCEL` (FIDO
/// only) observed via [`CANCEL_REQUESTED`].
#[cfg(all(not(feature = "no-touch"), not(feature = "display")))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Confirmed,
    Timeout,
    Cancelled,
}

/// User presence via BOOTSEL (default) or a dedicated GPIO button.
#[cfg(not(feature = "display"))]
pub struct ButtonPresence {
    #[cfg_attr(feature = "no-touch", allow(dead_code))]
    button: Button,
    /// The button was still down when the last wait returned, so that press is
    /// spent: consent is per-operation, and the level-triggered wait would
    /// otherwise hand the same hold to the next queued request.
    #[cfg_attr(feature = "no-touch", allow(dead_code))]
    spent: bool,
}

/// The presence source: the BOOTSEL hardware button, or a GPIO button (the bool is
/// `active_high` — `true` reads a press as logic high, `false` as logic low).
#[cfg(not(feature = "display"))]
#[cfg_attr(feature = "no-touch", allow(dead_code))]
enum Button {
    Bootsel(Peri<'static, BOOTSEL>),
    Gpio(Input<'static>, bool),
}

/// The presence backend the [`crate::worker::Worker`] owns, selected at build
/// time so the worker wiring stays backend-agnostic. The standard key confirms
/// with the BOOTSEL button (or a `PRESENCE_PIN` GPIO); the `display` build swaps
/// this alias to the `crate::display::TouchPresence` that renders on-screen
/// Approve/Deny and returns a real `Declined` — every applet's `UserPresence`
/// trait is satisfied by whichever backend this names, so only this alias changes.
#[cfg(not(feature = "display"))]
pub type Presence = ButtonPresence;
#[cfg(feature = "display")]
pub type Presence = crate::display::TouchPresence;

#[cfg(not(feature = "display"))]
impl ButtonPresence {
    /// Build the default BOOTSEL-backed presence source.
    pub fn new_bootsel(bootsel: Peri<'static, BOOTSEL>) -> Self {
        Self {
            button: Button::Bootsel(bootsel),
            spent: false,
        }
    }

    /// Build a GPIO-backed presence source on `pin`. `active_high` picks the polarity:
    /// `false` = active-low (button to ground, internal pull-up, a press reads low);
    /// `true` = active-high (pull-down, a press reads high — e.g. a touch sensor).
    ///
    /// # Panics
    ///
    /// Panics if `pin` is out of the RP2350A range `0..=29`.
    pub fn new_gpio(pin: u8, active_high: bool) -> Self {
        assert!(
            pin <= 29,
            "PRESENCE_PIN={pin} out of range 0..=29 (RP2350A GPIOs)"
        );
        // Safety: `main` guarantees this pin is not handed to another driver.
        let any = unsafe { AnyPin::steal(pin) };
        let pull = if active_high { Pull::Down } else { Pull::Up };
        let input = Input::new(any, pull);
        Self {
            button: Button::Gpio(input, active_high),
            spent: false,
        }
    }

    #[cfg(not(feature = "no-touch"))]
    fn pressed(&mut self) -> bool {
        match &mut self.button {
            Button::Bootsel(bootsel) => is_bootsel_pressed(bootsel.reborrow()),
            Button::Gpio(button, active_high) => {
                if *active_high {
                    button.is_high()
                } else {
                    button.is_low()
                }
            }
        }
    }

    /// One non-blocking sample of the active presence source, for the typed-ticket
    /// button watcher. On the `no-touch` build it never samples.
    pub fn poll_pressed(&mut self) -> bool {
        #[cfg(not(feature = "no-touch"))]
        {
            self.pressed()
        }
        #[cfg(feature = "no-touch")]
        {
            false
        }
    }

    #[cfg(not(feature = "no-touch"))]
    fn wait(&mut self) -> Outcome {
        // Save the LED status, show the touch status for the wait, restore after.
        let saved = crate::led::status();
        crate::led::set_status(crate::led::STATUS_TOUCH);
        // Drop any cancel left from an earlier (already-finished) request so this
        // wait starts clean.
        CANCEL_REQUESTED.store(false, Ordering::Relaxed);
        UP_PENDING.store(true, Ordering::Release);
        let start = Instant::now();
        let timeout = Duration::from_millis(PRESENCE_TIMEOUT_MS.load(Ordering::Relaxed) as u64);
        // Wait for a press; a CTAPHID_CANCEL aborts it, and with neither before
        // the timeout it times out.
        let result = loop {
            if self.pressed() {
                // A press the previous ceremony already consumed is not consent for
                // this one; it stays spent until the finger actually lifts.
                if !self.spent {
                    break Outcome::Confirmed;
                }
            } else {
                self.spent = false;
            }
            if CANCEL_REQUESTED.load(Ordering::Acquire) {
                break Outcome::Cancelled;
            }
            if start.elapsed() >= timeout {
                break Outcome::Timeout;
            }
            block_for(Duration::from_millis(POLL_MS));
        };
        // Debounce: wait for release (bounded) so a held button doesn't
        // immediately satisfy the next operation.
        if result == Outcome::Confirmed {
            let release = Instant::now();
            while self.pressed() {
                if release.elapsed() >= timeout {
                    break;
                }
                block_for(Duration::from_millis(POLL_MS));
            }
        }
        // The debounce is bounded, so it can give up with the finger still down;
        // whatever the outcome, a button that never released carries no new consent.
        self.spent = self.pressed();
        UP_PENDING.store(false, Ordering::Release);
        // Clear any cancel that raced in (e.g. just after a confirm) so it can't
        // leak into the next request's wait.
        CANCEL_REQUESTED.store(false, Ordering::Relaxed);
        crate::led::set_status(saved);
        result
    }
}

#[cfg(not(feature = "display"))]
impl rsk_fido::UserPresence for ButtonPresence {
    fn request(&mut self, _confirm: rsk_fido::Confirm<'_>) -> rsk_fido::Presence {
        #[cfg(not(feature = "no-touch"))]
        {
            match self.wait() {
                Outcome::Confirmed => rsk_fido::Presence::Confirmed,
                Outcome::Timeout => rsk_fido::Presence::Timeout,
                Outcome::Cancelled => rsk_fido::Presence::Cancelled,
            }
        }
        #[cfg(feature = "no-touch")]
        {
            rsk_fido::Presence::Confirmed
        }
    }
}

#[cfg(not(feature = "display"))]
impl rsk_openpgp::UserPresence for ButtonPresence {
    fn request(&mut self, _confirm: rsk_openpgp::Confirm<'_>) -> rsk_openpgp::Presence {
        #[cfg(not(feature = "no-touch"))]
        {
            match self.wait() {
                Outcome::Confirmed => rsk_openpgp::Presence::Confirmed,
                // OpenPGP UIF runs over CCID, which carries no CTAPHID_CANCEL, so
                // Cancelled is unreachable here; treat it as a non-confirmation.
                Outcome::Timeout | Outcome::Cancelled => rsk_openpgp::Presence::Timeout,
            }
        }
        #[cfg(feature = "no-touch")]
        {
            rsk_openpgp::Presence::Confirmed
        }
    }
}

#[cfg(not(feature = "display"))]
impl rsk_otp::UserPresence for ButtonPresence {
    fn request(&mut self, _confirm: rsk_otp::Confirm<'_>) -> rsk_otp::Presence {
        #[cfg(not(feature = "no-touch"))]
        {
            match self.wait() {
                Outcome::Confirmed => rsk_otp::Presence::Confirmed,
                // CCID-only applet: no CTAPHID_CANCEL reaches it.
                Outcome::Timeout | Outcome::Cancelled => rsk_otp::Presence::Timeout,
            }
        }
        #[cfg(feature = "no-touch")]
        {
            rsk_otp::Presence::Confirmed
        }
    }
}

#[cfg(not(feature = "display"))]
impl rsk_oath::UserPresence for ButtonPresence {
    fn request(&mut self, _confirm: rsk_oath::Confirm<'_>) -> rsk_oath::Presence {
        #[cfg(not(feature = "no-touch"))]
        {
            match self.wait() {
                Outcome::Confirmed => rsk_oath::Presence::Confirmed,
                // CCID-only applet: no CTAPHID_CANCEL reaches it.
                Outcome::Timeout | Outcome::Cancelled => rsk_oath::Presence::Timeout,
            }
        }
        #[cfg(feature = "no-touch")]
        {
            rsk_oath::Presence::Confirmed
        }
    }
}

#[cfg(not(feature = "display"))]
impl rsk_rescue::UserPresence for ButtonPresence {
    fn request(&mut self, _confirm: rsk_rescue::Confirm<'_>) -> rsk_rescue::Presence {
        #[cfg(not(feature = "no-touch"))]
        {
            match self.wait() {
                Outcome::Confirmed => rsk_rescue::Presence::Confirmed,
                // CCID-only applet: no CTAPHID_CANCEL reaches it.
                Outcome::Timeout | Outcome::Cancelled => rsk_rescue::Presence::Timeout,
            }
        }
        #[cfg(feature = "no-touch")]
        {
            rsk_rescue::Presence::Confirmed
        }
    }
}

#[cfg(not(feature = "display"))]
impl rsk_vendor::UserPresence for ButtonPresence {
    fn request(&mut self, _confirm: rsk_vendor::Confirm<'_>) -> rsk_vendor::Presence {
        #[cfg(not(feature = "no-touch"))]
        {
            match self.wait() {
                Outcome::Confirmed => rsk_vendor::Presence::Confirmed,
                // Reachable over both transports, but a cancel is a decline here
                // either way — the reboot gate has nothing to resume.
                Outcome::Timeout | Outcome::Cancelled => rsk_vendor::Presence::Timeout,
            }
        }
        #[cfg(feature = "no-touch")]
        {
            rsk_vendor::Presence::Confirmed
        }
    }
}

#[cfg(not(feature = "display"))]
impl rsk_mgmt::UserPresence for ButtonPresence {
    fn request(&mut self, _confirm: rsk_mgmt::Confirm<'_>) -> rsk_mgmt::Presence {
        #[cfg(not(feature = "no-touch"))]
        {
            match self.wait() {
                Outcome::Confirmed => rsk_mgmt::Presence::Confirmed,
                // CCID-only applet: no CTAPHID_CANCEL reaches it.
                Outcome::Timeout | Outcome::Cancelled => rsk_mgmt::Presence::Timeout,
            }
        }
        #[cfg(feature = "no-touch")]
        {
            rsk_mgmt::Presence::Confirmed
        }
    }
}

// Accessors for the trusted display, which reaches these through
// `rsk_display::Hooks` rather than naming the statics across a crate boundary.
#[cfg(feature = "display")]
pub fn set_up_pending(pending: bool) {
    UP_PENDING.store(pending, Ordering::Release);
}
#[cfg(feature = "display")]
pub fn set_cancel_requested(requested: bool) {
    CANCEL_REQUESTED.store(requested, Ordering::Relaxed);
}
#[cfg(feature = "display")]
pub fn cancel_requested() -> bool {
    CANCEL_REQUESTED.load(Ordering::Acquire)
}
#[cfg(feature = "display")]
pub fn presence_timeout_ms() -> u32 {
    PRESENCE_TIMEOUT_MS.load(Ordering::Relaxed)
}
#[cfg(feature = "display")]
pub fn set_presence_timeout_ms(ms: u32) {
    PRESENCE_TIMEOUT_MS.store(ms, Ordering::Relaxed);
}
