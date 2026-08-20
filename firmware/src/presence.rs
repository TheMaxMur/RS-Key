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
//!
//! The arbitration itself — which transport owns the wait, whose cancel may end
//! it, and the `spent` latch that stops one hold satisfying two ceremonies —
//! lives in [`rsk_device::presence`], where it is host-tested and carries the
//! Kani harnesses for `NoCrossTransportTouchConsumption`. What stays here is the
//! board half: the button sample, the embassy clock, the LED indicator, and the
//! one `static` the transport and worker executors share.

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

#[cfg(not(feature = "display"))]
use rsk_device::presence::ButtonWait;
#[cfg(all(not(feature = "no-touch"), not(feature = "display")))]
use rsk_device::presence::{Board, Outcome};

use rsk_device::presence::Arbiter;

pub(crate) use rsk_device::presence::MIN_TIMEOUT_SECS;
pub use rsk_device::presence::{SCOPE_CCID, SCOPE_FIDO, SCOPE_NONE, SCOPE_OTP};

/// The one presence arbiter. Cross-executor: the CTAPHID / keyboard transports
/// run on the high-priority interrupt executor and raise cancels or read
/// "is a touch pending", while the worker runs the wait on the thread executor.
static ARBITER: Arbiter = Arbiter::new();

#[cfg(feature = "display")]
const _: () = assert!(MIN_TIMEOUT_SECS as u16 == rsk_ui::TIMEOUT_CHOICES[0]);

/// Mark which transport the worker is dispatching for. Set around every dispatch,
/// `SCOPE_NONE` between them so an on-panel ceremony is nobody's to cancel.
pub fn set_wait_scope(scope: u8) {
    ARBITER.set_wait_scope(scope);
}

/// The CTAPHID keepalive hook passed to `CtapHid::new`: is a touch being awaited
/// *for this transport*? Always `false` on the `no-touch` build, so the status
/// stays `PROCESSING`. Scoping it also closes a cross-transport oracle — an
/// unscoped `UPNEEDED` told a parked FIDO request that a human was about to touch
/// the key for somebody else's operation — and keeps the transport from arming the
/// frame reader that turns a cancel into a cross-transport abort.
pub fn up_pending() -> bool {
    ARBITER.pending_for(SCOPE_FIDO)
}

/// The keyboard-interface status-frame hook: is *its* touch pending? Reported in
/// the OTP status byte so a host polling for a touch-gated challenge-response sees
/// the wait (issue #55).
pub fn otp_up_pending() -> bool {
    ARBITER.pending_for(SCOPE_OTP)
}

/// The CTAPHID cancel hook passed to `CtapHid::new`: request that an in-flight
/// touch wait be abandoned. Only ever ends a FIDO ceremony — the wait it aborts
/// must be the one the cancelling channel owns.
pub fn request_cancel() {
    ARBITER.request_cancel();
}

/// End an OTP touch wait because the host moved on: it sent the dummy write that
/// aborts (`0x8f`), or a new frame — a YubiKey lets either supersede the wait, and
/// without that every later command reads "would block" until the wait times out.
pub fn cancel_otp_wait() {
    ARBITER.cancel_otp_wait();
}

/// Override the touch-wait timeout from the phy record — value in **seconds**,
/// matching PicoForge's tag `0x08`. `0` (or an absent tag) keeps the built-in
/// 30 s default; anything below [`MIN_TIMEOUT_SECS`] is raised to it, which
/// `main.rs`'s `effective_timeout_secs` has to mirror by hand. Call once at
/// boot, before any applet runs.
pub fn set_timeout_secs(secs: u8) {
    ARBITER.set_timeout_secs(secs);
}

/// User presence via BOOTSEL (default) or a dedicated GPIO button.
#[cfg(not(feature = "display"))]
pub struct ButtonPresence {
    #[cfg_attr(feature = "no-touch", allow(dead_code))]
    button: Button,
    #[cfg_attr(feature = "no-touch", allow(dead_code))]
    latch: ButtonWait,
}

/// The presence source: the BOOTSEL hardware button, or a GPIO button (the bool is
/// `active_high` — `true` reads a press as logic high, `false` as logic low).
#[cfg(not(feature = "display"))]
#[cfg_attr(feature = "no-touch", allow(dead_code))]
enum Button {
    Bootsel(Peri<'static, BOOTSEL>),
    Gpio(Input<'static>, bool),
}

#[cfg(all(not(feature = "no-touch"), not(feature = "display")))]
impl Button {
    fn sample(&mut self) -> bool {
        match self {
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
}

// `Instant::as_micros` floors and `Duration::from_millis` rounds up, so the
// crate's `now_us - start >= ms * 1000` is only the exact comparison the wait
// used to make while a tick *is* a microsecond. Pin it rather than comment it.
#[cfg(all(not(feature = "no-touch"), not(feature = "display")))]
const _: () = assert!(embassy_time::TICK_HZ == 1_000_000);

/// `block_for` keeps interrupts enabled, so the high-priority executor (USB +
/// keepalives) runs between polls; only the ~4000-cycle `is_bootsel_pressed` read
/// briefly masks them.
#[cfg(all(not(feature = "no-touch"), not(feature = "display")))]
impl Board for Button {
    fn pressed(&mut self) -> bool {
        self.sample()
    }

    fn now_us(&self) -> u64 {
        Instant::now().as_micros()
    }

    fn block_for_ms(&mut self, ms: u64) {
        block_for(Duration::from_millis(ms));
    }
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
            latch: ButtonWait::new(),
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
            latch: ButtonWait::new(),
        }
    }

    /// One non-blocking sample of the active presence source, for the typed-ticket
    /// button watcher. On the `no-touch` build it never samples.
    pub fn poll_pressed(&mut self) -> bool {
        #[cfg(not(feature = "no-touch"))]
        {
            self.button.sample()
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
        let result = self.latch.wait(&ARBITER, &mut self.button);
        crate::led::set_status(saved);
        result
    }
}

#[cfg(not(feature = "display"))]
impl rsk_sdk::UserPresence for ButtonPresence {
    /// A smartcard touch policy (OpenPGP UIF, a PIV slot, OATH/OTP, management,
    /// rescue, vendor). Those applets are reached over CCID, which carries no
    /// `CTAPHID_CANCEL`, so a cancel is just a non-confirmation here.
    fn request(&mut self, _confirm: rsk_sdk::Confirm<'_>) -> rsk_sdk::Presence {
        #[cfg(not(feature = "no-touch"))]
        {
            match self.wait() {
                Outcome::Confirmed => rsk_sdk::Presence::Confirmed,
                Outcome::Timeout | Outcome::Cancelled => rsk_sdk::Presence::Timeout,
            }
        }
        #[cfg(feature = "no-touch")]
        {
            rsk_sdk::Presence::Confirmed
        }
    }

    /// A CTAP2 ceremony, which *can* be cancelled mid-wait — the in-flight
    /// command owes `CTAP2_ERR_KEEPALIVE_CANCEL`, so report it.
    fn request_ceremony(&mut self, _confirm: rsk_sdk::Confirm<'_>) -> rsk_sdk::Presence {
        #[cfg(not(feature = "no-touch"))]
        {
            match self.wait() {
                Outcome::Confirmed => rsk_sdk::Presence::Confirmed,
                Outcome::Timeout => rsk_sdk::Presence::Timeout,
                Outcome::Cancelled => rsk_sdk::Presence::Cancelled,
            }
        }
        #[cfg(feature = "no-touch")]
        {
            rsk_sdk::Presence::Confirmed
        }
    }
}

// Accessors for the trusted display, which reaches these through
// `rsk_display::Hooks` rather than naming the arbiter across a crate boundary.
#[cfg(feature = "display")]
pub fn set_up_pending(pending: bool) {
    ARBITER.set_up_pending(pending);
}
#[cfg(feature = "display")]
pub fn set_cancel_requested(requested: bool) {
    ARBITER.set_cancel_requested(requested);
}
#[cfg(feature = "display")]
pub fn cancel_requested() -> bool {
    ARBITER.cancel_requested()
}
#[cfg(feature = "display")]
pub fn presence_timeout_ms() -> u32 {
    ARBITER.timeout_ms()
}
#[cfg(feature = "display")]
pub fn set_presence_timeout_ms(ms: u32) {
    ARBITER.set_timeout_ms(ms);
}
