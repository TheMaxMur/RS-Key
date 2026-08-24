// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The user-presence seam every applet is handed by its composition root: one
//! physical source (the BOOTSEL button, the trusted display's touch pad, the
//! emulator's terminal prompt), asked the same way by all of them.

use crate::Confirm;

/// Outcome of asking for physical user presence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// The user touched the device.
    Confirmed,
    /// No touch within the timeout.
    Timeout,
    /// The user actively declined (no decline path on the BOOTSEL button today,
    /// but tests and other front-ends can produce it → `OPERATION_DENIED`).
    Declined,
    /// The platform sent `CTAPHID_CANCEL` while the touch was awaited; the
    /// in-flight CTAP2 command must answer `CTAP2_ERR_KEEPALIVE_CANCEL`. Only
    /// [`UserPresence::request_ceremony`] can report it — CCID carries no cancel.
    Cancelled,
}

/// Outcome of collecting a built-in-UV PIN on the device's own UI (the
/// trusted-display PIN pad). Built-in UV proves *user verification* without the
/// PIN ever crossing the host — the anti-keylogger counterpart to the on-screen
/// Approve/Deny that proves *user presence*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinEntry {
    /// The user committed a PIN of this many ASCII-digit bytes, in `out[..len]`.
    Entered(usize),
    /// The user tapped Cancel on the pad — a deliberate decline.
    Declined,
    /// No completed entry within the presence timeout.
    Timeout,
    /// The platform sent `CTAPHID_CANCEL` while the pad was up.
    Cancelled,
    /// The backend has no on-device UI to collect a PIN (the default).
    Unsupported,
}

/// Obtains physical user presence. The firmware polls the BOOTSEL button; with
/// no button configured it confirms immediately, which is also what host tests
/// use via [`AlwaysConfirm`].
///
/// One trait for every applet: the board has one button and one screen, so a
/// per-applet copy of this only ever forced the composition roots to write the
/// same impl seven times. The two ceremonies a front-end may genuinely answer
/// differently are [`request`](Self::request) and
/// [`request_ceremony`](Self::request_ceremony); the rest defaults to "this
/// build has no screen", which is what a screenless key is.
pub trait UserPresence {
    /// Ask for presence on a smartcard touch policy — OpenPGP UIF, a PIV slot,
    /// an OATH/OTP credential, a management/rescue/vendor write. `confirm`
    /// describes the pending operation for a trusted on-screen Approve/Deny
    /// prompt; the BOOTSEL-button backend ignores it. These applets are reached
    /// over CCID, which carries no `CTAPHID_CANCEL`, so a backend that can see
    /// one reports it here as [`Presence::Timeout`].
    fn request(&mut self, confirm: Confirm<'_>) -> Presence;

    /// Ask for presence to open a ceremony a host raised: a CTAP2/WebAuthn
    /// command, or the trusted display's gate before it collects a CCID pinpad
    /// PIN. One ask per command, where [`request`](Self::request) is one per
    /// signature. Split from it because a screen answers the two differently:
    /// the trusted display runs the registration card for
    /// [`ConfirmKind::Register`](crate::ConfirmKind::Register) and closes an
    /// approved ceremony with a brief "Approved" pop, which on a per-signature
    /// card touch policy would be both wrong-worded and a latency regression.
    /// A backend that can observe a `CTAPHID_CANCEL` must override this and
    /// report [`Presence::Cancelled`], or the command loses its
    /// `CTAP2_ERR_KEEPALIVE_CANCEL`.
    fn request_ceremony(&mut self, confirm: Confirm<'_>) -> Presence {
        self.request(confirm)
    }

    /// Whether this backend actually shows the [`Confirm`] to the user, so a touch
    /// carries *which* operation it approves. The BOOTSEL button discards the title
    /// and raises the same indication for every ceremony; only the trusted display
    /// overrides this. CTAP 2.1 §6.6 exempts exactly such an authenticator from the
    /// `authenticatorReset` power-up window.
    fn shows_confirm(&self) -> bool {
        false
    }

    /// Whether this backend can collect built-in user verification — a PIN entered
    /// on the authenticator's own UI, so it never reaches the host. Only the
    /// trusted-display backend overrides this; the BOOTSEL button and the host-test
    /// stand-in have no UI to type a PIN, so built-in UV is absent and `options.uv`
    /// stays unadvertised (and `clientPIN` 0x06/0x07 answer `UnsupportedOption`).
    fn uv_available(&self) -> bool {
        false
    }

    /// Collect a built-in-UV PIN on the device's own UI as ASCII digits into `out`,
    /// refusing to *commit* below `min_len` characters so a fat-fingered short entry
    /// can't burn a retry. Returns how the entry ended. The default — no on-device
    /// UI — reports [`PinEntry::Unsupported`]; this is only reached on a backend
    /// that also overrides [`uv_available`](Self::uv_available).
    fn collect_pin(&mut self, _min_len: usize, _out: &mut [u8]) -> PinEntry {
        PinEntry::Unsupported
    }

    /// Collect the authenticator's **own** device PIN — the one a trusted-display
    /// build's onboarding sets, not the clientPIN — on the device's own UI. Separate
    /// from [`collect_pin`](Self::collect_pin) because the screen must name which PIN
    /// it is asking for: a pad captioned "FIDO PIN" that verifies the device PIN is
    /// exactly the kind of lie the trusted display exists to prevent. Used by the
    /// vendor gate when no clientPIN is set.
    fn collect_device_pin(&mut self, _min_len: usize, _out: &mut [u8]) -> PinEntry {
        PinEntry::Unsupported
    }
}

/// A [`UserPresence`] that confirms instantly — the no-button default and the
/// host-test / fuzz stand-in.
pub struct AlwaysConfirm;

impl UserPresence for AlwaysConfirm {
    fn request(&mut self, _confirm: Confirm<'_>) -> Presence {
        Presence::Confirmed
    }
}

#[cfg(test)]
#[path = "presence_tests.rs"]
mod tests;
