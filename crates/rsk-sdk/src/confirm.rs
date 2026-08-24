// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The trusted-display confirmation context threaded through both
//! [`UserPresence`](crate::UserPresence) asks. It says *what* an Approve/Deny prompt should
//! show: a short, trusted, device-controlled `title` plus up to two **untrusted**
//! relying-party fields the screen sanitizes before painting. The button presence
//! backend ignores all of it; only the `display` build's on-screen backend reads
//! it. It lives here, in the crate every applet already depends on, so threading
//! the context pulls no display code into a standard (screenless) key — the
//! fields are borrowed, so it costs nothing when ignored.

/// Which ceremony a confirmation is for, so a richer front-end (the trusted
/// display) can show the right screen. The button-presence backend and the
/// host-test stand-in ignore it — they confirm on a press regardless — so a key
/// with no screen behaves exactly as before.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfirmKind {
    /// An Approve/Deny presence prompt — the default for FIDO sign-in
    /// (`getAssertion`), FIDO selection/probe, and the OpenPGP/PIV/OATH/OTP touch
    /// policies.
    Generic,
    /// A WebAuthn registration (`makeCredential`) — the display offers to save a new
    /// passkey for the named account instead of a bare Approve/Deny.
    Register,
}

/// What an on-screen Approve/Deny prompt should say while a touch is requested.
///
/// `title` is firmware-controlled trusted text (e.g. `"Sign in?"`); `primary` and
/// `secondary` are **untrusted** relying-party bytes (an rp id, an account name)
/// the display backend reduces to bounded printable ASCII before rendering. Pass
/// empty slices for fields an operation does not carry. `kind` lets a screen pick
/// the matching ceremony layout; the button backend disregards it.
#[derive(Clone, Copy)]
pub struct Confirm<'a> {
    pub title: &'static str,
    pub primary: &'a [u8],
    pub secondary: &'a [u8],
    pub kind: ConfirmKind,
}

impl<'a> Confirm<'a> {
    /// A generic prompt with a trusted title and untrusted primary/secondary fields.
    pub const fn new(title: &'static str, primary: &'a [u8], secondary: &'a [u8]) -> Self {
        Self {
            title,
            primary,
            secondary,
            kind: ConfirmKind::Generic,
        }
    }

    /// A title-only generic prompt — no relying-party text (e.g. reset, selection).
    pub const fn titled(title: &'static str) -> Self {
        Self::new(title, &[], &[])
    }

    /// A WebAuthn registration: the relying party and the account being enrolled.
    pub const fn register(primary: &'a [u8], secondary: &'a [u8]) -> Self {
        Self {
            title: "Register key?",
            primary,
            secondary,
            kind: ConfirmKind::Register,
        }
    }
}
