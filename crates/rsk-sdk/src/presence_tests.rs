// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// A backend with no screen: it implements only `request`, so the ceremony ask
/// has to reach the same code — this is the default every simple front-end and
/// every host test relies on.
struct TouchOnly(Presence);

impl UserPresence for TouchOnly {
    fn request(&mut self, _confirm: Confirm<'_>) -> Presence {
        self.0
    }
}

/// A backend with a screen: the two asks answer differently, and the CCID one
/// folds a cancel into a timeout exactly as `firmware`'s button backend does.
struct Screen;

impl UserPresence for Screen {
    fn request(&mut self, _confirm: Confirm<'_>) -> Presence {
        Presence::Timeout
    }

    fn request_ceremony(&mut self, _confirm: Confirm<'_>) -> Presence {
        Presence::Cancelled
    }
}

#[test]
fn ceremony_defaults_to_request() {
    for p in [
        Presence::Confirmed,
        Presence::Timeout,
        Presence::Declined,
        Presence::Cancelled,
    ] {
        let mut b = TouchOnly(p);
        assert_eq!(b.request_ceremony(Confirm::titled("x")), p);
    }
}

#[test]
fn ceremony_override_does_not_leak_into_request() {
    let mut b = Screen;
    assert_eq!(b.request(Confirm::titled("x")), Presence::Timeout);
    assert_eq!(
        b.request_ceremony(Confirm::titled("x")),
        Presence::Cancelled
    );
}

#[test]
fn always_confirm_confirms_both_asks() {
    let mut b = AlwaysConfirm;
    assert_eq!(b.request(Confirm::titled("x")), Presence::Confirmed);
    assert_eq!(
        b.request_ceremony(Confirm::register(b"rp", b"user")),
        Presence::Confirmed
    );
}

/// The stand-in has no screen and no pad: `getInfo` must not advertise
/// `options.uv` because a host test happened to be the backend.
#[test]
fn always_confirm_has_no_screen_and_no_pad() {
    let mut b = AlwaysConfirm;
    assert!(!b.shows_confirm());
    assert!(!b.uv_available());
    let mut out = [0u8; 8];
    assert_eq!(b.collect_pin(4, &mut out), PinEntry::Unsupported);
    assert_eq!(b.collect_device_pin(4, &mut out), PinEntry::Unsupported);
}
