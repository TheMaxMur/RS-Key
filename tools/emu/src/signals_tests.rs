// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// A touch wait belongs to one transport, and the others must not report it.
///
/// Before the scope existed, `tests/77_otp_touch_wait.py` — whose whole subject
/// is the OTP status frame's wait bit — could have read a FIDO ceremony's touch
/// as its own, and a FIDO client would say "touch your security key" for an
/// OpenPGP signature.
#[test]
fn a_wait_is_only_visible_to_the_transport_that_owns_it() {
    let s = Signals::default();
    s.set_wait_scope(SCOPE_OTP);
    s.set_up_pending(true);
    assert!(s.up_pending_for(SCOPE_OTP));
    assert!(!s.up_pending_for(SCOPE_FIDO));
    assert!(!s.up_pending_for(SCOPE_CCID));

    s.set_wait_scope(SCOPE_CCID);
    assert!(
        !s.up_pending_for(SCOPE_OTP),
        "an OpenPGP touch is not the OTP transport's"
    );
    assert!(
        !s.up_pending_for(SCOPE_FIDO),
        "nor a FIDO client's to announce"
    );
}

#[test]
fn no_wait_is_nobodys() {
    let s = Signals::default();
    s.set_wait_scope(SCOPE_FIDO);
    // The scope alone means nothing: it says who a wait *would* belong to.
    assert!(!s.up_pending_for(SCOPE_FIDO));
    s.set_up_pending(true);
    assert!(s.up_pending_for(SCOPE_FIDO));
    // `end` drops the wait; the display's own ceremonies run under SCOPE_NONE and
    // are nobody's to report.
    s.end();
    assert!(!s.up_pending_for(SCOPE_FIDO));
}

/// The cancel scoping this sits beside, kept honest at the same time: a second
/// process on its own CTAPHID channel cannot end this one's ceremony (audit
/// run-31 filed the unscoped form as HIGH), and the OTP host's dummy write ends
/// only an OTP wait.
#[test]
fn a_cancel_reaches_only_its_own_command() {
    let s = Signals::default();
    s.begin(0x1111_1111);
    s.request_cancel(0x2222_2222);
    assert!(
        !s.cancelled(),
        "another channel's CANCEL is not this ceremony's"
    );
    s.request_cancel(0x1111_1111);
    assert!(s.cancelled());

    let s = Signals::default();
    s.begin(0x1111_1111);
    s.cancel_otp();
    assert!(
        !s.cancelled(),
        "no OTP wait is running, so there is nothing to end"
    );
    s.begin_otp();
    s.cancel_otp();
    assert!(s.cancelled());
}
