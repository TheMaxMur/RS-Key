// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use std::vec;

use super::*;
use crate::tests::{Env, Pad, TestUi, center};

// The two asks this one backend answers differently: a CTAP2 ceremony (the
// registration card, the closing "Approved" pop, a reportable cancel) and a
// smartcard touch policy (the bare Approve/Deny prompt).
fn ask_fido<'a>(ui: &'a RefCell<TestUi<'a>>, confirm: Confirm<'_>) -> rsk_sdk::Presence {
    rsk_sdk::UserPresence::request_ceremony(&mut TouchPresence::new(ui), confirm)
}

fn ask_card<'a>(ui: &'a RefCell<TestUi<'a>>, confirm: Confirm<'_>) -> rsk_sdk::Presence {
    rsk_sdk::UserPresence::request(&mut TouchPresence::new(ui), confirm)
}

/// The anti-phishing prompt as an applet asks for it: a trusted title plus the
/// untrusted relying-party text the screen sanitizes.
fn sign_in() -> Confirm<'static> {
    Confirm::new("Sign in?", b"example.com", b"alex@example.com")
}

fn allow() -> rsk_ui::Point {
    center(ALLOW_RECT)
}

fn deny() -> rsk_ui::Point {
    center(rsk_ui::DENY_RECT)
}

/// A prompt with a presence timeout long enough for the gesture under test.
fn prompt(env: &Env, pad: Pad, timeout_ms: u32) -> RefCell<TestUi<'_>> {
    let mut ui = env.ui(pad);
    ui.hooks.presence_ms = timeout_ms;
    RefCell::new(ui)
}

#[test]
fn a_deny_tap_is_a_real_decline() {
    // The BOOTSEL button has no decline gesture; the screen does, and it must
    // reach the applet as `Declined` (→ OPERATION_DENIED), not as a timeout.
    let env = Env::new();
    let ui = prompt(&env, Pad::taps(&[deny()]), 2_000);
    let got = ask_fido(&ui, sign_in());
    assert_eq!(got, rsk_sdk::Presence::Declined);
}

#[test]
fn a_brush_on_allow_does_not_approve() {
    // Approve is a deliberate hold precisely so an accidental contact cannot
    // produce a signature.
    let env = Env::new();
    let ui = prompt(&env, Pad::taps(&[allow()]), 400);
    let got = ask_fido(&ui, sign_in());
    assert_eq!(got, rsk_sdk::Presence::Timeout);
}

#[test]
fn a_completed_hold_approves() {
    let env = Env::new();
    let ui = prompt(&env, Pad::hold(allow()), 4_000);
    let start = Instant::now();
    let got = ask_fido(&ui, sign_in());
    assert_eq!(got, rsk_sdk::Presence::Confirmed);
    assert!(start.elapsed() >= Duration::from_millis(HOLD_MS));
}

/// Every ceremony opens by dropping a cancel an earlier wait left behind and by
/// noting the LED status its exit restores. `Board::cancel_in` exists *because* of
/// the first half — a test cannot deliver a mid-wait cancel any other way — yet
/// neither half was ever read back, so the whole entry could be skipped unnoticed.
#[test]
fn a_ceremony_drops_a_stale_cancel_and_restores_the_led_it_found() {
    let env = Env::new();
    let mut ui = env.ui(Pad::hold(allow()));
    ui.hooks.presence_ms = 4_000;
    ui.hooks.cancel = true;
    // Anything but the touch indicator the ceremony switches to, so a restore of
    // the wrong status cannot pass by coincidence.
    ui.hooks.led = rsk_led::STATUS_BOOT;
    let ui = RefCell::new(ui);

    let got = ask_fido(&ui, sign_in());
    assert_eq!(
        got,
        rsk_sdk::Presence::Confirmed,
        "a cancel from an earlier wait aborted this one"
    );
    assert_eq!(
        ui.borrow().hooks.led,
        rsk_led::STATUS_BOOT,
        "the exit restored an LED status the entry never found"
    );
}

#[test]
fn a_hold_that_is_released_starts_over() {
    // Two three-quarter holds are not one whole one: lifting the finger resets the
    // fill, so approval always costs one uninterrupted HOLD_MS.
    let polls = (HOLD_MS as usize * 3 / 4) / TOUCH_POLL_MS as usize;
    let mut script = vec![None];
    script.extend(vec![Some(allow()); polls]);
    script.push(None);
    script.extend(vec![Some(allow()); polls]);
    let env = Env::new();
    let ui = prompt(&env, Pad::script(&script), 1_800);
    let got = ask_fido(&ui, sign_in());
    assert_eq!(got, rsk_sdk::Presence::Timeout);
}

#[test]
fn a_finger_still_down_when_the_prompt_appears_cannot_approve_it() {
    // The panel reports a level, so a finger left over from a previous ceremony
    // would start filling this hold on the first poll — one press approving two
    // ceremonies. The release wait in front of the loop is what stops it, and it
    // holds even for a contact that outlasts a completed hold.
    let polls = (HOLD_MS as usize * 2) / TOUCH_POLL_MS as usize;
    let env = Env::new();
    let ui = prompt(&env, Pad::held_for(allow(), polls), 1_500);
    let got = ask_fido(&ui, sign_in());
    assert_eq!(got, rsk_sdk::Presence::Timeout);
}

#[test]
fn a_host_cancel_ends_the_prompt() {
    let env = Env::new();
    let ui = prompt(&env, Pad::idle(), 5_000);
    ui.borrow_mut().hooks.cancel_in.set(Some(2));
    let got = ask_fido(&ui, sign_in());
    assert_eq!(got, rsk_sdk::Presence::Cancelled);
}

#[test]
fn an_untouched_prompt_times_out() {
    let env = Env::new();
    let ui = prompt(&env, Pad::idle(), 300);
    let got = ask_fido(&ui, sign_in());
    assert_eq!(got, rsk_sdk::Presence::Timeout);
}

#[test]
fn the_prompt_leaves_the_presence_flags_and_the_status_as_it_found_them() {
    let env = Env::new();
    let ui = prompt(&env, Pad::taps(&[deny()]), 2_000);
    ui.borrow_mut().hooks.led = rsk_led::STATUS_PROCESSING;
    ask_fido(&ui, sign_in());
    let u = ui.borrow();
    assert!(
        !u.hooks.up_pending,
        "the keepalive stops reporting UPNEEDED"
    );
    assert!(
        !u.hooks.cancel,
        "a stale cancel must not abort the next ceremony"
    );
    assert_eq!(u.hooks.led, rsk_led::STATUS_PROCESSING);
}

#[test]
fn a_registration_card_saves_on_a_single_tap() {
    // Registration is the lower-stakes ceremony: Save is a tap, and the deliberate
    // hold is reserved for the sign-in approve.
    let env = Env::new();
    let ui = prompt(&env, Pad::taps(&[allow()]), 2_000);
    let got = ask_fido(&ui, Confirm::register(b"example.com", b"alex"));
    assert_eq!(got, rsk_sdk::Presence::Confirmed);
}

#[test]
fn a_registration_card_declines_on_cancel() {
    let env = Env::new();
    let ui = prompt(&env, Pad::taps(&[deny()]), 2_000);
    let got = ask_fido(&ui, Confirm::register(b"example.com", b"alex"));
    assert_eq!(got, rsk_sdk::Presence::Declined);
}

#[test]
fn an_expired_registration_card_ignores_a_leftover_press() {
    // A finger that never lifts outlasts the release wait's own bound, so the loop
    // is entered with the ceremony already expired AND the button still pressed.
    // Save is a single tap, so the deadline has to be tested BEFORE the read or
    // that leftover press reads as a fresh approval — a mistake the sign-in hold
    // cannot make and this card can. Costs the release floor, which is the point.
    let env = Env::new();
    let ui = prompt(&env, Pad::held(allow()), 400);
    let got = ask_fido(&ui, Confirm::register(b"example.com", b"alex"));
    assert_eq!(got, rsk_sdk::Presence::Timeout);
}

#[test]
fn a_ccid_applet_reads_a_cancel_as_a_timeout() {
    // OpenPGP and PIV run over CCID, which carries no `CTAPHID_CANCEL` — so the
    // cancel outcome has no wire form there and must degrade to the timeout.
    let env = Env::new();
    let ui = prompt(&env, Pad::idle(), 5_000);
    ui.borrow_mut().hooks.cancel_in.set(Some(2));
    let got = ask_card(&ui, Confirm::titled("Sign?"));
    assert_eq!(got, rsk_sdk::Presence::Timeout);
}

#[test]
fn a_ccid_applet_still_hears_a_deny() {
    let env = Env::new();
    let ui = prompt(&env, Pad::taps(&[deny()]), 2_000);
    let got = ask_card(&ui, Confirm::titled("Sign?"));
    assert_eq!(got, rsk_sdk::Presence::Declined);
}

#[test]
fn a_ceremony_names_the_operation_it_approves() {
    // The CTAP 2.1 §6.6 exemption from the reset window rests on this being true,
    // and the on-screen pad is what makes built-in UV available.
    let env = Env::new();
    let ui = prompt(&env, Pad::idle(), 300);
    let presence = TouchPresence::new(&ui);
    assert!(rsk_sdk::UserPresence::shows_confirm(&presence));
    assert!(rsk_sdk::UserPresence::uv_available(&presence));
}

#[test]
fn the_screen_has_no_bootsel_click_counter() {
    let env = Env::new();
    let ui = prompt(&env, Pad::idle(), 300);
    assert!(!TouchPresence::new(&ui).poll_pressed());
}

/// The two asks exist so the display can answer them differently, and the whole
/// difference is invisible to every other case in this file: a merge that made
/// `request` run the ceremony body would leave the suite green while every
/// OpenPGP/PIV signature — one presence ask *each* — paid the closing pop.
/// Frames, not wall time: the pop is a painted screen, and `Panel` counts those.
#[test]
fn only_the_ceremony_ask_pops_the_approved_card() {
    // Two holds on one pad: `Pad::hold`'s finger never lifts, so a second ask
    // behind it would sit in its opening release wait until the timeout.
    let polls = (HOLD_MS / TOUCH_POLL_MS) as usize * 2;
    let mut script = vec![None];
    for _ in 0..2 {
        script.extend(std::iter::repeat_n(Some(allow()), polls));
        script.extend([None; 4]);
    }
    let env = Env::new();
    let ui = prompt(&env, Pad::script(&script), 4_000);

    let before = ui.borrow().panel.frames;
    assert_eq!(ask_card(&ui, sign_in()), rsk_sdk::Presence::Confirmed);
    let card = ui.borrow().panel.frames - before;

    let before = ui.borrow().panel.frames;
    assert_eq!(ask_fido(&ui, sign_in()), rsk_sdk::Presence::Confirmed);
    let ceremony = ui.borrow().panel.frames - before;

    assert!(
        ceremony > card,
        "ceremony painted {ceremony} frames, touch policy {card}: either the \
         ceremony lost its Approved pop, or a card signature is now paying it"
    );
}
