// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! ⚠️ These scripts count **polls**; `pin.rs` and `touch.rs` measure `Instant::now()`.
//! Under load a poll outlasts `TOUCH_POLL_MS`, so a script sized at a fraction of
//! `HOLD_MS` spans more wall-clock than it names and a hold completes where the
//! test expects it not to. Three of them have been seen to fail that way inside a
//! loaded `check.sh` and pass on every isolated re-run. Widening a script does not
//! fix it and narrowing it removes what the assertion tests; the fix is a clock
//! seam through the crate, which nothing has yet.

use std::vec;

use super::*;
use crate::tests::{Env, NEW_PIN, PIN, Pad, WRONG_PIN, center, dev, pin_entry, pin_key};

/// The T9 group the tests type from: `"2abc"`, so a cycle is visible in one press.
const ABC: usize = 1;
/// A second group, to prove a different key commits what the first left pending.
const DEF: usize = 2;

#[test]
fn a_repeat_press_cycles_within_its_group() {
    let mut t9 = T9::new(&Label::default());
    t9.press(ABC);
    assert_eq!(t9.pending, Some(b'2'));
    t9.press(ABC);
    assert_eq!(t9.pending, Some(b'a'));
    assert_eq!(
        t9.value().as_str(),
        "",
        "a cycling character is not in the value"
    );
    for _ in 0..rsk_ui::T9_GROUPS[ABC].len() {
        t9.press(ABC);
    }
    assert_eq!(t9.pending, Some(b'a'), "the cycle wraps");
}

#[test]
fn a_different_key_commits_what_was_pending() {
    // This is what makes "abc" typable on one keypad.
    let mut t9 = T9::new(&Label::default());
    t9.press(ABC);
    t9.press(ABC);
    t9.press(DEF);
    assert_eq!(t9.value().as_str(), "a");
    assert_eq!(t9.pending, Some(b'3'));
}

#[test]
fn backspace_undoes_the_last_thing_that_appeared() {
    let mut t9 = T9::new(&Label::clamp(b"ab"));
    assert_eq!(t9.value().as_str(), "ab");
    t9.press(DEF);
    t9.backspace();
    assert_eq!(t9.pending, None);
    assert_eq!(
        t9.value().as_str(),
        "ab",
        "the pending character went first"
    );
    t9.backspace();
    assert_eq!(t9.value().as_str(), "a");
    t9.backspace();
    t9.backspace();
    assert_eq!(t9.value().as_str(), "", "an empty field takes no more");
}

#[test]
fn a_quiet_key_settles_the_pending_character() {
    // The one place the field moves on its own, so it is timed against the real
    // window rather than a stubbed clock.
    let mut t9 = T9::new(&Label::default());
    t9.press(ABC);
    assert!(
        !t9.settle(),
        "a character must not settle the moment it is typed"
    );
    std::thread::sleep(std::time::Duration::from_millis(T9_COMMIT_MS + 50));
    assert!(t9.settle());
    assert_eq!(t9.value().as_str(), "2");
    assert_eq!(t9.pending, None);
    assert!(!t9.settle(), "and settling is not a repaint every tick");
}

#[test]
fn a_full_field_takes_no_more_characters() {
    let full = [b'a'; rsk_fido::passkeys::RP_NICK_MAX_LEN];
    let mut t9 = T9::new(&Label::clamp(&full));
    assert_eq!(t9.len, full.len());
    t9.press(ABC);
    t9.commit();
    assert_eq!(t9.len, full.len(), "the store's cap is the field's cap");
}

#[test]
fn a_nickname_longer_than_the_field_is_taken_as_far_as_it_fits() {
    let long = [b'b'; rsk_fido::passkeys::RP_NICK_MAX_LEN * 2];
    let t9 = T9::new(&Label::clamp(&long));
    assert_eq!(t9.len, rsk_fido::passkeys::RP_NICK_MAX_LEN);
}

// --- the PIN pad -----------------------------------------------------------

/// The CTAP floor the pad enforces, whatever the policy above it.
const FLOOR: usize = 4;

fn title() -> &'static str {
    PinScope::Device.pin_title()
}

#[test]
fn a_typed_pin_is_committed_by_ok() {
    let env = Env::new();
    let mut ui = env.ui(Pad::taps(&pin_entry(PIN)));
    let mut out = [0u8; 64];
    let got = ui.collect_pin(title(), None, FLOOR, FLOOR as u8, &mut out, false);
    assert!(matches!(got, rsk_fido::PinEntry::Entered(n) if n == PIN.len()));
    assert_eq!(&out[..PIN.len()], PIN);
}

#[test]
fn backspace_drops_the_last_digit() {
    let env = Env::new();
    let mut taps = vec![pin_key(rsk_ui::PinKey::Digit(9))];
    taps.push(pin_key(rsk_ui::PinKey::Del));
    taps.extend(pin_entry(PIN));
    let mut ui = env.ui(Pad::taps(&taps));
    let mut out = [0u8; 64];
    let got = ui.collect_pin(title(), None, FLOOR, FLOOR as u8, &mut out, false);
    assert!(matches!(got, rsk_fido::PinEntry::Entered(n) if n == PIN.len()));
    assert_eq!(&out[..PIN.len()], PIN);
}

#[test]
fn the_eye_toggle_is_not_a_digit() {
    // The reveal toggle sits in the band between the header and the grid. A rect
    // that overlapped a key would type a digit the user did not — and burn a retry.
    let env = Env::new();
    let mut taps = vec![center(rsk_ui::PIN_EYE_RECT)];
    taps.extend(pin_entry(PIN));
    let mut ui = env.ui(Pad::taps(&taps));
    let mut out = [0u8; 64];
    let got = ui.collect_pin(title(), None, FLOOR, FLOOR as u8, &mut out, false);
    assert!(matches!(got, rsk_fido::PinEntry::Entered(n) if n == PIN.len()));
    assert_eq!(&out[..PIN.len()], PIN);
}

#[test]
fn ok_below_the_floor_does_not_commit() {
    // A short entry handed to a verify would spend a retry on a PIN the user never
    // finished typing.
    let env = Env::new();
    let taps = [
        pin_key(rsk_ui::PinKey::Digit(1)),
        pin_key(rsk_ui::PinKey::Digit(2)),
        pin_key(rsk_ui::PinKey::Ok),
    ];
    let mut ui = env.ui(Pad::taps(&taps));
    let mut out = [0u8; 64];
    let got = ui.collect_pin(title(), None, FLOOR, FLOOR as u8, &mut out, false);
    assert!(
        matches!(got, rsk_fido::PinEntry::Timeout),
        "the pad stays open"
    );
}

#[test]
fn cancel_is_a_deliberate_decline() {
    let env = Env::new();
    let mut ui = env.ui(Pad::taps(&[center(rsk_ui::PIN_CANCEL_RECT)]));
    let mut out = [0u8; 64];
    let got = ui.collect_pin(title(), None, FLOOR, FLOOR as u8, &mut out, false);
    assert!(matches!(got, rsk_fido::PinEntry::Declined));
}

#[test]
fn an_untouched_pad_times_out() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    let mut out = [0u8; 64];
    let got = ui.collect_pin(title(), None, FLOOR, FLOOR as u8, &mut out, false);
    assert!(matches!(got, rsk_fido::PinEntry::Timeout));
}

#[test]
fn a_host_cancel_ends_the_pad() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    ui.hooks.cancel_in.set(Some(2));
    let mut out = [0u8; 64];
    let got = ui.collect_pin(title(), None, FLOOR, FLOOR as u8, &mut out, false);
    assert!(matches!(got, rsk_fido::PinEntry::Cancelled));
}

#[test]
fn the_pad_leaves_the_presence_flags_and_the_status_as_it_found_them() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    ui.hooks.led = rsk_led::STATUS_PROCESSING;
    let mut out = [0u8; 64];
    ui.collect_pin(title(), None, FLOOR, FLOOR as u8, &mut out, false);
    assert!(
        !ui.hooks.up_pending,
        "the keepalive stops reporting UPNEEDED"
    );
    assert!(
        !ui.hooks.cancel,
        "a stale cancel must not abort the next wait"
    );
    assert_eq!(
        ui.hooks.led,
        rsk_led::STATUS_PROCESSING,
        "the LED is borrowed, not taken"
    );
}

#[test]
fn the_pad_holds_the_ambient_screen_back_on_its_way_out() {
    // pad → confirm inside one UV ceremony is a back-to-back hand-off; without the
    // quiet window the idle screen flashes in the host's round-trip gap.
    let env = Env::new();
    let mut ui = env.ui(Pad::taps(&[center(rsk_ui::PIN_CANCEL_RECT)]));
    let mut out = [0u8; 64];
    ui.collect_pin(title(), None, FLOOR, FLOOR as u8, &mut out, false);
    let now = Instant::now().as_millis() as u32;
    let quiet = AMBIENT_QUIET_UNTIL_MS.load(Ordering::Relaxed);
    assert!(
        quiet.wrapping_sub(now) as i32 > 0,
        "the window is still open"
    );
    assert!(quiet.wrapping_sub(now) <= AMBIENT_QUIET_MS);
}

#[test]
fn a_queued_host_command_cannot_shut_the_pad_at_once() {
    // `REQ` latches until the worker drains it and the worker cannot run while this
    // busy-waits — so without the floor one queued command closes the pad on its
    // very first poll, and a host repeating any ungated command (getInfo will do)
    // holds the owner's unlock pad shut for as long as it likes.
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    ui.hooks.host_pending = true;
    ui.hooks.presence_ms = (UI_YIELD_FLOOR_MS / 4) as u32;
    let mut out = [0u8; 64];
    let got = ui.collect_pin(title(), None, FLOOR, FLOOR as u8, &mut out, true);
    assert!(matches!(got, rsk_fido::PinEntry::Timeout));
}

#[test]
fn a_queued_host_command_closes_an_untouched_pad_after_the_floor() {
    // The other half: the yield does exist, so a pad nobody is using does not make
    // the parked worker wait out the whole presence timeout.
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    ui.hooks.host_pending = true;
    ui.hooks.presence_ms = (UI_YIELD_FLOOR_MS * 4) as u32;
    let mut out = [0u8; 64];
    let start = Instant::now();
    let got = ui.collect_pin(title(), None, FLOOR, FLOOR as u8, &mut out, true);
    assert!(matches!(got, rsk_fido::PinEntry::Cancelled));
    assert!(start.elapsed() >= Duration::from_millis(UI_YIELD_FLOOR_MS));
}

#[test]
fn the_pad_never_yields_mid_entry() {
    // A user half-way through typing must not have the pad shut under them by a
    // host command that arrived while they were reaching for the next digit.
    let env = Env::new();
    let mut ui = env.ui(Pad::taps(&[pin_key(rsk_ui::PinKey::Digit(7))]));
    ui.hooks.host_pending = true;
    ui.hooks.presence_ms = (UI_YIELD_FLOOR_MS + 500) as u32;
    let mut out = [0u8; 64];
    let got = ui.collect_pin(title(), None, FLOOR, FLOOR as u8, &mut out, true);
    assert!(
        matches!(got, rsk_fido::PinEntry::Timeout),
        "an entry in progress outlives the yield floor"
    );
}

// --- set / change PIN ------------------------------------------------------

#[test]
fn a_mismatched_confirmation_stores_nothing() {
    let env = Env::new();
    let mut taps = pin_entry(PIN);
    taps.extend(pin_entry(WRONG_PIN));
    let mut ui = env.ui(Pad::taps(&taps));
    ui.run_set_pin(PinScope::Device);
    assert!(!rsk_fido::passkeys::device_pin_is_set(
        &mut env.fs.borrow_mut()
    ));
}

#[test]
fn a_new_device_pin_replaces_the_old_one() {
    let env = Env::new();
    env.set_device_pin(PIN);
    let mut taps = pin_entry(PIN); // the gate on the current PIN
    taps.extend(pin_entry(NEW_PIN));
    taps.extend(pin_entry(NEW_PIN));
    let mut ui = env.ui(Pad::taps(&taps));
    ui.run_set_pin(PinScope::Device);
    assert!(matches!(
        rsk_fido::passkeys::spend_and_verify_device_pin(&dev(), &mut env.fs.borrow_mut(), NEW_PIN),
        rsk_fido::passkeys::LocalPin::Ok
    ));
    assert!(
        ui.home_pin_set,
        "the cached lock proxy must not go stale, or the next sleep skips the lock"
    );
    assert_eq!(
        ui.hooks.pin_changed, 0,
        "the device PIN is not the clientPIN — no CTAP session to end"
    );
}

#[test]
fn changing_the_device_pin_needs_the_current_one() {
    let env = Env::new();
    env.set_device_pin(PIN);
    // The gate in front is declined, so New / Confirm are never reached.
    let mut ui = env.ui(Pad::taps(&[center(rsk_ui::PIN_CANCEL_RECT)]));
    ui.run_set_pin(PinScope::Device);
    assert!(
        matches!(
            rsk_fido::passkeys::spend_and_verify_device_pin(&dev(), &mut env.fs.borrow_mut(), PIN),
            rsk_fido::passkeys::LocalPin::Ok
        ),
        "the old PIN still opens the device"
    );
}

#[test]
fn setting_the_fido_pin_from_the_panel_revokes_live_tokens() {
    // CTAP 2.1 §6.5.5.6. `FidoState` lives in the worker and outlives every
    // dispatch, and a pinUvAuthToken is random RAM state rather than a PIN
    // derivative — so without this a host holding a `PERM_CM` token minted under
    // the old PIN goes on deleting resident credentials, with no touch, right
    // after the owner did the one thing they believe revokes it.
    let env = Env::new();
    let mut taps = pin_entry(PIN);
    taps.extend(pin_entry(PIN));
    let mut ui = env.ui(Pad::taps(&taps));
    ui.run_set_pin(PinScope::Fido);
    assert!(rsk_fido::passkeys::pin_is_set(&mut env.fs.borrow_mut()));
    assert_eq!(ui.hooks.pin_changed, 1);
}

// --- the hold-to-confirm gesture -------------------------------------------

#[test]
fn a_brush_does_not_complete_a_hold() {
    // The gesture the passkey delete and the factory reset stand on: a single
    // sample on the button is not consent.
    let env = Env::new();
    let mut ui = env.ui(Pad::script(&[
        Some(center(rsk_ui::DEL_HOLD_RECT)),
        None,
        Some(center(rsk_ui::PK_BACK_RECT)),
    ]));
    assert!(!ui.hold_to_confirm("Delete", rsk_ui::theme::DANGER_FILL));
}

#[test]
fn a_completed_hold_confirms() {
    let env = Env::new();
    let mut ui = env.ui(Pad::hold(center(rsk_ui::DEL_HOLD_RECT)));
    let start = Instant::now();
    assert!(ui.hold_to_confirm("Delete", rsk_ui::theme::DANGER_FILL));
    assert!(start.elapsed() >= Duration::from_millis(HOLD_MS));
}

#[test]
fn a_hold_that_is_released_starts_over() {
    // Two half-holds are not one whole one — lifting the finger resets the fill.
    let half = (HOLD_MS as usize * 3 / 4) / TOUCH_POLL_MS as usize;
    let on = center(rsk_ui::DEL_HOLD_RECT);
    let mut script = vec![Some(on); half];
    script.push(None);
    script.extend(vec![Some(on); half]);
    script.push(Some(center(rsk_ui::PK_BACK_RECT)));
    let env = Env::new();
    let mut ui = env.ui(Pad::script(&script));
    assert!(!ui.hold_to_confirm("Delete", rsk_ui::theme::DANGER_FILL));
}

#[test]
fn the_back_chevron_abandons_a_hold_screen() {
    let env = Env::new();
    let mut ui = env.ui(Pad::taps(&[center(rsk_ui::PK_BACK_RECT)]));
    assert!(!ui.hold_to_confirm("Delete", rsk_ui::theme::DANGER_FILL));
}
