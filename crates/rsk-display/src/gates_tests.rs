// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use std::vec::Vec;

use super::*;
use crate::tests::{Env, PIN, Pad, WRONG_PIN, center, dev, nowhere, pin_entry};

#[test]
fn every_pad_names_which_credential_it_is_collecting() {
    // The reported confusion behind a factory reset: one bare "Enter PIN" served
    // the device lock, the FIDO clientPIN and the PIV PIN alike.
    let titles = [
        PinScope::Device.pin_title(),
        PinScope::Fido.pin_title(),
        piv_ref_title(rsk_piv::PinRef::Pin),
        piv_ref_title(rsk_piv::PinRef::Puk),
    ];
    for (i, a) in titles.iter().enumerate() {
        assert!(!a.is_empty());
        for b in &titles[i + 1..] {
            assert_ne!(a, b, "two PIN scopes share a screen header");
        }
    }
}

#[test]
fn a_gate_with_no_pin_set_opens_without_a_pad() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    let frames = ui.panel.frames;
    assert!(ui.local_pin_gate(PinScope::Device));
    assert_eq!(
        ui.panel.frames, frames,
        "there is nothing to verify against"
    );
}

#[test]
fn the_correct_pin_opens_the_gate() {
    let env = Env::new();
    env.set_device_pin(PIN);
    let mut ui = env.ui(Pad::taps(&pin_entry(PIN)));
    assert!(ui.local_pin_gate(PinScope::Device));
    assert_eq!(
        rsk_fido::passkeys::device_pin_retries_left(&mut env.fs.borrow_mut()),
        Some(rsk_fido::consts::MAX_PIN_RETRIES),
        "a correct PIN restores the whole budget"
    );
}

#[test]
fn a_wrong_pin_re_prompts_and_the_right_one_still_opens_it() {
    let env = Env::new();
    env.set_device_pin(PIN);
    let mut taps = pin_entry(WRONG_PIN);
    taps.extend(pin_entry(PIN));
    let mut ui = env.ui(Pad::taps(&taps));
    assert!(ui.local_pin_gate(PinScope::Device));
    assert_eq!(
        rsk_fido::passkeys::device_pin_retries_left(&mut env.fs.borrow_mut()),
        Some(rsk_fido::consts::MAX_PIN_RETRIES)
    );
}

#[test]
fn a_declined_pad_leaves_the_gate_shut() {
    let env = Env::new();
    env.set_device_pin(PIN);
    let mut ui = env.ui(Pad::taps(&[center(rsk_ui::PIN_CANCEL_RECT)]));
    assert!(!ui.local_pin_gate(PinScope::Device));
    assert_eq!(
        rsk_fido::passkeys::device_pin_retries_left(&mut env.fs.borrow_mut()),
        Some(rsk_fido::consts::MAX_PIN_RETRIES),
        "a decline is not an attempt"
    );
}

#[test]
fn a_spent_retry_budget_shuts_the_gate_for_good() {
    // The persistent counter is the real anti-bruteforce gate, and the panel is
    // held to exactly the same one the USB path is.
    let env = Env::new();
    env.set_device_pin(PIN);
    let budget = rsk_fido::consts::MAX_PIN_RETRIES as usize;
    let mut taps = Vec::new();
    // One past the budget: the last entry is the one that meets a spent counter and
    // is refused outright rather than compared.
    for _ in 0..=budget {
        taps.extend(pin_entry(WRONG_PIN));
    }
    let mut ui = env.ui(Pad::taps(&taps));
    // The "PIN blocked" notice holds until a tap or ~5 s; a queued host command
    // dismisses it too, which is what keeps this test to the entries themselves.
    ui.hooks.host_pending = true;
    assert!(!ui.local_pin_gate(PinScope::Device));
    assert_eq!(
        rsk_fido::passkeys::device_pin_retries_left(&mut env.fs.borrow_mut()),
        Some(0)
    );

    let mut ui = env.ui(Pad::taps(&pin_entry(PIN)));
    ui.hooks.host_pending = true;
    assert!(
        !ui.local_pin_gate(PinScope::Device),
        "the right PIN does not revive a spent counter"
    );
}

#[test]
fn the_two_pin_scopes_have_separate_counters() {
    // The device PIN gates local control; the clientPIN is WebAuthn's. Grinding one
    // must not spend the other's budget.
    let env = Env::new();
    env.set_device_pin(PIN);
    rsk_fido::passkeys::store_local_pin(&dev(), &mut env.fs.borrow_mut(), PIN)
        .expect("the fixture PIN must satisfy the clientPIN floor");
    let mut ui = env.ui(Pad::taps(&pin_entry(WRONG_PIN)));
    ui.hooks.presence_ms = 100; // the re-prompt then times out rather than looping
    assert!(!ui.local_pin_gate(PinScope::Device));
    assert_eq!(
        rsk_fido::passkeys::pin_retries_left(&mut env.fs.borrow_mut()),
        Some(rsk_fido::consts::MAX_PIN_RETRIES),
        "the FIDO clientPIN's budget is untouched"
    );
}

#[test]
fn unlocking_needs_the_device_pin() {
    let env = Env::new();
    env.set_device_pin(PIN);
    let mut ui = env.ui(Pad::taps(&pin_entry(PIN)));
    assert!(ui.locked, "a key with a PIN boots locked");
    ui.run_unlock();
    assert!(!ui.locked);
}

#[test]
fn a_wrong_pin_leaves_the_panel_locked() {
    let env = Env::new();
    env.set_device_pin(PIN);
    let mut ui = env.ui(Pad::taps(&pin_entry(WRONG_PIN)));
    ui.hooks.presence_ms = 100;
    ui.run_unlock();
    assert!(ui.locked);
}

#[test]
fn skipping_the_onboarding_offer_is_remembered() {
    // The offer is one-time: the choice rides `EF_DISPLAY` so a reboot does not
    // re-ask, and only a factory reset (which wipes the record) brings it back.
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    assert!(ui.onboarding);
    ui.run_onboarding(center(rsk_ui::ONBOARD_SKIP_RECT));
    assert!(!ui.onboarding);
    assert!(ui.pin_declined);

    let mut buf = [0u8; rsk_ui::DISPLAY_CONF_LEN];
    let n = env
        .fs
        .borrow_mut()
        .read(EF_DISPLAY, &mut buf)
        .expect("the choice was persisted");
    let mut cfg = rsk_ui::DisplayConfig::default();
    cfg.apply_block(&buf[..n]);
    assert!(cfg.pin_declined);
}

#[test]
fn a_missed_tap_leaves_the_onboarding_offer_standing() {
    // The offer must never be lost silently — a tap between the buttons re-shows it
    // on the next idle frame.
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    ui.run_onboarding(nowhere());
    assert!(ui.onboarding);
    assert!(!ui.pin_declined);
    assert!(
        !env.fs.borrow_mut().has_data(EF_DISPLAY),
        "and costs no write"
    );
}

#[test]
fn setting_a_pin_from_onboarding_finishes_the_offer() {
    let env = Env::new();
    // New + Confirm, on a device with no PIN yet — the gate in front is a no-op.
    let mut taps = pin_entry(PIN);
    taps.extend(pin_entry(PIN));
    let mut ui = env.ui(Pad::taps(&taps));
    ui.run_onboarding(center(rsk_ui::ONBOARD_SET_RECT));
    assert!(
        matches!(
            rsk_fido::passkeys::spend_and_verify_device_pin(&dev(), &mut env.fs.borrow_mut(), PIN),
            rsk_fido::passkeys::LocalPin::Ok
        ),
        "the PIN stored is the one the user typed, digit for digit"
    );
    assert!(!ui.onboarding);
    assert!(!ui.pin_declined, "setting a PIN is not declining one");
    assert!(ui.home_pin_set, "and Home's card knows it now");
}

#[test]
fn an_abandoned_pin_set_leaves_the_offer_standing() {
    let env = Env::new();
    let mut ui = env.ui(Pad::taps(&[center(rsk_ui::PIN_CANCEL_RECT)]));
    ui.run_onboarding(center(rsk_ui::ONBOARD_SET_RECT));
    assert!(!rsk_fido::passkeys::device_pin_is_set(
        &mut env.fs.borrow_mut()
    ));
    assert!(ui.onboarding, "the offer is re-shown, not consumed");
}
