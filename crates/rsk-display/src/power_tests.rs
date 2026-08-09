// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{Env, PIN, Pad, center};

#[test]
fn a_finger_already_down_is_not_a_tap_on_what_just_appeared() {
    // Audit run-33: the panel reports level, not edges, so a contact that predates
    // the screen was read as a tap on it — the wake press, or the finger still down
    // from a ceremony's approval hold, landing on Onboard's full-width "Continue
    // without PIN" button and consuming a fresh device's one-time PIN offer.
    let env = Env::new();
    let p = center(rsk_ui::ONBOARD_SKIP_RECT);
    let mut ui = env.ui(Pad::script(&[Some(p), Some(p), None, Some(p), Some(p)]));
    assert_eq!(ui.armed_touch(), None, "the contact predates the screen");
    assert_eq!(ui.armed_touch(), None, "and still does");
    assert_eq!(ui.armed_touch(), None, "an untouched sample only arms");
    assert_eq!(ui.armed_touch(), Some(p), "now it is a deliberate tap");
    assert_eq!(
        ui.armed_touch(),
        Some(p),
        "and stays deliberate until a repaint"
    );
}

#[test]
fn brightness_is_clamped_to_a_lit_panel() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    ui.set_brightness(0);
    assert_eq!(ui.brightness, 1);
    assert_eq!(ui.hooks.backlight, level_duty(1));
    ui.set_brightness(BRIGHTNESS_LEVELS + 4);
    assert_eq!(ui.brightness, BRIGHTNESS_LEVELS);
    assert_eq!(ui.hooks.backlight, BL_TOP);
}

#[test]
fn sleep_drops_the_image_and_wake_restores_the_saved_level() {
    // A *static* image is what burns into the IPS panel, so sleep clears the glass
    // rather than only dimming it.
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    ui.set_brightness(2);
    ui.shown = Some(Screen::Home(HomeView {
        status: StatusKind::Idle,
        pin_set: false,
        passkeys: 0,
    }));
    ui.sleep();
    assert!(ui.asleep);
    assert_eq!(ui.hooks.backlight, 0);
    assert_eq!(ui.shown, None, "nothing on screen is still believed");

    let frames = ui.panel.frames;
    ui.sleep();
    assert_eq!(ui.panel.frames, frames, "sleeping twice is one sleep");

    ui.wake();
    assert!(!ui.asleep);
    assert_eq!(ui.hooks.backlight, level_duty(2));
    ui.hooks.backlight = 0;
    ui.wake();
    assert_eq!(ui.hooks.backlight, 0, "waking twice is one wake");
}

#[test]
fn sleeping_without_a_pin_only_blanks() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    ui.enter_sleep();
    assert!(ui.asleep);
    assert!(!ui.locked, "no PIN — the lock would be unopenable");
}

#[test]
fn sleeping_locks_the_ui_when_a_device_pin_is_set() {
    // A walked-away device must require the PIN to browse passkeys / settings.
    let env = Env::new();
    env.set_device_pin(PIN);
    let mut ui = env.ui(Pad::idle());
    ui.locked = false;
    ui.enter_sleep();
    assert!(ui.locked);
}

#[test]
fn a_sleep_mid_ceremony_falls_back_to_the_cached_pin_bit() {
    // Called from a host-ceremony screen the worker still holds `fs` borrowed for,
    // so the PIN-set bit has to come from the cache rather than a second borrow —
    // which would panic the RefCell.
    let env = Env::new();
    env.set_device_pin(PIN);
    let mut ui = env.ui(Pad::idle());
    ui.locked = false;
    let worker = env.fs.borrow_mut();
    ui.enter_sleep();
    drop(worker);
    assert!(ui.locked);
    assert!(ui.asleep);
}

#[test]
fn the_auto_lock_is_a_no_op_without_a_device_pin() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    assert!(!ui.lock_now(), "no device PIN, nothing to re-arm");
    assert!(!ui.locked);
}

#[test]
fn the_auto_lock_fires_once() {
    // `status_task` repaints Locked on a `true`, so a second `true` on an already
    // locked panel would repaint it every tick.
    let env = Env::new();
    env.set_device_pin(PIN);
    let mut ui = env.ui(Pad::idle());
    ui.locked = false;
    assert!(ui.lock_now());
    assert!(!ui.lock_now());
}

#[test]
fn the_power_button_sleeps_and_its_press_is_consumed() {
    // One press toggles sleep exactly once — `wait_wake_release` must not leave the
    // press standing for the next poll to read again.
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    ui.hooks.press_wake(1);
    assert!(ui.sleep_button_pressed());
    assert!(ui.asleep);
    assert!(
        !ui.wake_pressed(),
        "the press was spent by the release wait"
    );
    assert!(!ui.sleep_button_pressed());
}

#[test]
fn an_unpressed_wake_button_costs_a_modal_nothing() {
    // Every blocking on-device loop polls this once per tick; a board with no wake
    // button (`WAKE_PIN=none`) must not pay a release wait for the reading.
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    let start = Instant::now();
    assert!(!ui.sleep_button_pressed());
    assert!(!ui.asleep);
    assert!(start.elapsed() < Duration::from_millis(500));
}
