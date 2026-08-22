// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{Env, Pad, center, nowhere};

#[test]
fn an_adjust_page_decodes_only_minus_and_plus() {
    assert_eq!(adjust_step(center(rsk_ui::ADJ_MINUS_RECT)), Some(-1));
    assert_eq!(adjust_step(center(rsk_ui::ADJ_PLUS_RECT)), Some(1));
    assert_eq!(adjust_step(center(rsk_ui::TITLE_BACK_RECT)), None);
    assert_eq!(adjust_step(nowhere()), None);
}

#[test]
fn back_on_an_adjust_page_returns_to_the_display_list() {
    assert!(matches!(
        adjust_exit(center(rsk_ui::TITLE_BACK_RECT)),
        Nav::Goto(SettingsPage::Display)
    ));
    assert!(matches!(adjust_exit(nowhere()), Nav::Idle));
}

#[test]
fn the_display_list_drills_into_each_knob() {
    let mut random_pin_pad = true;
    let mut dirty = false;
    assert!(matches!(
        settings_display(
            center(rsk_ui::TITLE_BACK_RECT),
            &mut random_pin_pad,
            &mut dirty
        ),
        Nav::Goto(SettingsPage::Root)
    ));
    for (i, want) in [
        SettingsPage::Brightness,
        SettingsPage::Sleep,
        SettingsPage::Timeout,
    ]
    .into_iter()
    .enumerate()
    {
        let row = center(rsk_ui::settings_row_rect(i as u16));
        let got = settings_display(row, &mut random_pin_pad, &mut dirty);
        assert!(
            matches!(got, Nav::Goto(page) if page == want),
            "display row {i} does not open {want:?}"
        );
    }
    assert!(matches!(
        settings_display(nowhere(), &mut random_pin_pad, &mut dirty),
        Nav::Idle
    ));
    assert!(!dirty);
}

#[test]
fn the_random_pin_pad_row_toggles_and_marks_the_display_record_dirty() {
    let mut random_pin_pad = true;
    let mut dirty = false;
    let row = center(rsk_ui::settings_row_rect(3));
    assert!(matches!(
        settings_display(row, &mut random_pin_pad, &mut dirty),
        Nav::Stay
    ));
    assert!(!random_pin_pad);
    assert!(dirty);
}

#[test]
fn factory_reset_does_not_restore_a_pending_display_edit() {
    let env = Env::new();
    let root_display = center(rsk_ui::settings_row_rect(0));
    let random_pin_pad = center(rsk_ui::settings_row_rect(3));
    let root_security = center(rsk_ui::settings_row_rect(1));
    let factory_reset = center(rsk_ui::settings_row_rect(rsk_ui::SECURITY_ROWS - 1));
    let mut script = vec![None];
    for p in [
        root_display,
        random_pin_pad,
        center(rsk_ui::TITLE_BACK_RECT),
        root_security,
        factory_reset,
    ] {
        script.push(Some(p));
        script.extend([None; 2]);
    }
    let hold_polls = HOLD_MS as usize / TOUCH_POLL_MS as usize + 2;
    script.extend(core::iter::repeat_n(
        Some(center(rsk_ui::DEL_HOLD_RECT)),
        hold_polls,
    ));

    let mut ui = env.ui(Pad::script(&script));
    ui.run_settings();

    assert!(!ui.random_pin_pad, "the setting was changed before reset");
    assert!(ui.hooks.reboot_pending());
    assert!(
        !env.fs.borrow_mut().has_data(EF_DISPLAY),
        "a pending edit must not recreate EF_DISPLAY after factory reset"
    );
}

#[test]
fn a_sleep_step_that_moves_marks_the_session_dirty() {
    // The dirty flag is what turns a run of −/+ taps into ONE flash write; a step
    // that changed nothing must not buy a write into the credential partition.
    let _env = Env::new();
    let mut dirty = false;
    assert!(matches!(
        settings_sleep(center(rsk_ui::ADJ_PLUS_RECT), &mut dirty),
        Nav::Stay
    ));
    assert!(dirty);

    let mut clamped = false;
    while adjust_sleep(1) {}
    assert!(matches!(
        settings_sleep(center(rsk_ui::ADJ_PLUS_RECT), &mut clamped),
        Nav::Stay
    ));
    assert!(!clamped, "a step at the clamp is not an edit");
}

#[test]
fn a_brightness_step_that_moves_marks_the_session_dirty() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    ui.set_brightness(BRIGHTNESS_LEVELS);
    let mut clamped = false;
    ui.settings_brightness(center(rsk_ui::ADJ_PLUS_RECT), &mut clamped);
    assert_eq!(ui.brightness, BRIGHTNESS_LEVELS);
    assert!(!clamped);

    let mut dirty = false;
    ui.settings_brightness(center(rsk_ui::ADJ_MINUS_RECT), &mut dirty);
    assert_eq!(ui.brightness, BRIGHTNESS_LEVELS - 1);
    assert!(dirty);
    assert_eq!(
        ui.hooks.backlight,
        level_duty(ui.brightness),
        "applied live"
    );
}

#[test]
fn the_root_nav_hands_the_next_tab_back_to_the_ambient_loop() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    let mut last = Instant::now();
    let tab = |i: usize| center(rsk_ui::nav_tab_rect(i as u16));
    assert!(matches!(
        ui.settings_root(tab(0), &mut last),
        Nav::Leave(None)
    ));
    assert!(matches!(
        ui.settings_root(tab(1), &mut last),
        Nav::Leave(Some(NavTab::Passkeys))
    ));
    assert!(matches!(
        ui.settings_root(tab(2), &mut last),
        Nav::Leave(Some(NavTab::Apps))
    ));
    assert!(
        matches!(ui.settings_root(tab(3), &mut last), Nav::Idle),
        "Settings is already open"
    );
}

#[test]
fn saving_the_display_settings_preserves_the_onboarding_choice() {
    // Every `EF_DISPLAY` write goes through one function precisely so a
    // brightness save cannot drop the "continue without a PIN" flag, or the
    // first-run prompt comes back on the next boot.
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    ui.pin_declined = true;
    ui.random_pin_pad = false;
    ui.set_brightness(2);
    SLEEP_TIMEOUT_MS.store(15_000, Ordering::Relaxed);
    ui.save_display_config();

    let mut buf = [0u8; rsk_ui::DISPLAY_CONF_LEN];
    let n = env
        .fs
        .borrow_mut()
        .read(EF_DISPLAY, &mut buf)
        .expect("the record was written");
    let mut cfg = rsk_ui::DisplayConfig::default();
    cfg.apply_block(&buf[..n]);
    assert_eq!(cfg.brightness, 2);
    assert_eq!(cfg.sleep_secs, 15);
    assert!(cfg.pin_declined);
    assert!(!cfg.random_pin_pad);
}

#[test]
fn persisting_the_touch_timeout_keeps_the_rest_of_the_phy_record() {
    // The timeout shares `EF_PHY` with `rsk hw`, so the menu read-modify-writes it:
    // a blind write would take the board's LED wiring and USB ids down with it.
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    {
        let mut fs = env.fs.borrow_mut();
        let phy = rsk_rescue::phy::PhyData {
            vid_pid: Some((0x1234, 0x5678)),
            led_gpio: Some(21),
            ..Default::default()
        };
        rsk_rescue::phy::save(&mut fs, &phy).expect("EF_PHY");
    }
    ui.hooks.presence_ms = 20_000;
    ui.persist_settings(false, true);

    let stored = rsk_rescue::phy::load(&mut env.fs.borrow_mut()).expect("EF_PHY");
    assert_eq!(stored.presence_timeout, Some(20));
    assert_eq!(stored.vid_pid, Some((0x1234, 0x5678)));
    assert_eq!(stored.led_gpio, Some(21));
}

#[test]
fn a_clean_settings_session_writes_no_flash() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    ui.persist_settings(false, false);
    assert!(
        !env.fs.borrow_mut().has_data(EF_DISPLAY),
        "opening the menu and leaving it must not cost a write"
    );
}
