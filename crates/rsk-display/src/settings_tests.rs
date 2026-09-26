// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{Env, Pad, center, nowhere, settings_row};

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
    assert!(matches!(
        settings_display(center(rsk_ui::TITLE_BACK_RECT)),
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
        let got = settings_display(row);
        assert!(
            matches!(got, Nav::Goto(page) if page == want),
            "display row {i} does not open {want:?}"
        );
    }
    assert!(matches!(settings_display(nowhere()), Nav::Idle));
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
    env.local(&mut ui)
        .settings_brightness(center(rsk_ui::ADJ_PLUS_RECT), &mut clamped);
    assert_eq!(ui.brightness, BRIGHTNESS_LEVELS);
    assert!(!clamped);

    let mut dirty = false;
    env.local(&mut ui)
        .settings_brightness(center(rsk_ui::ADJ_MINUS_RECT), &mut dirty);
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
        env.local(&mut ui).settings_root(tab(0), &mut last),
        Nav::Leave(None)
    ));
    assert!(matches!(
        env.local(&mut ui).settings_root(tab(1), &mut last),
        Nav::Leave(Some(NavTab::Passkeys))
    ));
    assert!(matches!(
        env.local(&mut ui).settings_root(tab(2), &mut last),
        Nav::Leave(Some(NavTab::Apps))
    ));
    assert!(
        matches!(
            env.local(&mut ui).settings_root(tab(3), &mut last),
            Nav::Idle
        ),
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
    ui.set_brightness(2);
    SLEEP_TIMEOUT_MS.store(15_000, Ordering::Relaxed);
    env.local(&mut ui).save_display_config();

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
}

#[test]
fn persisting_the_touch_timeout_keeps_the_rest_of_the_phy_record() {
    // The timeout shares `EF_PHY` with `rsk hw`, so the menu read-modify-writes it:
    // a blind write would take the board's LED wiring and USB ids down with it.
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    {
        let mut fs = env.fs.borrow_mut();
        let phy = rsk_phy::PhyData {
            vid_pid: Some((0x1234, 0x5678)),
            led_gpio: Some(21),
            ..Default::default()
        };
        rsk_phy::save(&mut fs, &phy).expect("EF_PHY");
    }
    ui.hooks.presence_ms = 20_000;
    env.local(&mut ui).persist_settings(false, true);

    let stored = rsk_phy::load(&mut env.fs.borrow_mut()).expect("EF_PHY");
    assert_eq!(stored.presence_timeout, Some(20));
    assert_eq!(stored.vid_pid, Some((0x1234, 0x5678)));
    assert_eq!(stored.led_gpio, Some(21));
}

#[test]
fn a_clean_settings_session_writes_no_flash() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    env.local(&mut ui).persist_settings(false, false);
    assert!(
        !env.fs.borrow_mut().has_data(EF_DISPLAY),
        "opening the menu and leaving it must not cost a write"
    );
}

/// The Security row is a toggle, not a drill-in: a tap flips it, marks the record
/// dirty so the debounce writes it, and leaves the page where it was.
#[test]
fn the_scramble_row_toggles_in_place_and_persists() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    let mut last = Instant::now();
    let mut dirty = false;
    assert!(!ui.scramble_pin, "off is the shipped default");

    let row = rsk_ui::settings_row_rect(3);
    let tap = rsk_ui::Point::new(row.x + row.w / 2, row.y + row.h / 2);
    assert!(matches!(
        env.local(&mut ui)
            .settings_security(tap, &mut last, &mut dirty),
        Nav::Stay
    ));
    assert!(ui.scramble_pin, "the tap did not flip it");
    assert!(
        dirty,
        "a flip that is never written is a setting that forgets itself"
    );

    env.local(&mut ui).save_display_config();
    let mut buf = [0u8; rsk_ui::DISPLAY_CONF_LEN];
    let n = env
        .fs
        .borrow_mut()
        .read(EF_DISPLAY, &mut buf)
        .expect("the record was written");
    let mut cfg = rsk_ui::DisplayConfig::default();
    cfg.apply_block(&buf[..n]);
    assert!(cfg.scramble_pin);

    // And back off again — a toggle that only travels one way is a trap.
    assert!(matches!(
        env.local(&mut ui)
            .settings_security(tap, &mut last, &mut dirty),
        Nav::Stay
    ));
    assert!(!ui.scramble_pin);
}

/// `EF_DISPLAY` as the next boot would read it, if there is one.
fn stored_display<S: rsk_fs::Storage>(fs: &RefCell<Fs<S>>) -> Option<rsk_ui::DisplayConfig> {
    let mut buf = [0u8; rsk_ui::DISPLAY_CONF_LEN];
    let n = fs.borrow_mut().read(EF_DISPLAY, &mut buf)?;
    let mut cfg = rsk_ui::DisplayConfig::default();
    cfg.apply_block(&buf[..n]);
    Some(cfg)
}

/// A completed factory reset leaves the menu at once, writing nothing. An edit the debounce
/// had not flushed rode the exit persist into the store the reset had just wiped, ahead of
/// its queued reboot, and that reboot read both records back.
#[test]
fn a_factory_reset_writes_no_edit_into_the_store_it_wiped() {
    let env = Env::new();
    let taps = [
        settings_row(
            rsk_ui::SETTINGS_ROWS,
            rsk_ui::hit_settings_root,
            RootEntry::Display,
        ),
        settings_row(
            rsk_ui::DISPLAY_ROWS,
            rsk_ui::hit_display,
            DisplayEntry::Timeout,
        ),
        center(rsk_ui::ADJ_PLUS_RECT),
        center(rsk_ui::TITLE_BACK_RECT),
        center(rsk_ui::TITLE_BACK_RECT),
        settings_row(
            rsk_ui::SETTINGS_ROWS,
            rsk_ui::hit_settings_root,
            RootEntry::Security,
        ),
        settings_row(
            rsk_ui::SECURITY_ROWS,
            rsk_ui::hit_security,
            SecurityEntry::ScramblePin,
        ),
        settings_row(
            rsk_ui::SECURITY_ROWS,
            rsk_ui::hit_security,
            SecurityEntry::FactoryReset,
        ),
    ];
    let mut ui = env.ui(Pad::taps_then_hold(&taps, center(rsk_ui::DEL_HOLD_RECT)));
    // What declining onboarding leaves behind, so the wipe has a record to remove.
    ui.pin_declined = true;
    env.local(&mut ui).save_display_config();

    let started = Instant::now();
    env.local(&mut ui).run_settings();
    // Well inside the menu's own idle exit, which a menu still open over the wipe waits out.
    let left_at_once = started.elapsed() < Duration::from_millis(MENU_INACTIVITY_MS / 2);
    let phy = env.fs.borrow_mut().has_data(rsk_phy::EF_PHY);
    assert_eq!(
        (ui.hooks.reboot, stored_display(&env.fs), phy, left_at_once),
        (Some(false), None, false, true),
        "a completed reset must leave the menu at once, with no display or phy record \
         for its reboot to read"
    );
}

/// A wipe that cannot prove it emptied the store says so and reboots nothing: coming up
/// fresh is what would make a half-erased device read as factory-clean. The refused
/// record is still there, and the reset answers `false`, so the menu stays open.
#[test]
fn a_wipe_the_store_refuses_reboots_nothing() {
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let env = crate::tests::Env::over(backend);
    let hold = center(rsk_ui::DEL_HOLD_RECT);
    let polls = 3 * (crate::HOLD_MS / crate::TOUCH_POLL_MS) as usize;
    let mut script = vec![None, None];
    script.extend(vec![Some(hold); polls]);
    // The lift, then the tap that dismisses the failure notice.
    script.extend([None, Some(hold), None]);
    let mut ui = env.ui(Pad::script(&script));
    ui.pin_declined = true;
    env.local(&mut ui).save_display_config();
    assert!(
        medium.value(EF_DISPLAY).is_some(),
        "control: a record to wipe"
    );
    medium.refuse_remove(Some(EF_DISPLAY));

    let done = env.local(&mut ui).run_factory_reset();
    assert_eq!(
        (done, ui.hooks.reboot, medium.value(EF_DISPLAY).is_some()),
        (false, None, true),
        "a refused wipe must answer false, reboot nothing, and leave the record"
    );
}

/// A firmware update's reboot keeps an edit the user has watched take effect, as every
/// other exit does: it wipes nothing, and the image is replaced under the store.
#[test]
fn an_edit_is_written_before_a_firmware_update_reboots() {
    let env = Env::new();
    let taps = [
        settings_row(
            rsk_ui::SETTINGS_ROWS,
            rsk_ui::hit_settings_root,
            RootEntry::Display,
        ),
        settings_row(
            rsk_ui::DISPLAY_ROWS,
            rsk_ui::hit_display,
            DisplayEntry::Brightness,
        ),
        center(rsk_ui::ADJ_MINUS_RECT),
        center(rsk_ui::TITLE_BACK_RECT),
        center(rsk_ui::TITLE_BACK_RECT),
        settings_row(
            rsk_ui::SETTINGS_ROWS,
            rsk_ui::hit_settings_root,
            RootEntry::Firmware,
        ),
    ];
    let mut ui = env.ui(Pad::taps_then_hold(&taps, center(rsk_ui::DEL_HOLD_RECT)));
    ui.set_brightness(BRIGHTNESS_LEVELS);

    env.local(&mut ui).run_settings();
    assert_eq!(
        (
            ui.hooks.reboot,
            stored_display(&env.fs).map(|cfg| cfg.brightness)
        ),
        (Some(true), Some(BRIGHTNESS_LEVELS - 1)),
        "the brightness step must be on flash before the update reboot"
    );
}

/// Only a completed wipe drops the edit: a reset abandoned at its confirm screen falls back
/// to the Security page, and the edit is written when the menu is left.
#[test]
fn an_abandoned_factory_reset_keeps_the_edit() {
    let env = Env::new();
    let taps = [
        settings_row(
            rsk_ui::SETTINGS_ROWS,
            rsk_ui::hit_settings_root,
            RootEntry::Security,
        ),
        settings_row(
            rsk_ui::SECURITY_ROWS,
            rsk_ui::hit_security,
            SecurityEntry::ScramblePin,
        ),
        settings_row(
            rsk_ui::SECURITY_ROWS,
            rsk_ui::hit_security,
            SecurityEntry::FactoryReset,
        ),
        center(rsk_ui::PK_BACK_RECT),
        center(rsk_ui::TITLE_BACK_RECT),
        center(rsk_ui::nav_tab_rect(0)),
    ];
    let mut ui = env.ui(Pad::taps(&taps));

    env.local(&mut ui).run_settings();
    assert_eq!(
        (
            ui.hooks.reboot,
            stored_display(&env.fs).map(|cfg| cfg.scramble_pin)
        ),
        (None, Some(true)),
        "an abandoned reset must neither reboot nor lose the scramble toggle"
    );
}

/// The touch-timeout save carried its own copy of the phy read-modify-write — a
/// `load(..).unwrap_or_default()` — so a probe the flash could not answer read as
/// "no record was ever written" and the exit path saved a DEFAULT record with the
/// new timeout on top, taking the USB identity and LED wiring with it. The
/// non-faulted half of this is `persisting_the_touch_timeout_keeps_the_rest_of_the_phy_record`.
#[test]
fn a_faulted_phy_probe_does_not_wipe_the_record_the_timeout_shares() {
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let env = crate::tests::Env::over(backend);
    let mut ui = env.ui(Pad::idle());
    {
        let mut fs = env.fs.borrow_mut();
        let phy = rsk_phy::PhyData {
            vid_pid: Some((0x1234, 0x5678)),
            usb_product: rsk_phy::Product::new(b"RSK Custom"),
            led_gpio: Some(21),
            led_num: Some(4),
            ..Default::default()
        };
        rsk_phy::save(&mut fs, &phy).expect("EF_PHY");
    }
    let before = medium.value(rsk_phy::EF_PHY).expect("record written");

    ui.hooks.presence_ms = 20_000;
    medium.stick_once(rsk_phy::EF_PHY);
    env.local(&mut ui).persist_settings(false, true);

    let after = medium.value(rsk_phy::EF_PHY).expect("record present");
    let kept = rsk_phy::PhyData::parse(&after);
    assert_eq!(
        (kept.vid_pid, kept.usb_product, kept.led_gpio, kept.led_num),
        (
            Some((0x1234, 0x5678)),
            rsk_phy::Product::new(b"RSK Custom"),
            Some(21),
            Some(4)
        ),
        "a faulted probe wiped the fields the timeout save does not carry \
         ({} bytes stored, was {})",
        after.len(),
        before.len()
    );
    assert_eq!(after, before, "a refused save must leave the record alone");
}
