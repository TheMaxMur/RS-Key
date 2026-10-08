// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{Env, PIN, Pad, center, nowhere, pin_entry, pin_key};

struct IdleThenOk {
    samples: std::collections::VecDeque<Option<rsk_ui::Point>>,
    pause: bool,
    ok: bool,
}

impl TouchPad for IdleThenOk {
    fn read(&mut self) -> Option<rsk_ui::Point> {
        if let Some(sample) = self.samples.pop_front() {
            return sample;
        }
        if !self.pause {
            self.pause = true;
            block_for(Duration::from_millis(REVEAL_MASK_MS + 50));
            None
        } else if !self.ok {
            self.ok = true;
            Some(pin_key(PinKey::Ok))
        } else {
            None
        }
    }
}

#[test]
fn unattended_local_windows_return_at_their_real_inactivity_deadlines() {
    let _env = Env::new();
    std::thread::scope(|scope| {
        macro_rules! window {
            ($limit:expr, $run:expr) => {
                scope.spawn(|| {
                    crate::tests::with_isolated_ui(|ui, cells| {
                        rsk_piv::files::scan_files(
                            &crate::tests::dev(),
                            &mut cells.fs.borrow_mut(),
                            &mut *cells.rng.borrow_mut(),
                        )
                        .unwrap();
                        let generation = cells.fs.borrow().write_gen();
                        let started = Instant::now();
                        let mut local = Local::new(ui, cells);
                        $run(&mut local);
                        let elapsed = started.elapsed();
                        assert!(elapsed >= Duration::from_millis($limit));
                        assert!(elapsed < Duration::from_millis($limit) + Duration::from_secs(10));
                        assert!(!local.asleep);
                        assert!(!local.hooks.host_request_pending());
                        assert_eq!(local.cells.fs.borrow().write_gen(), generation);
                        assert!(!local.panel.oob);
                    });
                });
            };
        }
        window!(NOTICE_DWELL_MS, |local: &mut Local<
            '_,
            '_,
            _,
            _,
            _,
            _,
            _,
        >| local.hold_notice());
        window!(MENU_INACTIVITY_MS, |local: &mut Local<
            '_,
            '_,
            _,
            _,
            _,
            _,
            _,
        >| assert_eq!(
            local.run_rename(&Label::default(), &[0; 32]),
            None
        ));
        window!(MENU_INACTIVITY_MS, |local: &mut Local<
            '_,
            '_,
            _,
            _,
            _,
            _,
            _,
        >| assert!(
            !local.hold_to_confirm("Hold to delete", rsk_ui::theme::DANGER_FILL)
        ));
        window!(MENU_INACTIVITY_MS, |local: &mut Local<
            '_,
            '_,
            _,
            _,
            _,
            _,
            _,
        >| local
            .show_success(SuccessKind::Deleted, None));
        window!(MENU_INACTIVITY_MS, |local: &mut Local<
            '_,
            '_,
            _,
            _,
            _,
            _,
            _,
        >| local.run_piv_pins());
        window!(MENU_INACTIVITY_MS, |local: &mut Local<
            '_,
            '_,
            _,
            _,
            _,
            _,
            _,
        >| assert_eq!(
            local.run_settings(),
            None
        ));
    });
}

#[test]
fn a_revealed_pin_is_masked_after_idle_without_changing_the_entry() {
    let env = Env::new();
    let mut taps = pin_entry(PIN);
    taps.pop();
    taps.push(center(rsk_ui::PIN_EYE_RECT));
    let Ui {
        panel, hooks, info, ..
    } = env.ui(Pad::idle());
    let mut samples = std::collections::VecDeque::from([None, None]);
    for tap in taps {
        samples.extend([Some(tap), None, None]);
    }
    let mut ui = Ui::new(
        panel,
        IdleThenOk {
            samples,
            pause: false,
            ok: false,
        },
        hooks,
        info,
        env.cells(),
    );
    ui.hooks.presence_ms = (REVEAL_MASK_MS + 3000) as u32;
    let mut out = [0; 64];
    assert!(
        matches!(ui.collect_pin("FIDO PIN", None, PIN.len(), PIN.len() as u8, &mut out, false), rsk_sdk::PinEntry::Entered(n) if n == PIN.len())
    );
    assert_eq!(&out[..PIN.len()], PIN);
    let entry = rsk_ui::Rect::new(0, 40, rsk_ui::PANEL_W, 40);
    let masked = ui.panel.area_pixels(entry);
    rsk_ui::render_pin_dots(&mut ui.panel, PIN.len(), PIN.len() as u8, Some(PIN)).unwrap();
    assert_ne!(ui.panel.area_pixels(entry), masked);
    rsk_ui::render_pin_dots(&mut ui.panel, PIN.len(), PIN.len() as u8, None).unwrap();
    assert_eq!(ui.panel.area_pixels(entry), masked);
}

#[test]
fn a_long_pin_title_scrolls_and_power_cancels_without_an_attempt() {
    let env = Env::new();
    let title = "OpenPGP authentication PIN";
    assert!(rsk_ui::pin_title_overflows(title));
    let mut ui = env.ui(Pad::idle());
    let writes = ui.panel.writes;
    let mut out = [0; 64];
    assert!(matches!(
        ui.collect_pin(title, None, 6, 6, &mut out, false),
        rsk_sdk::PinEntry::Timeout
    ));
    assert!(ui.panel.writes > writes);
    assert!(!ui.panel.oob);
    let mut ui = env.ui(Pad::idle());
    ui.hooks.press_wake(1);
    assert!(matches!(
        ui.collect_pin(title, None, 6, 6, &mut out, false),
        rsk_sdk::PinEntry::Cancelled
    ));
    assert!(ui.asleep);
    assert_eq!(out, [0; 64]);
}

#[test]
fn rename_backspace_save_and_cancellation_obey_the_store_result() {
    let env = Env::new();
    let hash = [0xA5; 32];
    let mut ui = env.ui(Pad::taps(&[
        center(rsk_ui::t9_key_rect(3, 0)),
        nowhere(),
        center(rsk_ui::t9_key_rect(3, 2)),
    ]));
    assert_eq!(
        env.local(&mut ui).run_rename(&Label::clamp(b"Work"), &hash),
        None
    );
    for exit in 0..3 {
        let mut ui = env.ui(Pad::taps(&[center(rsk_ui::TITLE_BACK_RECT)]));
        ui.hooks.host_pending = exit == 1;
        if exit == 2 {
            ui.hooks.press_wake(1);
        }
        assert_eq!(
            env.local(&mut ui).run_rename(&Label::default(), &hash),
            None
        );
        assert_eq!(ui.asleep, exit == 2);
    }
}

#[test]
fn firmware_entry_requires_the_device_pin_and_can_be_cancelled_before_reboot() {
    let env = Env::new();
    env.set_device_pin(PIN);
    let mut ui = env.ui(Pad::taps(&[center(rsk_ui::PIN_CANCEL_RECT)]));
    assert!(!env.local(&mut ui).run_firmware());
    assert_eq!(ui.hooks.reboot, None);
    let mut taps = pin_entry(PIN);
    taps.push(center(rsk_ui::TITLE_BACK_RECT));
    let mut samples = vec![None, None];
    for tap in taps {
        samples.extend([Some(tap), None, None, None, None]);
    }
    let mut ui = env.ui(Pad::script(&samples));
    ui.hooks.presence_ms = 3000;
    let started = Instant::now();
    assert!(!env.local(&mut ui).run_firmware());
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(ui.hooks.reboot, None);
}

#[test]
fn unread_fused_key_cannot_store_a_new_device_pin_or_enumerate_accounts() {
    let mut env = Env::new();
    env.keys.mkek_source = Some(FusedKey::latched(|_| false));
    let mut taps = pin_entry(PIN);
    taps.extend(pin_entry(PIN));
    let mut ui = env.ui(Pad::taps(&taps));
    env.local(&mut ui).run_set_pin(PinScope::Device);
    assert!(!rsk_fido::passkeys::device_pin_is_set(
        &mut env.fs.borrow_mut()
    ));
    let mut accts = [AccountRow::default(); rsk_ui::PK_ROWS_MAX];
    let mut fids = [0; rsk_ui::PK_ROWS_MAX];
    assert_eq!(
        env.local(&mut ui)
            .load_accts(&[0; 32], &mut accts, &mut fids, 0),
        (0, 0)
    );
    assert!(!rsk_fido::passkeys::device_pin_is_set(
        &mut env.fs.borrow_mut()
    ));
}
