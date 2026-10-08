// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{Env, NEW_PIN, PIN, Pad, center, dev, nowhere, pin_entry};
use rsk_piv::{PinRef, files};

fn provision(env: &Env) {
    files::scan_files(&dev(), &mut env.fs.borrow_mut(), &mut *env.rng.borrow_mut()).unwrap();
}

fn default(which: PinRef) -> &'static [u8] {
    match which {
        PinRef::Pin => b"123456",
        PinRef::Puk => b"12345678",
    }
}

fn verify(env: &Env, which: PinRef, pin: &[u8]) -> rsk_sdk::Sw {
    rsk_piv::verify_reference(
        &dev(),
        &mut env.fs.borrow_mut(),
        which,
        rsk_piv::pad_pin(pin).unwrap().expose(),
    )
}

#[test]
fn the_piv_menu_materializes_defaults_and_runs_each_subflow() {
    for selection in 0..4 {
        let env = Env::new();
        let mut ui = env.ui(Pad::taps(&[
            center(rsk_ui::row_rect(rsk_ui::PIV_KEYGEN_PICK_TOP, selection)),
            center(if selection == 3 {
                rsk_ui::TITLE_BACK_RECT
            } else {
                rsk_ui::PIN_CANCEL_RECT
            }),
            nowhere(),
            center(rsk_ui::TITLE_BACK_RECT),
        ]));
        env.local(&mut ui).run_piv_pins();
        assert_eq!(verify(&env, PinRef::Pin, b"123456"), rsk_sdk::Sw::OK);
        assert_eq!(verify(&env, PinRef::Puk, b"12345678"), rsk_sdk::Sw::OK);
        assert!(!ui.panel.oob);
    }
}

#[test]
fn the_piv_menu_yields_on_host_requests_and_power() {
    for power in [false, true] {
        let env = Env::new();
        let mut ui = env.ui(Pad::taps(&[nowhere()]));
        ui.hooks.host_pending = !power;
        if power {
            ui.hooks.press_wake(1);
        }
        env.local(&mut ui).run_piv_pins();
        assert_eq!(ui.asleep, power);
    }
}

#[test]
fn changing_each_reference_verifies_the_old_secret_and_accepts_the_new_one_over_the_host_seam() {
    for which in [PinRef::Pin, PinRef::Puk] {
        let env = Env::new();
        provision(&env);
        let mut taps = pin_entry(default(which));
        taps.extend(pin_entry(NEW_PIN));
        taps.extend(pin_entry(NEW_PIN));
        let mut ui = env.ui(Pad::taps(&taps));
        ui.hooks.presence_ms = 3000;
        env.local(&mut ui).run_change_piv_ref(which);
        assert_eq!(verify(&env, which, NEW_PIN), rsk_sdk::Sw::OK);
        assert_ne!(verify(&env, which, default(which)), rsk_sdk::Sw::OK);
        let other = match which {
            PinRef::Pin => PinRef::Puk,
            PinRef::Puk => PinRef::Pin,
        };
        assert_eq!(verify(&env, other, default(other)), rsk_sdk::Sw::OK);
    }
}

#[test]
fn cancel_at_either_new_pin_step_keeps_the_reference() {
    for confirm in [false, true] {
        let env = Env::new();
        provision(&env);
        let mut taps = pin_entry(default(PinRef::Pin));
        if confirm {
            taps.extend(pin_entry(NEW_PIN));
        }
        taps.push(center(rsk_ui::PIN_CANCEL_RECT));
        let mut ui = env.ui(Pad::taps(&taps));
        ui.hooks.presence_ms = 3000;
        env.local(&mut ui).run_change_piv_ref(PinRef::Pin);
        assert_eq!(
            verify(&env, PinRef::Pin, default(PinRef::Pin)),
            rsk_sdk::Sw::OK
        );
    }
}

#[test]
fn mismatch_reprompts_until_the_new_piv_pin_is_confirmed() {
    let env = Env::new();
    let mut taps = pin_entry(NEW_PIN);
    taps.extend(pin_entry(PIN));
    taps.extend(pin_entry(NEW_PIN));
    taps.extend(pin_entry(NEW_PIN));
    let mut ui = env.ui(Pad::taps(&taps));
    ui.hooks.presence_ms = 3000;
    assert_eq!(
        ui.collect_new_piv_pin("PIV PIN").unwrap().expose(),
        rsk_piv::pad_pin(NEW_PIN).unwrap().expose()
    );
}

#[test]
fn wrong_piv_pin_spends_one_retry_before_cancel() {
    let env = Env::new();
    provision(&env);
    let mut taps = pin_entry(NEW_PIN);
    taps.push(center(rsk_ui::PIN_CANCEL_RECT));
    let mut ui = env.ui(Pad::taps(&taps));
    ui.hooks.presence_ms = 3000;
    let mut scratch = [0; 8];
    assert!(
        env.local(&mut ui)
            .gate_piv_ref(PinRef::Pin, &mut scratch)
            .is_none()
    );
    assert_eq!(
        rsk_piv::reference_retries_left(&mut env.fs.borrow_mut(), PinRef::Pin),
        Some(2)
    );
    assert_eq!(
        rsk_piv::reference_retries_left(&mut env.fs.borrow_mut(), PinRef::Puk),
        Some(3)
    );
}

#[test]
fn a_blocked_reference_does_not_open_even_with_the_correct_value() {
    let env = Env::new();
    provision(&env);
    for _ in 0..3 {
        assert_ne!(verify(&env, PinRef::Pin, NEW_PIN), rsk_sdk::Sw::OK);
    }
    let mut ui = env.ui(Pad::taps(&pin_entry(default(PinRef::Pin))));
    ui.hooks.host_pending = true;
    let mut scratch = [0; 8];
    assert!(
        env.local(&mut ui)
            .gate_piv_ref(PinRef::Pin, &mut scratch)
            .is_none()
    );
    assert_eq!(
        rsk_piv::reference_retries_left(&mut env.fs.borrow_mut(), PinRef::Pin),
        Some(0)
    );
}

#[test]
fn the_puk_unblocks_the_pin_and_restores_the_retry_budget() {
    let env = Env::new();
    provision(&env);
    for _ in 0..3 {
        assert_ne!(verify(&env, PinRef::Pin, NEW_PIN), rsk_sdk::Sw::OK);
    }
    let mut taps = pin_entry(default(PinRef::Puk));
    taps.extend(pin_entry(NEW_PIN));
    taps.extend(pin_entry(NEW_PIN));
    let mut ui = env.ui(Pad::taps(&taps));
    ui.hooks.presence_ms = 3000;
    env.local(&mut ui).run_unblock_piv_pin();
    assert_eq!(
        rsk_piv::reference_retries_left(&mut env.fs.borrow_mut(), PinRef::Pin),
        Some(3)
    );
    assert_eq!(verify(&env, PinRef::Pin, NEW_PIN), rsk_sdk::Sw::OK);
    assert_eq!(
        verify(&env, PinRef::Puk, default(PinRef::Puk)),
        rsk_sdk::Sw::OK
    );
}

#[test]
fn cancelling_unblock_at_the_gate_or_new_pin_step_changes_nothing() {
    for gate in [false, true] {
        let env = Env::new();
        provision(&env);
        let mut taps = if gate {
            vec![]
        } else {
            pin_entry(default(PinRef::Puk))
        };
        taps.push(center(rsk_ui::PIN_CANCEL_RECT));
        let mut ui = env.ui(Pad::taps(&taps));
        ui.hooks.presence_ms = 3000;
        env.local(&mut ui).run_unblock_piv_pin();
        assert_eq!(
            verify(&env, PinRef::Pin, default(PinRef::Pin)),
            rsk_sdk::Sw::OK
        );
        assert_eq!(
            verify(&env, PinRef::Puk, default(PinRef::Puk)),
            rsk_sdk::Sw::OK
        );
    }
}

#[test]
fn an_unread_fused_key_spends_no_piv_retry() {
    let mut env = Env::new();
    provision(&env);
    env.keys.mkek_source = Some(FusedKey::latched(|_| false));
    let mut ui = env.ui(Pad::taps(&pin_entry(default(PinRef::Pin))));
    let mut scratch = [0; 8];
    assert!(
        env.local(&mut ui)
            .gate_piv_ref(PinRef::Pin, &mut scratch)
            .is_none()
    );
    assert_eq!(
        rsk_piv::reference_retries_left(&mut env.fs.borrow_mut(), PinRef::Pin),
        Some(3)
    );
}

#[test]
fn protecting_the_management_key_requires_device_pin_and_hold() {
    let env = Env::new();
    env.set_device_pin(PIN);
    let mut ui = env.ui(Pad::taps(&[center(rsk_ui::PIN_CANCEL_RECT)]));
    env.local(&mut ui).run_protect_mgm_key();
    assert!(!env.fs.borrow_mut().has_data(files::EF_PIVMAN_DATA));
    let mut taps = pin_entry(PIN);
    taps.push(center(rsk_ui::TITLE_BACK_RECT));
    let mut ui = env.ui(Pad::taps(&taps));
    env.local(&mut ui).run_protect_mgm_key();
    assert!(!env.fs.borrow_mut().has_data(files::EF_PIVMAN_DATA));
    let mut ui = env.ui(Pad::taps_then_hold(
        &pin_entry(PIN),
        center(rsk_ui::DEL_HOLD_RECT),
    ));
    env.local(&mut ui).run_protect_mgm_key();
    let mut admin = [0; 64];
    let n = env
        .fs
        .borrow_mut()
        .read(files::EF_PIVMAN_DATA, &mut admin)
        .unwrap();
    assert_eq!(&admin[..n], &[0x80, 3, 0x81, 1, 2]);
    assert_eq!(
        verify(&env, PinRef::Pin, default(PinRef::Pin)),
        rsk_sdk::Sw::OK
    );
}

#[test]
fn an_unread_fused_key_or_refused_write_cannot_protect_the_management_key() {
    {
        let mut env = Env::new();
        env.keys.mkek_source = Some(FusedKey::latched(|_| false));
        let mut samples = vec![None; 4];
        samples.extend(core::iter::repeat_n(
            Some(center(rsk_ui::DEL_HOLD_RECT)),
            3 * (HOLD_MS / TOUCH_POLL_MS) as usize,
        ));
        let mut ui = env.ui(Pad::script(&samples));
        let generation = env.fs.borrow().write_gen();
        env.local(&mut ui).run_protect_mgm_key();
        assert_eq!(env.fs.borrow().write_gen(), generation);
        assert_eq!(ui.hooks.pin_changed, 0);
    }
    let (backend, medium) = rsk_fs::storage::faults::Cut::new();
    let env = Env::over(backend);
    files::scan_files(&dev(), &mut env.fs.borrow_mut(), &mut *env.rng.borrow_mut()).unwrap();
    let mut samples = vec![None; 4];
    samples.extend(core::iter::repeat_n(
        Some(center(rsk_ui::DEL_HOLD_RECT)),
        3 * (HOLD_MS / TOUCH_POLL_MS) as usize,
    ));
    let mut ui = env.ui(Pad::script(&samples));
    let generation = env.fs.borrow().write_gen();
    medium.arm(0);
    Local::new(&mut ui, env.cells()).run_protect_mgm_key();
    assert_eq!(env.fs.borrow().write_gen(), generation);
    assert_eq!(ui.hooks.pin_changed, 0);
}

#[test]
fn unequal_piv_confirmation_lengths_do_not_change_either_reference() {
    let env = Env::new();
    provision(&env);
    let mut taps = pin_entry(PIN);
    taps.extend(pin_entry(b"4816297"));
    taps.push(center(rsk_ui::PIN_CANCEL_RECT));
    let mut ui = env.ui(Pad::taps(&taps));
    let generation = env.fs.borrow().write_gen();
    assert!(env.local(&mut ui).collect_new_piv_pin("PIV PIN").is_none());
    assert_eq!(env.fs.borrow().write_gen(), generation);
}

#[test]
fn the_piv_menu_can_cancel_without_a_device_key_and_sleep_inside_a_pin_subflow() {
    use crate::tests::{PanelSignal, SignalAfterTouches};
    {
        let mut env = Env::new();
        env.keys.mkek_source = Some(FusedKey::latched(|_| false));
        let mut ui = env.ui(Pad::taps(&[center(rsk_ui::TITLE_BACK_RECT)]));
        let generation = env.fs.borrow().write_gen();
        env.local(&mut ui).run_piv_pins();
        assert_eq!(env.fs.borrow().write_gen(), generation);
    }
    let env = Env::new();
    provision(&env);
    let generation = env.fs.borrow().write_gen();
    let Ui {
        panel, hooks, info, ..
    } = env.ui(Pad::idle());
    let mut samples = std::collections::VecDeque::from([None; 4]);
    samples.extend([
        Some(center(rsk_ui::row_rect(rsk_ui::PIV_KEYGEN_PICK_TOP, 0))),
        None,
        None,
        None,
        None,
    ]);
    let touch = SignalAfterTouches {
        samples,
        signal: std::rc::Rc::clone(&hooks.signal),
        event: PanelSignal::Wake,
        sent: false,
    };
    let mut ui = Ui::new(panel, touch, hooks, info, env.cells());
    Local::new(&mut ui, env.cells()).run_piv_pins();
    assert!(ui.asleep);
    assert_eq!(env.fs.borrow().write_gen(), generation);
}
