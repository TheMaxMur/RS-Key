// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{Env, PIN, Pad, PanelSignal, WRONG_PIN, center, dev, nowhere, pin_entry};
use std::collections::VecDeque;
use std::rc::Rc;
use std::vec;

const SEED: [u8; 32] = [0x5A; 32];

fn provision(env: &Env) {
    rsk_fido::seed::encrypt_keydev_f1(&dev(), &mut env.fs.borrow_mut(), &SEED).unwrap();
    env.fs
        .borrow_mut()
        .put(rsk_fido::consts::EF_AUDIT_ENABLED, &[1])
        .unwrap();
}

fn held_then_taps(before: &[rsk_ui::Point], after: &[rsk_ui::Point]) -> Pad {
    let mut samples = vec![None; 4];
    for &point in before {
        samples.push(Some(point));
        samples.extend([None; 4]);
    }
    let polls = 3 * (HOLD_MS / TOUCH_POLL_MS) as usize;
    samples.extend(vec![Some(center(rsk_ui::DEL_HOLD_RECT)); polls]);
    samples.extend([None; 4]);
    for &point in after {
        samples.push(Some(point));
        samples.extend([None; 4]);
    }
    Pad::script(&samples)
}

fn exports(env: &Env) -> usize {
    let mut count = 0;
    rsk_fido::journal::for_each_event(&dev(), &mut env.fs.borrow_mut(), |event| {
        if event.event == rsk_fido::journal::EV_BACKUP_EXPORT {
            count += 1;
        }
        true
    });
    count
}

struct SignalAfterTouches {
    samples: VecDeque<Option<rsk_ui::Point>>,
    signal: Rc<core::cell::Cell<PanelSignal>>,
    event: PanelSignal,
    sent: bool,
}

impl TouchPad for SignalAfterTouches {
    fn read(&mut self) -> Option<rsk_ui::Point> {
        if let Some(sample) = self.samples.pop_front() {
            return sample;
        }
        if !self.sent {
            self.sent = true;
            self.signal.set(self.event);
        }
        None
    }
}

#[cfg(not(feature = "fips-profile"))]
#[test]
fn a_power_press_or_host_request_closes_revealed_words_and_every_parent_modal() {
    for event in [PanelSignal::Wake, PanelSignal::HostRequest] {
        let env = Env::new();
        provision(&env);
        env.set_device_pin(PIN);
        let Ui {
            panel,
            mut hooks,
            info,
            ..
        } = env.ui(Pad::idle());
        hooks.presence_ms = 3000;
        let mut points = vec![center(rsk_ui::BACKUP_REVEAL_RECT)];
        points.extend(pin_entry(PIN));
        points.push(center(rsk_ui::FMT_PHRASE_RECT));
        let mut samples = VecDeque::from([None; 4]);
        for point in points {
            samples.extend([Some(point), None, None, None, None]);
        }
        samples.extend(vec![
            Some(center(rsk_ui::DEL_HOLD_RECT));
            3 * (HOLD_MS / TOUCH_POLL_MS) as usize
        ]);
        samples.extend([None; 4]);
        let touch = SignalAfterTouches {
            samples,
            signal: Rc::clone(&hooks.signal),
            event,
            sent: false,
        };
        let mut ui = Ui::new(panel, touch, hooks, info, env.cells());
        let started = Instant::now();
        Local::new(&mut ui, env.cells()).run_backup();
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(exports(&env), 1);
        assert_eq!(ui.asleep, event == PanelSignal::Wake);
        assert!(!ui.panel.oob);
        if ui.asleep {
            assert!(
                ui.panel
                    .area_pixels(rsk_ui::Rect::new(0, 0, rsk_ui::PANEL_W, rsk_ui::PANEL_H))
                    .iter()
                    .all(|&pixel| pixel == Rgb565::BLACK)
            );
        }
    }
}

#[test]
fn backup_actions_require_an_exportable_seed_and_device_pin() {
    let env = Env::new();
    let mut ui = env.ui(Pad::idle());
    let view = env.local(&mut ui).load_backup();
    assert!(!view.has_seed);
    assert!(!view.can_reveal);
    provision(&env);
    assert!(!env.local(&mut ui).load_backup().can_reveal);
    env.set_device_pin(PIN);
    let view = env.local(&mut ui).load_backup();
    assert!(view.has_seed);
    assert_eq!(view.can_reveal, !cfg!(feature = "fips-profile"));
    assert!(rsk_fido::passkeys::mark_backup_sealed(
        &mut env.fs.borrow_mut()
    ));
    let view = env.local(&mut ui).load_backup();
    assert!(view.sealed);
    assert!(!view.can_reveal);
}

#[test]
fn backup_status_exits_on_back_host_request_and_power_without_exporting() {
    for exit in 0..3 {
        let env = Env::new();
        provision(&env);
        let mut ui = env.ui(Pad::taps(&[nowhere(), center(rsk_ui::TITLE_BACK_RECT)]));
        ui.hooks.host_pending = exit == 1;
        if exit == 2 {
            ui.hooks.press_wake(1);
        }
        env.local(&mut ui).run_backup();
        assert_eq!(exports(&env), 0);
        assert_eq!(ui.asleep, exit == 2);
        assert!(!ui.panel.oob);
        assert!(!rsk_fido::passkeys::backup_sealed(&mut env.fs.borrow_mut()));
    }
}

#[test]
#[cfg(not(feature = "fips-profile"))]
fn backup_actions_return_to_status_after_the_pin_is_declined() {
    for action in [rsk_ui::BACKUP_REVEAL_RECT, rsk_ui::BACKUP_SEAL_RECT] {
        let env = Env::new();
        provision(&env);
        env.set_device_pin(PIN);
        let mut ui = env.ui(Pad::taps(&[
            center(action),
            center(rsk_ui::PIN_CANCEL_RECT),
            center(rsk_ui::TITLE_BACK_RECT),
        ]));
        env.local(&mut ui).run_backup();
        assert_eq!(exports(&env), 0);
        assert!(!rsk_fido::passkeys::backup_sealed(&mut env.fs.borrow_mut()));
        assert!(ui.panel.frames >= 4);
    }
}

#[test]
fn each_recovery_format_returns_to_the_chooser_after_cancellation() {
    for format in [rsk_ui::FMT_PHRASE_RECT, rsk_ui::FMT_SHARES_RECT] {
        let env = Env::new();
        provision(&env);
        let mut ui = env.ui(Pad::taps(&[
            center(format),
            center(rsk_ui::TITLE_BACK_RECT),
            center(rsk_ui::TITLE_BACK_RECT),
        ]));
        env.local(&mut ui).run_reveal_recovery();
        assert_eq!(exports(&env), 0);
        assert!(ui.panel.frames >= 4);
    }
}

#[test]
fn shares_require_a_completed_hold_and_a_readable_seed() {
    for unread in 0..3 {
        let mut env = Env::new();
        if unread != 0 {
            provision(&env);
        }
        if unread == 1 {
            env.keys.mkek_source = Some(FusedKey::latched(|_| false));
        }
        let pad = if unread == 2 {
            Pad::taps(&[
                center(rsk_ui::PICK_CONTINUE_RECT),
                center(rsk_ui::TITLE_BACK_RECT),
            ])
        } else {
            held_then_taps(&[center(rsk_ui::PICK_CONTINUE_RECT)], &[])
        };
        let mut ui = env.ui(pad);
        let entropy = env.rng.borrow().served.len();
        env.local(&mut ui).reveal_shares();
        assert_eq!(exports(&env), 0);
        assert_eq!(env.rng.borrow().served.len(), entropy);
    }
}

#[test]
fn the_share_pages_close_on_host_requests_and_power() {
    for power in [false, true] {
        let env = Env::new();
        let mut ui = env.ui(Pad::idle());
        ui.hooks.host_pending = !power;
        if power {
            ui.hooks.press_wake(1);
        }
        env.local(&mut ui).show_shares(
            &[[0; rsk_slip39::WORDS_PER_SHARE]; rsk_slip39::MAX_SHARES],
            2,
        );
        assert_eq!(ui.asleep, power);
        assert!(!ui.panel.oob);
    }
}

#[test]
fn a_declined_or_wrong_pin_reveals_and_seals_nothing() {
    for seal in [false, true] {
        let env = Env::new();
        provision(&env);
        env.set_device_pin(PIN);
        let mut taps = pin_entry(WRONG_PIN);
        taps.push(center(rsk_ui::PIN_CANCEL_RECT));
        let mut ui = env.ui(Pad::taps(&taps));
        let entropy = env.rng.borrow().served.len();
        if seal {
            env.local(&mut ui).run_seal_backup();
        } else {
            env.local(&mut ui).run_reveal_recovery();
        }
        assert_eq!(exports(&env), 0);
        assert!(!rsk_fido::passkeys::backup_sealed(&mut env.fs.borrow_mut()));
        assert_eq!(
            rsk_fido::passkeys::device_pin_retries_left(&mut env.fs.borrow_mut()),
            Some(rsk_fido::consts::MAX_PIN_RETRIES - 1)
        );
        assert_eq!(env.rng.borrow().served.len(), entropy);
    }
}

#[test]
fn a_recovery_chooser_returns_without_exporting_when_no_format_is_selected() {
    for exit in 0..3 {
        let env = Env::new();
        provision(&env);
        let mut ui = env.ui(Pad::taps(&[nowhere(), center(rsk_ui::TITLE_BACK_RECT)]));
        ui.hooks.host_pending = exit == 1;
        if exit == 2 {
            ui.hooks.press_wake(1);
        }
        env.local(&mut ui).run_reveal_recovery();
        assert_eq!(exports(&env), 0);
        assert_eq!(ui.asleep, exit == 2);
    }
}

#[test]
fn a_phrase_requires_a_completed_hold_and_a_readable_seed() {
    let env = Env::new();
    provision(&env);
    let mut ui = env.ui(Pad::taps(&[center(rsk_ui::TITLE_BACK_RECT)]));
    env.local(&mut ui).reveal_phrase();
    assert_eq!(exports(&env), 0);

    let mut ui = env.ui(held_then_taps(
        &[],
        &[
            center(rsk_ui::PAGER_NEXT_RECT),
            center(rsk_ui::PAGER_PREV_RECT),
            nowhere(),
            center(rsk_ui::TITLE_BACK_RECT),
        ],
    ));
    env.local(&mut ui).reveal_phrase();
    assert_eq!(exports(&env), 1);
    assert!(!ui.panel.oob);
    assert!(ui.panel.frames >= 4);
    assert_eq!(
        rsk_fido::passkeys::load_keydev(&dev(), &mut env.fs.borrow_mut())
            .unwrap()
            .expose(),
        &SEED
    );
}

#[test]
fn a_completed_hold_with_no_seed_exports_nothing() {
    let env = Env::new();
    let mut ui = env.ui(held_then_taps(&[], &[]));
    let frames = ui.panel.frames;
    env.local(&mut ui).reveal_phrase();
    assert_eq!(exports(&env), 0);
    assert_eq!(ui.panel.frames, frames + 1);
}

#[test]
fn an_unread_fused_key_cannot_reveal_the_phrase() {
    let mut env = Env::new();
    provision(&env);
    env.keys.mkek_source = Some(rsk_crypto::FusedKey::latched(|_| false));
    let mut ui = env.ui(held_then_taps(&[], &[]));
    let frames = ui.panel.frames;
    env.local(&mut ui).reveal_phrase();
    assert_eq!(exports(&env), 0);
    assert_eq!(ui.panel.frames, frames + 1);
}

#[test]
fn share_picker_cancellation_never_draws_entropy() {
    for exit in 0..3 {
        let env = Env::new();
        provision(&env);
        let mut ui = env.ui(Pad::taps(&[nowhere(), center(rsk_ui::TITLE_BACK_RECT)]));
        let entropy = env.rng.borrow().served.len();
        ui.hooks.host_pending = exit == 1;
        if exit == 2 {
            ui.hooks.press_wake(1);
        }
        env.local(&mut ui).reveal_shares();
        assert_eq!(env.rng.borrow().served.len(), entropy);
        assert_eq!(exports(&env), 0);
    }
}

#[test]
fn shares_are_generated_after_confirmation_and_preserve_the_master_seed() {
    let env = Env::new();
    provision(&env);
    let mut ui = env.ui(held_then_taps(
        &[
            center(rsk_ui::PICK_T_PLUS_RECT),
            center(rsk_ui::PICK_N_PLUS_RECT),
            center(rsk_ui::PICK_T_MINUS_RECT),
            center(rsk_ui::PICK_N_MINUS_RECT),
            center(rsk_ui::PICK_CONTINUE_RECT),
        ],
        &[
            center(rsk_ui::PAGER_NEXT_RECT),
            center(rsk_ui::PAGER_NEXT_RECT),
            center(rsk_ui::PAGER_NEXT_RECT),
            center(rsk_ui::PAGER_PREV_RECT),
            nowhere(),
            center(rsk_ui::TITLE_BACK_RECT),
        ],
    ));
    let entropy = env.rng.borrow().served.len();
    env.local(&mut ui).reveal_shares();
    assert_eq!(exports(&env), 1);
    assert!(env.rng.borrow().served.len() > entropy);
    assert!(!ui.panel.oob);
    assert!(ui.panel.frames >= 10);
    assert_eq!(
        rsk_fido::passkeys::load_keydev(&dev(), &mut env.fs.borrow_mut())
            .unwrap()
            .expose(),
        &SEED
    );
}

#[test]
fn sealing_requires_pin_and_confirmation_and_changes_the_backup_status() {
    let env = Env::new();
    provision(&env);
    env.set_device_pin(PIN);
    let mut ui = env.ui(held_then_taps(&pin_entry(PIN), &[]));
    ui.hooks.presence_ms = 3_000;
    env.local(&mut ui).run_seal_backup();
    assert!(rsk_fido::passkeys::backup_sealed(&mut env.fs.borrow_mut()));
    assert!(!env.local(&mut ui).load_backup().can_reveal);
    let mut finalized = false;
    rsk_fido::journal::for_each_event(&dev(), &mut env.fs.borrow_mut(), |event| {
        finalized |= event.event == rsk_fido::journal::EV_BACKUP_FINALIZE;
        true
    });
    assert!(finalized);
    assert_eq!(exports(&env), 0);
}

#[test]
fn backing_out_after_the_correct_pin_keeps_backup_exportable_and_unfinalized() {
    let env = Env::new();
    provision(&env);
    env.set_device_pin(PIN);
    assert!(
        matches!(rsk_fido::passkeys::spend_and_verify_device_pin(&dev(), &mut env.fs.borrow_mut(), WRONG_PIN), rsk_fido::passkeys::LocalPin::Wrong { retries_left } if retries_left == rsk_fido::consts::MAX_PIN_RETRIES - 1)
    );
    assert_eq!(
        rsk_fido::passkeys::device_pin_retries_left(&mut env.fs.borrow_mut()),
        Some(rsk_fido::consts::MAX_PIN_RETRIES - 1)
    );
    let mut samples = vec![None; 4];
    for point in pin_entry(PIN) {
        samples.push(Some(point));
        samples.extend([None; 4]);
    }
    samples.extend([None; 4]);
    samples.push(Some(center(rsk_ui::TITLE_BACK_RECT)));
    samples.extend([None; 4]);
    let mut ui = env.ui(Pad::script(&samples));
    ui.hooks.presence_ms = 3_000;
    env.local(&mut ui).run_seal_backup();
    assert_eq!(
        rsk_fido::passkeys::device_pin_retries_left(&mut env.fs.borrow_mut()),
        Some(rsk_fido::consts::MAX_PIN_RETRIES)
    );
    assert!(!ui.panel.pin_pads_painted().is_empty());
    assert!(!rsk_fido::passkeys::backup_sealed(&mut env.fs.borrow_mut()));
    assert_eq!(exports(&env), 0);
    let mut finalized = false;
    rsk_fido::journal::for_each_event(&dev(), &mut env.fs.borrow_mut(), |event| {
        finalized |= event.event == rsk_fido::journal::EV_BACKUP_FINALIZE;
        true
    });
    assert!(!finalized);
    assert_eq!(
        rsk_fido::passkeys::load_keydev(&dev(), &mut env.fs.borrow_mut())
            .unwrap()
            .expose(),
        &SEED
    );
    assert_eq!(
        env.local(&mut ui).load_backup().can_reveal,
        !cfg!(feature = "fips-profile")
    );
}
