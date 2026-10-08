// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::{Env, Pad, center, dev, nowhere};
use rsk_fido::journal as j;

fn seed_log(env: &Env) {
    let mut fs = env.fs.borrow_mut();
    rsk_fido::seed::encrypt_keydev_f1(&dev(), &mut fs, &[0x5A; 32]).unwrap();
    fs.put(rsk_fido::consts::EF_AUDIT_ENABLED, &[1]).unwrap();
    for (ms, event) in [
        (9000, j::EV_GET_ASSERT),
        (1000, j::EV_BOOT),
        (2000, j::EV_MAKE_CRED),
        (3000, j::EV_PIN_LOCKOUT),
        (4000, j::EV_BACKUP_EXPORT),
        (5000, j::EV_RESET),
        (6000, j::EV_PIN_CHANGE),
    ] {
        j::append_local(&dev(), &mut fs, ms, event, 0);
    }
}

#[test]
fn audit_pages_keep_the_boot_boundary_even_when_it_is_on_a_previous_page() {
    let env = Env::new();
    seed_log(&env);
    let mut ui = env.ui(Pad::idle());
    ui.hooks.attach_ms = 10000;
    let mut rows = [AuditRow::default(); rsk_ui::PK_ROWS_MAX];
    let local = env.local(&mut ui);
    assert_eq!(local.load_events(&mut rows, 0), (5, 7));
    assert_eq!(rows[0].secs_ago, Some(4));
    assert_eq!(rows[4].secs_ago, Some(8));
    assert_eq!(local.load_events(&mut rows, 1), (2, 7));
    assert_eq!(rows[0].secs_ago, Some(9));
    assert_eq!(rows[1].secs_ago, None);
    assert_eq!(local.load_events(&mut rows, 2), (0, 7));
}

#[test]
fn future_timestamps_are_not_presented_as_wrapped_ages() {
    let env = Env::new();
    seed_log(&env);
    let mut ui = env.ui(Pad::idle());
    ui.hooks.attach_ms = 5000;
    let mut rows = [AuditRow::default(); rsk_ui::PK_ROWS_MAX];
    assert_eq!(env.local(&mut ui).load_events(&mut rows, 0), (5, 7));
    assert_eq!(rows[0].secs_ago, None);
    assert_eq!(rows[1].secs_ago, Some(0));
}

#[test]
fn the_live_clock_saturates_at_the_journal_resolution() {
    let env = Env::new();
    seed_log(&env);
    j::append_local(
        &dev(),
        &mut env.fs.borrow_mut(),
        u64::MAX,
        j::EV_GET_ASSERT,
        0,
    );
    let mut ui = env.ui(Pad::idle());
    ui.hooks.attach_ms = u64::MAX;
    let mut rows = [AuditRow::default(); rsk_ui::PK_ROWS_MAX];
    assert_eq!(env.local(&mut ui).load_events(&mut rows, 0), (5, 8));
    assert_eq!(rows[0].secs_ago, Some(0));
}

#[test]
fn audit_navigation_is_read_only_and_pages_in_both_directions() {
    let env = Env::new();
    seed_log(&env);
    let mut ui = env.ui(Pad::taps(&[
        center(rsk_ui::PAGER_PREV_RECT),
        center(rsk_ui::PAGER_NEXT_RECT),
        center(rsk_ui::PAGER_NEXT_RECT),
        nowhere(),
        center(rsk_ui::PAGER_PREV_RECT),
        center(rsk_ui::TITLE_BACK_RECT),
    ]));
    let entropy = env.rng.borrow().served.len();
    env.local(&mut ui).run_auditlog();
    let mut count = 0;
    j::for_each_event(&dev(), &mut env.fs.borrow_mut(), |_| {
        count += 1;
        true
    });
    assert_eq!(count, 7);
    assert_eq!(env.rng.borrow().served.len(), entropy);
    assert!(ui.panel.damage_presentations >= 2);
    assert!(!ui.panel.oob);
}

#[test]
fn an_empty_or_disabled_audit_log_yields_on_host_requests_and_power() {
    for power in [false, true] {
        let env = Env::new();
        let mut ui = env.ui(Pad::idle());
        ui.hooks.host_pending = !power;
        if power {
            ui.hooks.press_wake(1);
        }
        env.local(&mut ui).run_auditlog();
        assert_eq!(ui.asleep, power);
        assert!(
            !env.fs
                .borrow_mut()
                .has_data(rsk_fido::consts::EF_AUDIT_ENABLED)
        );
    }
}

#[test]
fn a_zero_row_output_keeps_the_journal_total_without_writing_a_row() {
    let env = Env::new();
    seed_log(&env);
    let mut ui = env.ui(Pad::idle());
    let generation = env.fs.borrow().write_gen();
    assert_eq!(env.local(&mut ui).load_events(&mut [], 0), (0, 7));
    assert_eq!(env.fs.borrow().write_gen(), generation);
}
