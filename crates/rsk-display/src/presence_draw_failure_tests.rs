// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::draw_failure::fault_ui;

#[test]
#[should_panic(expected = "direct display presentation failed")]
fn a_failed_approval_hold_fill_is_reported() {
    let env = Env::new();
    let ui = fault_ui(&env, Pad::hold(allow()));
    ui.panel.remaining.set(0);
    let ui = RefCell::new(ui);
    TouchPresence::new(&ui).confirm_wait(sign_in());
}

#[test]
#[should_panic(expected = "direct display presentation failed")]
fn a_failed_released_approval_hold_button_is_reported() {
    let env = Env::new();
    let ui = fault_ui(&env, Pad::taps(&[allow()]));
    ui.panel.remaining.set(0);
    let ui = RefCell::new(ui);
    TouchPresence::new(&ui).confirm_wait(sign_in());
}
