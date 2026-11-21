// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::draw_failure::fault_ui;

#[test]
#[should_panic(expected = "direct display presentation failed")]
fn a_failed_busy_arc_paint_is_reported() {
    let env = Env::new();
    let mut ui = fault_ui(&env, Pad::idle());
    ui.onboarding = false;
    ui.hooks.led = rsk_led::STATUS_PROCESSING;
    ui.panel.remaining.set(0);
    Local::new(&mut ui, env.cells()).ambient_repaint(0, &mut 0, &mut 0);
}

#[test]
#[should_panic(expected = "direct display presentation failed")]
fn a_failed_locked_breathe_paint_is_reported() {
    let env = Env::new();
    env.set_device_pin(PIN);
    let mut ui = fault_ui(&env, Pad::idle());
    ui.onboarding = false;
    ui.panel.remaining.set(0);
    Local::new(&mut ui, env.cells()).ambient_repaint(0, &mut 0, &mut 0);
}
