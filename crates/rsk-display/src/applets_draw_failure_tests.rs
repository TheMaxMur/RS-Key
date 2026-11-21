// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::draw_failure::fault_ui;

#[test]
#[should_panic(expected = "direct display presentation failed")]
fn a_failed_rsa_search_arc_paint_is_reported() {
    let env = Env::new();
    let mut ui = fault_ui(&env, Pad::idle());
    ui.hooks.rsa_late_tick_only = true;
    ui.panel.remaining.set(0);
    Local::new(&mut ui, env.cells()).piv_search_rsa(2048);
}
