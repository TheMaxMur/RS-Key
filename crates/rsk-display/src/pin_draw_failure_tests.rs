// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::draw_failure::fault_ui;

#[test]
#[should_panic(expected = "direct display presentation failed")]
fn a_failed_rename_field_paint_is_reported() {
    let env = Env::new();
    let mut ui = fault_ui(&env, Pad::idle());
    ui.panel.remaining.set(0);
    ui.repaint_rename(&T9::new(&Label::default()), &mut None);
}

#[test]
#[should_panic(expected = "direct display presentation failed")]
fn a_failed_rename_key_paint_is_reported() {
    let env = Env::new();
    let mut ui = fault_ui(&env, Pad::idle());
    let mut t9 = T9::new(&Label::default());
    t9.press(ABC);
    rsk_ui::render_rename_field(&mut ui.panel, t9.value().as_str(), t9.pending).unwrap();
    ui.panel.remaining.set(ui.panel.calls.get());
    ui.repaint_rename(&t9, &mut None);
}

#[test]
#[should_panic(expected = "direct display presentation failed")]
fn a_failed_pin_dot_paint_is_reported() {
    let env = Env::new();
    let mut ui = fault_ui(&env, Pad::taps(&[pin_key(rsk_ui::PinKey::Digit(1))]));
    ui.panel.remaining.set(0);
    ui.collect_pin(title(), None, FLOOR, FLOOR as u8, &mut [0; 64], false);
}

#[test]
#[should_panic(expected = "direct display presentation failed")]
fn a_failed_success_circle_paint_is_reported() {
    let env = Env::new();
    let mut ui = fault_ui(&env, Pad::idle());
    ui.panel.remaining.set(0);
    ui.show_success(rsk_ui::SuccessKind::Deleted, Some(1));
}

#[test]
#[should_panic(expected = "direct display presentation failed")]
fn a_failed_released_hold_button_is_reported() {
    let env = Env::new();
    let mut ui = fault_ui(&env, Pad::taps(&[center(rsk_ui::DEL_HOLD_RECT)]));
    ui.panel.remaining.set(0);
    ui.hold_to_confirm("Delete", rsk_ui::theme::DANGER_FILL);
}

#[test]
#[should_panic(expected = "direct display presentation failed")]
fn a_failed_hold_fill_is_reported() {
    let env = Env::new();
    let mut ui = fault_ui(&env, Pad::held(center(rsk_ui::DEL_HOLD_RECT)));
    ui.panel.remaining.set(0);
    ui.hold_to_confirm("Delete", rsk_ui::theme::DANGER_FILL);
}

#[test]
#[should_panic(expected = "direct display presentation failed")]
fn a_failed_automatic_remask_paint_is_reported() {
    struct RemaskPad {
        tapped: bool,
        failure: std::rc::Rc<core::cell::Cell<usize>>,
    }
    impl TouchPad for RemaskPad {
        fn read(&mut self) -> Option<rsk_ui::Point> {
            if self.tapped {
                None
            } else {
                self.tapped = true;
                Some(center(rsk_ui::PIN_EYE_RECT))
            }
        }
        fn wait_release_ceremony(&mut self, _: Instant, _: Duration) {}
        fn wait_release(&mut self, _: Instant, _: Duration) {
            self.failure.set(0);
            std::thread::sleep(std::time::Duration::from_millis(REVEAL_MASK_MS + 10));
        }
    }
    let env = Env::new();
    let failure = std::rc::Rc::new(core::cell::Cell::new(usize::MAX));
    let mut ui = fault_ui(
        &env,
        RemaskPad {
            tapped: false,
            failure: failure.clone(),
        },
    );
    ui.panel.remaining = failure;
    ui.hooks.presence_ms = u32::try_from(REVEAL_MASK_MS + 1000).unwrap();
    ui.collect_pin(title(), None, FLOOR, FLOOR as u8, &mut [0; 64], false);
}
