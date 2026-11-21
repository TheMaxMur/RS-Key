// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn the_pin_pad_respects_the_output_window_and_its_independent_length_floor() {
    const DIGITS: &[u8] = b"12345";
    for capacity in [0, FLOOR - 1, FLOOR, DIGITS.len()] {
        let env = Env::new();
        let mut taps = pin_entry(DIGITS);
        taps.push(center(rsk_ui::PIN_CANCEL_RECT));
        let mut ui = env.ui(Pad::taps(&taps));
        ui.hooks.set_presence_timeout_ms(5000);
        ui.hooks.led = rsk_led::STATUS_PROCESSING;
        let mut out = [0xA5; DIGITS.len() + 2];
        let outcome = ui.collect_pin(
            title(),
            None,
            FLOOR,
            FLOOR as u8,
            &mut out[1..1 + capacity],
            false,
        );
        if capacity >= FLOOR {
            assert!(matches!(outcome, rsk_sdk::PinEntry::Entered(n) if n == capacity));
        } else {
            assert!(matches!(outcome, rsk_sdk::PinEntry::Declined));
        }
        assert_eq!(&out[1..1 + capacity], &DIGITS[..capacity]);
        assert_eq!(out[0], 0xA5);
        assert_eq!(
            &out[1 + capacity..],
            &[0xA5; DIGITS.len() + 2][1 + capacity..]
        );
        assert!(!ui.hooks.up_pending && !ui.hooks.cancel);
        assert_eq!(ui.hooks.led, rsk_led::STATUS_PROCESSING);
    }
}
