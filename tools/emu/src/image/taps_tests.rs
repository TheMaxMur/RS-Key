// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use std::time::Duration;

#[test]
fn holds_follow_image_time_and_retain_a_release_between_contacts() {
    let tap = Tap {
        at: rsk_ui::Point::new(170, 272),
        hold: Duration::from_millis(800),
        gap: Duration::from_millis(80),
    };
    let mut pad = Pad::new(vec![tap, tap], None);
    assert_eq!(pad.read(0), None);
    for _ in 0..100 {
        assert_eq!(pad.read(79_999_999), None);
    }
    assert_eq!(pad.read(80_000_000), Some(tap.at));
    assert_eq!(pad.read(879_999_999), Some(tap.at));
    assert_eq!(pad.read(880_000_000), None);
    assert_eq!(pad.read(959_999_999), None);
    assert_eq!(pad.read(960_000_000), Some(tap.at));
    pad.reboot(1_000_000_000);
    assert_eq!(pad.read(759_999_999), Some(tap.at));
    assert_eq!(pad.read(760_000_000), None);
}
