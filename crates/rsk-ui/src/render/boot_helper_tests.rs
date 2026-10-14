// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::render::tests::Rec;
use embedded_graphics::prelude::RgbColor;

#[test]
fn runtime_breathe_rgb_conversion_preserves_the_high_component_bits() {
    for channels in [(0, 0, 0), (255, 255, 255), (154, 163, 173), (75, 80, 87)] {
        let (red, green, blue) = std::hint::black_box(channels);
        let color = rgb(red, green, blue);
        assert_eq!(color.r(), red / 8);
        assert_eq!(color.g(), green / 4);
        assert_eq!(color.b(), blue / 8);
    }
}

/// The frozen-roster frame controls for the boot screens. The expected frames are
/// rebuilt from independent literals (a circle centre/diameter, a glyph origin, a text
/// anchor), not the geometry the mutants rewrite, so a moved coordinate or a changed
/// size fails the pixel equality.
#[test]
fn locked_frame_matches_its_geometry() {
    let mut actual = Rec::new();
    locked(&mut actual).unwrap();

    let mut expected = Rec::new();
    crate::aa::filled_circle(
        &mut expected,
        EgPoint::new(85, 96),
        70,
        theme::SURFACE,
        theme::BG,
    )
    .unwrap();
    glyph::draw(
        &mut expected,
        Glyph::Lock,
        Point::new(103, 114),
        34,
        theme::ACCENT,
        theme::SURFACE,
    )
    .unwrap();
    text(
        &mut expected,
        "Locked",
        EgPoint::new(120, 200),
        Role::Heading,
        FG,
    )
    .unwrap();
    text(
        &mut expected,
        "Touch to unlock",
        EgPoint::new(120, 228),
        Role::Body,
        rgb(154, 163, 173),
    )
    .unwrap();

    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

/// A full ramp cycle wraps: phase 8 is the brightest shade again, so the hint reads
/// `BREATHE[0]`, not `BREATHE[1]`. Pinned at the wrap so `%` and `/` cannot agree.
#[test]
fn locked_breathe_wraps_at_a_full_phase_cycle() {
    let mut actual = Rec::new();
    render_locked_breathe(&mut actual, 8).unwrap();

    let mut expected = Rec::new();
    text(
        &mut expected,
        "Touch to unlock",
        EgPoint::new(120, 228),
        Role::Body,
        rgb(154, 163, 173),
    )
    .unwrap();

    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

#[test]
fn onboard_frame_matches_its_geometry() {
    let mut actual = Rec::new();
    onboard(&mut actual).unwrap();

    let mut expected = Rec::new();
    crate::aa::filled_circle(
        &mut expected,
        EgPoint::new(88, 36),
        64,
        theme::SURFACE,
        theme::BG,
    )
    .unwrap();
    glyph::draw(
        &mut expected,
        Glyph::Lock,
        Point::new(104, 52),
        32,
        theme::ACCENT,
        theme::SURFACE,
    )
    .unwrap();
    text(
        &mut expected,
        "Set a PIN?",
        EgPoint::new(120, 120),
        Role::Heading,
        FG,
    )
    .unwrap();
    text(
        &mut expected,
        "A device PIN locks the",
        EgPoint::new(120, 146),
        Role::Body,
        MUTED,
    )
    .unwrap();
    text(
        &mut expected,
        "on-device menus.",
        EgPoint::new(120, 164),
        Role::Body,
        MUTED,
    )
    .unwrap();
    button(
        &mut expected,
        ONBOARD_SET_RECT,
        "Set a PIN",
        theme::ACCENT_FILL,
    )
    .unwrap();
    crate::aa::rounded_rect(
        &mut expected,
        ONBOARD_SKIP_RECT,
        BTN_RADIUS,
        None,
        Some((MUTED, 2)),
        BG,
    )
    .unwrap();
    text(
        &mut expected,
        "Continue without PIN",
        center(ONBOARD_SKIP_RECT),
        Role::Body,
        MUTED,
    )
    .unwrap();

    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

#[test]
fn splash_frame_matches_its_geometry() {
    let mut actual = Rec::new();
    splash(&mut actual).unwrap();

    let mut expected = Rec::new();
    glyph::draw(
        &mut expected,
        Glyph::Shield,
        Point::new(100, 92),
        40,
        theme::ACCENT,
        BG,
    )
    .unwrap();
    text(
        &mut expected,
        "RS-Key",
        EgPoint::new(120, 158),
        Role::Heading,
        FG,
    )
    .unwrap();
    text(
        &mut expected,
        "trusted display",
        EgPoint::new(120, 186),
        Role::Body,
        MUTED,
    )
    .unwrap();

    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}
