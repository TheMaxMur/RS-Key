// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Frame controls for the destructive-flow and success screens (frozen mutation
//! roster). The expected frames are reconstructed from independent literals, not
//! the geometry the mutants rewrite, so a moved coordinate or a dropped draw
//! call fails the equality.

use super::*;
use crate::render::tests::Rec;

fn factory_reset_frame(d: &mut Rec) {
    back_button(d, Rect::new(8, 6, 42, 34), theme::DENY).unwrap();
    text_left(
        d,
        "Factory reset",
        EgPoint::new(58, 22),
        Role::Heading,
        theme::DENY,
    )
    .unwrap();
    crate::aa::filled_circle(d, EgPoint::new(91, 46), 58, theme::DANGER_BG, theme::BG).unwrap();
    glyph::draw(
        d,
        Glyph::Warn,
        Point::new(106, 62),
        28,
        theme::DANGER,
        theme::DANGER_BG,
    )
    .unwrap();
    text(d, "Erase RS-Key?", EgPoint::new(120, 124), Role::Strong, FG).unwrap();
    text(
        d,
        "This erases everything.",
        EgPoint::new(120, 150),
        Role::Body,
        MUTED,
    )
    .unwrap();
    text(
        d,
        "It cannot be undone.",
        EgPoint::new(120, 168),
        Role::Body,
        MUTED,
    )
    .unwrap();
    for (cy, label) in [
        (196, "All passkeys"),
        (216, "Device PIN & lock"),
        (236, "All applet keys"),
    ] {
        crate::aa::filled_circle(d, EgPoint::new(60, cy - 3), 6, theme::DANGER, theme::BG).unwrap();
        text_left(d, label, EgPoint::new(74, cy), Role::Body, theme::TEXT_2).unwrap();
    }
    render_hold_button(
        d,
        Rect::new(14, 248, 212, 56),
        "Hold to wipe",
        theme::DANGER_FILL,
    )
    .unwrap();
}

#[test]
fn factory_reset_frame_matches_its_geometry() {
    let mut actual = Rec::new();
    render_confirm_factory_reset(&mut actual).unwrap();
    let mut expected = Rec::new();
    factory_reset_frame(&mut expected);
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

fn erasing_frame(d: &mut Rec) {
    glyph::draw(d, Glyph::Warn, Point::new(104, 104), 32, theme::DENY, BG).unwrap();
    text(
        d,
        "Erasing...",
        EgPoint::new(120, 168),
        Role::Heading,
        theme::TEXT,
    )
    .unwrap();
    text(
        d,
        "Do not unplug",
        EgPoint::new(120, 196),
        Role::Body,
        MUTED,
    )
    .unwrap();
}

#[test]
fn erasing_frame_matches_its_geometry() {
    let mut actual = Rec::new();
    render_erasing(&mut actual).unwrap();
    let mut expected = Rec::new();
    erasing_frame(&mut expected);
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

fn pin_blocked_frame(d: &mut Rec) {
    crate::aa::filled_circle(d, EgPoint::new(85, 84), 70, theme::DANGER_BG, theme::BG).unwrap();
    glyph::draw(
        d,
        Glyph::Lock,
        Point::new(103, 102),
        34,
        theme::DANGER,
        theme::DANGER_BG,
    )
    .unwrap();
    text(
        d,
        "PIN blocked",
        EgPoint::new(120, 188),
        Role::Heading,
        theme::DANGER,
    )
    .unwrap();
    text(
        d,
        "Too many wrong PINs.",
        EgPoint::new(120, 216),
        Role::Body,
        MUTED,
    )
    .unwrap();
    text(
        d,
        "Reset from a host to recover.",
        EgPoint::new(120, 236),
        Role::Body,
        MUTED,
    )
    .unwrap();
}

#[test]
fn pin_blocked_frame_matches_its_geometry() {
    let mut actual = Rec::new();
    render_pin_blocked(&mut actual).unwrap();
    let mut expected = Rec::new();
    pin_blocked_frame(&mut expected);
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

fn wipe_failed_frame(d: &mut Rec) {
    crate::aa::filled_circle(d, EgPoint::new(85, 84), 70, theme::DANGER_BG, theme::BG).unwrap();
    glyph::draw(
        d,
        Glyph::Warn,
        Point::new(103, 102),
        34,
        theme::DANGER,
        theme::DANGER_BG,
    )
    .unwrap();
    text(
        d,
        "Erase failed",
        EgPoint::new(120, 188),
        Role::Heading,
        theme::DANGER,
    )
    .unwrap();
    text(
        d,
        "The store was not proven",
        EgPoint::new(120, 216),
        Role::Body,
        MUTED,
    )
    .unwrap();
    text(
        d,
        "empty. Data may remain.",
        EgPoint::new(120, 236),
        Role::Body,
        MUTED,
    )
    .unwrap();
}

#[test]
fn wipe_failed_frame_matches_its_geometry() {
    let mut actual = Rec::new();
    render_wipe_failed(&mut actual).unwrap();
    let mut expected = Rec::new();
    wipe_failed_frame(&mut expected);
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

fn success_frame(d: &mut Rec, kind: SuccessKind, with_button: bool) {
    let (_, _, _, heading, subtitle) = success_visuals(kind);
    text(d, heading, EgPoint::new(120, 178), Role::Heading, FG).unwrap();
    if !subtitle.is_empty() {
        text(d, subtitle, EgPoint::new(120, 206), Role::Body, MUTED).unwrap();
    }
    if with_button {
        crate::aa::rounded_rect(
            d,
            Rect::new(14, 248, 212, 56),
            11,
            Some(theme::ACCENT_FILL),
            None,
            BG,
        )
        .unwrap();
        text_on(
            d,
            "Done",
            EgPoint::new(120, 276),
            Role::Strong,
            FG,
            theme::ACCENT_FILL,
        )
        .unwrap();
    }
}

#[test]
fn success_frame_matches_its_geometry() {
    // Deleted carries the subtitle branch, Approved the subtitle-absent one;
    // both the wait-for-Done and dismiss-on-tap variants are covered.
    for (kind, with_button) in [
        (SuccessKind::Deleted, true),
        (SuccessKind::Deleted, false),
        (SuccessKind::Approved, false),
        (SuccessKind::Wiped, true),
    ] {
        let mut actual = Rec::new();
        render_success(&mut actual, kind, with_button).unwrap();
        let mut expected = Rec::new();
        success_frame(&mut expected, kind, with_button);
        assert_eq!(actual.px, expected.px, "{kind:?} button={with_button}");
        assert!(!actual.oob && !expected.oob);
    }
}

fn success_circle_frame(d: &mut Rec, kind: SuccessKind, scale_pct: u16) {
    // A primer larger than the fixed clear box makes the box (and its size) load-
    // bearing: a fresh background would hide a mis-placed or shrunken clear.
    Rectangle::new(EgPoint::new(70, 60), Size::new(100, 100))
        .into_styled(PrimitiveStyle::with_fill(theme::DANGER_FILL))
        .draw(d)
        .unwrap();
    let (mark, fill, mark_glyph, _, _) = success_visuals(kind);
    Rectangle::new(EgPoint::new(75, 67), Size::new(90, 90))
        .into_styled(PrimitiveStyle::with_fill(BG))
        .draw(d)
        .unwrap();
    let dia = (72 * scale_pct as u32 / 100).max(4);
    crate::aa::filled_circle(
        d,
        EgPoint::new(120 - dia as i32 / 2, 112 - dia as i32 / 2),
        dia,
        fill,
        theme::BG,
    )
    .unwrap();
    let gs = (dia * 48 / 100).max(10) as u16;
    glyph::draw(
        d,
        mark_glyph,
        Point::new((120 - gs as i32 / 2) as u16, (112 - gs as i32 / 2) as u16),
        gs,
        mark,
        fill,
    )
    .unwrap();
}

#[test]
fn success_circle_frame_matches_and_erases_the_previous_frame() {
    for (kind, pct) in [
        (SuccessKind::Approved, 60u16),
        (SuccessKind::Approved, 100),
        (SuccessKind::Wiped, 106),
    ] {
        let mut actual = Rec::new();
        Rectangle::new(EgPoint::new(70, 60), Size::new(100, 100))
            .into_styled(PrimitiveStyle::with_fill(theme::DANGER_FILL))
            .draw(&mut actual)
            .unwrap();
        render_success_circle(&mut actual, kind, pct).unwrap();
        let mut expected = Rec::new();
        success_circle_frame(&mut expected, kind, pct);
        assert_eq!(actual.px, expected.px, "{kind:?} at {pct}%");
    }
}
