// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Frame controls for the read-only audit log (frozen mutation roster). The expected
//! frames are reconstructed from independent literals — a row rect, a dot centre, a
//! trailing-token anchor — not the geometry the mutants rewrite, so a moved coordinate
//! or a widened clip fails the pixel equality.

use super::*;
use crate::render::tests::Rec;

fn empty_body_frame(d: &mut Rec, logging: bool) {
    let (icon, color, headline) = if logging {
        (Glyph::Clock, MUTED, "No activity yet")
    } else {
        (Glyph::Warn, theme::WARN, "Logging is off")
    };
    glyph::draw(d, icon, Point::new(102, 96), 36, color, BG).unwrap();
    text(d, headline, EgPoint::new(120, 160), Role::Body, color).unwrap();
    if !logging {
        text(
            d,
            "Nothing is being recorded",
            EgPoint::new(120, 184),
            Role::MonoSmall,
            theme::CAPTION,
        )
        .unwrap();
    }
}

#[test]
fn empty_audit_page_pins_the_placeholder_geometry() {
    for logging in [true, false] {
        let mut actual = Rec::new();
        audit_body_list(&mut actual, &[], 0, 0, logging).unwrap();

        let mut expected = Rec::new();
        empty_body_frame(&mut expected, logging);

        assert_eq!(actual.px, expected.px, "logging={logging}");
        assert!(!actual.oob && !expected.oob, "logging={logging}");
    }
}

fn row_frame(d: &mut Rec, rect: Rect, secs: Option<u32>, dot: Rgb565, label: &str) {
    let cy = rect.y as i32 + rect.h as i32 / 2;
    crate::aa::filled_circle(
        d,
        EgPoint::new(rect.x as i32 + 10, cy - 4),
        8,
        dot,
        theme::ROW_BG,
    )
    .unwrap();
    let right_x = rect.x as i32 + rect.w as i32 - 8;
    let label_x = rect.x as i32 + 30;
    let label_right = if let Some(secs) = secs {
        let mut buf = [0u8; 8];
        let s = fmt_ago(secs, &mut buf);
        font::right(
            d,
            s,
            EgPoint::new(right_x, cy),
            Role::Mono,
            theme::CAPTION,
            theme::ROW_BG,
        )
        .unwrap();
        right_x - font::width(s, Role::Mono).unwrap_or(0) as i32 - ROW_TRAILING_GAP
    } else {
        right_x - ROW_TRAILING_GAP
    };
    let clip = Rect::new(
        label_x as u16,
        rect.y,
        (label_right - label_x).max(0) as u16,
        rect.h,
    );
    text_left_ellipsized_on(
        d,
        label,
        EgPoint::new(label_x, cy),
        Role::Body,
        FG,
        theme::ROW_BG,
        clip,
        false,
    )
    .unwrap();
}

#[test]
fn audit_row_with_a_time_ago_token_pins_its_geometry() {
    let rect = crate::row_rect(crate::PK_LIST_TOP, 3);
    let row = AuditRow {
        kind: AuditKind::Login,
        secs_ago: Some(300),
    };
    let mut actual = Rec::new();
    audit_body(&mut actual, rect, &row).unwrap();

    let mut expected = Rec::new();
    row_frame(&mut expected, rect, Some(300), theme::SUCCESS, "Signed in");

    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

#[test]
fn audit_row_without_a_time_ago_token_pins_its_geometry() {
    let rect = crate::row_rect(crate::PK_LIST_TOP, 1);
    let row = AuditRow {
        kind: AuditKind::Login,
        secs_ago: None,
    };
    let mut actual = Rec::new();
    audit_body(&mut actual, rect, &row).unwrap();

    let mut expected = Rec::new();
    row_frame(&mut expected, rect, None, theme::SUCCESS, "Signed in");

    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}
