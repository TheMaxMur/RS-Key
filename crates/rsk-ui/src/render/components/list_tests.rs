// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Frame tests for the list components. The card span, divider midpoints and the row's
//! icon / trailing / label-clip geometry are written out from their literals, so a
//! mutation of any single term moves a pixel.

use super::*;
use crate::render::tests::Rec;

/// `group_card`: the rounded span covering rows 0..n, plus a hairline divider at every
/// inter-row gap midpoint. Three rows exercises both dividers and the last-row extent.
#[test]
fn group_card_matches_its_literal_geometry() {
    let y0 = crate::PK_LIST_TOP;
    let n = 3u16;
    let mut actual = Rec::new();
    group_card(&mut actual, y0, n).unwrap();

    let mut expected = Rec::new();
    let first = crate::row_rect(y0, 0);
    let last = crate::row_rect(y0, n - 1);
    let span = Rect::new(first.x, first.y, first.w, last.y + last.h - first.y);
    crate::aa::rounded_rect(
        &mut expected,
        span,
        LIST_RADIUS,
        Some(theme::ROW_BG),
        Some((theme::BORDER_CARD, 1)),
        theme::BG,
    )
    .unwrap();
    for i in 1..n {
        let prev = crate::row_rect(y0, i - 1);
        let curr = crate::row_rect(y0, i);
        let dy = (prev.y + crate::LIST_ROW_H + curr.y) / 2;
        Line::new(
            EgPoint::new(first.x as i32 + 12, dy as i32),
            EgPoint::new((first.x + first.w) as i32 - 12, dy as i32),
        )
        .into_styled(PrimitiveStyle::with_stroke(theme::DIVIDER, 1))
        .draw(&mut expected)
        .unwrap();
    }

    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

/// An independent repaint of one [`row`], from its literal constants.
#[allow(clippy::too_many_arguments)]
fn expected_row(
    rec: &mut Rec,
    y0: u16,
    i: u16,
    icon: Glyph,
    label: &str,
    trailing: Option<(&str, Rgb565)>,
    chevron: bool,
    chip: bool,
) {
    let rect = crate::row_rect(y0, i);
    let cy = rect.y as i32 + rect.h as i32 / 2;
    let gx = if chip {
        crate::aa::rounded_rect(
            rec,
            Rect::new(rect.x + 3, (cy - 11) as u16, 22, 22),
            6,
            Some(theme::CHIP),
            None,
            theme::ROW_BG,
        )
        .unwrap();
        rect.x + 7
    } else {
        rect.x + 8
    };
    glyph::draw(
        rec,
        icon,
        Point::new(gx, (cy - 7) as u16),
        14,
        theme::GREY,
        if chip { theme::CHIP } else { theme::ROW_BG },
    )
    .unwrap();

    let mut right_x = rect.x as i32 + rect.w as i32 - 8;
    if chevron {
        right_x -= 12;
        glyph::draw(
            rec,
            Glyph::Chevron,
            Point::new(right_x as u16, (cy - 6) as u16),
            12,
            theme::MUTED,
            theme::ROW_BG,
        )
        .unwrap();
    }
    let label_x = rect.x as i32 + 28;
    let label_right = if let Some((txt, col)) = trailing {
        let tx = right_x - 4;
        let tmax = (rect.w as i32 / 2).max(0);
        let tleft = (tx - tmax).max(label_x);
        let tclip = Rect::new(tleft as u16, rect.y, (tx - tleft).max(0) as u16, rect.h);
        font::right(
            &mut rec.clipped(&eg_rect(tclip)),
            txt,
            EgPoint::new(tx, cy),
            font::Role::Body,
            col,
            theme::ROW_BG,
        )
        .unwrap();
        let tw = (font::width(txt, font::Role::Body).unwrap_or(0) as i32).min(tx - tleft);
        tx - tw - TRAILING_GAP
    } else {
        right_x - TRAILING_GAP
    };
    let clip = Rect::new(
        label_x as u16,
        rect.y,
        (label_right - label_x).max(0) as u16,
        rect.h,
    );
    text_left_ellipsized_on(
        rec,
        label,
        EgPoint::new(label_x, cy),
        font::Role::Body,
        theme::TEXT,
        theme::ROW_BG,
        clip,
        false,
    )
    .unwrap();
}

const LONG_LABEL: &str = "An unusually long display label that must be clipped";
const LONG_VALUE: &str = "123456789012345678901234567890123456789012345678901234567890";

/// The chipped variant with a long trailing value: pins the chip tile + glyph, the
/// chevron, and the trailing/label clip split (both sides ellipsized).
#[test]
fn list_row_with_a_chip_and_trailing_matches_its_literals() {
    let (y0, i) = (crate::PK_LIST_TOP, 1u16);
    let mut actual = Rec::new();
    row(
        &mut actual,
        y0,
        i,
        Glyph::Key,
        LONG_LABEL,
        Some((LONG_VALUE, theme::WARN)),
        true,
        true,
        false,
        false,
    )
    .unwrap();
    let mut expected = Rec::new();
    expected_row(
        &mut expected,
        y0,
        i,
        Glyph::Key,
        LONG_LABEL,
        Some((LONG_VALUE, theme::WARN)),
        true,
        true,
    );
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

/// The plain variant (no chip, no trailing): pins the non-chip glyph inset and the
/// no-trailing label clip from `right_x - TRAILING_GAP`.
#[test]
fn list_row_without_chip_or_trailing_matches_its_literals() {
    let (y0, i) = (crate::PK_LIST_TOP, 1u16);
    let mut actual = Rec::new();
    row(
        &mut actual,
        y0,
        i,
        Glyph::Key,
        LONG_LABEL,
        None,
        true,
        false,
        false,
        false,
    )
    .unwrap();
    let mut expected = Rec::new();
    expected_row(
        &mut expected,
        y0,
        i,
        Glyph::Key,
        LONG_LABEL,
        None,
        true,
        false,
    );
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}
