// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn an_empty_audit_page_replaces_the_whole_previous_body() {
    let rows = [
        AuditRow {
            kind: AuditKind::Login,
            secs_ago: Some(120),
        },
        AuditRow {
            kind: AuditKind::Register,
            secs_ago: Some(3600),
        },
        AuditRow {
            kind: AuditKind::Denied,
            secs_ago: None,
        },
    ];
    let mut actual = Rec::new();
    render_audit_log(&mut actual, &rows, 0, 3, true).unwrap();
    render_audit_page(&mut actual, &[], 0, 0, true).unwrap();
    let mut expected = Rec::new();
    render_audit_log(&mut expected, &[], 0, 0, true).unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}

#[test]
fn page_labels_preserve_both_numbers_and_the_separator() {
    for (page, pages, expected) in [
        (1, 3, "1 / 3"),
        (12, 345, "12 / 345"),
        (u16::MAX, u16::MAX, "65535 / 65535"),
    ] {
        assert_eq!(fmt_pages(page, pages, &mut [0xEE; 13]), expected);
    }
}

#[test]
fn a_one_page_list_paints_its_literal_singular_or_plural_footer() {
    for (total, label) in [(1, "1 event"), (2, "2 events")] {
        let mut actual = Rec::new();
        list_tail(&mut actual, 0, total, "event", "events").unwrap();
        let mut expected = Rec::new();
        font::right(
            &mut expected,
            label,
            EgPoint::new(228, 274),
            Role::Mono,
            MUTED,
            BG,
        )
        .unwrap();
        assert_eq!(actual.px, expected.px);
        assert!(!actual.oob);
    }
}

#[test]
fn pager_arrows_align_with_hit_rect_centers_and_the_visible_page_number() {
    let mut actual = Rec::new();
    render_pager(&mut actual, 1, 3).unwrap();
    let mut expected = Rec::new();
    for (glyph, rect) in [
        (Glyph::Back, PAGER_PREV_RECT),
        (Glyph::Chevron, PAGER_NEXT_RECT),
    ] {
        let x = rect.x + rect.w / 2;
        let y = rect.y + rect.h / 2;
        glyph::draw(
            &mut expected,
            glyph,
            Point::new(x - 8, y - 8),
            16,
            theme::ACCENT,
            BG,
        )
        .unwrap();
    }
    font::centered(
        &mut expected,
        "2 / 3",
        EgPoint::new(120, 261),
        Role::Mono,
        MUTED,
        BG,
    )
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}

#[test]
fn the_pin_eye_is_centered_inside_its_actual_hit_rect() {
    let mut actual = Rec::new();
    glyph_centered(&mut actual, Glyph::Eye, PIN_EYE_RECT, 18, FG, BG).unwrap();
    let mut expected = Rec::new();
    glyph::draw(&mut expected, Glyph::Eye, Point::new(213, 51), 18, FG, BG).unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}

#[test]
fn clipped_left_text_paints_visible_ink_without_writing_outside_its_clip() {
    let clip = Rect::new(4, 4, 10, 16);
    let mut actual = Rec::new();
    text_left_clipped_on(
        &mut actual,
        "AAA",
        EgPoint::new(2, 12),
        Role::Body,
        FG,
        BG,
        clip,
    )
    .unwrap();
    assert!(actual.any_non_bg_in(clip));
    assert!(actual.wrote_in(clip));
    assert!(!actual.wrote_outside(clip));
    assert!(!actual.oob);
}
