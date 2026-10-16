// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn same_pixels(actual: &Rec, expected: &Rec) {
    let difference = actual
        .px
        .iter()
        .zip(&expected.px)
        .enumerate()
        .find(|(_, (a, b))| a != b)
        .map(|(index, (a, b))| (index, *a, *b));
    assert_eq!(difference, None);
}

#[test]
fn status_bar_places_the_wordmark_and_usb_indicator_at_the_panel_margins() {
    let mut actual = Rec::new();
    status_bar(&mut actual).unwrap();
    let mut expected = Rec::new();
    font::left(
        &mut expected,
        "RS-Key",
        EgPoint::new(13, 13),
        Role::MonoSmall,
        theme::FAINT,
        BG,
    )
    .unwrap();
    font::right(
        &mut expected,
        "USB",
        EgPoint::new(227, 13),
        Role::MonoSmall,
        theme::FAINT,
        BG,
    )
    .unwrap();
    let width = font::width("USB", Role::MonoSmall).unwrap() as u16;
    glyph::draw(
        &mut expected,
        Glyph::Usb,
        Point::new(211 - width, 6),
        14,
        theme::GREY,
        BG,
    )
    .unwrap();
    same_pixels(&actual, &expected);
    assert!(!actual.oob);
}

#[test]
fn a_fitting_domain_label_keeps_all_its_characters() {
    let mut actual = Rec::new();
    let width = font::width("abc", Role::Body).unwrap() as u16;
    let clip = Rect::new(20, 30, width, 20);
    text_right_ellipsized(
        &mut actual,
        "abc",
        EgPoint::new(20, 40),
        Role::Body,
        FG,
        clip,
        false,
    )
    .unwrap();
    let mut expected = Rec::new();
    font::left(
        &mut expected.clipped(&eg_rect(clip)),
        "abc",
        EgPoint::new(20, 40),
        Role::Body,
        FG,
        BG,
    )
    .unwrap();
    same_pixels(&actual, &expected);
    assert!(actual.drew_anything());
}

#[test]
fn an_overflowing_domain_label_keeps_the_suffix_after_its_marker() {
    let mut actual = Rec::new();
    let width = font::width("...abc", Role::Body).unwrap() as u16;
    let clip = Rect::new(20, 30, width, 20);
    text_right_ellipsized(
        &mut actual,
        "WWWWabc",
        EgPoint::new(20, 40),
        Role::Body,
        FG,
        clip,
        false,
    )
    .unwrap();
    let mut expected = Rec::new();
    font::left(
        &mut expected.clipped(&eg_rect(clip)),
        "...abc",
        EgPoint::new(20, 40),
        Role::Body,
        FG,
        BG,
    )
    .unwrap();
    same_pixels(&actual, &expected);
    assert!(actual.drew_anything());
}

#[test]
fn a_marked_domain_label_shows_the_marker_even_when_the_label_fits() {
    let mut actual = Rec::new();
    let clip = Rect::new(20, 30, 100, 20);
    text_right_ellipsized(
        &mut actual,
        "abc",
        EgPoint::new(20, 40),
        Role::Body,
        FG,
        clip,
        true,
    )
    .unwrap();
    let mut expected = Rec::new();
    font::left(
        &mut expected.clipped(&eg_rect(clip)),
        "...abc",
        EgPoint::new(20, 40),
        Role::Body,
        FG,
        BG,
    )
    .unwrap();
    same_pixels(&actual, &expected);
}

#[test]
fn a_thin_marked_domain_label_retains_more_than_22_suffix_bytes() {
    let label = Label::clamp(&[b'i'; 49]);
    let text = format!("...{}", label.as_str());
    assert!(font::width(&text, Role::Body).unwrap() <= 200);
    let clip = Rect::new(20, 30, 200, 20);
    let mut actual = Rec::new();
    text_right_ellipsized(
        &mut actual,
        label.as_str(),
        EgPoint::new(20, 40),
        Role::Body,
        FG,
        clip,
        true,
    )
    .unwrap();
    let mut expected = Rec::new();
    font::left(
        &mut expected.clipped(&eg_rect(clip)),
        &text,
        EgPoint::new(20, 40),
        Role::Body,
        FG,
        BG,
    )
    .unwrap();
    same_pixels(&actual, &expected);
}

#[test]
fn title_text_aligns_with_the_back_target_or_the_plain_content_margin() {
    for back in [false, true] {
        let mut actual = Rec::new();
        title_bar_wide(&mut actual, "OATH", FG, back).unwrap();
        let mut expected = Rec::new();
        let x = if back {
            back_button(&mut expected, TITLE_BACK_RECT, FG).unwrap();
            54
        } else {
            13
        };
        font::left(
            &mut expected.clipped(&eg_rect(Rect::new(x, 24, 227 - x, 30))),
            "OATH",
            EgPoint::new(i32::from(x), 39),
            Role::Heading,
            FG,
            BG,
        )
        .unwrap();
        same_pixels(&actual, &expected);
        assert!(!actual.oob);
    }
}

#[test]
fn a_wide_title_uses_the_space_after_the_edit_pencil_zone() {
    let mut actual = Rec::new();
    title_bar_wide(&mut actual, "WWWWWWWWWWW", FG, false).unwrap();
    let mut expected = Rec::new();
    font::left(
        &mut expected.clipped(&eg_rect(Rect::new(13, 24, 214, 30))),
        "WWWWWWWWWWW",
        EgPoint::new(13, 39),
        Role::Heading,
        FG,
        BG,
    )
    .unwrap();
    same_pixels(&actual, &expected);
    assert!(actual.wrote_in(Rect::new(193, 24, 34, 30)));
}

#[test]
fn a_wide_credential_title_still_clips_at_the_panel_margin() {
    let title = Label::clamp(b"WWWWWWWWWWWWW");
    let mut actual = Rec::new();
    title_bar_wide_label(&mut actual, &title, FG, false).unwrap();
    assert!(!actual.oob);
    assert!(!actual.wrote_outside(Rect::new(13, 24, 214, 30)));
    let mut expected = Rec::new();
    font::left(
        &mut expected.clipped(&eg_rect(Rect::new(13, 24, 214, 30))),
        "WWWWWWWWWW...",
        EgPoint::new(13, 39),
        Role::Heading,
        FG,
        BG,
    )
    .unwrap();
    same_pixels(&actual, &expected);
}

#[test]
fn a_header_status_glyph_keeps_its_right_margin() {
    let mut actual = Rec::new();
    render_header(&mut actual, "OATH", true, Some(Glyph::Lock)).unwrap();
    let mut expected = Rec::new();
    font::left(
        &mut expected,
        "OATH",
        EgPoint::new(12, 15),
        Role::Heading,
        theme::ACCENT,
        BG,
    )
    .unwrap();
    glyph::draw(
        &mut expected,
        Glyph::Lock,
        Point::new(214, 6),
        18,
        theme::MUTED,
        BG,
    )
    .unwrap();
    same_pixels(&actual, &expected);
    assert!(!actual.oob);
}

#[test]
fn plain_home_rows_align_the_leading_icon_label_and_trailing_count() {
    for (rect, glyph, label, count) in [
        (
            Rect::new(8, 128, 224, 34),
            Glyph::Lock,
            "Device PIN set",
            None,
        ),
        (
            Rect::new(8, 164, 224, 34),
            Glyph::Key,
            "Passkeys",
            Some("65535"),
        ),
    ] {
        let mut actual = Rec::new();
        row_body(
            &mut actual,
            rect,
            glyph,
            label,
            count.map(|s| (s, theme::GREY)),
            false,
            false,
        )
        .unwrap();
        let mut expected = Rec::new();
        let cy = i32::from(rect.y) + 17;
        glyph::draw(
            &mut expected,
            glyph,
            Point::new(16, rect.y + 10),
            14,
            theme::GREY,
            theme::ROW_BG,
        )
        .unwrap();
        font::left(
            &mut expected,
            label,
            EgPoint::new(36, cy),
            Role::Body,
            theme::TEXT,
            theme::ROW_BG,
        )
        .unwrap();
        if let Some(count) = count {
            font::right(
                &mut expected,
                count,
                EgPoint::new(220, cy),
                Role::Body,
                theme::GREY,
                theme::ROW_BG,
            )
            .unwrap();
        }
        same_pixels(&actual, &expected);
        assert!(!actual.oob);
    }
}

#[test]
fn the_three_home_rows_share_one_card_with_two_inset_dividers() {
    let mut actual = Rec::new();
    group_card(&mut actual, 92, 3).unwrap();
    let mut expected = Rec::new();
    crate::aa::rounded_rect(
        &mut expected,
        Rect::new(8, 92, 224, 106),
        11,
        Some(theme::ROW_BG),
        Some((theme::BORDER_CARD, 1)),
        BG,
    )
    .unwrap();
    for y in [127, 163] {
        Line::new(EgPoint::new(20, y), EgPoint::new(220, y))
            .into_styled(PrimitiveStyle::with_stroke(theme::DIVIDER, 1))
            .draw(&mut expected)
            .unwrap();
    }
    same_pixels(&actual, &expected);
    assert!(!actual.oob);
}

#[test]
fn service_icons_require_the_complete_case_insensitive_ssh_substring() {
    for label in ["ssh", "SSH", "host.sSh.example"] {
        assert_eq!(service_glyph(label), Glyph::Terminal);
    }
    for label in ["ash", "sah", "ssa", "example.com"] {
        assert_eq!(service_glyph(label), Glyph::Globe);
    }
}

#[test]
fn nav_icons_and_captions_share_the_centers_of_their_four_hit_cells() {
    let mut actual = Rec::new();
    render_nav(&mut actual, NavTab::Apps).unwrap();
    let mut expected = Rec::new();
    Rectangle::new(EgPoint::new(0, 284), Size::new(240, 36))
        .into_styled(PrimitiveStyle::with_fill(theme::NAV_BG))
        .draw(&mut expected)
        .unwrap();
    Line::new(EgPoint::new(0, 284), EgPoint::new(239, 284))
        .into_styled(PrimitiveStyle::with_stroke(theme::HAIRLINE, 1))
        .draw(&mut expected)
        .unwrap();
    for (cx, glyph, label, active) in [
        (30, Glyph::Home, "Home", false),
        (90, Glyph::Key, "Passkeys", false),
        (150, Glyph::Apps, "Apps", true),
        (210, Glyph::Gear, "Settings", false),
    ] {
        let color = if active {
            theme::ACCENT
        } else {
            theme::NAV_INACTIVE
        };
        glyph::draw(
            &mut expected,
            glyph,
            Point::new(cx - 8, 288),
            16,
            color,
            theme::NAV_BG,
        )
        .unwrap();
        font::centered(
            &mut expected,
            label,
            EgPoint::new(i32::from(cx), 312),
            Role::MonoSmall,
            color,
            theme::NAV_BG,
        )
        .unwrap();
    }
    same_pixels(&actual, &expected);
    assert!(!actual.oob);
}
