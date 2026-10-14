// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn share_titles_name_both_numbers() {
    let mut buf = [0u8; 18];
    assert_eq!(fmt_share_title(1, 3, &mut buf), "Share 1/3");
    assert_eq!(fmt_share_title(2, 12, &mut buf), "Share 2/12");
    assert_eq!(fmt_share_title(65535, 65535, &mut buf), "Share 65535/65535");
}

#[test]
fn word_grid_pages_twelve_numbered_words_in_two_columns() {
    let words: [&str; 14] = [
        "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
        "juliet", "kilo", "lima", "mike", "november",
    ];
    // The layout is the wire-facing paging contract: columns at 16/126, rows from 76
    // every 27, the number right-aligned 22 px before the word at 27 px.
    let expected_after = |page: u16| {
        let mut e = crate::render::tests::Rec::new();
        let start = page as usize * 12;
        for c in 0..12usize {
            let gi = start + c;
            if gi >= words.len() {
                break;
            }
            let base_x = if c / 6 == 0 { 16 } else { 126 };
            let cy = 76 + (c % 6) as i32 * 27;
            let ns = std::format!("{}.", gi + 1);
            text_right(
                &mut e,
                &ns,
                EgPoint::new(base_x + 22, cy),
                Role::Mono,
                theme::CAPTION,
            )
            .unwrap();
            text_left(
                &mut e,
                words[gi],
                EgPoint::new(base_x + 27, cy),
                Role::BodyStrong,
                FG,
            )
            .unwrap();
        }
        e
    };
    for page in [0u16, 1] {
        let mut actual = crate::render::tests::Rec::new();
        word_grid(&mut actual, &words, page).unwrap();
        let expected = expected_after(page);
        assert_eq!(actual.px, expected.px, "page {page}");
        assert!(!actual.oob);
    }
}

#[test]
fn the_choice_card_places_its_title_and_sub_below_the_surface() {
    let r = Rect::new(20, 40, 200, 60);
    let mut actual = crate::render::tests::Rec::new();
    choice_card(&mut actual, r, "Back up", "24 words").unwrap();
    let mut expected = crate::render::tests::Rec::new();
    key_surface(&mut expected, r, KEY_FILL, true).unwrap();
    text_left_on(
        &mut expected,
        "Back up",
        EgPoint::new(34, 62),
        Role::Strong,
        FG,
        KEY_FILL,
    )
    .unwrap();
    text_left_on(
        &mut expected,
        "24 words",
        EgPoint::new(34, 84),
        Role::Body,
        MUTED,
        KEY_FILL,
    )
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}

#[test]
fn a_stepper_row_centres_its_value_between_the_two_keys() {
    let minus = Rect::new(60, 200, 30, 30);
    let plus = Rect::new(150, 200, 30, 30);
    let mut actual = crate::render::tests::Rec::new();
    stepper_row(&mut actual, "Threshold", minus, plus, 7).unwrap();
    let mut expected = crate::render::tests::Rec::new();
    text_left(
        &mut expected,
        "Threshold",
        EgPoint::new(16, 186),
        Role::Body,
        MUTED,
    )
    .unwrap();
    key_surface(&mut expected, minus, KEY_FILL, true).unwrap();
    text_on(
        &mut expected,
        "-",
        center(minus),
        Role::Strong,
        FG,
        KEY_FILL,
    )
    .unwrap();
    key_surface(&mut expected, plus, KEY_FILL, true).unwrap();
    text_on(&mut expected, "+", center(plus), Role::Strong, FG, KEY_FILL).unwrap();
    let mut b = [0u8; 5];
    text(
        &mut expected,
        fmt_u16(7, &mut b),
        EgPoint::new(MIDX, 215),
        Role::Ready,
        FG,
    )
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}
