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

#[test]
fn the_share_picker_reports_both_steppers_and_one_summary_line() {
    let mut actual = crate::render::tests::Rec::new();
    render_share_picker(&mut actual, 2, 3).unwrap();
    let mut expected = crate::render::tests::Rec::new();
    back_button(&mut expected, PK_BACK_RECT, theme::ACCENT).unwrap();
    text_left(
        &mut expected,
        "Shamir shares",
        EgPoint::new(58, 22),
        Role::Heading,
        theme::TEXT,
    )
    .unwrap();
    stepper_row(
        &mut expected,
        "Needed to recover",
        PICK_T_MINUS_RECT,
        PICK_T_PLUS_RECT,
        2,
    )
    .unwrap();
    stepper_row(
        &mut expected,
        "Total shares",
        PICK_N_MINUS_RECT,
        PICK_N_PLUS_RECT,
        3,
    )
    .unwrap();
    text(
        &mut expected,
        "Any 2 of 3 shares",
        EgPoint::new(MIDX, 228),
        Role::Body,
        theme::ACCENT_TEXT,
    )
    .unwrap();
    button(
        &mut expected,
        PICK_CONTINUE_RECT,
        "Continue",
        theme::ACCENT_FILL,
    )
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}

#[test]
fn the_reveal_gate_draws_its_warning_lines_and_hold_button() {
    let mut actual = crate::render::tests::Rec::new();
    render_reveal_warning(&mut actual, RevealKind::Phrase).unwrap();
    let mut expected = crate::render::tests::Rec::new();
    back_button(&mut expected, PK_BACK_RECT, theme::ACCENT).unwrap();
    text_left(
        &mut expected,
        "Reveal phrase",
        EgPoint::new(58, 22),
        Role::Heading,
        theme::TEXT,
    )
    .unwrap();
    glyph::draw(
        &mut expected,
        Glyph::Warn,
        Point::new(104, 56),
        32,
        theme::WARN,
        BG,
    )
    .unwrap();
    text_left(
        &mut expected,
        "Showing 24 secret words",
        EgPoint::new(16, 118),
        Role::Body,
        theme::WARN,
    )
    .unwrap();
    text_left(
        &mut expected,
        "that restore everything.",
        EgPoint::new(16, 136),
        Role::Body,
        theme::WARN,
    )
    .unwrap();
    text_left(
        &mut expected,
        "Make sure no person or",
        EgPoint::new(16, 160),
        Role::Body,
        MUTED,
    )
    .unwrap();
    text_left(
        &mut expected,
        "camera can see the screen.",
        EgPoint::new(16, 178),
        Role::Body,
        MUTED,
    )
    .unwrap();
    render_hold_button(
        &mut expected,
        DEL_HOLD_RECT,
        "Hold to reveal",
        theme::DANGER_FILL,
    )
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}

#[test]
fn the_seal_gate_draws_its_warning_lines_and_hold_button() {
    let mut actual = crate::render::tests::Rec::new();
    render_seal_confirm(&mut actual).unwrap();
    let mut expected = crate::render::tests::Rec::new();
    back_button(&mut expected, PK_BACK_RECT, theme::ACCENT).unwrap();
    text_left(
        &mut expected,
        "Seal backup",
        EgPoint::new(58, 22),
        Role::Heading,
        theme::TEXT,
    )
    .unwrap();
    glyph::draw(
        &mut expected,
        Glyph::Lock,
        Point::new(104, 56),
        32,
        theme::WARN,
        BG,
    )
    .unwrap();
    text_left(
        &mut expected,
        "Closes the backup window.",
        EgPoint::new(16, 118),
        Role::Body,
        theme::WARN,
    )
    .unwrap();
    text_left(
        &mut expected,
        "You can't show or export the",
        EgPoint::new(16, 142),
        Role::Body,
        MUTED,
    )
    .unwrap();
    text_left(
        &mut expected,
        "phrase again until a reset.",
        EgPoint::new(16, 160),
        Role::Body,
        MUTED,
    )
    .unwrap();
    render_hold_button(
        &mut expected,
        DEL_HOLD_RECT,
        "Hold to seal",
        theme::DANGER_FILL,
    )
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}

#[test]
fn a_share_shows_the_sub_page_page_modulo_its_own_page_count() {
    let words: [&str; 24] = [
        "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
        "juliet", "kilo", "lima", "mike", "november", "oscar", "papa", "quebec", "romeo", "sierra",
        "tango", "uniform", "victor", "whiskey", "xray",
    ];
    let mut actual = crate::render::tests::Rec::new();
    render_slip39_share(&mut actual, &words, 1, 2, 1, 2).unwrap();
    let mut expected = crate::render::tests::Rec::new();
    status_bar(&mut expected).unwrap();
    title_bar(&mut expected, "Share 1/2", theme::ACCENT, true).unwrap();
    word_grid(&mut expected, &words, 1).unwrap();
    render_pager(&mut expected, 1, 2).unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}

#[test]
fn the_format_chooser_lists_both_cards_under_its_heading() {
    let mut actual = crate::render::tests::Rec::new();
    render_backup_format(&mut actual).unwrap();
    let mut expected = crate::render::tests::Rec::new();
    back_button(&mut expected, PK_BACK_RECT, theme::ACCENT).unwrap();
    text_left(
        &mut expected,
        "Choose format",
        EgPoint::new(58, 22),
        Role::Heading,
        theme::TEXT,
    )
    .unwrap();
    choice_card(
        &mut expected,
        FMT_PHRASE_RECT,
        "Single phrase",
        "24 words (BIP-39)",
    )
    .unwrap();
    choice_card(
        &mut expected,
        FMT_SHARES_RECT,
        "Shamir shares",
        "Split T-of-N (SLIP-39)",
    )
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}

#[test]
fn the_backup_screen_draws_its_plate_facts_and_open_window_actions() {
    let v = BackupView {
        sealed: false,
        has_seed: true,
        exportable: true,
        can_reveal: true,
    };
    let mut actual = crate::render::tests::Rec::new();
    render_backup(&mut actual, &v).unwrap();
    let mut expected = crate::render::tests::Rec::new();
    status_bar(&mut expected).unwrap();
    title_bar(&mut expected, "Backup", theme::ACCENT, true).unwrap();
    let plate = Rect::new(14, CONTENT_TOP + 8, PANEL_W - 28, 54);
    crate::aa::rounded_rect(
        &mut expected,
        plate,
        11,
        Some(theme::WARN_BG),
        Some((theme::WARN_BORDER, 1)),
        BG,
    )
    .unwrap();
    glyph::draw(
        &mut expected,
        Glyph::Warn,
        Point::new(plate.x + 12, plate.y + 18),
        18,
        theme::WARN,
        theme::WARN_BG,
    )
    .unwrap();
    let tx = plate.x as i32 + 42;
    let clip = Rect::new(
        tx as u16,
        plate.y,
        (plate.x + plate.w).saturating_sub(6 + tx as u16),
        plate.h,
    );
    text_left_clipped_on(
        &mut expected,
        "Review needed",
        EgPoint::new(tx, plate.y as i32 + 20),
        Role::Strong,
        theme::WARN,
        theme::WARN_BG,
        clip,
    )
    .unwrap();
    text_left_clipped_on(
        &mut expected,
        "Seed export still open.",
        EgPoint::new(tx, plate.y as i32 + 38),
        Role::Body,
        MUTED,
        theme::WARN_BG,
        clip,
    )
    .unwrap();
    text_left(
        &mut expected,
        "RECOVERY SHARES",
        EgPoint::new(14, plate.y as i32 + plate.h as i32 + 14),
        Role::Mono,
        theme::CAPTION,
    )
    .unwrap();
    let row0 = Rect::new(16, 138, PANEL_W - 32, 34);
    let row1 = Rect::new(16, 176, PANEL_W - 32, 34);
    group_panel(
        &mut expected,
        Rect::new(row0.x, row0.y, row0.w, row1.y + row1.h - row0.y),
    )
    .unwrap();
    group_divider(
        &mut expected,
        row0.x,
        row0.w,
        (row0.y + row0.h + row1.y) as i32 / 2,
    )
    .unwrap();
    row_body(
        &mut expected,
        row0,
        Glyph::Lifebuoy,
        "Seed",
        Some(("Present", theme::OK)),
        false,
        false,
    )
    .unwrap();
    row_body(
        &mut expected,
        row1,
        Glyph::Lock,
        "Backup window",
        Some(("Open", theme::WARN)),
        false,
        false,
    )
    .unwrap();
    button(
        &mut expected,
        BACKUP_REVEAL_RECT,
        "Show recovery phrase",
        theme::ACCENT_FILL,
    )
    .unwrap();
    button(
        &mut expected,
        BACKUP_SEAL_RECT,
        "Seal backup",
        theme::KEY_BG,
    )
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}
