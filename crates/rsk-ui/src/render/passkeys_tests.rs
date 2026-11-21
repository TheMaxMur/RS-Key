// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn the_rename_field_draws_the_value_and_the_underlined_pending_char() {
    let mut actual = crate::render::tests::Rec::new();
    render_rename_field(&mut actual, "abc", Some(b'x')).unwrap();
    let mut expected = crate::render::tests::Rec::new();
    let field = RN_FIELD_RECT;
    let clear = Rect::new(
        field.x.saturating_sub(4),
        field.y.saturating_sub(4),
        field.w + 8,
        field.h + 8,
    );
    Rectangle::new(
        EgPoint::new(clear.x as i32, clear.y as i32),
        Size::new(clear.w as u32, clear.h as u32),
    )
    .into_styled(PrimitiveStyle::with_fill(BG))
    .draw(&mut expected)
    .unwrap();
    crate::aa::rounded_rect(
        &mut expected,
        field,
        8,
        Some(theme::SURFACE),
        Some((theme::BORDER_FIELD, 1)),
        BG,
    )
    .unwrap();
    let pad = 10i32;
    let inner = Rect::new(
        field.x + pad as u16,
        field.y,
        field.w - 2 * pad as u16,
        field.h,
    );
    let baseline = field.y as i32 + field.h as i32 / 2;
    text_left_clipped_on(
        &mut expected,
        "abc",
        EgPoint::new(inner.x as i32, baseline),
        Role::Body,
        FG,
        theme::SURFACE,
        inner,
    )
    .unwrap();
    let text_w = font::width("abc", Role::Body).unwrap_or(0) as i32;
    let cursor_x = (inner.x as i32 + text_w).min(field.x as i32 + field.w as i32 - 12);
    let pw = font::width("x", Role::Body).unwrap_or(0) as i32;
    let px = cursor_x + 4;
    text_left_on(
        &mut expected,
        "x",
        EgPoint::new(px, baseline),
        Role::Body,
        theme::ACCENT,
        theme::SURFACE,
    )
    .unwrap();
    Line::new(
        EgPoint::new(px, baseline + 4),
        EgPoint::new(px + pw, baseline + 4),
    )
    .into_styled(PrimitiveStyle::with_stroke(theme::ACCENT, 2))
    .draw(&mut expected)
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}

#[test]
fn the_rename_field_draws_a_bare_cursor_without_a_pending_char() {
    let mut actual = crate::render::tests::Rec::new();
    render_rename_field(&mut actual, "abc", None).unwrap();
    let mut expected = crate::render::tests::Rec::new();
    let field = RN_FIELD_RECT;
    let clear = Rect::new(
        field.x.saturating_sub(4),
        field.y.saturating_sub(4),
        field.w + 8,
        field.h + 8,
    );
    Rectangle::new(
        EgPoint::new(clear.x as i32, clear.y as i32),
        Size::new(clear.w as u32, clear.h as u32),
    )
    .into_styled(PrimitiveStyle::with_fill(BG))
    .draw(&mut expected)
    .unwrap();
    crate::aa::rounded_rect(
        &mut expected,
        field,
        8,
        Some(theme::SURFACE),
        Some((theme::BORDER_FIELD, 1)),
        BG,
    )
    .unwrap();
    let pad = 10i32;
    let inner = Rect::new(
        field.x + pad as u16,
        field.y,
        field.w - 2 * pad as u16,
        field.h,
    );
    let baseline = field.y as i32 + field.h as i32 / 2;
    text_left_clipped_on(
        &mut expected,
        "abc",
        EgPoint::new(inner.x as i32, baseline),
        Role::Body,
        FG,
        theme::SURFACE,
        inner,
    )
    .unwrap();
    let text_w = font::width("abc", Role::Body).unwrap_or(0) as i32;
    let cursor_x = (inner.x as i32 + text_w).min(field.x as i32 + field.w as i32 - 12);
    Line::new(
        EgPoint::new(cursor_x, field.y as i32 + 7),
        EgPoint::new(cursor_x, field.y as i32 + field.h as i32 - 7),
    )
    .into_styled(PrimitiveStyle::with_stroke(theme::ACCENT, 1))
    .draw(&mut expected)
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}

#[test]
fn the_confirm_delete_screen_names_the_relying_party_and_account() {
    let rp = Label::clamp(&[b'a'; 60]);
    let account = Label::clamp(&[b'b'; 60]);
    let mut actual = crate::render::tests::Rec::new();
    render_confirm_delete(&mut actual, &rp, &account).unwrap();
    let mut expected = crate::render::tests::Rec::new();
    back_button(&mut expected, PK_BACK_RECT, theme::DENY).unwrap();
    text_left(
        &mut expected,
        "Delete passkey",
        EgPoint::new(58, 22),
        Role::Heading,
        theme::DENY,
    )
    .unwrap();
    let card = Rect::new(14, 54, PANEL_W - 28, 46);
    crate::aa::rounded_rect(&mut expected, card, 8, Some(theme::ROW_BG), None, BG).unwrap();
    glyph::draw(
        &mut expected,
        Glyph::Globe,
        Point::new(card.x + 10, card.y + 13),
        20,
        theme::MUTED,
        theme::ROW_BG,
    )
    .unwrap();
    let tx = card.x as i32 + 40;
    let clip = Rect::new(tx as u16, card.y, (card.x + card.w) - tx as u16, card.h);
    text_right_ellipsized_on(
        &mut expected,
        rp.as_str(),
        EgPoint::new(tx, card.y as i32 + 16),
        Role::Body,
        theme::TEXT,
        theme::ROW_BG,
        clip,
        rp.truncated,
    )
    .unwrap();
    text_left_ellipsized_on(
        &mut expected,
        account.as_str(),
        EgPoint::new(tx, card.y as i32 + 32),
        Role::Body,
        theme::MUTED,
        theme::ROW_BG,
        clip,
        account.truncated,
    )
    .unwrap();
    for (line, y) in [
        ("This removes the passkey", 124),
        ("from RS-Key. The site may", 142),
        ("still expect it.", 160),
    ] {
        text_left(
            &mut expected,
            line,
            EgPoint::new(16, y),
            Role::Body,
            theme::WARN,
        )
        .unwrap();
    }
    render_hold_button(
        &mut expected,
        DEL_HOLD_RECT,
        "Hold to delete",
        theme::DANGER_FILL,
    )
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}

#[test]
fn the_rename_field_erases_a_longer_previous_value_and_clips_a_long_one() {
    let long = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP";
    let prefill = |e: &mut crate::render::tests::Rec| {
        Rectangle::new(
            EgPoint::new((RN_FIELD_RECT.x - 8) as i32, (RN_FIELD_RECT.y - 8) as i32),
            Size::new((RN_FIELD_RECT.w + 16) as u32, (RN_FIELD_RECT.h + 16) as u32),
        )
        .into_styled(PrimitiveStyle::with_fill(theme::CAPTION))
        .draw(e)
        .unwrap();
    };
    let mut actual = crate::render::tests::Rec::new();
    prefill(&mut actual);
    render_rename_field(&mut actual, long, None).unwrap();

    let mut expected = crate::render::tests::Rec::new();
    prefill(&mut expected);
    let field = RN_FIELD_RECT;
    let clear = Rect::new(
        field.x.saturating_sub(4),
        field.y.saturating_sub(4),
        field.w + 8,
        field.h + 8,
    );
    Rectangle::new(
        EgPoint::new(clear.x as i32, clear.y as i32),
        Size::new(clear.w as u32, clear.h as u32),
    )
    .into_styled(PrimitiveStyle::with_fill(BG))
    .draw(&mut expected)
    .unwrap();
    crate::aa::rounded_rect(
        &mut expected,
        field,
        8,
        Some(theme::SURFACE),
        Some((theme::BORDER_FIELD, 1)),
        BG,
    )
    .unwrap();
    let pad = 10i32;
    let inner = Rect::new(
        field.x + pad as u16,
        field.y,
        field.w - 2 * pad as u16,
        field.h,
    );
    let baseline = field.y as i32 + field.h as i32 / 2;
    text_left_clipped_on(
        &mut expected,
        long,
        EgPoint::new(inner.x as i32, baseline),
        Role::Body,
        FG,
        theme::SURFACE,
        inner,
    )
    .unwrap();
    let text_w = font::width(long, Role::Body).unwrap_or(0) as i32;
    let cursor_x = (inner.x as i32 + text_w).min(field.x as i32 + field.w as i32 - 12);
    Line::new(
        EgPoint::new(cursor_x, field.y as i32 + 7),
        EgPoint::new(cursor_x, field.y as i32 + field.h as i32 - 7),
    )
    .into_styled(PrimitiveStyle::with_stroke(theme::ACCENT, 1))
    .draw(&mut expected)
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}

#[test]
fn the_rename_chrome_places_its_caption_above_the_field() {
    let mut actual = crate::render::tests::Rec::new();
    render_rename_chrome(&mut actual).unwrap();
    let mut expected = crate::render::tests::Rec::new();
    status_bar(&mut expected).unwrap();
    title_bar(&mut expected, "Rename", theme::ACCENT, true).unwrap();
    text_left(
        &mut expected,
        "NICKNAME",
        EgPoint::new(14, RN_FIELD_RECT.y as i32 - 10),
        Role::Mono,
        theme::CAPTION,
    )
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}

#[test]
fn the_keypad_paints_every_key_with_the_active_group_highlighted() {
    let mut actual = crate::render::tests::Rec::new();
    render_rename_keys(&mut actual, Some(4)).unwrap();
    let mut expected = crate::render::tests::Rec::new();
    for row in 0..4u16 {
        for col in 0..3u16 {
            let r = t9_key_rect(row, col);
            match (row, col) {
                (3, 0) => {
                    key_surface(&mut expected, r, theme::KEY_DARK, true).unwrap();
                    glyph_centered(
                        &mut expected,
                        Glyph::Backspace,
                        r,
                        20,
                        MUTED,
                        theme::KEY_DARK,
                    )
                    .unwrap();
                }
                (3, 2) => {
                    crate::aa::rounded_rect(
                        &mut expected,
                        r,
                        KEY_RADIUS,
                        Some(ALLOW_FILL),
                        None,
                        BG,
                    )
                    .unwrap();
                    text_on(
                        &mut expected,
                        "Save",
                        center(r),
                        Role::Strong,
                        FG,
                        ALLOW_FILL,
                    )
                    .unwrap();
                }
                _ => {
                    let idx = if row < 3 { (row * 3 + col) as usize } else { 9 };
                    let is_active = Some(4) == Some(idx);
                    let fill = if is_active {
                        theme::ACCENT_FILL
                    } else {
                        KEY_FILL
                    };
                    key_surface(&mut expected, r, fill, !is_active).unwrap();
                    let color = if is_active { FG } else { theme::TEXT };
                    let (digit, letters) = T9_KEY_LABELS[idx];
                    let cx = r.x as i32 + r.w as i32 / 2;
                    text_on(
                        &mut expected,
                        digit,
                        EgPoint::new(cx, r.y as i32 + 14),
                        Role::Strong,
                        color,
                        fill,
                    )
                    .unwrap();
                    text_on(
                        &mut expected,
                        letters,
                        EgPoint::new(cx, r.y as i32 + 32),
                        Role::MonoSmall,
                        color,
                        fill,
                    )
                    .unwrap();
                }
            }
        }
    }
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}

#[test]
fn the_empty_passkeys_body_draws_its_glyph_and_hint() {
    let mut actual = crate::render::tests::Rec::new();
    passkeys_body(&mut actual, &[], 0, 0).unwrap();
    let mut expected = crate::render::tests::Rec::new();
    glyph::draw(
        &mut expected,
        Glyph::Key,
        Point::new(MIDX as u16 - 18, 96),
        36,
        MUTED,
        BG,
    )
    .unwrap();
    text(
        &mut expected,
        "No passkeys yet",
        EgPoint::new(MIDX, 160),
        Role::Body,
        MUTED,
    )
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}

#[test]
fn a_row_with_several_accounts_carries_their_count_and_a_single_one_does_not() {
    let row = |accounts: u8| RpRow {
        id: Label::clamp(b"example.com"),
        nick: Label::default(),
        accounts,
    };
    for (accounts, want) in [(2u8, Some("2")), (1, None)] {
        let mut actual = crate::render::tests::Rec::new();
        passkey_row(&mut actual, 0, &row(accounts)).unwrap();
        let mut expected = crate::render::tests::Rec::new();
        let mut buf = [0u8; 5];
        let trailing = want.map(|w| (w, MUTED));
        let _ = &mut buf;
        components::list::row(
            &mut expected,
            PK_LIST_TOP,
            0,
            service_glyph("example.com"),
            "example.com",
            trailing,
            true,
            true,
            true,
            false,
        )
        .unwrap();
        assert_eq!(actual.px, expected.px, "accounts {accounts}");
        assert!(!actual.oob);
    }
}

#[test]
fn an_account_row_offers_uv_only_when_the_credential_is_protected() {
    let account = AccountRow {
        name: Label::clamp(b"user"),
        protected: true,
    };
    let mut actual = crate::render::tests::Rec::new();
    account_row(&mut actual, 0, &account).unwrap();
    let mut expected = crate::render::tests::Rec::new();
    components::list::row(
        &mut expected,
        PK_LIST_TOP,
        0,
        Glyph::Key,
        "user",
        Some(("UV", theme::ACCENT)),
        false,
        true,
        false,
        false,
    )
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}

#[test]
fn the_service_screen_places_its_edit_glyph_and_paged_body() {
    let title = Label::clamp(b"example.com");
    let accounts = [AccountRow {
        name: Label::clamp(b"user"),
        protected: false,
    }];
    let mut actual = crate::render::tests::Rec::new();
    render_service(&mut actual, &title, false, &accounts, 0, 1).unwrap();
    let mut expected = crate::render::tests::Rec::new();
    status_bar(&mut expected).unwrap();
    title_bar(&mut expected, "example.com", theme::ACCENT, true).unwrap();
    let er = TITLE_EDIT_RECT;
    glyph::draw(
        &mut expected,
        Glyph::Edit,
        Point::new(er.x + er.w - 18 - 4, er.y + er.h / 2 - 9),
        18,
        theme::ACCENT,
        BG,
    )
    .unwrap();
    components::list::group_card(&mut expected, PK_LIST_TOP, 1).unwrap();
    account_row(&mut expected, 0, &accounts[0]).unwrap();
    list_tail(&mut expected, 0, 1, "account", "accounts").unwrap();
    render_nav(&mut expected, NavTab::Passkeys).unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}
