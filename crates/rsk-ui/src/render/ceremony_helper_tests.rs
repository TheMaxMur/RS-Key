// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::render::tests::Rec;

#[test]
fn a_direct_one_line_ceremony_plate_has_a_distinct_caption_layout() {
    let mut one = Rec::new();
    let mut two = Rec::new();
    ceremony_plate(
        &mut one,
        Glyph::Key,
        "first",
        "",
        theme::SURFACE,
        theme::BORDER_CARD,
        FG,
    )
    .unwrap();
    ceremony_plate(
        &mut two,
        Glyph::Key,
        "first",
        "second",
        theme::SURFACE,
        theme::BORDER_CARD,
        FG,
    )
    .unwrap();
    assert_ne!(one.px, two.px);
    assert!(!one.oob && !two.oob);
    assert!(one.px.contains(&FG));
    assert!(two.px.contains(&FG));
}

// --- Frame controls (frozen mutation roster) --------------------------------
//
// The expected frames are reconstructed from independent literals, not the
// ceremony constants/call sites the mutants rewrite, so any moved coordinate
// or dropped draw call fails the equality.

/// The frame `confirm` must paint for a prompt, reconstructed from literals.
fn confirm_frame(d: &mut Rec, title: &str, primary: &Label, secondary: &Label) {
    status_bar(d).unwrap();
    glyph::draw(d, Glyph::Shield, Point::new(13, 30), 18, theme::ACCENT, BG).unwrap();
    text_left_ellipsized(
        d,
        title,
        EgPoint::new(39, 39),
        Role::BodyStrong,
        theme::TEXT,
        Rect::new(39, 24, 188, 30),
        false,
    )
    .unwrap();
    if !primary.as_str().is_empty() {
        crate::aa::rounded_rect(d, Rect::new(14, 60, 38, 38), 9, Some(theme::CHIP), None, BG)
            .unwrap();
        glyph::draw(
            d,
            Glyph::Globe,
            Point::new(22, 68),
            22,
            theme::TEXT,
            theme::CHIP,
        )
        .unwrap();
        let clip = Rect::new(63, 60, 163, 38);
        if secondary.as_str().is_empty() {
            text_right_ellipsized(
                d,
                primary.as_str(),
                EgPoint::new(63, 79),
                Role::Strong,
                theme::TEXT,
                clip,
                primary.truncated,
            )
            .unwrap();
        } else {
            text_right_ellipsized(
                d,
                primary.as_str(),
                EgPoint::new(63, 72),
                Role::Strong,
                theme::TEXT,
                clip,
                primary.truncated,
            )
            .unwrap();
            text_left_ellipsized(
                d,
                secondary.as_str(),
                EgPoint::new(63, 88),
                Role::Body,
                theme::GREY,
                clip,
                secondary.truncated,
            )
            .unwrap();
        }
    }
    crate::aa::rounded_rect(
        d,
        Rect::new(14, 108, 212, 46),
        11,
        Some(theme::WARN_BG),
        Some((theme::WARN_BORDER, 1)),
        BG,
    )
    .unwrap();
    glyph::draw(
        d,
        Glyph::Warn,
        Point::new(26, 121),
        16,
        theme::WARN,
        theme::WARN_BG,
    )
    .unwrap();
    text_left_on(
        d,
        "Approve only if you",
        EgPoint::new(52, 124),
        Role::Body,
        theme::WARN,
        theme::WARN_BG,
    )
    .unwrap();
    text_left_on(
        d,
        "started this",
        EgPoint::new(52, 140),
        Role::Body,
        theme::WARN,
        theme::WARN_BG,
    )
    .unwrap();
    outline_button(d, Rect::new(14, 248, 72, 56), "Deny", theme::DENY).unwrap();
    render_hold_button(
        d,
        Rect::new(98, 248, 128, 56),
        "Hold to approve",
        theme::APPROVE,
    )
    .unwrap();
}

#[test]
fn approve_confirm_frame_matches_its_geometry() {
    // A title wider than the band makes the clip load-bearing; the long rp and
    // account force the ellipsized head/suffix paths so their clips matter too.
    let p = ConfirmPrompt::new(
        "Approve an OpenPGP signature request from this device",
        b"login.accounts.google.com.attacker-padded-lookalike.example",
        b"a-very-long-account-name-that-needs-the-head-kept-and-clipped",
    );
    let mut actual = Rec::new();
    confirm(&mut actual, &p).unwrap();
    let mut expected = Rec::new();
    confirm_frame(&mut expected, p.title, &p.primary, &p.secondary);
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

#[test]
fn approve_confirm_without_a_secondary_matches_its_geometry() {
    // The account-absent branch centres the single rp line (service_head's `+ 19`).
    let p = ConfirmPrompt::new("FIDO", b"example.com", b"");
    let mut actual = Rec::new();
    confirm(&mut actual, &p).unwrap();
    let mut expected = Rec::new();
    confirm_frame(&mut expected, p.title, &p.primary, &p.secondary);
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

/// The add-passkey frame `render_add_passkey` must paint, from literals.
fn add_passkey_frame(d: &mut Rec, rp: &Label, account: &Label) {
    status_bar(d).unwrap();
    title_bar(d, "Add passkey", theme::ACCENT, false).unwrap();
    let tile = Rect::new(83, 70, 74, 74);
    crate::aa::rounded_rect(d, tile, 16, None, Some((theme::BORDER_CARD, 2)), BG).unwrap();
    glyph::draw(d, Glyph::Globe, Point::new(101, 88), 38, theme::TEXT, BG).unwrap();
    centered_clipped(
        d,
        rp.as_str(),
        120,
        160,
        Role::Strong,
        theme::TEXT,
        Rect::new(6, 149, 228, 22),
        rp.truncated,
        true,
    )
    .unwrap();
    if !account.as_str().is_empty() {
        centered_clipped(
            d,
            account.as_str(),
            120,
            180,
            Role::Body,
            theme::GREY,
            Rect::new(6, 169, 228, 22),
            account.truncated,
            false,
        )
        .unwrap();
    }
    text(
        d,
        "Save new passkey",
        EgPoint::new(120, 204),
        Role::Body,
        theme::TEXT_2,
    )
    .unwrap();
    text(
        d,
        "for this account?",
        EgPoint::new(120, 220),
        Role::Body,
        theme::TEXT_2,
    )
    .unwrap();
    outline_button(d, Rect::new(14, 248, 72, 56), "Cancel", theme::DENY).unwrap();
    button(d, Rect::new(98, 248, 128, 56), "Save", theme::ACCENT_FILL).unwrap();
}

#[test]
fn ceremony_plate_one_line_branch_matches_its_geometry() {
    // The confirm/approve screens always pass two lines; this pins the single-line
    // branch (its `plate.y + 23` baseline) with a frame equality.
    let mut actual = Rec::new();
    ceremony_plate(
        &mut actual,
        Glyph::Key,
        "first",
        "",
        theme::SURFACE,
        theme::BORDER_CARD,
        FG,
    )
    .unwrap();
    let mut expected = Rec::new();
    crate::aa::rounded_rect(
        &mut expected,
        Rect::new(14, 108, 212, 46),
        11,
        Some(theme::SURFACE),
        Some((theme::BORDER_CARD, 1)),
        BG,
    )
    .unwrap();
    glyph::draw(
        &mut expected,
        Glyph::Key,
        Point::new(26, 121),
        16,
        FG,
        theme::SURFACE,
    )
    .unwrap();
    text_left_on(
        &mut expected,
        "first",
        EgPoint::new(52, 108 + 23),
        Role::Body,
        FG,
        theme::SURFACE,
    )
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

#[test]
fn add_passkey_frame_matches_its_geometry() {
    let rp = Label::clamp_domain(b"login.accounts.google.com.attacker-padded-lookalike.example");
    let account = Label::clamp(b"a-very-long-account-name-that-needs-the-head-kept-and-clipped");
    let mut actual = Rec::new();
    render_add_passkey(&mut actual, &rp, &account).unwrap();
    let mut expected = Rec::new();
    add_passkey_frame(&mut expected, &rp, &account);
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}
