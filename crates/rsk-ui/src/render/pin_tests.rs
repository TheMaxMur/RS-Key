// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::render::tests::Rec;
use embedded_graphics::{
    draw_target::DrawTargetExt,
    geometry::Size,
    prelude::Primitive,
    primitives::{PrimitiveStyle, Rectangle},
};

#[test]
fn direct_key_captions_include_every_non_grid_key() {
    for (key, caption) in [
        (PinKey::Del, "Del"),
        (PinKey::Ok, "OK"),
        (PinKey::Cancel, "Cancel"),
        (PinKey::Reveal, ""),
        (PinKey::Digit(0), "0"),
        (PinKey::Digit(9), "9"),
        (PinKey::Digit(255), "5"),
    ] {
        assert_eq!(key_label(key), caption);
    }
}

/// The band's overflow predicate is strict: a title exactly `band.w` wide still fits (and
/// [`render_pin_title`] centres it). Pins the `>` / `>=` boundary.
#[test]
fn a_title_exactly_the_band_width_fits() {
    // 8 * 'W' (18) + 'O' (14) == PIN_TITLE_BAND.w (158) in the Heading face.
    let title = "WWWWWWWWO";
    assert_eq!(
        font::width(title, Role::Heading).unwrap_or(0),
        PIN_TITLE_BAND.w as u32,
        "fixture must be exactly the band width"
    );
    assert!(
        !pin_title_overflows(title),
        "a title exactly the band width overflows"
    );
}

/// Every caption's text is a fixed literal, and the remaining-tries counter clamps an
/// over-budget value to the last table entry rather than indexing past it.
#[test]
fn pin_caption_text_names_every_variant_and_clamps_the_counter() {
    assert_eq!(
        pin_caption_text(PinCaption::WrongPin { retries_left: 0 }),
        "Wrong PIN, 0 left"
    );
    assert_eq!(
        pin_caption_text(PinCaption::WrongPin { retries_left: 3 }),
        "Wrong PIN, 3 left"
    );
    assert_eq!(
        pin_caption_text(PinCaption::WrongPin { retries_left: 8 }),
        "Wrong PIN, 8 left"
    );
    assert_eq!(pin_caption_text(PinCaption::Mismatch), "PINs don't match");
    assert_eq!(
        pin_caption_text(PinCaption::TriesRemaining { left: 0 }),
        "0 tries remaining"
    );
    assert_eq!(
        pin_caption_text(PinCaption::TriesRemaining { left: 1 }),
        "1 try remaining"
    );
    assert_eq!(
        pin_caption_text(PinCaption::TriesRemaining { left: 7 }),
        "7 tries remaining"
    );
    // Past the table, the clamp keeps the last entry (the index must not run off the end).
    assert_eq!(
        pin_caption_text(PinCaption::TriesRemaining { left: 9 }),
        "8 tries remaining"
    );
    assert_eq!(pin_caption_text(PinCaption::ChoosePin), "Choose a PIN");
    assert_eq!(pin_caption_text(PinCaption::Reenter), "Re-enter to confirm");
    assert_eq!(pin_caption_text(PinCaption::TooWeak), "Too easy to guess");
}

/// A title that fits is centred in the band (its literal centre), not offset.
#[test]
fn a_fitting_pin_title_is_centred_in_the_band() {
    let title = "PIN";
    assert!(!pin_title_overflows(title), "fixture must not overflow");
    let mut actual = Rec::new();
    render_pin_title(&mut actual, title, 0).unwrap();

    let mut expected = Rec::new();
    let band = PIN_TITLE_BAND;
    Rectangle::new(
        EgPoint::new(band.x as i32, band.y as i32),
        Size::new(band.w as u32, band.h as u32),
    )
    .into_styled(PrimitiveStyle::with_fill(BG))
    .draw(&mut expected)
    .unwrap();
    text(
        &mut expected,
        title,
        EgPoint::new(band.x as i32 + band.w as i32 / 2, PIN_TITLE_CY),
        Role::Heading,
        FG,
    )
    .unwrap();

    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

/// An overflowing title marquees: two copies `w + PIN_TITLE_GAP` apart, clipped to the
/// band and scrolled left by the literal `offset % period`. The offset is one period minus
/// ten px so the *second* copy (starting at `band.x + 10`) is the visible one — an
/// off-by-one `period` or a shifted copy then empties the band.
#[test]
fn an_overflowing_pin_title_marquees_at_the_literal_offset() {
    let title = "OpenPGP Sign PIN";
    assert!(pin_title_overflows(title), "fixture must overflow");
    let band = PIN_TITLE_BAND;
    let w = font::width(title, Role::Heading).unwrap_or(band.w as u32);
    let period = w + PIN_TITLE_GAP;
    assert!(period > 10, "period must leave a valid offset");
    let offset = period - 10;
    let mut actual = Rec::new();
    render_pin_title(&mut actual, title, offset).unwrap();

    let mut expected = Rec::new();
    Rectangle::new(
        EgPoint::new(band.x as i32, band.y as i32),
        Size::new(band.w as u32, band.h as u32),
    )
    .into_styled(PrimitiveStyle::with_fill(BG))
    .draw(&mut expected)
    .unwrap();
    let x0 = band.x as i32 - (offset % period) as i32;
    let mut clip = expected.clipped(&eg_rect(band));
    font::left(
        &mut clip,
        title,
        EgPoint::new(x0, PIN_TITLE_CY),
        Role::Heading,
        FG,
        BG,
    )
    .unwrap();
    font::left(
        &mut clip,
        title,
        EgPoint::new(x0 + period as i32, PIN_TITLE_CY),
        Role::Heading,
        FG,
        BG,
    )
    .unwrap();

    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

/// The pad paints the Lock glyph in the top-right header slot (`PANEL_W - 26`); nothing
/// else paints there, so a shifted slot is visible as a changed pixel block.
#[test]
fn pin_paints_the_lock_glyph_in_its_literal_header_slot() {
    let pad = PinPad::new(0);
    let mut actual = Rec::new();
    pin(&mut actual, &pad).unwrap();
    assert!(!actual.oob);

    let mut expected = Rec::new();
    glyph::draw(
        &mut expected,
        Glyph::Lock,
        Point::new(PANEL_W - 26, 6),
        18,
        theme::ACCENT,
        BG,
    )
    .unwrap();

    let slot = Rect::new(PANEL_W - 26, 6, 18, 18);
    for y in slot.y..slot.y + slot.h {
        for x in slot.x..slot.x + slot.w {
            let i = y as usize * PANEL_W as usize + x as usize;
            assert_eq!(actual.px[i], expected.px[i], "lock pixel ({x},{y})");
        }
    }
}

/// The revealed row shows the digits (up to the cap) and a `+` only when there are more
/// than the cap; the marker's increment must keep every shown digit.
#[test]
fn revealed_entry_marks_overflow_with_a_plus() {
    for digits in [&b"1234567890"[..], &b"12345678901"[..]] {
        let mut actual = Rec::new();
        masked_entry(&mut actual, digits.len(), 0, Some(digits)).unwrap();

        let mut expected = Rec::new();
        glyph_centered(
            &mut expected,
            Glyph::Eye,
            PIN_EYE_RECT,
            18,
            theme::FAINT,
            BG,
        )
        .unwrap();
        let shown = digits.len().min(ENTRY_MAX_SHOWN);
        let mut buf = [0u8; ENTRY_MAX_SHOWN + 1];
        buf[..shown].copy_from_slice(&digits[..shown]);
        let mut n = shown;
        if digits.len() > ENTRY_MAX_SHOWN {
            buf[n] = b'+';
            n += 1;
        }
        let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
        text_left(
            &mut expected,
            s,
            EgPoint::new(ENTRY_X0, ENTRY_CY),
            Role::Body,
            theme::TEXT_2,
        )
        .unwrap();

        assert_eq!(actual.px, expected.px, "reveal len {}", digits.len());
        assert!(!actual.oob && !expected.oob);
    }
}

/// The masked row: dim placeholder outlines up to the expected minimum, filled accent
/// dots for what was entered, and a `+` past the shown cap — all at the literal dot
/// geometry.
#[test]
fn masked_entry_dots_and_overflow_match_their_literals() {
    for (entered, expected) in [(4usize, 0u8), (10usize, 0u8)] {
        let mut actual = Rec::new();
        masked_entry(&mut actual, entered, expected, None).unwrap();

        let mut expected_rec = Rec::new();
        glyph_centered(
            &mut expected_rec,
            Glyph::Eye,
            PIN_EYE_RECT,
            18,
            theme::FAINT,
            BG,
        )
        .unwrap();
        let total = (expected as usize).max(entered).min(ENTRY_MAX_SHOWN);
        for i in 0..total {
            let at = EgPoint::new(
                ENTRY_X0 + i as i32 * ENTRY_STEP,
                ENTRY_CY - ENTRY_DIA as i32 / 2,
            );
            if i < entered {
                crate::aa::filled_circle(
                    &mut expected_rec,
                    at,
                    ENTRY_DIA,
                    theme::ACCENT,
                    theme::BG,
                )
                .unwrap();
            } else {
                crate::aa::circle(&mut expected_rec, at, ENTRY_DIA, 1, theme::CAPTION, BG).unwrap();
            }
        }
        if entered > ENTRY_MAX_SHOWN {
            let mx = ENTRY_X0 + total as i32 * ENTRY_STEP;
            text_left(
                &mut expected_rec,
                "+",
                EgPoint::new(mx, ENTRY_CY),
                Role::Body,
                theme::CAPTION,
            )
            .unwrap();
        }

        assert_eq!(actual.px, expected_rec.px, "entered={entered}");
        assert!(!actual.oob && !expected_rec.oob);
    }
}

/// [`render_pin_dots`] must clear exactly the band it owns — from `ENTRY_X0 - 2`, spanning
/// `(ENTRY_MAX_SHOWN + 1) * ENTRY_STEP + 4` px wide and `ENTRY_DIA + 4` tall. Painting a
/// sentinel band underneath makes the clear's edges observable.
#[test]
fn render_pin_dots_clears_exactly_the_entry_band() {
    let top = ENTRY_CY - ENTRY_DIA as i32 / 2 - 2;
    let sentinel = theme::OK;
    let mut d = Rec::new();
    Rectangle::new(EgPoint::new(0, top), Size::new(PANEL_W as u32, 40))
        .into_styled(PrimitiveStyle::with_fill(sentinel))
        .draw(&mut d)
        .unwrap();
    render_pin_dots(&mut d, 4, 0, None).unwrap();
    assert!(!d.oob);

    let at = |x: u16, y: u16| d.px[y as usize * PANEL_W as usize + x as usize];
    let y = ENTRY_CY as u16;
    // The clear's left edge is ENTRY_X0 - 2: that column is wiped, the one left of it not.
    assert_eq!(at((ENTRY_X0 - 2) as u16, y), BG, "left edge not cleared");
    assert_eq!(
        at((ENTRY_X0 - 3) as u16, y),
        sentinel,
        "clear reached left of its origin"
    );
    // The clear spans (ENTRY_MAX_SHOWN + 1) * ENTRY_STEP + 4 px; one past its end survives.
    let last = ENTRY_X0 - 2 + (ENTRY_MAX_SHOWN as i32 + 1) * ENTRY_STEP + 4 - 1;
    assert_eq!(at(last as u16, y), BG, "clear ended short of its width");
    assert_eq!(
        at((last + 1) as u16, y),
        sentinel,
        "clear ran past its width"
    );
    // The clear is ENTRY_DIA + 4 tall: the last row is wiped, 20 px down (outside) is not.
    assert_eq!(at(100, (top + 15) as u16), BG, "band interior not cleared");
    assert_eq!(
        at(100, (top + 20) as u16),
        sentinel,
        "clear ran past its height"
    );
}
