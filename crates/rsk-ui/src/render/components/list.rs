// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! List components: grouped cards with divider-separated rows.
//!
//! These replace the old `group_card` / `row_body` / `row_body_side` pattern in
//! list-style screens (Passkeys, Audit log, Applets). They use the shared
//! `crate::LIST_ROW_H` / `crate::LIST_ROW_GAP` / `crate::row_rect()` geometry so
//! paint and hit-test stay aligned.

use embedded_graphics::{
    Drawable,
    draw_target::{DrawTarget, DrawTargetExt},
    pixelcolor::Rgb565,
    prelude::{Point as EgPoint, Primitive},
    primitives::{Line, PrimitiveStyle},
};

use super::super::{eg_rect, text_left_ellipsized_on, text_right_ellipsized_on};
use crate::font;
use crate::{Glyph, Point, Rect, glyph, theme};

/// Corner radius for list group cards.
const LIST_RADIUS: u32 = super::CARD_RADIUS;

/// Gap kept between a row's (clipped) label and its trailing value / chevron.
const TRAILING_GAP: i32 = 8;

/// Draw one grouped card surface behind list rows 0..n (each at `crate::row_rect(y0, i)`),
/// with hairline dividers at every inter-row gap.
pub fn group_card<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    y0: u16,
    n: u16,
) -> Result<(), D::Error> {
    if n == 0 {
        return Ok(());
    }
    let first = crate::row_rect(y0, 0);
    let last = crate::row_rect(y0, n - 1);
    let span = Rect::new(first.x, first.y, first.w, last.y + last.h - first.y);

    crate::aa::rounded_rect(
        t,
        span,
        LIST_RADIUS,
        Some(theme::ROW_BG),
        Some((theme::BORDER_CARD, 1)),
        theme::BG,
    )?;

    // Hairline dividers at every inter-row gap midpoint.
    for i in 1..n {
        let prev = crate::row_rect(y0, i - 1);
        let curr = crate::row_rect(y0, i);
        let dy = (prev.y + crate::LIST_ROW_H + curr.y) / 2;
        Line::new(
            EgPoint::new(first.x as i32 + 12, dy as i32),
            EgPoint::new((first.x + first.w) as i32 - 12, dy as i32),
        )
        .into_styled(PrimitiveStyle::with_stroke(theme::DIVIDER, 1))
        .draw(t)?;
    }
    Ok(())
}

/// Draw the content of one list row at `crate::row_rect(y0, i)`, above the grouped-card
/// surface. `chip` wraps the leading glyph in a rounded tile (for relying-party rows);
/// `domain` keeps the registrable-domain suffix visible (head-ellipsis) for attacker-chosen
/// rpIds. `marked` forces the ellipsis even when what remains happens to fit — pass
/// [`Label::truncated`](crate::Label::truncated) so a value already clipped to
/// `LABEL_MAX` bytes cannot present itself as whole.
#[allow(clippy::too_many_arguments)]
pub fn row<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    y0: u16,
    i: u16,
    icon: Glyph,
    label: &str,
    trailing: Option<(&str, Rgb565)>,
    chevron: bool,
    chip: bool,
    domain: bool,
    marked: bool,
) -> Result<(), D::Error> {
    let rect = crate::row_rect(y0, i);
    let cy = rect.y as i32 + rect.h as i32 / 2;

    // Optional icon chip (rounded tile behind the glyph for relying-party rows).
    let gx = if chip {
        crate::aa::rounded_rect(
            t,
            Rect::new(rect.x + 3, (cy - 11) as u16, 22, 22),
            6,
            Some(theme::CHIP),
            None,
            theme::ROW_BG,
        )?;
        rect.x + 7
    } else {
        rect.x + 8
    };
    glyph::draw(
        t,
        icon,
        Point::new(gx, (cy - 7) as u16),
        14,
        theme::GREY,
        if chip { theme::CHIP } else { theme::ROW_BG },
    )?;

    // Trailing block: chevron then value, tracking the leftmost x.
    let mut right_x = rect.x as i32 + rect.w as i32 - 8;
    if chevron {
        right_x -= 12;
        glyph::draw(
            t,
            Glyph::Chevron,
            Point::new(right_x as u16, (cy - 6) as u16),
            12,
            theme::MUTED,
            theme::ROW_BG,
        )?;
    }
    let label_x = rect.x as i32 + 28;
    let label_right = if let Some((txt, col)) = trailing {
        let tx = right_x - 4;
        // Keep the label a floor. The trailing is laid out first, so subtracting its
        // full width drove the label clip to zero and the row's *device-owned* label
        // vanished with no marker — a long value (an OpenPGP card-holder name) simply
        // erased the caption beside it. Cap the trailing at half the row and
        // ellipsize it, so both sides always read as themselves (audit run-33).
        let tmax = (rect.w as i32 / 2).max(0);
        let tleft = (tx - tmax).max(label_x);
        let tclip = Rect::new(tleft as u16, rect.y, (tx - tleft).max(0) as u16, rect.h);
        font::right(
            &mut t.clipped(&eg_rect(tclip)),
            txt,
            EgPoint::new(tx, cy),
            font::Role::Body,
            col,
            theme::ROW_BG,
        )?;
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
    let at = EgPoint::new(label_x, cy);
    if domain {
        text_right_ellipsized_on(
            t,
            label,
            at,
            font::Role::Body,
            theme::TEXT,
            theme::ROW_BG,
            clip,
            marked,
        )
    } else {
        text_left_ellipsized_on(
            t,
            label,
            at,
            font::Role::Body,
            theme::TEXT,
            theme::ROW_BG,
            clip,
            marked,
        )
    }
}
