// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Reusable UI components with consistent spacing.

#![allow(dead_code)]

pub mod list;

use embedded_graphics::{
    draw_target::{DrawTarget, DrawTargetExt},
    pixelcolor::Rgb565,
    prelude::Point as EgPoint,
};

use super::{eg_rect, text, text_left_ellipsized_on, text_left_on, text_on};
use crate::{Glyph, PANEL_W, Point, Rect, font, glyph, theme};

/// Horizontal screen margin (both sides).
pub const MARGIN: u16 = 6;
/// Internal card padding.
pub const PAD: u16 = 12;
/// Standard row height inside cards.
pub const ROW_H: u16 = 44;
/// Gap between card rows.
pub const ROW_GAP: u16 = 4;
/// Card corner radius.
pub const CARD_RADIUS: u32 = 10;

/// Draw a full-width rounded card surface.
pub fn card<D: DrawTarget<Color = Rgb565>>(t: &mut D, y: u16, h: u16) -> Result<(), D::Error> {
    crate::aa::rounded_rect(
        t,
        Rect::new(MARGIN, y, PANEL_W - 2 * MARGIN, h),
        CARD_RADIUS,
        Some(theme::SURFACE),
        None,
        theme::BG,
    )
}

/// A card title row: icon + heading text, left-aligned.
pub fn card_title<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    card_y: u16,
    icon: Glyph,
    label: &str,
) -> Result<(), D::Error> {
    let y = card_y + PAD;
    glyph::draw(
        t,
        icon,
        Point::new(MARGIN + PAD, y),
        28,
        theme::ACCENT,
        theme::SURFACE,
    )?;
    text_left_on(
        t,
        label,
        EgPoint::new((MARGIN + PAD + 28 + 8) as i32, y as i32 + 20),
        font::Role::Heading,
        theme::TEXT,
        theme::SURFACE,
    )
}

/// A card content row: icon + label + optional right-aligned value.
pub fn card_row<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    card_y: u16,
    row_idx: u16,
    icon: Glyph,
    label: &str,
    value: Option<(&str, Rgb565)>,
) -> Result<(), D::Error> {
    let y = card_y + PAD + ROW_H + row_idx * (ROW_H + ROW_GAP);
    let x = MARGIN + PAD;
    glyph::draw(t, icon, Point::new(x, y), 22, theme::MUTED, theme::SURFACE)?;
    text_left_on(
        t,
        label,
        EgPoint::new((x + 22 + 8) as i32, y as i32 + 16),
        font::Role::Body,
        theme::TEXT,
        theme::SURFACE,
    )?;
    if let Some((val, color)) = value {
        let w = font::width(val, font::Role::Body).unwrap_or(0) as i32;
        text_on(
            t,
            val,
            EgPoint::new((PANEL_W - MARGIN - PAD) as i32 - w, y as i32 + 16),
            font::Role::Body,
            color,
            theme::SURFACE,
        )?;
    }
    Ok(())
}

/// Draw a rounded card surface at an arbitrary `rect` (for settings rows and other
/// screens that use non-standard geometry).
pub fn rect_card<D: DrawTarget<Color = Rgb565>>(t: &mut D, rect: Rect) -> Result<(), D::Error> {
    crate::aa::rounded_rect(
        t,
        rect,
        CARD_RADIUS,
        Some(theme::ROW_BG),
        Some((theme::BORDER_CARD, 1)),
        theme::BG,
    )
}

/// Total height of a card with `rows` rows (including title row if present).
#[allow(dead_code)]
pub fn card_h(has_title: bool, rows: u16) -> u16 {
    let title = if has_title { ROW_H } else { 0 };
    PAD + title + rows * ROW_H + rows.saturating_sub(1) * ROW_GAP + PAD
}

/// A card row with a right chevron (for drill-in navigation).
pub fn card_row_chevron<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    card_y: u16,
    row_idx: u16,
    icon: Glyph,
    label: &str,
    value: Option<(&str, Rgb565)>,
) -> Result<(), D::Error> {
    card_row(t, card_y, row_idx, icon, label, value)?;
    let y = card_y + PAD + ROW_H + row_idx * (ROW_H + ROW_GAP);
    glyph::draw(
        t,
        Glyph::Chevron,
        Point::new(PANEL_W - MARGIN - PAD - 14, y + (ROW_H - 14) / 2),
        14,
        theme::MUTED,
        theme::SURFACE,
    )?;
    Ok(())
}

/// A single content row at an arbitrary `rect` (for settings and other screens
/// with non-standard geometry).
#[allow(clippy::too_many_arguments)]
pub fn rect_row<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    rect: Rect,
    icon: Glyph,
    label: &str,
    trailing: Option<(&str, Rgb565)>,
    chevron: bool,
) -> Result<(), D::Error> {
    let cy = rect.y as i32 + rect.h as i32 / 2;
    let gx = rect.x + 8;
    glyph::draw(
        t,
        icon,
        Point::new(gx, (cy - 7) as u16),
        14,
        theme::GREY,
        theme::ROW_BG,
    )?;
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
        font::right(
            &mut t.clipped(&eg_rect(Rect::new(
                label_x as u16,
                rect.y,
                (tx - label_x).max(0) as u16,
                rect.h,
            ))),
            txt,
            EgPoint::new(tx, cy),
            font::Role::Body,
            col,
            theme::ROW_BG,
        )?;
        tx - font::width(txt, font::Role::Body).unwrap_or(0) as i32 - 8
    } else {
        right_x - 8
    };
    let clip = Rect::new(
        label_x as u16,
        rect.y,
        (label_right - label_x).max(0) as u16,
        rect.h,
    );
    text_left_ellipsized_on(
        t,
        label,
        EgPoint::new(label_x, cy),
        font::Role::Body,
        theme::TEXT,
        theme::ROW_BG,
        clip,
        false,
    )
}

/// Centered empty-state message: large icon + body text.
pub fn empty_state<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    card_y: u16,
    card_h: u16,
    icon: Glyph,
    label: &str,
) -> Result<(), D::Error> {
    let cy = card_y + card_h / 2;
    glyph::draw(
        t,
        icon,
        Point::new((crate::PANEL_W as i32 / 2) as u16 - 18, cy - 30),
        36,
        theme::MUTED,
        theme::BG,
    )?;
    text(
        t,
        label,
        EgPoint::new(crate::PANEL_W as i32 / 2, cy as i32 + 8),
        font::Role::Body,
        theme::MUTED,
    )
}
