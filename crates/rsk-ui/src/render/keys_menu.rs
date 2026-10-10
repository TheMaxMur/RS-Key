// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The no-host idle menu pages of the touchless (display-keys) build: paged,
//! read-only label/value listings — applet slot metadata, credential counts,
//! backup state, firmware identity — that the GEEK shows when no USB host has
//! enumerated it for a while. Every page is one frame with fixed bands: a title
//! line (with the in-section page indicator), up to [`KEYS_MENU_ROWS_PER_PAGE`]
//! rows of a left label and a right value, and a gesture-hint foot line. The
//! rows arrive pre-formatted ASCII (the firmware's boundary mapping, like
//! `render_keys_confirm`'s `ConfirmPrompt`), so this module only lays them out,
//! clips an over-wide left label against the value column, and clips an
//! over-wide title against the page indicator (a detail page titles its frame
//! with a device-supplied name). No input geometry lives here — the one-button
//! navigation is the firmware's `keys_menu` module.
//!
//! The band geometry is sized for the 240×135 panel and asserted at compile
//! time below; it shares the panel constants and the horizontal inset with
//! [`super::keys`] so every touchless page speaks one margin.

use embedded_graphics::{
    draw_target::DrawTarget,
    geometry::{Point as EgPoint, Size},
    pixelcolor::Rgb565,
    primitives::Rectangle,
};

use super::keys::{KEYS_H, KEYS_INSET, KEYS_TEXT_W, KEYS_W};
use super::*;

/// Rows per page: the body band between the title and the hint line fits four
/// 13 px text rows at a 19 px pitch with a 2 px gutter on every seam (asserted
/// below) — five would collide with the foot hints on the 135-row panel.
pub const KEYS_MENU_ROWS_PER_PAGE: usize = 4;

/// Title centre row (Heading face, 26 px tall → glyphs span 3..=29).
const TITLE_CY: i32 = 16;
/// First body row centre; each next row steps [`ROW_PITCH`] down.
const ROW0_CY: i32 = 40;
/// Body row pitch (Body face 18 px tall, centred → 1 px air between rows).
const ROW_PITCH: i32 = 19;
/// Gesture-hint centre row (Body face → glyphs end at 126, clear of 135).
const HINT_CY: i32 = 117;

/// Horizontal gap between the left label's clip edge and the right value.
const COL_GAP_PX: i32 = 8;

/// The gesture hint under every menu page — the single-button navigation the
/// firmware's browse loop maps (tap = next page, double = back; a hold enters
/// a level — the settings select, a slot's detail page — which the shared
/// foot line does not claim).
const HINT: &str = "TAP NEXT   DOUBLE BACK";

/// Compile-time geometry sanity for the menu bands: each face's half-height
/// clears the neighbouring band by at least 1 px, and nothing leaves the panel.
const _: () = {
    // Heading ascent 20 + descent 6 → half 13; Body ascent 14 + descent 4 → half 9.
    const HEADING_HALF: i32 = 13;
    const BODY_HALF: i32 = 9;
    assert!(TITLE_CY - HEADING_HALF >= 0, "title leaves the top edge");
    assert!(
        ROW0_CY - BODY_HALF - (TITLE_CY + HEADING_HALF) >= 1,
        "title and first row collide"
    );
    assert!(
        HINT_CY + BODY_HALF <= 134,
        "hint line leaves the 135-row panel"
    );
    assert!(
        HINT_CY
            - BODY_HALF
            - (ROW0_CY + KEYS_MENU_ROWS_PER_PAGE as i32 * ROW_PITCH - ROW_PITCH + BODY_HALF)
            >= 1,
        "last row and hint line collide"
    );
    assert!(KEYS_INSET * 2 < KEYS_W, "inset leaves no text width");
};

/// Slice `total` rows into pages: returns `(start, count)` for 0-based `page`
/// under [`KEYS_MENU_ROWS_PER_PAGE`] rows per page — the single source the
/// caller uses both to page and to paint the "P/N" indicator, so the indicator
/// and the slice can never disagree.
pub fn keys_menu_page_slice(total: usize, page: usize) -> (usize, usize) {
    let pages = total.div_ceil(KEYS_MENU_ROWS_PER_PAGE);
    let page = page.min(pages.saturating_sub(1));
    let start = page * KEYS_MENU_ROWS_PER_PAGE;
    (
        start,
        total.saturating_sub(start).min(KEYS_MENU_ROWS_PER_PAGE),
    )
}

/// Paint one menu page: dark surface, title + page indicator band, up to
/// [`KEYS_MENU_ROWS_PER_PAGE`] label/value rows, gesture hint foot. The title
/// is device-controlled text; the rows arrive pre-sanitized ASCII (the
/// firmware assembled them from applet metadata through the `rsk_*` crates'
/// own name mappers), so no further clamp happens here — an over-wide left
/// label is clipped with a visible `"..."` against the value column instead.
pub fn render_keys_menu_page<D>(
    t: &mut D,
    title: &str,
    page: u16,
    pages: u16,
    rows: &[KeysMenuRow],
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    // Fill the panel explicitly (see `render_keys_status` — the shared panel's
    // bounding box is the touch panel's, and a `clear()` would overrun ours).
    let bg_area = Rectangle::new(EgPoint::zero(), Size::new(KEYS_W.into(), KEYS_H.into()));
    t.fill_solid(&bg_area, BG)?;

    // Title left, page indicator right, same band. The title's clip stops a
    // column gap short of the indicator so a long device-supplied name (a
    // detail page's relying party or slot tag) ellipsizes instead of running
    // under the indicator.
    let mut ind_buf = [0u8; 11];
    let ind = fmt_page_indicator(page, pages, &mut ind_buf);
    let ind_w = font::width(ind, Role::Mono).unwrap_or(0) as u16;
    let title_w = (KEYS_W - 2 * KEYS_INSET).saturating_sub(if ind.is_empty() {
        0
    } else {
        ind_w + COL_GAP_PX as u16
    });
    text_left_ellipsized(
        t,
        title,
        EgPoint::new(i32::from(KEYS_INSET), TITLE_CY),
        Role::Heading,
        FG,
        Rect::new(KEYS_INSET, 0, title_w, KEYS_H),
        false,
    )?;
    if !ind.is_empty() {
        font::right(
            t,
            ind,
            EgPoint::new(i32::from(KEYS_W - KEYS_INSET), TITLE_CY),
            Role::Mono,
            MUTED,
            BG,
        )?;
    }

    // Body rows: the value (right-aligned at the margin) first fixes the left
    // label's budget, then the label is drawn clipped to that column.
    let right_x = i32::from(KEYS_W - KEYS_INSET);
    let body_clip_w = i32::from(KEYS_TEXT_W);
    for (i, row) in rows.iter().enumerate().take(KEYS_MENU_ROWS_PER_PAGE) {
        let cy = ROW0_CY + i as i32 * ROW_PITCH;
        let value_w = font::width(row.right, Role::Mono).unwrap_or(0) as i32;
        if !row.right.is_empty() {
            font::right(
                t,
                row.right,
                EgPoint::new(right_x, cy),
                Role::Mono,
                tone_color(row.tone),
                BG,
            )?;
        }
        // The label's clip ends where the value column (plus the gap) begins;
        // an empty value leaves the label the whole text width.
        let clip_w = if row.right.is_empty() {
            body_clip_w
        } else {
            (right_x - value_w - i32::from(KEYS_INSET) - COL_GAP_PX)
                .max(0)
                .min(body_clip_w)
        } as u16;
        let clip = Rect::new(KEYS_INSET, 0, clip_w, KEYS_H);
        // An emphasised row paints its label in the value's tone (the select
        // cursor), so both columns read as "the current one".
        let label_color = if row.emph { tone_color(row.tone) } else { FG };
        text_left_ellipsized(
            t,
            row.left,
            EgPoint::new(i32::from(KEYS_INSET), cy),
            Role::Body,
            label_color,
            clip,
            false,
        )?;
    }

    text(
        t,
        HINT,
        EgPoint::new(i32::from(KEYS_W) / 2, HINT_CY),
        Role::Body,
        MUTED,
    )
}

/// The value-column colour for a row's `tone`: status tones keep their theme
/// colours, the plain value reads as the secondary text grey.
fn tone_color(tone: Tone) -> Rgb565 {
    match tone {
        Tone::Plain => theme::GREY,
        Tone::Good => theme::SUCCESS,
        Tone::Warn => theme::WARN,
        Tone::Bad => theme::DANGER,
    }
}

/// Format the "P/N" indicator: page is 0-based, shown 1-based; empty when the
/// page count is unknown (0) — callers pass ≥ 1, but a 0 total renders a
/// title-only page rather than a lying indicator.
fn fmt_page_indicator(page: u16, pages: u16, buf: &mut [u8; 11]) -> &str {
    if pages == 0 {
        return "";
    }
    // Both halves are u16-domain, like `render::fmt_u16`'s own buffer: 5 + 1 + 5.
    let mut a = [0u8; 5];
    let ps = fmt_u16(page.saturating_add(1), &mut a);
    let mut b = [0u8; 5];
    let ns = fmt_u16(pages, &mut b);
    let mut i = 0;
    for &c in ps.as_bytes() {
        buf[i] = c;
        i += 1;
    }
    buf[i] = b'/';
    i += 1;
    for &c in ns.as_bytes() {
        buf[i] = c;
        i += 1;
    }
    core::str::from_utf8(&buf[..i]).unwrap_or("?/?")
}

#[cfg(test)]
#[path = "keys_menu_tests.rs"]
mod tests;
