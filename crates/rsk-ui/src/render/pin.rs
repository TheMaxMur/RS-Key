// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The PIN pad: title marquee, masked entry, and the key grid.

use super::*;

/// The built-in-UV PIN pad in the new design language: a lock-marked header with a
/// low-emphasis outlined Cancel, the cyan masked entry, then the 3×4 grid of dark
/// neutral key cards — Del a backspace glyph, OK a solid green check. Each key is
/// painted in the exact [`pin_key_rect`] that [`crate::hit_pin`] maps a tap to, and
/// only masked dots — never the digits — are shown.
/// Vertical centre of the PIN-screen title row (matches the back button + Lock glyph).
const PIN_TITLE_CY: i32 = 20;
/// Gap (px) between the two looped copies of a scrolling (marquee) PIN title.
const PIN_TITLE_GAP: u32 = 28;

/// The PIN-screen title band: the gap between the top-left back button and the top-right
/// Lock glyph, inset a few px so text never touches either. A title that fits is centred
/// here; one too wide scrolls within it ([`render_pin_title`]). Public so the firmware can
/// size + place the off-screen buffer it composites the marquee into for a flicker-free
/// single-transaction blit.
pub const PIN_TITLE_BAND: Rect = Rect::new(
    PIN_CANCEL_RECT.x + PIN_CANCEL_RECT.w + 4,
    6,
    (PANEL_W - 26) - 4 - (PIN_CANCEL_RECT.x + PIN_CANCEL_RECT.w + 4),
    28,
);

/// Whether `title` is too wide for the PIN title band — i.e. it needs the marquee.
pub fn pin_title_overflows(title: &str) -> bool {
    font::width(title, Role::Heading).is_some_and(|w| w > PIN_TITLE_BAND.w as u32)
}

/// Draw the PIN-screen title into its band (clearing it first). A title that fits is
/// centred (static); one that overflows scrolls as a **marquee** — two copies a gap
/// apart, shifted left by `offset` px (mod the loop period) and hard-clipped to the band,
/// so a long title like "OpenPGP Sign PIN" reads in full without ever painting over the
/// back chevron or the Lock glyph. The caller advances `offset` over time to animate it;
/// `offset` is ignored when the title fits. (Same band a static [`pin`] frame uses, so a
/// non-overflowing title looks identical whether or not the caller animates.)
pub fn render_pin_title<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    title: &str,
    offset: u32,
) -> Result<(), D::Error> {
    let band = PIN_TITLE_BAND;
    Rectangle::new(
        EgPoint::new(band.x as i32, band.y as i32),
        Size::new(band.w as u32, band.h as u32),
    )
    .into_styled(PrimitiveStyle::with_fill(BG))
    .draw(t)?;
    let w = font::width(title, Role::Heading).unwrap_or(band.w as u32);
    if w <= band.w as u32 {
        return text(
            t,
            title,
            EgPoint::new(band.x as i32 + band.w as i32 / 2, PIN_TITLE_CY),
            Role::Heading,
            FG,
        );
    }
    // Two copies a `period` apart, clipped to the band, scrolled left by `offset` — when
    // the first slides fully out the second has wrapped in, so the loop is seamless.
    let period = w + PIN_TITLE_GAP;
    let x0 = band.x as i32 - (offset % period) as i32;
    let mut clip = t.clipped(&eg_rect(band));
    font::left(
        &mut clip,
        title,
        EgPoint::new(x0, PIN_TITLE_CY),
        Role::Heading,
        FG,
    )?;
    font::left(
        &mut clip,
        title,
        EgPoint::new(x0 + period as i32, PIN_TITLE_CY),
        Role::Heading,
        FG,
    )
}

pub(super) fn pin<D: DrawTarget<Color = Rgb565>>(t: &mut D, pad: &PinPad) -> Result<(), D::Error> {
    // Custom header (not `render_header`): the Cancel back button keeps its top-left hit
    // rect — clear of the digit grid, so a digit tap can never abandon entry. The title is
    // drawn in the band *between* that button and the Lock — centred if it fits, else a
    // marquee (here at offset 0 = head-first; `collect_pin` animates it) so a wide title
    // like "OpenPGP Sign PIN" can't slide under either.
    let lock_x = PANEL_W - 26;
    render_pin_title(t, pad.title, 0)?;
    glyph::draw(t, Glyph::Lock, Point::new(lock_x, 6), 18, theme::ACCENT)?;
    // Cancel is an outlined back button (not a wide "Cancel" word that would collide
    // with the centred title) in the decline colour, filling its PIN_CANCEL_RECT hit area.
    back_button(t, PIN_CANCEL_RECT, theme::DENY)?;
    // Entry starts masked; the reveal eye (drawn by `masked_entry`) toggles it live.
    masked_entry(t, pad.entered, pad.expected, None)?;
    let mut row = 0;
    while row < PIN_ROWS {
        let mut col = 0;
        while col < PIN_COLS {
            let r = pin_key_rect(col, row);
            match pin_grid_key(col, row) {
                // OK is a solid green key with a white check; Del a backspace glyph on a
                // dark card; the digits are dark cards with a white numeral.
                PinKey::Ok => {
                    key_surface(t, r, ALLOW_FILL, false)?;
                    glyph_centered(t, Glyph::Check, r, 24, FG)?;
                }
                PinKey::Del => {
                    // The design's darker backspace key (#101317), set apart from the
                    // neutral digit cards (#15191F).
                    key_surface(t, r, theme::KEY_DARK, true)?;
                    glyph_centered(t, Glyph::Backspace, r, 24, MUTED)?;
                }
                key => {
                    key_surface(t, r, KEY_FILL, true)?;
                    text(t, key_label(key), center(r), Role::Strong, FG)?;
                }
            }
            col += 1;
        }
        row += 1;
    }
    // The caption strip below the grid: a rejection is danger-coloured (a wrong PIN /
    // mismatch is visible, never a silent re-prompt); an informational hint (tries
    // remaining / choose / re-enter) is muted so it reads as guidance, not an error.
    if let Some(caption) = pad.caption {
        let color = if caption.is_rejection() {
            theme::DANGER
        } else {
            MUTED
        };
        text(
            t,
            pin_caption_text(caption),
            EgPoint::new(MIDX, PANEL_H as i32 - 9),
            Role::Body,
            color,
        )?;
    }
    Ok(())
}

/// The feedback line for a [`PinCaption`]. Wrong-PIN counts index a fixed table so the
/// remaining attempts render with no alloc (the counter never exceeds the retry budget).
fn pin_caption_text(c: PinCaption) -> &'static str {
    const WRONG: [&str; 9] = [
        "Wrong PIN, 0 left",
        "Wrong PIN, 1 left",
        "Wrong PIN, 2 left",
        "Wrong PIN, 3 left",
        "Wrong PIN, 4 left",
        "Wrong PIN, 5 left",
        "Wrong PIN, 6 left",
        "Wrong PIN, 7 left",
        "Wrong PIN, 8 left",
    ];
    // "N tries remaining" up front (the unlock pad), singular at one. Indexed by the live
    // budget, which never exceeds the retry ceiling, so the table needs no alloc.
    const TRIES: [&str; 9] = [
        "0 tries remaining",
        "1 try remaining",
        "2 tries remaining",
        "3 tries remaining",
        "4 tries remaining",
        "5 tries remaining",
        "6 tries remaining",
        "7 tries remaining",
        "8 tries remaining",
    ];
    match c {
        PinCaption::WrongPin { retries_left } => {
            WRONG[(retries_left as usize).min(WRONG.len() - 1)]
        }
        PinCaption::Mismatch => "PINs don't match",
        PinCaption::TriesRemaining { left } => TRIES[(left as usize).min(TRIES.len() - 1)],
        PinCaption::ChoosePin => "Choose a PIN",
        PinCaption::Reenter => "Re-enter to confirm",
        PinCaption::TooWeak => "Too easy to guess",
    }
}

/// Pixels: the entry row's left margin, dot diameter, dot pitch, and vertical centre. The
/// row is left-aligned (not centred) so the reveal eye has a fixed home on the right.
const ENTRY_X0: i32 = 24;
const ENTRY_DIA: u32 = 12;
const ENTRY_STEP: i32 = 16;
const ENTRY_CY: i32 = 60;
/// The most dots/digits the entry row shows before a "+" overflow marker (it fits left of
/// the eye); a longer PIN is still entered and verified in full.
const ENTRY_MAX_SHOWN: usize = 10;

/// The masked entry row plus the reveal (eye) toggle. Masked (`reveal = None`): a filled
/// accent dot per entered digit over `expected` dim placeholder outlines (the design's
/// fixed indicator), so an empty pad already shows how many digits are wanted. Revealed
/// (`reveal = Some(digits)`): the typed digits themselves, so the user can check them
/// before committing. Either way at most [`ENTRY_MAX_SHOWN`] symbols show, then a "+"; the
/// eye is always drawn at [`PIN_EYE_RECT`]. The PIN is only painted while revealed, and
/// only ever lives in the firmware's buffer — `masked_entry` is handed it transiently.
fn masked_entry<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    entered: usize,
    expected: u8,
    reveal: Option<&[u8]>,
) -> Result<(), D::Error> {
    // The reveal toggle, always present at the right of the band.
    glyph_centered(t, Glyph::Eye, PIN_EYE_RECT, 18, theme::FAINT)?;
    if let Some(digits) = reveal {
        // Build "<digits>[+]" in a small buffer (ASCII digits, device-internal → trusted).
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
            t,
            s,
            EgPoint::new(ENTRY_X0, ENTRY_CY),
            Role::Body,
            theme::TEXT_2,
        )?;
        return Ok(());
    }
    // Show outline dots only while below the expected minimum. Once reached,
    // only the entered count matters (no leftover outlines on delete).
    let total = if entered >= expected as usize {
        entered.min(ENTRY_MAX_SHOWN)
    } else {
        (expected as usize).min(ENTRY_MAX_SHOWN)
    };
    for i in 0..total {
        let at = EgPoint::new(
            ENTRY_X0 + i as i32 * ENTRY_STEP,
            ENTRY_CY - ENTRY_DIA as i32 / 2,
        );
        if i < entered {
            crate::aa::filled_circle(t, at, ENTRY_DIA, theme::ACCENT)?;
        } else {
            Circle::new(at, ENTRY_DIA)
                .into_styled(PrimitiveStyle::with_stroke(theme::CAPTION, 1))
                .draw(t)?;
        }
    }
    // A PIN longer than the row marks the extra digits with a "+", so the dot count never
    // reads as the whole PIN (the full PIN is still entered and verified).
    if entered > ENTRY_MAX_SHOWN {
        let mx = ENTRY_X0 + total as i32 * ENTRY_STEP;
        text_left(
            t,
            "+",
            EgPoint::new(mx, ENTRY_CY),
            Role::Body,
            theme::CAPTION,
        )?;
    }
    Ok(())
}

/// Repaint the masked dots (and eye toggle): clear one strip over the entry band
/// — every dot position plus the "+" overflow slot to its right — then redraw.
/// A per-dot clear missed the "+" and dot 10's right tail, so a delete mis-read.
pub fn render_pin_dots<D>(
    target: &mut D,
    entered: usize,
    expected: u8,
    reveal: Option<&[u8]>,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    Rectangle::new(
        EgPoint::new(ENTRY_X0 - 2, ENTRY_CY - ENTRY_DIA as i32 / 2 - 2),
        Size::new(
            (ENTRY_MAX_SHOWN as u32 + 1) * ENTRY_STEP as u32 + 4,
            ENTRY_DIA + 4,
        ),
    )
    .into_styled(PrimitiveStyle::with_fill(BG))
    .draw(target)?;
    masked_entry(target, entered, expected, reveal)
}

/// A static caption for a pad key — no alloc: digits index a fixed table.
fn key_label(k: PinKey) -> &'static str {
    const DIGITS: [&str; 10] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];
    match k {
        PinKey::Digit(n) => DIGITS[(n % 10) as usize],
        PinKey::Del => "Del",
        PinKey::Ok => "OK",
        PinKey::Cancel => "Cancel",
        // Not a grid key — the eye toggle is drawn by `masked_entry`, never labelled here.
        PinKey::Reveal => "",
    }
}
