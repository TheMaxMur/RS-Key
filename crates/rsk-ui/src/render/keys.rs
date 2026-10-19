// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Touchless (physical-button) screens: the ambient status wash and the one-key
//! confirm page.
//!
//! These paint the `display-keys` boards' 240×135 landscape panel (the Waveshare
//! RP2350-GEEK's 1.14" ST7789). Every `KEYS_*` layout value lives here and is
//! deliberately independent of the 240×320 touch-flow geometry ([`crate::PANEL_W`]
//! / [`crate::PANEL_H`]): the touch screens never run on a keys build, so sharing
//! the constants would couple two forms that must not share a panel size. The
//! anti-phishing contract is the same as the touch confirm's — the relying party
//! is rendered verbatim (head-truncated with a forced marker when clamped) on the
//! same screen the button approves.

use super::*;

/// Touchless panel width in pixels (matches the GEEK's ST7789 row count).
pub const KEYS_W: u16 = 240;
/// Touchless panel height in pixels (the GEEK's 135-row landscape panel).
pub const KEYS_H: u16 = 135;

/// Horizontal inset for every text line; the text clip spans `KEYS_INSET` to
/// `KEYS_W - KEYS_INSET`, so no line can touch the panel edges.
const KEYS_INSET: u16 = 12;
const KEYS_TEXT_W: u16 = KEYS_W - 2 * KEYS_INSET;

/// Vertical centres of the confirm page's lines, top to bottom. The hint lines
/// carry the one-button gestures the wait maps: press approves, a hold denies.
const KEYS_TITLE_CY: u16 = 26;
const KEYS_RP_CY: u16 = 62;
const KEYS_ACCOUNT_CY: u16 = 82;
const KEYS_HINT_CY: u16 = 112;
const KEYS_HINT_ALT_CY: u16 = 126;

/// Compile-time geometry sanity: every text line centre leaves room above and
/// below for its face, and the lines do not collide (title band vs subject band
/// vs the two hint lines).
const _: () = {
    assert!(KEYS_H >= 135, "keys geometry is tuned for a 135-row panel");
    assert!(KEYS_TITLE_CY > 13, "no room above the title face");
    assert!(
        KEYS_RP_CY - KEYS_TITLE_CY >= 22,
        "title and subject lines collide"
    );
    assert!(
        KEYS_ACCOUNT_CY - KEYS_RP_CY >= 16,
        "subject and account lines collide"
    );
    assert!(
        KEYS_HINT_CY - KEYS_ACCOUNT_CY >= 24,
        "subject and hint lines collide"
    );
    assert!(
        KEYS_H - KEYS_HINT_ALT_CY >= 8,
        "no room below the second hint line"
    );
};

/// The press hint — the single button's approve gesture, shown on every confirm.
const HINT_PRESS: &str = "PRESS TO CONFIRM";
/// The hold hint — the single button's decline gesture.
const HINT_HOLD: &str = "HOLD TO DENY";

/// The status colour, glyph and word for one state (the phase-0 face; the
/// animated page breathes or spins it).
fn status_face(kind: StatusKind) -> (Rgb565, Glyph, &'static str) {
    match kind {
        StatusKind::Idle => (theme::SUCCESS, Glyph::CheckCircle, "READY"),
        StatusKind::Processing => (theme::ACCENT, Glyph::Rotate, "WORKING"),
        StatusKind::Touch => (theme::ACCENT, Glyph::Shield, "CONFIRM"),
        StatusKind::Boot => (theme::WARN, Glyph::Usb, "STARTING"),
    }
}

/// One centred row on the dark surface — leading glyph, gap, then the word,
/// vertically centred on the panel's midline (KEYS_H is odd, so the centre row
/// is 67). Shared by the ambient status, the approve/decline feedback and any
/// future keys page, so the whole touchless UI speaks one layout. The panel is
/// filled explicitly: the shared `Panel`'s bounding box is the touch panel's
/// 240×320, and a `clear()` would paint 185 rows past this panel.
fn centred_row<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    glyph: Glyph,
    color: Rgb565,
    label: &str,
) -> Result<(), D::Error> {
    let area = Rectangle::new(EgPoint::zero(), Size::new(KEYS_W.into(), KEYS_H.into()));
    t.fill_solid(&area, BG)?;
    let (x0, word_x) = row_slots(label);
    let glyph_rect = Rect::new(x0, 0, ROW_GLYPH_PX, KEYS_H);
    glyph_centered(t, glyph, glyph_rect, ROW_GLYPH_PX, color, BG)?;
    font::left(
        t,
        label,
        EgPoint::new(i32::from(word_x), KEYS_MID_Y),
        Role::Ready,
        color,
        BG,
    )
}

/// Row layout shared by every keys page: a glyph slot then the word, the whole
/// row centred on the panel (KEYS_H is odd — the centre row is 67).
const ROW_GLYPH_PX: u16 = 32;
const ROW_GAP_PX: u16 = 10;
const KEYS_MID_Y: i32 = KEYS_H as i32 / 2;

/// The horizontal slot positions for one row: `x0` is the glyph slot's left
/// edge, `word_x` the word's left edge.
fn row_slots(label: &str) -> (u16, u16) {
    let word_w = font::width(label, Role::Ready).unwrap_or(0);
    let total = u32::from(ROW_GLYPH_PX) + u32::from(ROW_GAP_PX) + word_w;
    let x0 = (i32::from(KEYS_W) - total as i32) / 2;
    (
        x0.max(0) as u16,
        (x0 + i32::from(ROW_GLYPH_PX) + i32::from(ROW_GAP_PX)).max(0) as u16,
    )
}

/// One breathe ramp (triangle 1.0 → dimmest → 1.0 over the dark surface) in
/// 4-bit coverages, 16 phases of a single step each — a finer ramp than the
/// touch build's 8-phase one because this glyph is large and adjacent 2-step
/// shades read as steps on the small panel. The caller steps `phase` on a
/// timer; `ramp[0]` is the full colour, so phase 0 equals the static face.
const BREATHE_RAMP: [u8; 16] = [15, 14, 13, 12, 11, 10, 9, 8, 7, 8, 9, 10, 11, 12, 13, 14];

/// The colour at breathe `phase` — `base` lit over the panel background.
pub(crate) fn breathe_color(base: Rgb565, phase: u32) -> Rgb565 {
    crate::aa::blend_coverage(base, BG, BREATHE_RAMP[(phase % 16) as usize])
}

/// The animated status page — the touchless build's stand-in for the status
/// LED. Working and Ready breathe their bare word — no leading icon, so the
/// breathed colour is all the aliveness there is (and a tick on Ready could
/// read as "just approved something"); Starting breathes its glyph and word;
/// Awaiting-touch is a static shield. Phase 0 equals the static layout, so
/// callers that never animate get a fixed frame.
pub fn render_keys_status_phase<D>(t: &mut D, kind: StatusKind, phase: u32) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let area = Rectangle::new(EgPoint::zero(), Size::new(KEYS_W.into(), KEYS_H.into()));
    t.fill_solid(&area, BG)?;
    let (base, glyph, label) = status_face(kind);
    let (x0, word_x) = row_slots(label);
    match kind {
        // Working/Ready are the bare word breathing (no leading icon): a
        // breathed colour reads as alive even while a single RSA candidate
        // occupies the core for seconds with no hook firing — and nothing
        // could look stuck mid-gesture.
        StatusKind::Processing | StatusKind::Idle => {
            let c = breathe_color(base, phase);
            font::centered(
                t,
                label,
                EgPoint::new(KEYS_W as i32 / 2, KEYS_MID_Y),
                Role::Ready,
                c,
                BG,
            )?;
        }
        StatusKind::Boot => {
            let c = breathe_color(base, phase);
            paint_slot_glyph(t, x0, glyph, c)?;
            font::left(
                t,
                label,
                EgPoint::new(i32::from(word_x), KEYS_MID_Y),
                Role::Ready,
                c,
                BG,
            )?;
        }
        StatusKind::Touch => {
            paint_slot_glyph(t, x0, glyph, base)?;
            font::left(
                t,
                label,
                EgPoint::new(i32::from(word_x), KEYS_MID_Y),
                Role::Ready,
                base,
                BG,
            )?;
        }
    }
    Ok(())
}

/// Paint a glyph centred in the row's leading slot at `x0`.
fn paint_slot_glyph<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    x0: u16,
    glyph: Glyph,
    color: Rgb565,
) -> Result<(), D::Error> {
    let rect = Rect::new(x0, 0, ROW_GLYPH_PX, KEYS_H);
    glyph_centered(t, glyph, rect, ROW_GLYPH_PX, color, BG)
}

/// The ambient status page at breathe/arc phase 0 — a fixed frame for callers
/// that repaint on state change only.
pub fn render_keys_status<D>(t: &mut D, kind: StatusKind) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    render_keys_status_phase(t, kind, 0)
}

/// The boot-time storage-check page: the one-shot hardening lap (a full GC
/// scrub after a re-keyed OpenPGP PIN) takes ~30 s on a cold boot, and the
/// screen build shows this instead of a black panel. A static face in the
/// working-page's ink — the caller holds the thread executor for the whole
/// lap, so nothing animates it — and, like Working/Ready, the bare word with
/// no leading icon: every status word speaks one layout.
pub fn render_keys_checking<D>(t: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let area = Rectangle::new(EgPoint::zero(), Size::new(KEYS_W.into(), KEYS_H.into()));
    t.fill_solid(&area, BG)?;
    font::centered(
        t,
        "CHECKING",
        EgPoint::new(KEYS_W as i32 / 2, KEYS_MID_Y),
        Role::Ready,
        theme::ACCENT,
        BG,
    )
}

/// Animation steps repaint only their own region, never the whole panel — a
/// full-frame rewrite mid-scan tears visibly on the small panel, while an
/// in-place recolour of a bounded area does not (the touch build's spinner and
/// breathe work the same way). The glyph/word paints carry the background
/// colour, so a same-spot repaint fully overwrites its own ink; no clear needed.
/// The caller paints the full frame first ([`render_keys_status`]), then steps
/// these on the timer. Step one animated state in place at breathe `phase`:
/// recolour the bare breathing word (Working/Ready) or the leading glyph and
/// word (Starting). Awaiting-touch never animates (a ceremony paints over it),
/// so it needs no step.
pub fn render_keys_status_step<D>(t: &mut D, kind: StatusKind, phase: u32) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let (base, glyph, label) = status_face(kind);
    let c = breathe_color(base, phase);
    let (x0, word_x) = row_slots(label);
    match kind {
        StatusKind::Processing | StatusKind::Idle => font::centered(
            t,
            label,
            EgPoint::new(KEYS_W as i32 / 2, KEYS_MID_Y),
            Role::Ready,
            c,
            BG,
        ),
        StatusKind::Boot => {
            paint_slot_glyph(t, x0, glyph, c)?;
            font::left(
                t,
                label,
                EgPoint::new(i32::from(word_x), KEYS_MID_Y),
                Role::Ready,
                c,
                BG,
            )
        }
        StatusKind::Touch => Ok(()),
    }
}

/// The brief approve/decline feedback page shown after a button gesture decides
/// a confirm, so the outcome is readable on the panel before the ambient wash
/// returns (the touch build's "Approved" pop is the same idea). One centred row
/// on the dark surface the confirm page shares — glyph then word, same colour —
/// green APPROVED / red DECLINED.
pub fn render_keys_decision<D>(t: &mut D, approved: bool) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let (color, glyph, label) = if approved {
        (theme::SUCCESS, Glyph::Check, "APPROVED")
    } else {
        (theme::DANGER, Glyph::Warn, "DECLINED")
    };
    centred_row(t, glyph, color, label)
}

/// Paint the one-key confirm page: the device-controlled operation title, the
/// sanitized relying-party fields, and the gesture hints. There are no Allow/Deny
/// buttons — the single physical button approves on press and declines on hold —
/// so the page is text only, sized for the 135-row panel.
pub fn render_keys_confirm<D>(t: &mut D, prompt: &ConfirmPrompt) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    // Fill the panel explicitly (see `render_keys_status` — the shared panel's
    // bounding box is the touch panel's, and a `clear()` would overrun ours).
    let bg_area = Rectangle::new(EgPoint::zero(), Size::new(KEYS_W.into(), KEYS_H.into()));
    t.fill_solid(&bg_area, BG)?;
    // Title: trusted, device-controlled operation name (never rp text).
    let clip = Rect::new(KEYS_INSET, 0, KEYS_TEXT_W, KEYS_H);
    text(
        t,
        prompt.title,
        EgPoint::new(KEYS_W as i32 / 2, KEYS_TITLE_CY as i32),
        Role::Heading,
        FG,
    )?;
    // The relying-party id keeps its registrable suffix (head-truncated with the
    // marker forced when the upstream clamp already cut it) — the same
    // anti-phishing rule the touch confirm's plate follows.
    text_right_ellipsized(
        t,
        prompt.primary.as_str(),
        EgPoint::new(KEYS_INSET as i32, KEYS_RP_CY as i32),
        Role::BodyStrong,
        FG,
        clip,
        prompt.primary.truncated,
    )?;
    if !prompt.secondary.as_str().is_empty() {
        text_left_ellipsized(
            t,
            prompt.secondary.as_str(),
            EgPoint::new(KEYS_INSET as i32, KEYS_ACCOUNT_CY as i32),
            Role::Body,
            theme::GREY,
            clip,
            prompt.secondary.truncated,
        )?;
    }
    // Gesture hints at the foot of the page.
    text(
        t,
        HINT_PRESS,
        EgPoint::new(KEYS_W as i32 / 2, KEYS_HINT_CY as i32),
        Role::Body,
        MUTED,
    )?;
    text(
        t,
        HINT_HOLD,
        EgPoint::new(KEYS_W as i32 / 2, KEYS_HINT_ALT_CY as i32),
        Role::Body,
        MUTED,
    )
}

#[cfg(test)]
#[path = "keys_tests.rs"]
mod tests;
