// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Destructive-flow screens: factory reset, erasing, PIN blocked, and the success pop.

use super::*;

/// The trusted Factory-Reset confirm screen (reached from Settings → Factory reset):
/// a header back chevron to cancel, a centred warning, a plain-language note that
/// every credential and the PIN are erased, and the full-width hold-to-confirm button
/// — the same [`DEL_HOLD_RECT`] geometry the delete flow uses, so only a deliberate
/// hold commits. The firmware gates it on the device PIN (if set) before the hold.
pub fn render_confirm_factory_reset<D>(t: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    back_button(t, PK_BACK_RECT, theme::DENY)?;
    text_left(
        t,
        "Factory reset",
        EgPoint::new(PK_BACK_RECT.x as i32 + PK_BACK_RECT.w as i32 + 8, 22),
        Role::Heading,
        theme::DENY,
    )?;
    // A red-tinted disc around the warning triangle marks this as the destructive
    // ceremony — danger red, not the amber of a recoverable caution.
    const DIA: u32 = 58;
    let circle_top = 46;
    crate::aa::filled_circle(
        t,
        EgPoint::new(MIDX - DIA as i32 / 2, circle_top),
        DIA,
        theme::DANGER_BG,
        theme::BG,
    )?;
    let cyc = circle_top + DIA as i32 / 2;
    glyph::draw(
        t,
        Glyph::Warn,
        Point::new((MIDX - 14) as u16, (cyc - 13) as u16),
        28,
        theme::DANGER,
    )?;
    text(
        t,
        "Erase RS-Key?",
        EgPoint::new(MIDX, 124),
        Role::Strong,
        FG,
    )?;
    text(
        t,
        "This erases everything.",
        EgPoint::new(MIDX, 150),
        Role::Body,
        MUTED,
    )?;
    text(
        t,
        "It cannot be undone.",
        EgPoint::new(MIDX, 168),
        Role::Body,
        MUTED,
    )?;
    // The what-gets-wiped checklist: a red dot per item, so the stakes are explicit.
    erase_item(t, 196, "All passkeys")?;
    erase_item(t, 216, "Device PIN & lock")?;
    erase_item(t, 236, "All applet keys")?;
    render_hold_button(t, DEL_HOLD_RECT, "Hold to wipe", theme::DANGER_FILL)
}

/// One red-dot row of the factory-reset "what gets wiped" checklist, the block centred
/// under the heading (dot at a fixed indent, label flush after it).
fn erase_item<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    cy: i32,
    label: &str,
) -> Result<(), D::Error> {
    const X: i32 = 60;
    crate::aa::filled_circle(t, EgPoint::new(X, cy - 3), 6, theme::DANGER, theme::BG)?;
    text_left(
        t,
        label,
        EgPoint::new(X + 14, cy),
        Role::Body,
        theme::TEXT_2,
    )
}

/// The "wiping" notice shown after a factory reset is confirmed: a centred warning
/// plus "Do not unplug", painted once before the multi-second flash scrub (which
/// blocks the panel) so the screen isn't frozen on the full hold button. No
/// controls — the device reboots itself when the wipe finishes.
pub fn render_erasing<D>(t: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    glyph::draw(
        t,
        Glyph::Warn,
        Point::new(PANEL_W / 2 - 16, 104),
        32,
        theme::DENY,
    )?;
    text(
        t,
        "Erasing...",
        EgPoint::new(MIDX, 168),
        Role::Heading,
        theme::TEXT,
    )?;
    text(
        t,
        "Do not unplug",
        EgPoint::new(MIDX, 196),
        Role::Body,
        MUTED,
    )?;
    Ok(())
}

/// The "PIN blocked" notice, shown when a local PIN gate exhausts the retry budget
/// (the counter reached zero). A danger padlock in a tinted circle, a "PIN blocked"
/// heading, and a two-line hint that recovery is a host-side reset — on-device actions
/// (unlock, delete, factory reset) all share that one blocked `EF_PIN` counter, so the
/// escape hatch is the host's touch-only `authenticatorReset`. No controls; the caller
/// waits for a tap or a short timeout, then returns.
pub fn render_pin_blocked<D>(t: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    const DIA: u32 = 70;
    let circle_top = 84;
    crate::aa::filled_circle(
        t,
        EgPoint::new(MIDX - DIA as i32 / 2, circle_top),
        DIA,
        theme::DANGER_BG,
        theme::BG,
    )?;
    let cyc = circle_top + DIA as i32 / 2;
    glyph::draw(
        t,
        Glyph::Lock,
        Point::new((MIDX - 17) as u16, (cyc - 17) as u16),
        34,
        theme::DANGER,
    )?;
    text(
        t,
        "PIN blocked",
        EgPoint::new(MIDX, 188),
        Role::Heading,
        theme::DANGER,
    )?;
    text(
        t,
        "Too many wrong PINs.",
        EgPoint::new(MIDX, 216),
        Role::Body,
        MUTED,
    )?;
    text(
        t,
        "Reset from a host to recover.",
        EgPoint::new(MIDX, 236),
        Role::Body,
        MUTED,
    )
}

/// The "Erase failed" notice, shown when a factory wipe could not prove it emptied
/// the store — a truncated enumeration or a failed remove. It replaces the success
/// pop, because the one thing the owner must not be told is that a wipe they are
/// about to act on succeeded. Same shape and dwell as [`render_pin_blocked`].
pub fn render_wipe_failed<D>(t: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    const DIA: u32 = 70;
    let circle_top = 84;
    crate::aa::filled_circle(
        t,
        EgPoint::new(MIDX - DIA as i32 / 2, circle_top),
        DIA,
        theme::DANGER_BG,
        theme::BG,
    )?;
    let cyc = circle_top + DIA as i32 / 2;
    glyph::draw(
        t,
        Glyph::Warn,
        Point::new((MIDX - 17) as u16, (cyc - 17) as u16),
        34,
        theme::DANGER,
    )?;
    text(
        t,
        "Erase failed",
        EgPoint::new(MIDX, 188),
        Role::Heading,
        theme::DANGER,
    )?;
    text(
        t,
        "The store was not proven",
        EgPoint::new(MIDX, 216),
        Role::Body,
        MUTED,
    )?;
    text(
        t,
        "empty. Data may remain.",
        EgPoint::new(MIDX, 236),
        Role::Body,
        MUTED,
    )
}

// --- Success screens -------------------------------------------------------

/// Centre of the success "pop" circle.
const SUCCESS_CY: i32 = 112;
/// Resting diameter of the success circle (the 100% frame).
const SUCCESS_DIA: u32 = 72;
/// The fixed square the circle is cleared/redrawn within — large enough for the 1.06
/// overshoot frame plus a margin, and clear of the heading below it, so a smaller pop
/// frame fully erases a larger one without ever touching the static chrome.
const SUCCESS_BOX: u32 = SUCCESS_DIA + 18;

/// `(mark colour, circle fill, mark glyph, heading, subtitle)` for a success kind. A
/// green check on a green tint for approve/delete; the grey [`Glyph::Rotate`] on a
/// neutral chip for the wipe (which restarts, hence no green "all-good" check).
fn success_visuals(kind: SuccessKind) -> (Rgb565, Rgb565, Glyph, &'static str, &'static str) {
    match kind {
        SuccessKind::Approved => (
            theme::SUCCESS,
            theme::SUCCESS_BG,
            Glyph::Check,
            "Approved",
            "",
        ),
        SuccessKind::Deleted => (
            theme::SUCCESS,
            theme::SUCCESS_BG,
            Glyph::Check,
            "Passkey deleted",
            "Removed from RS-Key.",
        ),
        SuccessKind::Wiped => (
            theme::GREY,
            theme::CHIP,
            Glyph::Rotate,
            "RS-Key erased",
            "Restarting...",
        ),
        SuccessKind::Generated => (
            theme::SUCCESS,
            theme::SUCCESS_BG,
            Glyph::Check,
            "Key generated",
            "Stored in the retired slot.",
        ),
    }
}

/// Paint a success screen's static chrome: the heading, an optional subtitle, and —
/// when `with_button` — a primary **Done** button in [`DEL_HOLD_RECT`] (the firmware
/// dismisses it via [`crate::hit_success_done`]). The circle area is left as
/// background; the firmware animates the "pop" in with [`render_success_circle`],
/// which repaints *only* the circle and so never disturbs (or flickers) this chrome.
pub fn render_success<D>(t: &mut D, kind: SuccessKind, with_button: bool) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    let (_, _, _, heading, subtitle) = success_visuals(kind);
    text(t, heading, EgPoint::new(MIDX, 178), Role::Heading, FG)?;
    if !subtitle.is_empty() {
        text(t, subtitle, EgPoint::new(MIDX, 206), Role::Body, MUTED)?;
    }
    if with_button {
        RoundedRectangle::with_equal_corners(
            eg_rect(DEL_HOLD_RECT),
            Size::new(BTN_RADIUS, BTN_RADIUS),
        )
        .into_styled(PrimitiveStyle::with_fill(theme::ACCENT_FILL))
        .draw(t)?;
        text(t, "Done", center(DEL_HOLD_RECT), Role::Strong, FG)?;
    }
    Ok(())
}

/// Repaint just the success circle at `scale_pct`% of its resting size — the building
/// block of the firmware's pop (e.g. 60 → 106 → 100, ending at 100 for the resting
/// frame). It clears the fixed `SUCCESS_BOX` to background first (so a smaller frame
/// erases a larger one cleanly), then fills the tinted circle and centres the mark
/// glyph at ~48% of the circle (the Lock-in-circle proportion on the blocked screen).
pub fn render_success_circle<D>(
    t: &mut D,
    kind: SuccessKind,
    scale_pct: u16,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let (mark, fill, mark_glyph, _, _) = success_visuals(kind);
    Rectangle::new(
        EgPoint::new(
            MIDX - SUCCESS_BOX as i32 / 2,
            SUCCESS_CY - SUCCESS_BOX as i32 / 2,
        ),
        Size::new(SUCCESS_BOX, SUCCESS_BOX),
    )
    .into_styled(PrimitiveStyle::with_fill(BG))
    .draw(t)?;
    let dia = (SUCCESS_DIA * scale_pct as u32 / 100).max(4);
    crate::aa::filled_circle(
        t,
        EgPoint::new(MIDX - dia as i32 / 2, SUCCESS_CY - dia as i32 / 2),
        dia,
        fill,
        theme::BG,
    )?;
    let gs = (dia * 48 / 100).max(10) as u16;
    glyph::draw(
        t,
        mark_glyph,
        Point::new(
            (MIDX - gs as i32 / 2) as u16,
            (SUCCESS_CY - gs as i32 / 2) as u16,
        ),
        gs,
        mark,
    )
}
