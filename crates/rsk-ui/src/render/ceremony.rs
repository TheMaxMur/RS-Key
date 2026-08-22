// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Ceremony screens: the trusted approve prompt and the add-passkey enrolment.

use super::*;

// --- Ceremony screens (request / approve / add-passkey) --------------------

/// Left inset of the title-row leading icon (the approve shield).
const CEREMONY_ICON_X: i32 = 13;
/// Where the title text starts, after the 18px leading icon.
const CEREMONY_TITLE_X: i32 = CEREMONY_ICON_X + 18 + 8;
/// Vertical centre of the title row (matches [`title_bar`]).
const CEREMONY_TITLE_CY: i32 = STATUS_BAR_H as i32 + TITLE_BAR_H as i32 / 2;
/// The consent title's face. Smaller than the [`Role::Heading`] the other titles use:
/// most consent titles are sentences, and at Heading two thirds of them did not fit
/// [`CEREMONY_TITLE_BAND`]. Shared with the width test so the two cannot drift.
pub(super) const CEREMONY_TITLE_ROLE: Role = Role::BodyStrong;
/// The band the consent title is painted into: from the title origin to the panel's
/// right inset, the height of the title row. A title wider than this is ellipsized —
/// but on a [`ConfirmPrompt`] with no relying-party text the title is the *only* text
/// on screen, so the census test keeps that backstop from ever firing.
pub(super) const CEREMONY_TITLE_BAND: Rect = Rect::new(
    CEREMONY_TITLE_X as u16,
    STATUS_BAR_H,
    (PANEL_W - 13) - CEREMONY_TITLE_X as u16,
    TITLE_BAR_H,
);
/// The service header sits just under the chrome; the info / caution plate below it.
const CEREMONY_HEAD_TOP: i32 = CONTENT_TOP as i32 + 6;
const CEREMONY_PLATE_TOP: i32 = CONTENT_TOP as i32 + 54;
const CEREMONY_PLATE_H: u16 = 46;

/// Centred text that, when too wide to fit `clip`, falls back to left-aligned and is
/// hard-clipped at the boundary. So a short relying party stays nicely centred (the
/// design), but a long, attacker-influenced rp id can never overrun the panel and is
/// cut from one side (head readable) rather than centred with both ends hidden.
///
/// `mark` = the label was already clamped upstream (`Label.truncated`): force the
/// ellipsis even when the (clamped) prefix happens to fit the pixel clip, so a padded
/// look-alike id can't present a complete-looking prefix on a trust screen.
// A low-level text-draw primitive: target, string, x, y, role, colour, clip and the
// truncation flag are all irreducible draw inputs — a bundling struct would only
// obscure the call sites.
/// `right` selects the ellipsis side when the text overflows: `false` keeps the head
/// (account / user-chosen labels), `true` keeps the suffix (domain / relying-party
/// ids, so the registrable domain stays visible).
#[allow(clippy::too_many_arguments)]
pub(super) fn centered_clipped<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    s: &str,
    cx: i32,
    y: i32,
    role: Role,
    color: Rgb565,
    clip: Rect,
    mark: bool,
    right: bool,
) -> Result<(), D::Error> {
    let w = font::width(s, role).unwrap_or(clip.w as u32);
    if w <= clip.w as u32 && !mark {
        text(t, s, EgPoint::new(cx, y), role, color)
    } else if right {
        text_right_ellipsized(
            t,
            s,
            EgPoint::new(clip.x as i32, y),
            role,
            color,
            clip,
            mark,
        )
    } else {
        text_left_ellipsized(
            t,
            s,
            EgPoint::new(clip.x as i32, y),
            role,
            color,
            clip,
            mark,
        )
    }
}

/// The service header shared by the request and approve ceremonies: a rounded chip
/// with the generic relying-party globe (we ship no per-brand logos), then the
/// relying party and — when present — the account beneath it. Both untrusted fields
/// are clipped to the panel so a long rp id is cut, never overrun. Drawn from `y`
/// (the chip's top); the caller lays content out below it.
fn service_head<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    y: i32,
    rp: &Label,
    account: &Label,
) -> Result<(), D::Error> {
    let chip = Rect::new(14, y as u16, 38, 38);
    crate::aa::rounded_rect(t, chip, 9, Some(theme::CHIP), None, BG)?;
    glyph::draw(
        t,
        Glyph::Globe,
        Point::new(chip.x + 8, chip.y + 8),
        22,
        theme::TEXT,
        theme::CHIP,
    )?;
    let tx = chip.x as i32 + chip.w as i32 + 11;
    let clip = Rect::new(tx as u16, y as u16, PANEL_W - 14 - tx as u16, 38);
    // The relying party is attacker-chosen text: head-ellipsize (never hard-cut) so the
    // registrable-domain *suffix* stays on screen, and force the marker when the label
    // was already clamped, so a padded look-alike id can't hide the real domain behind
    // the cut on the very screen meant to expose it.
    if account.as_str().is_empty() {
        text_right_ellipsized(
            t,
            rp.as_str(),
            EgPoint::new(tx, y + 19),
            Role::Strong,
            theme::TEXT,
            clip,
            rp.truncated,
        )
    } else {
        text_right_ellipsized(
            t,
            rp.as_str(),
            EgPoint::new(tx, y + 12),
            Role::Strong,
            theme::TEXT,
            clip,
            rp.truncated,
        )?;
        text_left_ellipsized(
            t,
            account.as_str(),
            EgPoint::new(tx, y + 28),
            Role::Body,
            theme::GREY,
            clip,
            account.truncated,
        )
    }
}

/// A full-width info / caution plate (rounded, tinted) below the service header — the
/// "Sign in with passkey" hint on the request screen, the amber "did you start this?"
/// caution on the approve screen. Two short lines fit; the caller supplies them.
fn ceremony_plate<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    icon: Glyph,
    line1: &str,
    line2: &str,
    fill: Rgb565,
    border: Rgb565,
    text_color: Rgb565,
) -> Result<(), D::Error> {
    let plate = Rect::new(
        14,
        CEREMONY_PLATE_TOP as u16,
        PANEL_W - 28,
        CEREMONY_PLATE_H,
    );
    crate::aa::rounded_rect(t, plate, 11, Some(fill), Some((border, 1)), BG)?;
    glyph::draw(
        t,
        icon,
        Point::new(plate.x + 12, plate.y + 13),
        16,
        text_color,
        fill,
    )?;
    let tx = plate.x as i32 + 38;
    if line2.is_empty() {
        text_left_on(
            t,
            line1,
            EgPoint::new(tx, plate.y as i32 + 23),
            Role::Body,
            text_color,
            fill,
        )
    } else {
        text_left_on(
            t,
            line1,
            EgPoint::new(tx, plate.y as i32 + 16),
            Role::Body,
            text_color,
            fill,
        )?;
        text_left_on(
            t,
            line2,
            EgPoint::new(tx, plate.y as i32 + 32),
            Role::Body,
            text_color,
            fill,
        )
    }
}

/// The trusted Approve prompt: the status/title chrome with a shield + the operation
/// title, the relying-party header (chip + sanitized rp id / account), an amber "did
/// you start this?" caution, and the Deny / Hold-to-approve buttons. The hold button
/// starts empty; the firmware fills it via [`render_hold_button`] as the user holds.
/// Shared by the FIDO sign-in approve and the generic OpenPGP/PIV/OATH/OTP touch
/// policies — for those the title is the operation, and `primary` may be empty.
pub(super) fn confirm<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    p: &ConfirmPrompt,
) -> Result<(), D::Error> {
    t.clear(BG)?;
    status_bar(t)?;
    glyph::draw(
        t,
        Glyph::Shield,
        Point::new(CEREMONY_ICON_X as u16, (CEREMONY_TITLE_CY - 9) as u16),
        18,
        theme::ACCENT,
        BG,
    )?;
    // Clipped like every other label on this screen: an over-wide title used to paint
    // past the panel edge, and on a title-only prompt (`Confirm::titled`, e.g. the OTP
    // fuse burns) the cut sentence is the whole of what the owner is approving.
    text_left_ellipsized(
        t,
        p.title,
        EgPoint::new(CEREMONY_TITLE_X, CEREMONY_TITLE_CY),
        CEREMONY_TITLE_ROLE,
        theme::TEXT,
        CEREMONY_TITLE_BAND,
        false,
    )?;
    // Relying-party header, only when the request carries rp text (generic confirms
    // such as an OpenPGP signature may not).
    if !p.primary.is_empty() {
        service_head(t, CEREMONY_HEAD_TOP, &p.primary, &p.secondary)?;
    }
    // Caution — a deliberate, plain-language warning against phishing.
    ceremony_plate(
        t,
        Glyph::Warn,
        "Approve only if you",
        "started this",
        theme::WARN_BG,
        theme::WARN_BORDER,
        theme::WARN,
    )?;
    // Deny is a single tap (low emphasis); Approve is a deliberate hold that fills.
    outline_button(t, DENY_RECT, "Deny", theme::DENY)?;
    render_hold_button(t, ALLOW_RECT, "Hold to approve", theme::APPROVE)
}

/// The trusted **add-passkey** prompt (the design's `makeCredential` step): a dashed
/// placeholder tile with the generic globe, the relying party + account being enrolled,
/// "Save new passkey for this account?", and Cancel / Save. Save ([`ALLOW_RECT`])
/// confirms the registration; Cancel ([`DENY_RECT`]) refuses. Standalone full-frame.
/// The untrusted rp / account are clipped to the panel (centred when they fit, else
/// left-clipped) so a long rp id cannot overrun the trusted display.
pub fn render_add_passkey<D>(t: &mut D, rp: &Label, account: &Label) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    status_bar(t)?;
    title_bar(t, "Add passkey", theme::ACCENT, false)?;
    // Placeholder tile for the (logo-less) relying party. embedded-graphics has no
    // dashed stroke, so the border is solid — the tile still reads as "new / pending".
    let tile = Rect::new((MIDX - 37) as u16, CONTENT_TOP + 16, 74, 74);
    crate::aa::rounded_rect(t, tile, 16, None, Some((theme::BORDER_CARD, 2)), BG)?;
    glyph::draw(
        t,
        Glyph::Globe,
        Point::new(tile.x + 18, tile.y + 18),
        38,
        theme::TEXT,
        BG,
    )?;
    // Untrusted fields, clipped to the panel (with side margins) so they cannot overrun.
    let rp_y = tile.y as i32 + 90;
    let acct_y = tile.y as i32 + 110;
    centered_clipped(
        t,
        rp.as_str(),
        MIDX,
        rp_y,
        Role::Strong,
        theme::TEXT,
        Rect::new(6, (rp_y - 11) as u16, PANEL_W - 12, 22),
        rp.truncated,
        true, // rp is a domain — keep the registrable-domain suffix visible
    )?;
    if !account.as_str().is_empty() {
        centered_clipped(
            t,
            account.as_str(),
            MIDX,
            acct_y,
            Role::Body,
            theme::GREY,
            Rect::new(6, (acct_y - 11) as u16, PANEL_W - 12, 22),
            account.truncated,
            false, // account is a user-chosen label — keep the head
        )?;
    }
    text(
        t,
        "Save new passkey",
        EgPoint::new(MIDX, tile.y as i32 + 134),
        Role::Body,
        theme::TEXT_2,
    )?;
    text(
        t,
        "for this account?",
        EgPoint::new(MIDX, tile.y as i32 + 150),
        Role::Body,
        theme::TEXT_2,
    )?;
    outline_button(t, DENY_RECT, "Cancel", theme::DENY)?;
    button(t, ALLOW_RECT, "Save", theme::ACCENT_FILL)
}
