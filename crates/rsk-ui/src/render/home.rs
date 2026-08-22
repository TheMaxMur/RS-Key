// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The Home tab: the ready/status card and the status spinner ring.

use super::*;

/// Top of the Home status card — below the left-aligned "Ready" header, clear of the nav.
pub(super) const HOME_CARD_TOP: u16 = 92;

/// The Home tab: a left-aligned "✓ Ready" header, the three-row status card (USB, device
/// PIN, passkey count) backed by live data, and the bottom nav. While busy it shows the
/// centred status indicator instead. The old MENU affordance is gone — the nav bar is the
/// way into Passkeys / Settings now.
pub(super) fn home<D: DrawTarget<Color = Rgb565>>(t: &mut D, v: &HomeView) -> Result<(), D::Error> {
    status_bar(t)?;
    if matches!(v.status, StatusKind::Idle) {
        // The design's left-aligned "✓ Ready" header — a calm white headline beside the
        // accent check, not a lone centred accent word.
        glyph::draw(
            t,
            Glyph::CheckCircle,
            Point::new(14, 40),
            38,
            theme::ACCENT,
            BG,
        )?;
        text_left(t, "Ready", EgPoint::new(60, 58), Role::Ready, FG)?;
        // One grouped status card (USB / device PIN / passkey count), the design's panel —
        // not three floating pills.
        group_card(t, HOME_CARD_TOP, 3)?;
        row_body(
            t,
            crate::row_rect(HOME_CARD_TOP, 0),
            Glyph::Usb,
            "USB connected",
            None,
            false,
            false,
        )?;
        row_body(
            t,
            crate::row_rect(HOME_CARD_TOP, 1),
            Glyph::Lock,
            if v.pin_set {
                "Device PIN set"
            } else {
                "No device PIN"
            },
            None,
            false,
            false,
        )?;
        // The passkey count comes from the firmware's cached enumeration (refreshed at
        // modal boundaries, never per idle frame — a per-frame partition scan would stall
        // the panel, the lesson the PIV `has_data` lag taught).
        let mut buf = [0u8; 5];
        row_body(
            t,
            crate::row_rect(HOME_CARD_TOP, 2),
            Glyph::Key,
            "Passkeys",
            Some((fmt_u16(v.passkeys, &mut buf), theme::GREY)),
            false,
            false,
        )?;
    } else {
        // A themed ring + bright 270° arc reads as an in-progress spinner (the design's
        // request spinner), not a flat raw-colour disc. The firmware spins it by repainting
        // [`render_status_arc`] at an advancing angle while busy (the arc's redraw of the
        // full track erases the previous frame, so no per-frame clear / flicker).
        render_status_arc(t, v.status, STATUS_ARC_START)?;
        text(
            t,
            v.status.label(),
            EgPoint::new(MIDX, 158),
            Role::Heading,
            FG,
        )?;
    }
    render_nav(t, NavTab::Home)
}

/// The resting start angle of the status spinner's 270° arc (top, `-90°`), used for the
/// first paint; the firmware advances it to animate.
pub const STATUS_ARC_START: i32 = -90;

/// Centre + diameter of the status spinner ring — the firmware sizes nothing itself; it
/// only steps the angle through [`render_status_arc`].
const STATUS_RING_CY: i32 = 92;
const STATUS_RING_D: u32 = 50;

/// Repaint just the status spinner — the full track ring plus the 270° arc starting at
/// `angle_deg`. Drawing the full track every frame overwrites the previous arc with track
/// colour (no background clear), so stepping `angle_deg` spins the arc flicker-free. The
/// firmware calls this on a timer while the status is non-idle; the "Working…" label and
/// the rest of the Home frame are untouched.
pub fn render_status_arc<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    kind: StatusKind,
    angle_deg: i32,
) -> Result<(), D::Error> {
    let (track, mark) = status_ring(kind);
    crate::aa::ring_arc(
        t,
        EgPoint::new(MIDX, STATUS_RING_CY),
        STATUS_RING_D,
        3,
        angle_deg,
        270,
        track,
        mark,
        BG,
    )
}

/// Track + accent colours for the non-idle status ring (themed, not the LED layer's raw
/// RGB): blue = working, amber = awaiting touch, muted = booting.
fn status_ring(kind: StatusKind) -> (Rgb565, Rgb565) {
    match kind {
        StatusKind::Touch => (theme::BORDER_CARD, theme::WARN),
        StatusKind::Boot => (theme::BORDER_CARD, theme::MUTED),
        _ => (theme::BORDER_CARD, theme::ACCENT),
    }
}
