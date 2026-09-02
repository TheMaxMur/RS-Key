// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The Home tab: the ready/status card and the status spinner ring.

use super::*;

/// Top of the Home status card — below the left-aligned "Ready" header, clear of the nav.
pub(super) const HOME_CARD_TOP: u16 = 92;

/// Home content excluding the fixed status and navigation bars. A status-mode
/// change replaces this complete region because the idle card and busy ring overlap.
const HOME_CONTENT_RECT: Rect = Rect::new(0, STATUS_BAR_H, PANEL_W, NAV_TOP - STATUS_BAR_H);

/// The Home tab: a left-aligned "✓ Ready" header, the three-row status card (USB, device
/// PIN, passkey count) backed by live data, and the bottom nav. While busy it shows the
/// centred status indicator instead. The old MENU affordance is gone — the nav bar is the
/// way into Passkeys / Settings now.
pub(super) fn home<D: DrawTarget<Color = Rgb565>>(t: &mut D, v: &HomeView) -> Result<(), D::Error> {
    status_bar(t)?;
    home_body(t, v)?;
    render_nav(t, NavTab::Home)
}

fn home_body<D: DrawTarget<Color = Rgb565>>(t: &mut D, v: &HomeView) -> Result<(), D::Error> {
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
        home_card(t, v)?;
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
    Ok(())
}

fn home_card<D: DrawTarget<Color = Rgb565>>(t: &mut D, v: &HomeView) -> Result<(), D::Error> {
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
    )
}

fn repaint_home_row<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    v: &HomeView,
    index: u16,
) -> Result<(), D::Error> {
    let bounds = crate::row_rect(HOME_CARD_TOP, index);
    let mut clipped = t.clipped(&eg_rect(bounds));
    group_card(&mut clipped, HOME_CARD_TOP, 3)?;
    match index {
        1 => row_body(
            &mut clipped,
            bounds,
            Glyph::Lock,
            if v.pin_set {
                "Device PIN set"
            } else {
                "No device PIN"
            },
            None,
            false,
            false,
        ),
        _ => {
            let mut buf = [0u8; 5];
            row_body(
                &mut clipped,
                bounds,
                Glyph::Key,
                "Passkeys",
                Some((fmt_u16(v.passkeys, &mut buf), theme::GREY)),
                false,
                false,
            )
        }
    }
}

/// Repaint only the Home component whose typed visual state changed. The status
/// bar and navigation are stable for every `HomeView`. Unknown screen transitions
/// stay on [`crate::render()`]'s complete-frame path in the caller.
pub fn render_home_change<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    previous: &HomeView,
    next: &HomeView,
) -> Result<(), D::Error> {
    if previous == next {
        return Ok(());
    }

    let previous_idle = matches!(previous.status, StatusKind::Idle);
    let next_idle = matches!(next.status, StatusKind::Idle);
    if previous_idle && next_idle {
        if previous.pin_set != next.pin_set {
            repaint_home_row(t, next, 1)?;
        }
        if previous.passkeys != next.passkeys {
            repaint_home_row(t, next, 2)?;
        }
        return Ok(());
    }
    if !previous_idle && !next_idle && previous.status == next.status {
        // PIN/passkey facts are not visible while Home shows an activity state.
        return Ok(());
    }

    clear_region(t, HOME_CONTENT_RECT)?;
    home_body(t, next)
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
