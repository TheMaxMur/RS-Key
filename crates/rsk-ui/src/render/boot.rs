// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Boot-time screens: splash, the locked screen (with its breathe hint), and onboarding.

use super::*;

/// The device-locked screen: a padlock in a calm surface circle, the "Locked" heading,
/// and a muted "Touch to unlock" hint. The whole screen is the unlock affordance (the
/// firmware treats any tap as "start PIN entry"), so there is no per-control hit rect.
/// Gates only the on-device UI — host CTAP ceremonies paint their own prompts over this.
pub(super) fn locked<D: DrawTarget<Color = Rgb565>>(t: &mut D) -> Result<(), D::Error> {
    const DIA: u32 = 70;
    let cx = MIDX;
    let circle_top = 96;
    crate::aa::filled_circle(
        t,
        EgPoint::new(cx - DIA as i32 / 2, circle_top),
        DIA,
        theme::SURFACE,
        theme::BG,
    )?;
    let cyc = circle_top + DIA as i32 / 2;
    glyph::draw(
        t,
        Glyph::Lock,
        Point::new((cx - 17) as u16, (cyc - 17) as u16),
        34,
        theme::ACCENT,
    )?;
    text(t, "Locked", EgPoint::new(cx, 200), Role::Heading, FG)?;
    // The design breathes this hint (opacity 0.5↔1); the firmware pulses it by repainting
    // [`render_locked_breathe`] through the shade ramp on a timer. The first paint uses the
    // brightest shade (ramp index 0), the firmware then steps onward from there.
    render_locked_breathe(t, 0)
}

/// The "Touch to unlock" hint position on the [`locked`] screen — shared by the static
/// paint and the breathe repaint so they land on the same pixels (a recolour-in-place, no
/// clear needed: the same string at the same spot just overwrites its own ink).
const LOCKED_HINT_Y: i32 = 228;

/// Phases in the locked-hint breathe ramp (a triangle 1.0 → 0.45 → 1.0 opacity over the
/// background), one full cycle. The firmware passes any `u8`; the renderer wraps it here.
const BREATHE_PHASES: u8 = 8;

/// `MUTED` flattened onto the background at the ramp's opacities — precomputed because
/// embedded-graphics has no alpha blend (the design's `rgba` pulse becomes solid shades).
/// Index 0 is the brightest (the resting paint); the firmware steps a triangle from there.
const BREATHE: [Rgb565; BREATHE_PHASES as usize] = [
    rgb(154, 163, 173), // 1.00 (== MUTED)
    rgb(139, 148, 157), // 0.90
    rgb(118, 125, 134), // 0.75
    rgb(96, 103, 110),  // 0.60
    rgb(75, 80, 87),    // 0.45 (dimmest)
    rgb(96, 103, 110),  // 0.60
    rgb(118, 125, 134), // 0.75
    rgb(139, 148, 157), // 0.90
];

/// 8-bit `#rrggbb` → `Rgb565`, for the local breathe ramp.
const fn rgb(r: u8, g: u8, b: u8) -> Rgb565 {
    Rgb565::new(r >> 3, g >> 2, b >> 3)
}

/// Repaint just the locked screen's "Touch to unlock" hint at breathe `phase`
/// (`0..BREATHE_PHASES`). The firmware steps `phase` on a timer to pulse the hint without
/// touching the rest of the locked frame.
pub fn render_locked_breathe<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    phase: u8,
) -> Result<(), D::Error> {
    let color = BREATHE[(phase % BREATHE_PHASES) as usize];
    text(
        t,
        "Touch to unlock",
        EgPoint::new(MIDX, LOCKED_HINT_Y),
        Role::Body,
        color,
    )
}

/// The first-run onboarding prompt on a fresh, PIN-less device: a lock mark, a short
/// heading, two explanatory lines, then a primary **Set a PIN** (filled, in
/// [`ONBOARD_SET_RECT`]) above a low-emphasis **Continue without PIN** (outlined, in
/// [`ONBOARD_SKIP_RECT`]). Each caption is painted inside the exact rect
/// [`crate::hit_onboard`] maps a tap to, so paint and hit-test can't disagree. The
/// secondary label uses the [`Role::Body`] font so the long "Continue without PIN"
/// fits the button without scrolling.
pub(super) fn onboard<D: DrawTarget<Color = Rgb565>>(t: &mut D) -> Result<(), D::Error> {
    const DIA: u32 = 64;
    let cx = MIDX;
    let circle_top = 36;
    crate::aa::filled_circle(
        t,
        EgPoint::new(cx - DIA as i32 / 2, circle_top),
        DIA,
        theme::SURFACE,
        theme::BG,
    )?;
    let cyc = circle_top + DIA as i32 / 2;
    glyph::draw(
        t,
        Glyph::Lock,
        Point::new((cx - 16) as u16, (cyc - 16) as u16),
        32,
        theme::ACCENT,
    )?;
    text(t, "Set a PIN?", EgPoint::new(cx, 120), Role::Heading, FG)?;
    text(
        t,
        "A device PIN locks the",
        EgPoint::new(cx, 146),
        Role::Body,
        MUTED,
    )?;
    // Keep the last body line clear of the Set button below it (its centre + the Body
    // font's descent must stay above ONBOARD_SET_RECT.y — guarded by a render test).
    text(
        t,
        "on-device menus.",
        EgPoint::new(cx, 164),
        Role::Body,
        MUTED,
    )?;
    button(t, ONBOARD_SET_RECT, "Set a PIN", theme::ACCENT_FILL)?;
    // Low-emphasis outline; the Body font keeps the long caption inside the button.
    RoundedRectangle::with_equal_corners(
        eg_rect(ONBOARD_SKIP_RECT),
        Size::new(BTN_RADIUS, BTN_RADIUS),
    )
    .into_styled(
        PrimitiveStyleBuilder::new()
            .stroke_color(MUTED)
            .stroke_width(2)
            .stroke_alignment(StrokeAlignment::Inside)
            .build(),
    )
    .draw(t)?;
    text(
        t,
        "Continue without PIN",
        center(ONBOARD_SKIP_RECT),
        Role::Body,
        MUTED,
    )
}

pub(super) fn splash<D: DrawTarget<Color = Rgb565>>(t: &mut D) -> Result<(), D::Error> {
    // A shield brand mark over the wordmark — the device is a trusted authenticator, and the
    // shield echoes the approval prompt's glyph.
    glyph::draw(
        t,
        Glyph::Shield,
        Point::new(MIDX as u16 - 20, 92),
        40,
        theme::ACCENT,
    )?;
    text(t, "RS-Key", EgPoint::new(MIDX, 158), Role::Heading, FG)?;
    text(
        t,
        "trusted display",
        EgPoint::new(MIDX, 186),
        Role::Body,
        MUTED,
    )
}
