// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Settings screens: the menu pages, adjust controls, and the firmware update flow.

use super::components;
use super::*;

// --- Settings menu ---------------------------------------------------------

/// Paint the on-screen settings menu — dispatch by page. Every tappable control is
/// painted in the exact rect its `hit_*` test maps a tap to (the Allow/Deny contract,
/// extended to the menu).
pub(super) fn settings<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    v: &SettingsView,
) -> Result<(), D::Error> {
    match v.page {
        SettingsPage::Root => settings_root(t, v.version),
        SettingsPage::Display => settings_display(t),
        SettingsPage::Brightness => settings_brightness(t, v.brightness),
        SettingsPage::Timeout => settings_timeout(t, v.timeout_secs),
        SettingsPage::Sleep => settings_sleep(t, v.sleep_secs),
        SettingsPage::Security => {
            settings_security(t, v.device_pin_set, v.fido_pin_set, v.backup_sealed)
        }
    }
}

/// The Root list — the three settings domains: **Display** (panel knobs), **Security**, and
/// **Firmware** last (a rare maintenance action, its installed build inline). Settings is a
/// top-level tab, so it paints the four-tab nav (with itself active) like Home / Passkeys /
/// Apps — no back chevron; the nav is the way out.
fn settings_root<D: DrawTarget<Color = Rgb565>>(t: &mut D, version: u16) -> Result<(), D::Error> {
    status_bar(t)?;
    title_bar(t, "Settings", theme::ACCENT, false)?;
    // Display drills into the brightness / sleep / touch-timeout panel knobs.
    components::rect_card(t, settings_row_rect(0))?;
    components::rect_row(t, settings_row_rect(0), Glyph::Sun, "Display", None, true)?;
    // Security drills into the Set/Change PIN + Audit / Backup + Factory reset sub-page,
    // keeping the destructive reset one tap deeper.
    components::rect_card(t, settings_row_rect(1))?;
    components::rect_row(
        t,
        settings_row_rect(1),
        Glyph::Shield,
        "Security",
        None,
        true,
    )?;
    // Firmware (last): the installed build (bcdDevice) inline, drilling into the
    // reboot-to-update-over-USB screen.
    let mut vbuf = [b'0', b'x', 0, 0, 0, 0];
    vbuf[2..].copy_from_slice(&hex_u16(version));
    components::rect_card(t, settings_row_rect(2))?;
    components::rect_row(
        t,
        settings_row_rect(2),
        Glyph::Cpu,
        "Firmware",
        Some((str8(&vbuf), theme::FAINT)),
        true,
    )?;
    render_nav(t, NavTab::Settings)
}

/// The Display sub-page: the three panel/interaction knobs — Brightness, Display sleep, and
/// the Touch timeout — each drilling into its −/+ adjust page (which backs out to here). The
/// title-bar back chevron returns to the Root list; no nav (a sub-page).
fn settings_display<D: DrawTarget<Color = Rgb565>>(t: &mut D) -> Result<(), D::Error> {
    status_bar(t)?;
    title_bar(t, "Display", theme::ACCENT, true)?;
    // Row order must match [`crate::display_row_entry`] — paint and tap-dispatch share
    // `settings_row_rect(i)`.
    components::rect_card(t, settings_row_rect(0))?;
    components::rect_row(
        t,
        settings_row_rect(0),
        Glyph::Sun,
        "Brightness",
        None,
        true,
    )?;
    components::rect_card(t, settings_row_rect(1))?;
    components::rect_row(
        t,
        settings_row_rect(1),
        Glyph::Moon,
        "Display sleep",
        None,
        true,
    )?;
    components::rect_card(t, settings_row_rect(2))?;
    components::rect_row(
        t,
        settings_row_rect(2),
        Glyph::Clock,
        "Touch timeout",
        None,
        true,
    )
}

/// The Security sub-page: the PIN action (labelled by whether a PIN is set) above the
/// danger-styled Factory reset. Both rows reuse the Root list geometry; the title-bar
/// back chevron returns to the Root list.
fn settings_security<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    device_pin_set: bool,
    fido_pin_set: bool,
    backup_sealed: bool,
) -> Result<(), D::Error> {
    status_bar(t)?;
    title_bar(t, "Security", theme::ACCENT, true)?;
    // Row order here must match [`crate::security_row_entry`] — the paint and the tap-dispatch
    // share `settings_row_rect(i)` but not a single table, so the danger Factory reset stays
    // last on both. Two independent PINs: the device PIN (lock glyph) gates the on-device UI;
    // the FIDO clientPIN (key glyph) is WebAuthn's. Each row sets or changes only its own.
    components::rect_card(t, settings_row_rect(0))?;
    components::rect_row(
        t,
        settings_row_rect(0),
        Glyph::Lock,
        if device_pin_set {
            "Change device PIN"
        } else {
            "Set device PIN"
        },
        None,
        true,
    )?;
    components::rect_card(t, settings_row_rect(1))?;
    components::rect_row(
        t,
        settings_row_rect(1),
        Glyph::Key,
        if fido_pin_set {
            "Change FIDO PIN"
        } else {
            "Set FIDO PIN"
        },
        None,
        true,
    )?;
    // The PIV applet's own PIN/PUK — a drill-in to its sub-menu ([`render_piv_pin_menu`]),
    // grouped with the other two credential PINs above the audit/backup/reset rows.
    components::rect_card(t, settings_row_rect(2))?;
    components::rect_row(t, settings_row_rect(2), Glyph::Lock, "PIV PIN", None, true)?;
    components::rect_card(t, settings_row_rect(3))?;
    components::rect_row(
        t,
        settings_row_rect(3),
        Glyph::Clock,
        "Audit log",
        None,
        true,
    )?;
    // The row shows the cheap export-*window* bit only ("Sealed" / "Review"); the full
    // 4-way state (no-seed / restore-only / sealed / review) lives on the Backup page, which
    // also reads `has_seed` + the build profile. The row deliberately skips that extra lookup.
    components::rect_card(t, settings_row_rect(4))?;
    components::rect_row(
        t,
        settings_row_rect(4),
        Glyph::Lifebuoy,
        "Backup",
        Some(if backup_sealed {
            ("Sealed", theme::OK)
        } else {
            ("Review", theme::WARN)
        }),
        true,
    )?;
    danger_row(t, settings_row_rect(5), "Factory reset")
}

/// A destructive option row: a red-tinted rounded card with a warning glyph, label,
/// and drill-in chevron — so a destructive action stands out from the neutral rows.
fn danger_row<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    rect: Rect,
    label: &str,
) -> Result<(), D::Error> {
    let r = components::CARD_RADIUS;
    crate::aa::rounded_rect(
        t,
        rect,
        r,
        Some(theme::DANGER_BG),
        Some((theme::DANGER_BORDER, 1)),
        BG,
    )?;
    let cy = rect.y as i32 + rect.h as i32 / 2;
    glyph::draw(
        t,
        Glyph::Warn,
        Point::new(rect.x + 8, (cy - 7) as u16),
        14,
        theme::DENY,
        theme::DANGER_BG,
    )?;
    text_left_on(
        t,
        label,
        EgPoint::new(rect.x as i32 + 28, cy),
        Role::Body,
        theme::DENY,
        theme::DANGER_BG,
    )?;
    glyph::draw(
        t,
        Glyph::Chevron,
        Point::new(rect.x + rect.w - 20, (cy - 6) as u16),
        12,
        theme::DENY,
        theme::DANGER_BG,
    )
}

/// Brightness adjust: a coarse level bar plus the shared −/+/Back controls.
fn settings_brightness<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    level: u8,
) -> Result<(), D::Error> {
    status_bar(t)?;
    title_bar(t, "Brightness", theme::ACCENT, true)?;
    level_bar(t, level)?;
    adjust_controls(t)
}

/// Touch-timeout adjust: the current value in seconds plus −/+/Back.
fn settings_timeout<D: DrawTarget<Color = Rgb565>>(t: &mut D, secs: u16) -> Result<(), D::Error> {
    status_bar(t)?;
    title_bar(t, "Touch timeout", theme::ACCENT, true)?;
    let mut buf = [0u8; 8];
    text(
        t,
        fmt_secs(secs, &mut buf),
        EgPoint::new(MIDX, 104),
        Role::Heading,
        theme::TEXT,
    )?;
    adjust_controls(t)
}

/// Display-sleep adjust: the current timeout (or "Off") plus the shared −/+/Back.
fn settings_sleep<D: DrawTarget<Color = Rgb565>>(t: &mut D, secs: u16) -> Result<(), D::Error> {
    status_bar(t)?;
    title_bar(t, "Display sleep", theme::ACCENT, true)?;
    if secs == 0 {
        text(
            t,
            "Off",
            EgPoint::new(MIDX, 104),
            Role::Heading,
            theme::TEXT,
        )?;
    } else {
        let mut buf = [0u8; 8];
        text(
            t,
            fmt_secs(secs, &mut buf),
            EgPoint::new(MIDX, 104),
            Role::Heading,
            theme::TEXT,
        )?;
    }
    adjust_controls(t)
}

/// The **Firmware** screen (Settings → Firmware): the installed build (bcdDevice) above the
/// honest update story and the device serial. This authenticator can't discover updates on
/// its own — the RS-Key host app delivers a signed image over USB, and a deliberate hold
/// reboots into the BOOTSEL bootloader so the host can flash. `secure_boot` is the device's
/// *real* OTP fuse state: only when it is set does the RP2350 boot ROM verify the image
/// signature, so the screen states the verification as fact only then — on an un-fused board
/// it warns the update is unverified instead (the trusted display must not vouch for a check
/// the silicon isn't doing, mirroring the honest Backup-status screen). Same chrome-less
/// layout / hold mechanics as the reveal / seal gates, but the hold is the blue primary
/// action; the firmware drives [`crate::DEL_HOLD_RECT`] (hold) / [`crate::PK_BACK_RECT`] (cancel).
pub fn render_firmware<D>(
    t: &mut D,
    version: u16,
    chipid: u64,
    secure_boot: bool,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    back_button(t, PK_BACK_RECT, theme::ACCENT)?;
    text_left(
        t,
        "Firmware",
        EgPoint::new(PK_BACK_RECT.x as i32 + PK_BACK_RECT.w as i32 + 8, 22),
        Role::Heading,
        theme::TEXT,
    )?;
    glyph::draw(
        t,
        Glyph::Cpu,
        Point::new(PANEL_W / 2 - 14, 48),
        28,
        theme::ACCENT,
        BG,
    )?;
    text(
        t,
        "INSTALLED",
        EgPoint::new(MIDX, 96),
        Role::Mono,
        theme::CAPTION,
    )?;
    let mut vbuf = [b'0', b'x', 0, 0, 0, 0];
    vbuf[2..].copy_from_slice(&hex_u16(version));
    text(t, str8(&vbuf), EgPoint::new(MIDX, 118), Role::Heading, FG)?;
    text(
        t,
        "Updates arrive over USB.",
        EgPoint::new(MIDX, 150),
        Role::Body,
        MUTED,
    )?;
    // Only claim a signature check when secure boot is actually fused; otherwise the
    // bootloader takes any image, so say so rather than vouch for a check that isn't run.
    if secure_boot {
        text(
            t,
            "Secure boot checks the",
            EgPoint::new(MIDX, 170),
            Role::Body,
            MUTED,
        )?;
        text(
            t,
            "signature before it runs.",
            EgPoint::new(MIDX, 188),
            Role::Body,
            MUTED,
        )?;
    } else {
        text(
            t,
            "Secure boot is off —",
            EgPoint::new(MIDX, 170),
            Role::Body,
            theme::WARN,
        )?;
        text(
            t,
            "updates are NOT verified.",
            EgPoint::new(MIDX, 188),
            Role::Body,
            theme::WARN,
        )?;
    }
    let sh = hex_u64(chipid);
    text(
        t,
        str8(&sh),
        EgPoint::new(MIDX, 222),
        Role::Mono,
        theme::CAPTION,
    )?;
    render_hold_button(t, DEL_HOLD_RECT, "Verify & install", theme::ACCENT_FILL)
}

/// The brief notice painted the instant a [`render_firmware`] hold commits, before the
/// secure reboot into BOOTSEL drops the panel — it tells the user to finish the flash from
/// the host. The reboot follows within a worker tick, so this shows only momentarily.
pub fn render_rebooting<D>(t: &mut D) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    glyph::draw(
        t,
        Glyph::Usb,
        Point::new(PANEL_W / 2 - 16, 110),
        32,
        theme::ACCENT,
        BG,
    )?;
    text(
        t,
        "Rebooting to update",
        EgPoint::new(MIDX, 176),
        Role::Strong,
        FG,
    )?;
    text(
        t,
        "Flash from the RS-Key app.",
        EgPoint::new(MIDX, 200),
        Role::Body,
        MUTED,
    )
}

/// The −/+ controls shared by the adjust pages, painted in their hit rects. Back is the
/// title-bar chevron (like every other screen), so these pages carry no bottom Back slab.
fn adjust_controls<D: DrawTarget<Color = Rgb565>>(t: &mut D) -> Result<(), D::Error> {
    key_surface(t, ADJ_MINUS_RECT, KEY_FILL, true)?;
    text_on(t, "-", center(ADJ_MINUS_RECT), Role::Strong, FG, KEY_FILL)?;
    key_surface(t, ADJ_PLUS_RECT, KEY_FILL, true)?;
    text_on(t, "+", center(ADJ_PLUS_RECT), Role::Strong, FG, KEY_FILL)
}

/// A row of `BRIGHTNESS_LEVELS` segments, the first `filled` lit green — a coarse
/// gauge, centered above the −/+ controls.
fn level_bar<D: DrawTarget<Color = Rgb565>>(t: &mut D, filled: u8) -> Result<(), D::Error> {
    const SEG_W: u16 = 32;
    const SEG_H: u16 = 28;
    const SEG_GAP: u16 = 8;
    const BAR_Y: i32 = 96;
    let total = BRIGHTNESS_LEVELS as u16;
    let span = total * SEG_W + (total - 1) * SEG_GAP;
    let x0 = MIDX - span as i32 / 2;
    for i in 0..total {
        let fill = if i < filled as u16 { ALLOW_FILL } else { MUTED };
        Rectangle::new(
            EgPoint::new(x0 + i as i32 * (SEG_W + SEG_GAP) as i32, BAR_Y),
            Size::new(SEG_W as u32, SEG_H as u32),
        )
        .into_styled(PrimitiveStyle::with_fill(fill))
        .draw(t)?;
    }
    Ok(())
}
