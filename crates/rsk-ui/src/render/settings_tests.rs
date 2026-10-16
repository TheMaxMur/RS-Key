// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Frame tests for the settings screens whose geometry is otherwise only exercised for
//! "fits and draws". Each expected frame is written from the literals the screen is
//! specified with, so any single mutated term moves a pixel.

use super::*;
use crate::render::tests::Rec;

/// `danger_row` (the Factory reset row) draws its card, warning glyph, label and chevron
/// at exact offsets; a mutation of one added/subtracted term moves it.
#[test]
fn danger_row_matches_its_literal_geometry() {
    let rect = settings_row_rect(6);
    let mut actual = Rec::new();
    danger_row(&mut actual, rect, "Factory reset").unwrap();

    let mut expected = Rec::new();
    crate::aa::rounded_rect(
        &mut expected,
        rect,
        components::CARD_RADIUS,
        Some(theme::DANGER_BG),
        Some((theme::DANGER_BORDER, 1)),
        BG,
    )
    .unwrap();
    let cy = rect.y as i32 + rect.h as i32 / 2;
    glyph::draw(
        &mut expected,
        Glyph::Warn,
        Point::new(rect.x + 8, (cy - 7) as u16),
        14,
        theme::DENY,
        theme::DANGER_BG,
    )
    .unwrap();
    text_left_on(
        &mut expected,
        "Factory reset",
        EgPoint::new(rect.x as i32 + 28, cy),
        Role::Body,
        theme::DENY,
        theme::DANGER_BG,
    )
    .unwrap();
    glyph::draw(
        &mut expected,
        Glyph::Chevron,
        Point::new(rect.x + rect.w - 20, (cy - 6) as u16),
        12,
        theme::DENY,
        theme::DANGER_BG,
    )
    .unwrap();

    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

/// The Sleep page branches on `secs == 0`: zero is the "Off" sentinel, any other value
/// prints `"NN s"`. A frame test pins both arms (the sentinel word and its centre).
#[test]
fn settings_sleep_off_and_timed_match_their_literal_frames() {
    for secs in [0u16, 60] {
        let mut actual = Rec::new();
        settings_sleep(&mut actual, secs).unwrap();

        let mut expected = Rec::new();
        status_bar(&mut expected).unwrap();
        title_bar(&mut expected, "Display sleep", theme::ACCENT, true).unwrap();
        if secs == 0 {
            text(
                &mut expected,
                "Off",
                EgPoint::new(MIDX, 104),
                Role::Heading,
                theme::TEXT,
            )
            .unwrap();
        } else {
            let mut buf = [0u8; 8];
            text(
                &mut expected,
                fmt_secs(secs, &mut buf),
                EgPoint::new(MIDX, 104),
                Role::Heading,
                theme::TEXT,
            )
            .unwrap();
        }
        adjust_controls(&mut expected).unwrap();

        assert_eq!(actual.px, expected.px, "sleep secs={secs}");
        assert!(!actual.oob && !expected.oob);
    }
}

/// The Firmware screen places its title, icon, version, copy (branching on the real
/// secure-boot fuse) and hold button at fixed points.
#[test]
fn firmware_screen_matches_its_literal_layout() {
    let version = 0x07B6u16;
    let chipid = 0x8e0f_f6ae_ae0b_c470u64;
    for secure_boot in [true, false] {
        let mut actual = Rec::new();
        render_firmware(&mut actual, version, chipid, secure_boot).unwrap();

        let mut expected = Rec::new();
        expected.clear(BG);
        back_button(&mut expected, PK_BACK_RECT, theme::ACCENT).unwrap();
        text_left(
            &mut expected,
            "Firmware",
            EgPoint::new(PK_BACK_RECT.x as i32 + PK_BACK_RECT.w as i32 + 8, 22),
            Role::Heading,
            theme::TEXT,
        )
        .unwrap();
        glyph::draw(
            &mut expected,
            Glyph::Cpu,
            Point::new(PANEL_W / 2 - 14, 48),
            28,
            theme::ACCENT,
            BG,
        )
        .unwrap();
        text(
            &mut expected,
            "INSTALLED",
            EgPoint::new(MIDX, 96),
            Role::Mono,
            theme::CAPTION,
        )
        .unwrap();
        let mut vbuf = [b'0', b'x', 0, 0, 0, 0];
        vbuf[2..].copy_from_slice(&hex_u16(version));
        text(
            &mut expected,
            str8(&vbuf),
            EgPoint::new(MIDX, 118),
            Role::Heading,
            FG,
        )
        .unwrap();
        text(
            &mut expected,
            "Updates arrive over USB.",
            EgPoint::new(MIDX, 150),
            Role::Body,
            MUTED,
        )
        .unwrap();
        if secure_boot {
            text(
                &mut expected,
                "Secure boot checks the",
                EgPoint::new(MIDX, 170),
                Role::Body,
                MUTED,
            )
            .unwrap();
            text(
                &mut expected,
                "signature before it runs.",
                EgPoint::new(MIDX, 188),
                Role::Body,
                MUTED,
            )
            .unwrap();
        } else {
            text(
                &mut expected,
                "Secure boot is off —",
                EgPoint::new(MIDX, 170),
                Role::Body,
                theme::WARN,
            )
            .unwrap();
            text(
                &mut expected,
                "updates are NOT verified.",
                EgPoint::new(MIDX, 188),
                Role::Body,
                theme::WARN,
            )
            .unwrap();
        }
        let sh = hex_u64(chipid);
        text(
            &mut expected,
            str8(&sh),
            EgPoint::new(MIDX, 222),
            Role::Mono,
            theme::CAPTION,
        )
        .unwrap();
        render_hold_button(
            &mut expected,
            DEL_HOLD_RECT,
            "Verify & install",
            theme::ACCENT_FILL,
        )
        .unwrap();

        assert_eq!(actual.px, expected.px, "secure_boot={secure_boot}");
        assert!(!actual.oob && !expected.oob);
    }
}

/// The post-hold reboot notice: USB glyph, headline and instruction at their literals.
#[test]
fn rebooting_notice_matches_its_literal_layout() {
    let mut actual = Rec::new();
    render_rebooting(&mut actual).unwrap();

    let mut expected = Rec::new();
    expected.clear(BG);
    glyph::draw(
        &mut expected,
        Glyph::Usb,
        Point::new(PANEL_W / 2 - 16, 110),
        32,
        theme::ACCENT,
        BG,
    )
    .unwrap();
    text(
        &mut expected,
        "Rebooting to update",
        EgPoint::new(MIDX, 176),
        Role::Strong,
        FG,
    )
    .unwrap();
    text(
        &mut expected,
        "Flash from the RS-Key app.",
        EgPoint::new(MIDX, 200),
        Role::Body,
        MUTED,
    )
    .unwrap();

    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

/// The brightness gauge: five gap-separated segments, the first `filled` lit. The span,
/// centre, per-segment stride and the `i < filled` boundary are all pinned by literals.
#[test]
fn level_bar_segments_match_their_literal_geometry() {
    for filled in [0u8, 3, 5] {
        let mut actual = Rec::new();
        level_bar(&mut actual, filled).unwrap();

        let mut expected = Rec::new();
        const SEG_W: u16 = 32;
        const SEG_H: u16 = 28;
        const SEG_GAP: u16 = 8;
        const BAR_Y: i32 = 96;
        let total = BRIGHTNESS_LEVELS as u16;
        let span = total * SEG_W + (total - 1) * SEG_GAP;
        let x0 = MIDX - span as i32 / 2;
        for i in 0..total {
            let fill = if (i as u8) < filled {
                ALLOW_FILL
            } else {
                MUTED
            };
            Rectangle::new(
                EgPoint::new(x0 + i as i32 * (SEG_W + SEG_GAP) as i32, BAR_Y),
                Size::new(SEG_W as u32, SEG_H as u32),
            )
            .into_styled(PrimitiveStyle::with_fill(fill))
            .draw(&mut expected)
            .unwrap();
        }

        assert_eq!(actual.px, expected.px, "filled={filled}");
        assert!(!actual.oob && !expected.oob);
    }
}
