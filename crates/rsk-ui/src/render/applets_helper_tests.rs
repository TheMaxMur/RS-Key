// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::render::tests::Rec;
use crate::{PK_ROWS_MAX, PgpSlotRow, PivSlotRow};

#[test]
fn direct_numeric_formatters_refuse_short_windows_without_partial_text() {
    let mut output = [0xa5; 32];
    for room in 0..="sig 4294967295".len() {
        output.fill(0xa5);
        let formatted = fmt_labeled("sig", u32::MAX, &mut output[..room]);
        assert_eq!(
            formatted,
            if room < "sig 4294967295".len() {
                ""
            } else {
                "sig 4294967295"
            }
        );
        if room < "sig 4294967295".len() {
            assert_eq!(output, [0xa5; 32]);
        }
        assert_eq!(&output[room..], &[0xa5; 32][room..]);
    }
    for room in 0..="PIN 255/255".len() {
        output.fill(0xa5);
        let formatted = fmt_pair("PIN", 255, 255, &mut output[..room]);
        assert_eq!(
            formatted,
            if room < "PIN 255/255".len() {
                ""
            } else {
                "PIN 255/255"
            }
        );
        if room < "PIN 255/255".len() {
            assert_eq!(output, [0xa5; 32]);
        }
        assert_eq!(&output[room..], &[0xa5; 32][room..]);
    }
}

#[test]
fn grouped_hex_never_writes_outside_a_direct_short_window() {
    for (room, expected) in [(0, ""), (4, "1234"), (9, "1234 ABCD")] {
        let mut output = [0xa5; 16];
        assert_eq!(
            fmt_hex_grouped(&[0x12, 0x34, 0xab, 0xcd], &mut output[..room]),
            expected
        );
        assert_eq!(&output[room..], &[0xa5; 16][room..]);
    }
    let mut output = [0xa5; 1];
    assert_eq!(fmt_hex_grouped(&[0x12], &mut output), "");
    assert_eq!(output, [0xa5; 1]);
}

#[test]
fn retry_counts_distinguish_lockout_last_attempt_and_normal_caption() {
    for (remaining, expected) in [
        (0, theme::DANGER),
        (1, theme::WARN),
        (2, theme::CAPTION),
        (255, theme::CAPTION),
    ] {
        assert_eq!(retry_color(remaining), expected);
    }
}

#[test]
fn retired_slot_titles_number_from_the_wire_value() {
    let mut buf = [0u8; 12];
    assert_eq!(retired_title(0x81, &mut buf), "Retired #0");
    assert_eq!(retired_title(0x82, &mut buf), "Retired #1");
    assert_eq!(retired_title(0x95, &mut buf), "Retired #20");
}

#[test]
fn every_named_piv_slot_and_the_retired_range_render_their_own_screen() {
    let frame = |slot: u8| {
        let mut d = crate::render::tests::Rec::new();
        render_piv_slot(
            &mut d,
            &PivSlotView {
                slot,
                ..Default::default()
            },
        )
        .unwrap();
        d.px
    };
    // 0x96 and 0x9B are both outside every named arm and the retired range.
    let fallback = frame(0x96);
    assert_eq!(
        frame(0x9B),
        fallback,
        "unnamed slots share one fallback title"
    );
    for slot in [0x9A, 0x9C, 0x9D, 0x9E, 0xF9, 0x82, 0x95] {
        assert_ne!(
            frame(slot),
            fallback,
            "{slot:02X} must render its own title and purpose"
        );
    }
}

#[test]
fn openpgp_key_slots_render_distinct_titles() {
    let frame = |slot: u8| {
        let mut d = crate::render::tests::Rec::new();
        render_openpgp_key(
            &mut d,
            &PgpKeyView {
                slot,
                ..Default::default()
            },
        )
        .unwrap();
        d.px
    };
    let auth = frame(2);
    assert_ne!(frame(0), auth, "the sign slot is not the auth slot");
    assert_ne!(frame(1), auth, "the decrypt slot is not the auth slot");
    assert_ne!(frame(0), frame(1));
}

#[test]
fn an_empty_applet_slot_draws_its_glyph_and_both_lines_where_declared() {
    let mut actual = crate::render::tests::Rec::new();
    empty_slot(&mut actual, Glyph::Key, "No key", "Generate one").unwrap();
    let mut expected = crate::render::tests::Rec::new();
    glyph::draw(
        &mut expected,
        Glyph::Key,
        Point::new(MIDX as u16 - 22, 120),
        44,
        MUTED,
        BG,
    )
    .unwrap();
    text(
        &mut expected,
        "No key",
        EgPoint::new(MIDX, 192),
        Role::Strong,
        theme::TEXT_2,
    )
    .unwrap();
    text(
        &mut expected,
        "Generate one",
        EgPoint::new(MIDX, 216),
        Role::MonoSmall,
        theme::CAPTION,
    )
    .unwrap();
    let difference = actual
        .px
        .iter()
        .zip(&expected.px)
        .enumerate()
        .find(|(_, (a, b))| a != b)
        .map(|(index, (a, b))| (index, *a, *b));
    assert_eq!(difference, None);
    assert!(!actual.oob);
}

#[test]
fn a_two_row_detail_card_keeps_its_surface_divider_and_caption_positions() {
    let rows = [
        ("Algorithm", "ECC", theme::TEXT),
        ("Touch", "Off", theme::MUTED),
    ];
    let mut actual = crate::render::tests::Rec::new();
    detail_card(&mut actual, 82, &rows).unwrap();
    let mut expected = crate::render::tests::Rec::new();
    crate::aa::rounded_rect(
        &mut expected,
        Rect::new(13, 82, 214, 68),
        11,
        Some(theme::SURFACE),
        Some((theme::BORDER_CARD, 1)),
        BG,
    )
    .unwrap();
    Line::new(EgPoint::new(23, 116), EgPoint::new(217, 116))
        .into_styled(PrimitiveStyle::with_stroke(theme::DIVIDER, 1))
        .draw(&mut expected)
        .unwrap();
    for (label, value, color, y) in [
        ("Algorithm", "ECC", theme::TEXT, 101),
        ("Touch", "Off", theme::MUTED, 131),
    ] {
        font::left(
            &mut expected,
            label,
            EgPoint::new(25, y),
            Role::Body,
            theme::MUTED,
            theme::SURFACE,
        )
        .unwrap();
        font::right(
            &mut expected,
            value,
            EgPoint::new(215, y),
            Role::Mono,
            color,
            theme::SURFACE,
        )
        .unwrap();
    }
    let difference = actual
        .px
        .iter()
        .zip(&expected.px)
        .enumerate()
        .find(|(_, (a, b))| a != b)
        .map(|(index, (a, b))| (index, *a, *b));
    assert_eq!(difference, None);
    assert!(!actual.oob);
}

// --- Frame controls (frozen mutation roster) --------------------------------
//
// The expected frames are reconstructed from independent literals, not the applet
// constants / call sites the mutants rewrite, so any moved coordinate, flipped
// comparison or dropped unit selection fails the equality.

/// The Apps hub frame, from literals (the singular/plural unit chosen by `== 1`).
fn apps_frame(d: &mut Rec, v: &AppsView) {
    status_bar(d).unwrap();
    title_bar_wide(d, "Apps", theme::ACCENT, false).unwrap();
    let (mut b0, mut b1, mut b2) = ([0u8; 16], [0u8; 16], [0u8; 16]);
    let rows: [(Glyph, &str, &str); 3] = [
        (
            Glyph::Key,
            "OpenPGP",
            fmt_count(
                v.openpgp_keys as u16,
                if v.openpgp_keys == 1 { "key" } else { "keys" },
                &mut b0,
            ),
        ),
        (
            Glyph::Cpu,
            "PIV",
            fmt_count(
                v.piv_slots as u16,
                if v.piv_slots == 1 { "slot" } else { "slots" },
                &mut b1,
            ),
        ),
        (
            Glyph::Clock,
            "OATH",
            fmt_count(
                v.oath_codes,
                if v.oath_codes == 1 { "code" } else { "codes" },
                &mut b2,
            ),
        ),
    ];
    components::list::group_card(d, PK_LIST_TOP, 3).unwrap();
    for (i, (g, name, trailing)) in rows.into_iter().enumerate() {
        components::list::row(
            d,
            PK_LIST_TOP,
            i as u16,
            g,
            name,
            Some((trailing, MUTED)),
            true,
            true,
            false,
            false,
        )
        .unwrap();
    }
    render_nav(d, NavTab::Apps).unwrap();
}

#[test]
fn apps_hub_counts_render_the_unit_their_number_selects() {
    for v in [
        AppsView {
            openpgp_keys: 1,
            piv_slots: 1,
            oath_codes: 1,
        },
        AppsView {
            openpgp_keys: 0,
            piv_slots: 4,
            oath_codes: 2,
        },
        AppsView {
            openpgp_keys: 255,
            piv_slots: 2,
            oath_codes: 0,
        },
    ] {
        let mut actual = Rec::new();
        render_apps(&mut actual, &v).unwrap();
        let mut expected = Rec::new();
        apps_frame(&mut expected, &v);
        assert_eq!(actual.px, expected.px, "{v:?}");
        assert!(!actual.oob && !expected.oob);
    }
}

/// The OpenPGP overview frame, from literals (footer baseline `NAV_TOP - 10`, PIN
/// block flush at `PANEL_W - 13`).
fn openpgp_frame(d: &mut Rec, v: &OpenpgpView) {
    status_bar(d).unwrap();
    title_bar_wide(d, "OpenPGP", theme::ACCENT, true).unwrap();
    const NAMES: [&str; 3] = ["Signature", "Encryption", "Authentication"];
    const GLYPHS: [Glyph; 3] = [Glyph::Edit, Glyph::Lock, Glyph::Shield];
    components::list::group_card(d, PK_LIST_TOP, 4).unwrap();
    for (i, slot) in v.slots.iter().enumerate() {
        let trailing = if slot.present {
            (slot.algo.as_str(), MUTED)
        } else {
            ("—", theme::CAPTION)
        };
        components::list::row(
            d,
            PK_LIST_TOP,
            i as u16,
            GLYPHS[i],
            NAMES[i],
            Some(trailing),
            true,
            true,
            false,
            false,
        )
        .unwrap();
    }
    let ch_trailing = if v.cardholder_name.as_str().is_empty() {
        ("Not set", theme::CAPTION)
    } else {
        (v.cardholder_name.as_str(), MUTED)
    };
    components::list::row(
        d,
        PK_LIST_TOP,
        3,
        Glyph::User,
        "Card holder",
        Some(ch_trailing),
        true,
        true,
        false,
        false,
    )
    .unwrap();
    let cy = NAV_TOP as i32 - 10;
    let mut sbuf = [0u8; 16];
    text_left(
        d,
        fmt_labeled("sig", v.sig_count, &mut sbuf),
        EgPoint::new(13, cy),
        Role::Mono,
        theme::CAPTION,
    )
    .unwrap();
    let mut pbuf = [0u8; 16];
    text_right(
        d,
        fmt_pair("PIN", v.pw1, v.pw3, &mut pbuf),
        EgPoint::new(PANEL_W as i32 - 13, cy),
        Role::Mono,
        retry_color(v.pw1.min(v.pw3)),
    )
    .unwrap();
    render_nav(d, NavTab::Apps).unwrap();
}

#[test]
fn openpgp_overview_footer_sits_pinned_above_the_nav() {
    let v = OpenpgpView {
        slots: [
            PgpSlotRow {
                present: true,
                algo: Label::clamp(b"Ed25519"),
                touch: true,
            },
            PgpSlotRow::default(),
            PgpSlotRow {
                present: true,
                algo: Label::clamp(b"RSA 4096"),
                touch: false,
            },
        ],
        cardholder_name: Label::clamp(b"Ada Lovelace"),
        sig_count: 12345,
        pw1: 2,
        pw3: 2,
    };
    let mut actual = Rec::new();
    render_openpgp(&mut actual, &v).unwrap();
    let mut expected = Rec::new();
    openpgp_frame(&mut expected, &v);
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

/// One OpenPGP key's detail frame, from literals (`card_top = CONTENT_TOP + 28`,
/// `fp_top = card_top + 3 * 30 + 8 + 8`, fingerprint rows +24 / +44).
fn openpgp_key_frame(d: &mut Rec, v: &PgpKeyView) {
    status_bar(d).unwrap();
    let (title, purpose) = match v.slot {
        0 => ("Sign key", "Signs data and commits"),
        1 => ("Decrypt key", "Decrypts messages"),
        _ => ("Auth key", "SSH and authentication"),
    };
    title_bar_wide(d, title, theme::ACCENT, true).unwrap();
    text_left(
        d,
        purpose,
        EgPoint::new(14, CONTENT_TOP as i32 + 12),
        Role::Body,
        theme::MUTED,
    )
    .unwrap();
    let card_top = CONTENT_TOP + 28;
    detail_card(
        d,
        card_top,
        &[
            ("Algorithm", v.algo.as_str(), theme::TEXT),
            (
                "Touch to use",
                if v.touch { "Required" } else { "Off" },
                if v.touch {
                    theme::ACCENT_TEXT
                } else {
                    theme::MUTED
                },
            ),
            (
                "Created",
                if v.created { "Recorded" } else { "Not set" },
                theme::MUTED,
            ),
        ],
    )
    .unwrap();
    let fp_top = card_top as i32 + 3 * 30 + 8 + 8;
    text_left(
        d,
        "FINGERPRINT",
        EgPoint::new(14, fp_top),
        Role::Mono,
        theme::CAPTION,
    )
    .unwrap();
    if v.has_fp {
        let mut r0 = [0u8; 32];
        let mut r1 = [0u8; 32];
        text_left(
            d,
            fmt_hex_grouped(&v.fingerprint[..10], &mut r0),
            EgPoint::new(14, fp_top + 24),
            Role::Mono,
            theme::TEXT_2,
        )
        .unwrap();
        text_left(
            d,
            fmt_hex_grouped(&v.fingerprint[10..], &mut r1),
            EgPoint::new(14, fp_top + 44),
            Role::Mono,
            theme::TEXT_2,
        )
        .unwrap();
    } else {
        text_left(
            d,
            "Not set",
            EgPoint::new(14, fp_top + 26),
            Role::Body,
            theme::MUTED,
        )
        .unwrap();
    }
    text_left(
        d,
        "Public key is not exportable",
        EgPoint::new(14, PANEL_H as i32 - 18),
        Role::MonoSmall,
        theme::CAPTION,
    )
    .unwrap();
}

#[test]
fn openpgp_key_detail_fingerprint_and_footer_land_where_declared() {
    for has_fp in [true, false] {
        let v = PgpKeyView {
            slot: 0,
            present: true,
            algo: Label::clamp(b"Ed25519"),
            touch: true,
            created: true,
            fingerprint: core::array::from_fn(|i| i as u8),
            has_fp,
        };
        let mut actual = Rec::new();
        render_openpgp_key(&mut actual, &v).unwrap();
        let mut expected = Rec::new();
        openpgp_key_frame(&mut expected, &v);
        assert_eq!(actual.px, expected.px, "has_fp={has_fp}");
        assert!(!actual.oob && !expected.oob);
    }
}

/// The PIV overview frame, from literals (footer baseline and PUK edge).
fn piv_frame(d: &mut Rec, v: &PivView) {
    status_bar(d).unwrap();
    title_bar_wide(d, "PIV", theme::ACCENT, true).unwrap();
    const NAMES: [&str; 4] = ["Authentication", "Signature", "Key Management", "Card Auth"];
    components::list::group_card(d, PK_LIST_TOP, 5).unwrap();
    for (i, slot) in v.slots.iter().enumerate() {
        let trailing = if slot.present {
            (slot.algo.as_str(), MUTED)
        } else if slot.cert {
            ("cert", theme::CAPTION)
        } else {
            ("—", theme::CAPTION)
        };
        components::list::row(
            d,
            PK_LIST_TOP,
            i as u16,
            Glyph::Cpu,
            NAMES[i],
            Some(trailing),
            true,
            true,
            false,
            false,
        )
        .unwrap();
    }
    let mut eb = [0u8; 5];
    components::list::row(
        d,
        PK_LIST_TOP,
        4,
        Glyph::Apps,
        "Retired & F9",
        Some((fmt_u16(v.extra as u16, &mut eb), MUTED)),
        true,
        true,
        false,
        false,
    )
    .unwrap();
    let cy = NAV_TOP as i32 - 10;
    let mut a = [0u8; 12];
    text_left(
        d,
        fmt_labeled("PIN", v.pin as u32, &mut a),
        EgPoint::new(13, cy),
        Role::Mono,
        retry_color(v.pin),
    )
    .unwrap();
    let mut b = [0u8; 12];
    text_right(
        d,
        fmt_labeled("PUK", v.puk as u32, &mut b),
        EgPoint::new(PANEL_W as i32 - 13, cy),
        Role::Mono,
        retry_color(v.puk),
    )
    .unwrap();
    render_nav(d, NavTab::Apps).unwrap();
}

#[test]
fn piv_overview_footer_sits_pinned_above_the_nav() {
    let v = PivView {
        slots: [
            PivSlotRow {
                slot: 0x9A,
                present: true,
                cert: false,
                algo: Label::clamp(b"ECDSA"),
            },
            PivSlotRow {
                slot: 0x9C,
                present: false,
                cert: true,
                algo: Label::default(),
            },
            PivSlotRow::default(),
            PivSlotRow::default(),
        ],
        extra: 3,
        pin: 1,
        puk: 0,
    };
    let mut actual = Rec::new();
    render_piv(&mut actual, &v).unwrap();
    let mut expected = Rec::new();
    piv_frame(&mut expected, &v);
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

/// A populated PIV slot detail frame, from literals (`purpose` at
/// `CONTENT_TOP + 12`, the card at `CONTENT_TOP + 28`).
fn piv_slot_frame(d: &mut Rec, v: &PivSlotView) {
    status_bar(d).unwrap();
    let mut tb = [0u8; 12];
    let (title, purpose): (&str, &str) = match v.slot {
        0x9A => ("9A Auth", "Authentication / login"),
        0x9C => ("9C Sign", "Digital signatures"),
        0x9D => ("9D Key Mgmt", "Encryption / key mgmt"),
        0x9E => ("9E Card Auth", "Card auth, no PIN"),
        0xF9 => ("F9 Attestation", "Device attestation key"),
        s if (0x82..=0x95).contains(&s) => (retired_title(s, &mut tb), "Retired key-mgmt slot"),
        _ => ("PIV slot", ""),
    };
    title_bar_wide(d, title, theme::ACCENT, true).unwrap();
    text_left(
        d,
        purpose,
        EgPoint::new(14, CONTENT_TOP as i32 + 12),
        Role::Body,
        theme::MUTED,
    )
    .unwrap();
    detail_card(
        d,
        CONTENT_TOP + 28,
        &[
            ("Algorithm", v.algo.as_str(), theme::TEXT),
            ("PIN policy", v.pin_policy.as_str(), theme::MUTED),
            ("Touch policy", v.touch_policy.as_str(), theme::MUTED),
            ("Origin", v.origin.as_str(), theme::MUTED),
            (
                "Certificate",
                if v.cert { "Stored" } else { "None" },
                if v.cert {
                    theme::ACCENT_TEXT
                } else {
                    theme::CAPTION
                },
            ),
        ],
    )
    .unwrap();
}

#[test]
fn populated_piv_slot_detail_pins_its_purpose_and_card_top() {
    let v = PivSlotView {
        slot: 0x9A,
        present: true,
        cert: true,
        algo: Label::clamp(b"ECDSA"),
        pin_policy: Label::clamp(b"once"),
        touch_policy: Label::clamp(b"never"),
        origin: Label::clamp(b"generated"),
    };
    let mut actual = Rec::new();
    render_piv_slot(&mut actual, &v).unwrap();
    let mut expected = Rec::new();
    piv_slot_frame(&mut expected, &v);
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

/// The OATH page body, from literals (`total == 0` empty glyph at `MIDX - 18, 96`,
/// the footer at `NAV_TOP - 10`, the pager only past one page).
fn oath_body_frame(d: &mut Rec, rows: &[OathRow], page: u16, total: u16) {
    if total == 0 {
        glyph::draw(
            d,
            Glyph::Clock,
            Point::new(MIDX as u16 - 18, 96),
            36,
            MUTED,
            BG,
        )
        .unwrap();
        text(
            d,
            "No codes yet",
            EgPoint::new(MIDX, 160),
            Role::Body,
            MUTED,
        )
        .unwrap();
    } else {
        components::list::group_card(d, PK_LIST_TOP, rows.len() as u16).unwrap();
        for (i, r) in rows.iter().enumerate() {
            let icon = if r.touch { Glyph::Lock } else { Glyph::Clock };
            let kind = if r.hotp { "HOTP" } else { "TOTP" };
            components::list::row(
                d,
                PK_LIST_TOP,
                i as u16,
                icon,
                r.name.as_str(),
                Some((kind, MUTED)),
                true,
                true,
                false,
                r.name.truncated,
            )
            .unwrap();
        }
        if page_count(total) > 1 {
            render_pager(d, page, page_count(total)).unwrap();
        } else {
            text(
                d,
                "Codes shown in the RS-Key app",
                EgPoint::new(MIDX, NAV_TOP as i32 - 10),
                Role::MonoSmall,
                theme::CAPTION,
            )
            .unwrap();
        }
    }
}

fn oath_page_frame(d: &mut Rec, rows: &[OathRow], page: u16, total: u16) {
    status_bar(d).unwrap();
    title_bar_wide(d, "OATH", theme::ACCENT, true).unwrap();
    oath_body_frame(d, rows, page, total);
    render_nav(d, NavTab::Apps).unwrap();
}

#[test]
fn oath_empty_body_draws_its_glyph_and_caption_from_the_declared_midline() {
    let mut actual = Rec::new();
    render_oath(&mut actual, &[], 0, 0).unwrap();
    let mut expected = Rec::new();
    oath_page_frame(&mut expected, &[], 0, 0);
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

#[test]
fn oath_body_switches_between_footer_and_pager_on_the_page_count() {
    let one = [OathRow {
        name: Label::clamp(b"GitHub"),
        hotp: false,
        touch: true,
    }];
    let many: [OathRow; 5] = core::array::from_fn(|i| OathRow {
        name: Label::clamp(if i == 0 { b"HOTP token" } else { b"TOTP token" }),
        hotp: i == 0,
        touch: i % 2 == 0,
    });
    // total == 1 → one page → the "codes shown in the app" footer.
    let mut actual = Rec::new();
    render_oath(&mut actual, &one, 0, 1).unwrap();
    let mut expected = Rec::new();
    oath_page_frame(&mut expected, &one, 0, 1);
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
    // total > PK_ROWS_MAX → two pages → the pager.
    let mut actual = Rec::new();
    render_oath(&mut actual, &many, 0, (PK_ROWS_MAX + 1) as u16).unwrap();
    let mut expected = Rec::new();
    oath_page_frame(&mut expected, &many, 0, (PK_ROWS_MAX + 1) as u16);
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

/// One OATH credential's detail frame, from literals (`purpose` at
/// `CONTENT_TOP + 12`, footer at `PANEL_H - 18`).
fn oath_cred_frame(d: &mut Rec, v: &OathDetailView) {
    status_bar(d).unwrap();
    title_bar_wide_label(d, &v.name, theme::ACCENT, true).unwrap();
    let purpose = if v.hotp {
        "Counter-based \u{00B7} HOTP"
    } else {
        "Time-based \u{00B7} TOTP"
    };
    text_left(
        d,
        purpose,
        EgPoint::new(14, CONTENT_TOP as i32 + 12),
        Role::Body,
        theme::MUTED,
    )
    .unwrap();
    let mut digit_buf = [0u8; 5];
    let mut period_buf = [0u8; 8];
    let period = if v.hotp {
        "—"
    } else {
        fmt_secs(v.period, &mut period_buf)
    };
    detail_card(
        d,
        CONTENT_TOP + 28,
        &[
            ("Type", if v.hotp { "HOTP" } else { "TOTP" }, theme::TEXT),
            ("Algorithm", v.algo.as_str(), theme::TEXT),
            (
                "Digits",
                fmt_u16(v.digits as u16, &mut digit_buf),
                theme::TEXT,
            ),
            ("Period", period, theme::MUTED),
            (
                "Touch to use",
                if v.touch { "Required" } else { "Off" },
                if v.touch {
                    theme::ACCENT_TEXT
                } else {
                    theme::MUTED
                },
            ),
        ],
    )
    .unwrap();
    text_left(
        d,
        "Codes shown in the RS-Key app",
        EgPoint::new(14, PANEL_H as i32 - 18),
        Role::MonoSmall,
        theme::CAPTION,
    )
    .unwrap();
}

#[test]
fn oath_credential_purpose_and_footer_land_where_declared() {
    let v = OathDetailView {
        name: Label::clamp(b"GitHub"),
        hotp: false,
        algo: Label::clamp(b"SHA1"),
        digits: 6,
        period: 30,
        touch: true,
    };
    let mut actual = Rec::new();
    render_oath_cred(&mut actual, &v).unwrap();
    let mut expected = Rec::new();
    oath_cred_frame(&mut expected, &v);
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

/// The OpenPGP cardholder frame, from literals (captions from `CONTENT_TOP + 38`
/// stepping 46; each value clip `PANEL_W - 28` wide starting at x = 14).
fn cardholder_frame(d: &mut Rec, v: &CardholderView) {
    status_bar(d).unwrap();
    title_bar_wide(d, "Card holder", theme::ACCENT, true).unwrap();
    text_left(
        d,
        "Public card identity",
        EgPoint::new(14, CONTENT_TOP as i32 + 12),
        Role::Body,
        theme::MUTED,
    )
    .unwrap();
    let fields: [(&str, &Label); 4] = [
        ("NAME", &v.name),
        ("LOGIN", &v.login),
        ("URL", &v.url),
        ("LANGUAGE", &v.lang),
    ];
    let mut y = CONTENT_TOP as i32 + 38;
    for (cap, val) in fields {
        text_left(d, cap, EgPoint::new(14, y), Role::Mono, theme::CAPTION).unwrap();
        let (shown, color, marked) = if val.is_empty() {
            ("Not set", theme::MUTED, false)
        } else {
            (val.as_str(), theme::TEXT_2, val.truncated)
        };
        text_left_ellipsized(
            d,
            shown,
            EgPoint::new(14, y + 20),
            Role::Body,
            color,
            Rect::new(14, (y + 8) as u16, PANEL_W - 28, 24),
            marked,
        )
        .unwrap();
        y += 46;
    }
}

#[test]
fn cardholder_fields_step_down_the_page_and_clip_to_the_panel() {
    // A value past the clip width forces the ellipsis, so the clip rectangle is
    // load-bearing on the mutated side.
    let v = CardholderView {
        name: Label::clamp(b"Ada Lovelace, Countess of Computing and Mathematician"),
        login: Label::clamp(b"ada.lovelace@analytical-engine.example.invalid"),
        url: Label::clamp(b"https://example.invalid/a/very/long/cardholder/url/path"),
        lang: Label::clamp(b"en"),
        any: true,
    };
    let mut actual = Rec::new();
    render_openpgp_cardholder(&mut actual, &v).unwrap();
    let mut expected = Rec::new();
    cardholder_frame(&mut expected, &v);
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

/// The "Retired & F9" page body, from literals (`r.slot == 0xF9` picks the F9 row;
/// the pager only past one page).
fn piv_extra_body_frame(d: &mut Rec, rows: &[PivExtraRow], page: u16, total: u16) {
    components::list::group_card(d, PK_LIST_TOP, rows.len() as u16).unwrap();
    let mut tb = [0u8; 12];
    for (i, r) in rows.iter().enumerate() {
        if r.generate {
            components::list::row(
                d,
                PK_LIST_TOP,
                i as u16,
                Glyph::Key,
                "Generate key",
                None,
                true,
                true,
                false,
                false,
            )
            .unwrap();
            continue;
        }
        let (icon, label) = if r.slot == 0xF9 {
            (Glyph::Shield, "F9 Attestation")
        } else {
            (Glyph::Cpu, retired_title(r.slot, &mut tb))
        };
        let trailing = if r.present {
            (r.algo.as_str(), MUTED)
        } else if r.cert {
            ("cert", theme::CAPTION)
        } else {
            ("—", theme::CAPTION)
        };
        components::list::row(
            d,
            PK_LIST_TOP,
            i as u16,
            icon,
            label,
            Some(trailing),
            true,
            true,
            false,
            false,
        )
        .unwrap();
    }
    if page_count(total) > 1 {
        render_pager(d, page, page_count(total)).unwrap();
    }
}

fn piv_extra_frame(d: &mut Rec, rows: &[PivExtraRow], page: u16, total: u16) {
    status_bar(d).unwrap();
    title_bar_wide(d, "Retired & F9", theme::ACCENT, true).unwrap();
    piv_extra_body_frame(d, rows, page, total);
}

#[test]
fn retired_f9_rows_label_the_attestation_slot_and_page_past_one() {
    let rows = [
        PivExtraRow {
            slot: 0xF9,
            present: true,
            cert: false,
            algo: Label::clamp(b"RSA 2048"),
            generate: false,
        },
        PivExtraRow {
            slot: 0x82,
            present: false,
            cert: true,
            algo: Label::default(),
            generate: false,
        },
        PivExtraRow {
            slot: 0,
            present: false,
            cert: false,
            algo: Label::default(),
            generate: true,
        },
    ];
    let mut actual = Rec::new();
    render_piv_extra(&mut actual, &rows, 0, rows.len() as u16).unwrap();
    let mut expected = Rec::new();
    piv_extra_frame(&mut expected, &rows, 0, rows.len() as u16);
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);

    let many: [PivExtraRow; 5] = core::array::from_fn(|i| PivExtraRow {
        slot: 0x82 + i as u8,
        present: i % 2 == 0,
        cert: false,
        algo: Label::clamp(b"Ed25519"),
        generate: false,
    });
    let mut actual = Rec::new();
    render_piv_extra(&mut actual, &many, 0, (PK_ROWS_MAX + 1) as u16).unwrap();
    let mut expected = Rec::new();
    piv_extra_frame(&mut expected, &many, 0, (PK_ROWS_MAX + 1) as u16);
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

/// The keygen algorithm chooser frame, from literals (`purpose` at
/// `CONTENT_TOP + 12`, footer at `PANEL_H - 18`, its clip `PANEL_H - 30`).
fn keygen_pick_frame(d: &mut Rec, slot: u8) {
    status_bar(d).unwrap();
    title_bar_wide(d, "New key", theme::ACCENT, true).unwrap();
    let mut tb = [0u8; 12];
    text_left(
        d,
        retired_title(slot, &mut tb),
        EgPoint::new(14, CONTENT_TOP as i32 + 12),
        Role::Body,
        theme::MUTED,
    )
    .unwrap();
    components::list::group_card(d, PIV_KEYGEN_PICK_TOP, 5).unwrap();
    for (i, (label, trailing)) in [
        ("NIST P-256", "fast"),
        ("NIST P-384", "stronger"),
        ("Ed25519", "EdDSA"),
        ("X25519", "ECDH"),
        ("RSA", "2048-4096"),
    ]
    .into_iter()
    .enumerate()
    {
        components::list::row(
            d,
            PIV_KEYGEN_PICK_TOP,
            i as u16,
            Glyph::Cpu,
            label,
            Some((trailing, theme::CAPTION)),
            true,
            true,
            false,
            false,
        )
        .unwrap();
    }
    text_left_ellipsized(
        d,
        "Generated on-device, never leaves it",
        EgPoint::new(14, PANEL_H as i32 - 18),
        Role::MonoSmall,
        theme::CAPTION,
        Rect::new(14, PANEL_H - 30, PANEL_W - 28, 24),
        false,
    )
    .unwrap();
}

#[test]
fn keygen_pick_purpose_and_footer_land_where_declared() {
    let mut actual = Rec::new();
    render_piv_keygen_pick(&mut actual, 0x83).unwrap();
    let mut expected = Rec::new();
    keygen_pick_frame(&mut expected, 0x83);
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

/// The RSA size sub-picker frame, from literals (footer at `PANEL_H - 18`).
fn keygen_rsa_pick_frame(d: &mut Rec, slot: u8) {
    status_bar(d).unwrap();
    title_bar_wide(d, "RSA size", theme::ACCENT, true).unwrap();
    let mut tb = [0u8; 12];
    text_left(
        d,
        retired_title(slot, &mut tb),
        EgPoint::new(14, CONTENT_TOP as i32 + 12),
        Role::Body,
        theme::MUTED,
    )
    .unwrap();
    components::list::group_card(d, PIV_KEYGEN_PICK_TOP, 3).unwrap();
    for (i, (label, trailing)) in [
        ("RSA 2048", "slow"),
        ("RSA 3072", "slower"),
        ("RSA 4096", "slowest"),
    ]
    .into_iter()
    .enumerate()
    {
        components::list::row(
            d,
            PIV_KEYGEN_PICK_TOP,
            i as u16,
            Glyph::Cpu,
            label,
            Some((trailing, theme::CAPTION)),
            true,
            true,
            false,
            false,
        )
        .unwrap();
    }
    text_left(
        d,
        "Larger keys take much longer",
        EgPoint::new(14, PANEL_H as i32 - 18),
        Role::MonoSmall,
        theme::CAPTION,
    )
    .unwrap();
}

#[test]
fn keygen_rsa_pick_purpose_and_footer_land_where_declared() {
    let mut actual = Rec::new();
    render_piv_keygen_rsa_pick(&mut actual, 0x82).unwrap();
    let mut expected = Rec::new();
    keygen_rsa_pick_frame(&mut expected, 0x82);
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}

/// The PIV PIN menu frame, from literals (footer at `PANEL_H - 18`).
fn piv_pin_menu_frame(d: &mut Rec) {
    status_bar(d).unwrap();
    title_bar_wide(d, "PIV PIN", theme::ACCENT, true).unwrap();
    components::list::group_card(d, PIV_KEYGEN_PICK_TOP, 4).unwrap();
    components::list::row(
        d,
        PIV_KEYGEN_PICK_TOP,
        0,
        Glyph::Lock,
        "Change PIN",
        None,
        true,
        true,
        false,
        false,
    )
    .unwrap();
    components::list::row(
        d,
        PIV_KEYGEN_PICK_TOP,
        1,
        Glyph::Key,
        "Change PUK",
        None,
        true,
        true,
        false,
        false,
    )
    .unwrap();
    components::list::row(
        d,
        PIV_KEYGEN_PICK_TOP,
        2,
        Glyph::Lifebuoy,
        "Unblock PIN",
        Some(("with PUK", theme::CAPTION)),
        true,
        true,
        false,
        false,
    )
    .unwrap();
    components::list::row(
        d,
        PIV_KEYGEN_PICK_TOP,
        3,
        Glyph::Shield,
        "Protect mgmt key",
        None,
        true,
        true,
        false,
        false,
    )
    .unwrap();
    text_left(
        d,
        "PIN / PUK / management key",
        EgPoint::new(14, PANEL_H as i32 - 18),
        Role::MonoSmall,
        theme::CAPTION,
    )
    .unwrap();
}

#[test]
fn piv_pin_menu_footer_lands_where_declared() {
    let mut actual = Rec::new();
    render_piv_pin_menu(&mut actual).unwrap();
    let mut expected = Rec::new();
    piv_pin_menu_frame(&mut expected);
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob && !expected.oob);
}
