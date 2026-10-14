// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

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
