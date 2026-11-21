// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn passkey_updates_independently_change_rows_page_total_and_empty_state() {
    let rows = [
        RpRow {
            id: Label::clamp(b"a.example"),
            nick: Label::default(),
            accounts: 1,
        },
        RpRow {
            id: Label::clamp(b"b.example"),
            nick: Label::default(),
            accounts: 2,
        },
    ];
    let first = [
        RpRow {
            nick: Label::clamp(b"Work"),
            ..rows[0]
        },
        rows[1],
    ];
    let second = [
        rows[0],
        RpRow {
            accounts: 1,
            ..rows[1]
        },
    ];
    for (before, old_page, old_total, after, page, total) in [
        (&rows[..], 0, 7, &rows[..], 0, 7),
        (&rows[..], 0, 7, &first[..], 0, 7),
        (&rows[..], 0, 7, &second[..], 0, 7),
        (&rows[..], 0, 7, &rows[..], 1, 7),
        (&rows[..], 0, 2, &rows[..], 0, 7),
        (&rows[..], 0, 7, &rows[..1], 1, 7),
        (&rows[..], 0, 2, &[][..], 0, 0),
        (&[][..], 0, 0, &rows[..], 0, 2),
    ] {
        let mut actual = Rec::new();
        render_passkeys_list(&mut actual, before, old_page, old_total).unwrap();
        actual.reset_writes();
        render_passkeys_page(&mut actual, before, old_page, old_total, after, page, total).unwrap();
        let mut expected = Rec::new();
        render_passkeys_list(&mut expected, after, page, total).unwrap();
        assert_eq!(
            actual.px, expected.px,
            "passkey update omitted visible state"
        );
        assert!(!actual.oob && !expected.oob);
        assert!(!actual.wrote_outside(PAGED_BODY_RECT));
        assert_eq!(
            actual.wrote_anything(),
            before != after || old_page != page || old_total != total
        );
        if before.len() == after.len() && !after.is_empty() {
            for (i, (old, new)) in before.iter().zip(after).enumerate() {
                if old == new {
                    assert!(
                        !actual.wrote_in(crate::row_rect(PK_LIST_TOP, u16::try_from(i).unwrap())),
                        "an unchanged RP row was repainted"
                    );
                }
            }
        }
    }
}

#[test]
fn service_updates_independently_change_identity_protection_page_total_and_count() {
    let rows = [
        AccountRow {
            name: Label::clamp(b"Alice"),
            protected: false,
        },
        AccountRow {
            name: Label::clamp(b"Bob"),
            protected: true,
        },
    ];
    let first = [
        AccountRow {
            protected: true,
            ..rows[0]
        },
        rows[1],
    ];
    let second = [
        rows[0],
        AccountRow {
            name: Label::clamp(b"Carol"),
            ..rows[1]
        },
    ];
    let title = Label::clamp(b"service.example");
    for (before, old_page, old_total, after, page, total) in [
        (&rows[..], 0, 7, &rows[..], 0, 7),
        (&rows[..], 0, 7, &first[..], 0, 7),
        (&rows[..], 0, 7, &second[..], 0, 7),
        (&rows[..], 0, 7, &rows[..], 1, 7),
        (&rows[..], 0, 2, &rows[..], 0, 7),
        (&rows[..], 0, 7, &rows[..1], 1, 7),
        (&rows[..], 0, 2, &[][..], 0, 0),
        (&[][..], 0, 0, &rows[..], 0, 2),
    ] {
        let mut actual = Rec::new();
        render_service(&mut actual, &title, false, before, old_page, old_total).unwrap();
        actual.reset_writes();
        render_service_page(&mut actual, before, old_page, old_total, after, page, total).unwrap();
        let mut expected = Rec::new();
        render_service(&mut expected, &title, false, after, page, total).unwrap();
        assert_eq!(
            actual.px, expected.px,
            "service update omitted visible state"
        );
        assert!(!actual.oob && !expected.oob);
        assert!(!actual.wrote_outside(PAGED_BODY_RECT));
        assert_eq!(
            actual.wrote_anything(),
            before != after || old_page != page || old_total != total
        );
        if before.len() == after.len() && !after.is_empty() {
            for (i, (old, new)) in before.iter().zip(after).enumerate() {
                if old == new {
                    assert!(
                        !actual.wrote_in(crate::row_rect(PK_LIST_TOP, u16::try_from(i).unwrap())),
                        "an unchanged account row was repainted"
                    );
                }
            }
        }
    }
}
