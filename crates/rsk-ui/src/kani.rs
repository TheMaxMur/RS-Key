// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// `clamp` is total and its output is always bounded and printable 7-bit
/// ASCII — and since printable ASCII is a subset of UTF-8, that is exactly
/// what makes `as_str` infallible (verified concretely in the unit tests; we
/// keep `from_utf8` out of the proof, where CBMC would unwind its validation
/// loop unboundedly). Proven over a symbolic source one byte longer than the
/// cap, which exercises both the in-bounds copy and the truncation edge.
#[kani::proof]
fn clamp_sanitizes_and_bounds() {
    let src: [u8; LABEL_MAX + 1] = kani::any();
    let label = Label::clamp(&src);
    assert!(label.len <= LABEL_MAX);
    // Every kept byte is printable 7-bit ASCII.
    let mut i = 0;
    while i < label.len {
        assert!((0x20..=0x7E).contains(&label.buf[i]));
        i += 1;
    }
    // A source past the cap is flagged and cut exactly at the cap.
    assert!(label.truncated);
    assert!(label.len == LABEL_MAX);
}

/// `clamp_domain` is total and bounded like [`clamp_sanitizes_and_bounds`], but keeps
/// the **tail**: over a symbolic source one byte past the cap it drops the head byte
/// and the kept bytes are exactly the sanitized `src[1..]`, so a domain's registrable
/// suffix is never the part cut.
#[kani::proof]
fn clamp_domain_sanitizes_bounds_and_keeps_tail() {
    let src: [u8; LABEL_MAX + 1] = kani::any();
    let label = Label::clamp_domain(&src);
    assert!(label.len <= LABEL_MAX);
    let mut i = 0;
    while i < label.len {
        assert!((0x20..=0x7E).contains(&label.buf[i]));
        i += 1;
    }
    // A source past the cap is flagged and cut to exactly the cap.
    assert!(label.truncated);
    assert!(label.len == LABEL_MAX);
    // The kept bytes are the tail: buf[j] is the sanitized src[j + 1] (src[0] dropped).
    let mut j = 0;
    while j < LABEL_MAX {
        let s = src[j + 1];
        let expect = if (0x20..=0x7E).contains(&s) { s } else { b'?' };
        assert!(label.buf[j] == expect);
        j += 1;
    }
}

/// The Allow and Deny hit regions are disjoint, so no tap can select both.
#[kani::proof]
fn confirm_buttons_disjoint() {
    let p = Point::new(kani::any(), kani::any());
    assert!(!(ALLOW_RECT.contains(p) && DENY_RECT.contains(p)));
}

/// No tap selects two PIN-pad keys at once: the Cancel target is disjoint from
/// every grid key, and any two distinct grid cells are disjoint — so `hit_pin`
/// maps a tap to at most one key (a stray touch can't enter a digit *and*
/// commit).
#[kani::proof]
fn pin_keys_disjoint() {
    let p = Point::new(kani::any(), kani::any());
    let mut r = 0;
    while r < PIN_ROWS {
        let mut c = 0;
        while c < PIN_COLS {
            assert!(!(PIN_CANCEL_RECT.contains(p) && pin_key_rect(c, r).contains(p)));
            c += 1;
        }
        r += 1;
    }
    let (c1, r1): (u16, u16) = (kani::any(), kani::any());
    let (c2, r2): (u16, u16) = (kani::any(), kani::any());
    kani::assume(c1 < PIN_COLS && r1 < PIN_ROWS && c2 < PIN_COLS && r2 < PIN_ROWS);
    kani::assume((c1, r1) != (c2, r2));
    assert!(!(pin_key_rect(c1, r1).contains(p) && pin_key_rect(c2, r2).contains(p)));
    // The reveal (eye) toggle never overlaps Cancel or any grid key, so peeking at the
    // PIN can't enter a digit, commit, or cancel.
    assert!(!(PIN_EYE_RECT.contains(p) && PIN_CANCEL_RECT.contains(p)));
    let (c, r): (u16, u16) = (kani::any(), kani::any());
    kani::assume(c < PIN_COLS && r < PIN_ROWS);
    assert!(!(PIN_EYE_RECT.contains(p) && pin_key_rect(c, r).contains(p)));
}

/// No tap selects two settings controls at once: any two distinct Root rows are
/// disjoint, and the −/+/Back adjust controls are mutually disjoint — so a stray
/// touch can't, say, both decrement and go Back.
#[kani::proof]
fn settings_keys_disjoint() {
    let p = Point::new(kani::any(), kani::any());
    let (i, j): (u16, u16) = (kani::any(), kani::any());
    kani::assume(i < SETTINGS_ROWS && j < SETTINGS_ROWS && i != j);
    assert!(!(settings_row_rect(i).contains(p) && settings_row_rect(j).contains(p)));
    assert!(!(ADJ_MINUS_RECT.contains(p) && ADJ_PLUS_RECT.contains(p)));
    assert!(!(ADJ_MINUS_RECT.contains(p) && TITLE_BACK_RECT.contains(p)));
    assert!(!(ADJ_PLUS_RECT.contains(p) && TITLE_BACK_RECT.contains(p)));
}

/// No tap selects two nav tabs at once, and no tap selects two list rows at once
/// (for any first-row offset) — so the design-system navigation can't misfire.
#[kani::proof]
fn nav_and_rows_disjoint() {
    let p = Point::new(kani::any(), kani::any());
    let (i, j): (u16, u16) = (kani::any(), kani::any());
    kani::assume(i < 3 && j < 3 && i != j);
    assert!(!(nav_tab_rect(i).contains(p) && nav_tab_rect(j).contains(p)));

    let y0: u16 = kani::any();
    kani::assume(y0 <= PANEL_H);
    let (a, b): (u16, u16) = (kani::any(), kani::any());
    kani::assume(a < 8 && b < 8 && a != b);
    assert!(!(row_rect(y0, a).contains(p) && row_rect(y0, b).contains(p)));
}

/// The service-detail back chevron can't be confused with a passkey row tap or a
/// nav-bar tap, so returning to the list never collides with selecting one.
#[kani::proof]
fn passkeys_back_clear_of_rows_and_nav() {
    let p = Point::new(kani::any(), kani::any());
    let i: u16 = kani::any();
    kani::assume((i as usize) < PK_ROWS_MAX);
    assert!(!(hit_pk_back(p) && row_rect(PK_LIST_TOP, i).contains(p)));
    assert!(!(hit_pk_back(p) && p.y >= NAV_TOP));
}

/// The title-bar back chevron (a pushed tab screen's "return" affordance) can't be
/// confused with a content row tap or a nav-bar tap, so returning to the parent
/// screen never collides with selecting a row or switching tabs.
#[kani::proof]
fn title_back_clear_of_rows_and_nav() {
    let p = Point::new(kani::any(), kani::any());
    let i: u16 = kani::any();
    kani::assume((i as usize) < PK_ROWS_MAX);
    assert!(!(hit_title_back(p) && row_rect(PK_LIST_TOP, i).contains(p)));
    assert!(!(hit_title_back(p) && p.y >= NAV_TOP));
}

/// On the Confirm-Delete screen the destructive hold button and the cancel
/// (back) chevron are disjoint, so no tap can both cancel and start a delete.
#[kani::proof]
fn del_hold_clear_of_back() {
    let p = Point::new(kani::any(), kani::any());
    assert!(!(hit_del_hold(p) && hit_pk_back(p)));
}

/// The pager arrows are mutually exclusive and never collide with a list row or the
/// nav bar, so paging can't be mistaken for selecting a row or switching tabs.
#[kani::proof]
fn pager_clear_of_rows_and_nav() {
    let p = Point::new(kani::any(), kani::any());
    let i: u16 = kani::any();
    kani::assume((i as usize) < PK_ROWS_MAX);
    assert!(!(PAGER_PREV_RECT.contains(p) && PAGER_NEXT_RECT.contains(p)));
    assert!(!(hit_pager(p).is_some() && row_rect(PK_LIST_TOP, i).contains(p)));
    assert!(!(hit_pager(p).is_some() && p.y >= NAV_TOP));
}

/// On the rename screen no tap maps to two wheel keys, and a wheel tap never also
/// T9 keypad keys + back chevron are pairwise disjoint — no tap can be ambiguous.
#[kani::proof]
fn rename_keys_are_unambiguous() {
    let p = Point::new(kani::any(), kani::any());
    // Check all 12 keypad keys are disjoint
    let mut hits = 0u32;
    for row in 0..4u16 {
        for col in 0..3u16 {
            if t9_key_rect(row, col).contains(p) {
                hits += 1;
            }
        }
    }
    assert!(hits <= 1);
    assert!(!(hit_rename(p).is_some() && hit_title_back(p)));
}
