// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn clamp_passes_printable_ascii() {
    let l = Label::clamp(b"github.com");
    assert_eq!(l.as_str(), "github.com");
    assert!(!l.truncated);
}

#[test]
fn clamp_replaces_control_and_high_bytes() {
    // tab, newline, DEL, a high byte, and a UTF-8 lead byte all become '?'.
    let l = Label::clamp(b"a\tb\nc\x7fd\xffe\xc3\xa9");
    assert_eq!(l.as_str(), "a?b?c?d?e??");
}

#[test]
fn clamp_strips_terminal_escape() {
    // An ANSI escape sequence must not survive to the renderer.
    let l = Label::clamp(b"\x1b[31mevil\x1b[0m");
    assert_eq!(l.as_str(), "?[31mevil?[0m");
}

#[test]
fn clamp_truncates_and_flags() {
    let src = [b'a'; LABEL_MAX + 10];
    let l = Label::clamp(&src);
    assert_eq!(l.as_str().len(), LABEL_MAX);
    assert!(l.truncated);
}

#[test]
fn clamp_empty_is_empty() {
    let l = Label::clamp(b"");
    assert!(l.is_empty());
    assert_eq!(l.as_str(), "");
    assert!(!l.truncated);
}

#[test]
fn clamp_exactly_max_not_truncated() {
    let src = [b'x'; LABEL_MAX];
    let l = Label::clamp(&src);
    assert_eq!(l.as_str().len(), LABEL_MAX);
    assert!(!l.truncated);
}

#[test]
fn clamp_domain_keeps_short_id_whole() {
    let l = Label::clamp_domain(b"github.com");
    assert_eq!(l.as_str(), "github.com");
    assert!(!l.truncated);
}

#[test]
fn clamp_domain_keeps_the_registrable_suffix_not_the_head() {
    // The anti-phishing case: a look-alike pads the head, but the registrable domain
    // is the rightmost part. clamp_domain must keep the tail and flag the cut, so the
    // real domain (`attacker.com`) is never the part dropped.
    const SUF: &[u8] = b".attacker.com";
    let mut src = [b'a'; LABEL_MAX + SUF.len()]; // longer than LABEL_MAX → head is cut
    src[LABEL_MAX..].copy_from_slice(SUF);
    let l = Label::clamp_domain(&src);
    assert!(l.truncated);
    assert_eq!(l.as_str().len(), LABEL_MAX);
    assert!(
        l.as_str().ends_with(".attacker.com"),
        "kept text must end with the registrable domain, got {:?}",
        l.as_str()
    );
}

#[test]
fn clamp_domain_exactly_max_not_truncated() {
    let src = [b'x'; LABEL_MAX];
    let l = Label::clamp_domain(&src);
    assert_eq!(l.as_str().len(), LABEL_MAX);
    assert!(!l.truncated);
}

#[test]
fn clamp_domain_sanitizes_the_kept_tail() {
    // Control/high bytes in the kept tail still become '?'.
    let l = Label::clamp_domain(b"ok\x1b\xff.com");
    assert_eq!(l.as_str(), "ok??.com");
    assert!(!l.truncated);
}

#[test]
fn confirm_prompt_sanitizes_both_fields() {
    let p = ConfirmPrompt::new("Sign in?", b"login.example\x00", b"al\x1bice");
    assert_eq!(p.primary.as_str(), "login.example?");
    assert_eq!(p.secondary.as_str(), "al?ice");
    assert_eq!(p.title, "Sign in?");
}

#[test]
fn hit_centres_of_each_button() {
    let deny_c = Point::new(DENY_RECT.x + DENY_RECT.w / 2, DENY_RECT.y + BTN_H / 2);
    let allow_c = Point::new(ALLOW_RECT.x + ALLOW_RECT.w / 2, ALLOW_RECT.y + BTN_H / 2);
    assert_eq!(hit_confirm(deny_c), Some(Button::Deny));
    assert_eq!(hit_confirm(allow_c), Some(Button::Allow));
}

#[test]
fn hit_onboard_maps_each_stacked_button() {
    let set_c = Point::new(
        ONBOARD_SET_RECT.x + ONBOARD_SET_RECT.w / 2,
        ONBOARD_SET_RECT.y + ONBOARD_SET_RECT.h / 2,
    );
    let skip_c = Point::new(
        ONBOARD_SKIP_RECT.x + ONBOARD_SKIP_RECT.w / 2,
        ONBOARD_SKIP_RECT.y + ONBOARD_SKIP_RECT.h / 2,
    );
    assert_eq!(hit_onboard(set_c), Some(OnboardChoice::SetPin));
    assert_eq!(hit_onboard(skip_c), Some(OnboardChoice::Skip));
    // The gap between the two stacked buttons selects nothing.
    let gap_y = ONBOARD_SET_RECT.y + ONBOARD_SET_RECT.h + 2;
    assert_eq!(hit_onboard(Point::new(PANEL_W / 2, gap_y)), None);
    // Above the prompt's button area, too.
    assert_eq!(hit_onboard(Point::new(PANEL_W / 2, 0)), None);
}

#[test]
fn taps_off_the_floating_buttons_select_nothing() {
    let mid_h = BTN_BAND_TOP + BTN_H / 2;
    // Above the button row (the prompt area).
    assert_eq!(hit_confirm(Point::new(PANEL_W / 2, BTN_BAND_TOP - 1)), None);
    assert_eq!(hit_confirm(Point::new(0, 0)), None);
    // The gap between Deny and the (wider) Hold-to-approve button.
    let gap_x = DENY_RECT.x + DENY_RECT.w + 2;
    assert_eq!(hit_confirm(Point::new(gap_x, mid_h)), None);
    // The left and right side margins, at button height.
    assert_eq!(hit_confirm(Point::new(2, mid_h)), None);
    assert_eq!(hit_confirm(Point::new(PANEL_W - 2, mid_h)), None);
    // Below the floating buttons (the bottom margin).
    assert_eq!(hit_confirm(Point::new(PANEL_W / 2, PANEL_H - 1)), None);
}

#[test]
fn rect_contains_edges() {
    let r = Rect::new(10, 20, 30, 40);
    assert!(r.contains(Point::new(10, 20))); // top-left inclusive
    assert!(!r.contains(Point::new(40, 20))); // right exclusive (10+30)
    assert!(!r.contains(Point::new(10, 60))); // bottom exclusive (20+40)
    assert!(r.contains(Point::new(39, 59)));
}

#[test]
fn pin_key_centers_hit_their_keys() {
    // Every grid key's center hits exactly that key.
    for row in 0..PIN_ROWS {
        for col in 0..PIN_COLS {
            let r = pin_key_rect(col, row);
            let c = Point::new(r.x + PIN_KEY_W / 2, r.y + PIN_KEY_H / 2);
            assert_eq!(hit_pin(c), Some(pin_grid_key(col, row)));
        }
    }
    // Layout: rows 0–2 are digits 1–9 in reading order; the bottom row is Del/0/OK.
    assert_eq!(pin_grid_key(0, 0), PinKey::Digit(1));
    assert_eq!(pin_grid_key(2, 2), PinKey::Digit(9));
    assert_eq!(pin_grid_key(0, 3), PinKey::Del);
    assert_eq!(pin_grid_key(1, 3), PinKey::Digit(0));
    assert_eq!(pin_grid_key(2, 3), PinKey::Ok);
}

#[test]
fn pin_cancel_hits_and_gaps_select_nothing() {
    let c = PIN_CANCEL_RECT;
    assert_eq!(
        hit_pin(Point::new(c.x + c.w / 2, c.y + c.h / 2)),
        Some(PinKey::Cancel)
    );
    // The gap between column 0 and column 1 selects nothing.
    let k = pin_key_rect(0, 0);
    assert_eq!(hit_pin(Point::new(k.x + PIN_KEY_W + 1, k.y + 2)), None);
    // Below the grid (bottom-left margin) selects nothing.
    assert_eq!(hit_pin(Point::new(0, PANEL_H - 1)), None);
    // The eye toggle, between the header and the grid, maps to Reveal.
    let e = PIN_EYE_RECT;
    assert_eq!(
        hit_pin(Point::new(e.x + e.w / 2, e.y + e.h / 2)),
        Some(PinKey::Reveal)
    );
}

#[test]
fn pin_grid_is_horizontally_centred() {
    // The pad's left and right margins are equal, so the 3×4 grid sits centred on the
    // panel at the design's 7px gap. Guards PIN_GRID_X0 / PIN_GAP_X / PIN_KEY_W from
    // drifting out of balance (e.g. tightening the gap without re-deriving the origin).
    let left = pin_key_rect(0, 0);
    let right = pin_key_rect(PIN_COLS - 1, 0);
    assert_eq!(left.x, PANEL_W - (right.x + right.w));
}

#[test]
fn settings_root_rows_map_in_order() {
    let want = [RootEntry::Display, RootEntry::Security, RootEntry::Firmware];
    assert_eq!(want.len() as u16, SETTINGS_ROWS);
    for (i, &e) in want.iter().enumerate() {
        let r = settings_row_rect(i as u16);
        let c = Point::new(r.x + r.w / 2, r.y + r.h / 2);
        assert_eq!(hit_settings_root(c), Some(e));
        assert_eq!(settings_row_entry(i as u16), e);
    }
    // The gap between two rows selects nothing.
    let r0 = settings_row_rect(0);
    assert_eq!(
        hit_settings_root(Point::new(r0.x + r0.w / 2, r0.y + r0.h + 1)),
        None
    );
    // Above the list (header area) selects nothing.
    assert_eq!(hit_settings_root(Point::new(PANEL_W / 2, 10)), None);
}

#[test]
fn display_rows_map_in_order() {
    let want = [
        DisplayEntry::Brightness,
        DisplayEntry::Sleep,
        DisplayEntry::Timeout,
    ];
    assert_eq!(want.len() as u16, DISPLAY_ROWS);
    for (i, &e) in want.iter().enumerate() {
        let r = settings_row_rect(i as u16);
        let c = Point::new(r.x + r.w / 2, r.y + r.h / 2);
        assert_eq!(hit_display(c), Some(e));
        assert_eq!(display_row_entry(i as u16), e);
    }
    // The gap between two rows selects nothing.
    let r0 = settings_row_rect(0);
    assert_eq!(
        hit_display(Point::new(r0.x + r0.w / 2, r0.y + r0.h + 1)),
        None
    );
}

#[test]
fn security_rows_map_in_order() {
    let want = [
        SecurityEntry::DevicePin,
        SecurityEntry::FidoPin,
        SecurityEntry::PivPin,
        SecurityEntry::AuditLog,
        SecurityEntry::Backup,
        SecurityEntry::FactoryReset,
    ];
    for (i, &e) in want.iter().enumerate() {
        let r = settings_row_rect(i as u16);
        let c = Point::new(r.x + r.w / 2, r.y + r.h / 2);
        assert_eq!(hit_security(c), Some(e));
        assert_eq!(security_row_entry(i as u16), e);
    }
    // A tap past the Security rows (a later Root slot) selects no Security entry.
    let beyond = settings_row_rect(SECURITY_ROWS);
    assert_eq!(
        hit_security(Point::new(beyond.x + beyond.w / 2, beyond.y + beyond.h / 2)),
        None
    );
}

fn ctr(r: Rect) -> Point {
    Point::new(r.x + r.w / 2, r.y + r.h / 2)
}

#[test]
fn backup_format_cards_map() {
    assert_eq!(
        hit_backup_format(ctr(FMT_PHRASE_RECT)),
        Some(BackupFormat::Phrase)
    );
    assert_eq!(
        hit_backup_format(ctr(FMT_SHARES_RECT)),
        Some(BackupFormat::Shares)
    );
    // The gap between the two cards selects neither.
    let gap = Point::new(FMT_PHRASE_RECT.x, FMT_PHRASE_RECT.y + FMT_PHRASE_RECT.h + 1);
    assert_eq!(hit_backup_format(gap), None);
}

#[test]
fn share_picker_controls_map_to_their_rects() {
    for (r, k) in [
        (PICK_T_MINUS_RECT, ShareAdjust::TMinus),
        (PICK_T_PLUS_RECT, ShareAdjust::TPlus),
        (PICK_N_MINUS_RECT, ShareAdjust::NMinus),
        (PICK_N_PLUS_RECT, ShareAdjust::NPlus),
        (PICK_CONTINUE_RECT, ShareAdjust::Continue),
    ] {
        assert_eq!(hit_share_picker(ctr(r)), Some(k));
    }
    // The centre of the panel (between the two steppers) hits no control.
    assert_eq!(hit_share_picker(Point::new(PANEL_W / 2, 130)), None);
}

#[test]
fn step_share_params_keeps_a_valid_split() {
    // Default 2-of-3 is reachable and a valid split.
    let (t, n) = (2u8, 3u8);
    assert!(SHARE_MIN <= t && t <= n && n <= SHARE_MAX);

    // Raising T past N drags N up with it; never exceeds SHARE_MAX.
    let mut p = (3u8, 3u8);
    p = step_share_params(p.0, p.1, ShareAdjust::TPlus);
    assert_eq!(p, (4, 4));
    // Lowering N below T drags T down with it.
    let mut q = (3u8, 4u8);
    q = step_share_params(q.0, q.1, ShareAdjust::NMinus);
    assert_eq!(q, (3, 3));

    // Clamps: T floors at SHARE_MIN, N ceils at SHARE_MAX.
    assert_eq!(
        step_share_params(SHARE_MIN, 3, ShareAdjust::TMinus),
        (SHARE_MIN, 3)
    );
    assert_eq!(
        step_share_params(2, SHARE_MAX, ShareAdjust::NPlus),
        (2, SHARE_MAX)
    );

    // Exhaustive: every step from every valid (T,N) yields a valid (T,N).
    for t in SHARE_MIN..=SHARE_MAX {
        for n in t..=SHARE_MAX {
            for k in [
                ShareAdjust::TMinus,
                ShareAdjust::TPlus,
                ShareAdjust::NMinus,
                ShareAdjust::NPlus,
                ShareAdjust::Continue,
            ] {
                let (rt, rn) = step_share_params(t, n, k);
                assert!(
                    SHARE_MIN <= rt && rt <= rn && rn <= SHARE_MAX,
                    "step {k:?} from ({t},{n}) -> ({rt},{rn}) is not a valid split"
                );
            }
        }
    }
}

#[test]
fn adjust_controls_hit_their_keys() {
    let centers = [
        (ADJ_MINUS_RECT, AdjustKey::Minus),
        (ADJ_PLUS_RECT, AdjustKey::Plus),
        (TITLE_BACK_RECT, AdjustKey::Back),
    ];
    for (r, key) in centers {
        assert_eq!(
            hit_adjust(Point::new(r.x + r.w / 2, r.y + r.h / 2)),
            Some(key)
        );
    }
    // The gap between − and + selects nothing.
    let gap_x = ADJ_MINUS_RECT.x + ADJ_MINUS_RECT.w + 1;
    assert_eq!(hit_adjust(Point::new(gap_x, ADJ_Y + ADJ_H / 2)), None);
}

#[test]
fn hex_helpers_are_lowercase_ascii() {
    assert_eq!(core::str::from_utf8(&hex_u16(0x078A)).unwrap(), "078a");
    assert_eq!(core::str::from_utf8(&hex_u16(0)).unwrap(), "0000");
    assert_eq!(core::str::from_utf8(&hex_u16(0xFFFF)).unwrap(), "ffff");
    assert_eq!(
        core::str::from_utf8(&hex_u64(0x0123_4567_89ab_cdef)).unwrap(),
        "0123456789abcdef"
    );
}

#[test]
fn timeout_choices_are_sorted_and_nonzero() {
    // The timeout page steps through these; a non-monotone or zero entry would
    // make −/+ misbehave.
    assert!(TIMEOUT_CHOICES.windows(2).all(|w| w[0] < w[1]));
    assert!(TIMEOUT_CHOICES.iter().all(|&s| s > 0));
    // BRIGHTNESS_LEVELS >= 1 is a compile-time invariant (the const block above),
    // so it needs no runtime assert here.
}

#[test]
fn step_brightness_clamps_at_both_ends() {
    assert_eq!(step_brightness(1, -1), 1);
    assert_eq!(step_brightness(BRIGHTNESS_LEVELS, 1), BRIGHTNESS_LEVELS);
    assert_eq!(step_brightness(3, 1), 4);
    assert_eq!(step_brightness(3, -1), 2);
}

#[test]
fn step_timeout_steps_clamps_and_snaps() {
    // An exact-listed value steps to its neighbour.
    assert_eq!(step_timeout(30, 1), 60);
    assert_eq!(step_timeout(30, -1), 20);
    // Clamps at both ends of the choice list.
    let last = TIMEOUT_CHOICES[TIMEOUT_CHOICES.len() - 1];
    assert_eq!(step_timeout(TIMEOUT_CHOICES[0], -1), TIMEOUT_CHOICES[0]);
    assert_eq!(step_timeout(last, 1), last);
    // A non-listed current value (e.g. a 5 s phy override) snaps to nearest (10)
    // before stepping.
    assert_eq!(step_timeout(5, -1), 10);
    assert_eq!(step_timeout(5, 1), 20);
}

#[test]
fn step_sleep_walks_durations_and_off() {
    // Steps between adjacent durations.
    assert_eq!(step_sleep(30, 1), 60);
    assert_eq!(step_sleep(60, -1), 30);
    // The longest real duration (300) steps up to Off (0), and Off steps back down.
    assert_eq!(step_sleep(300, 1), 0);
    assert_eq!(step_sleep(0, -1), 300);
    // Clamps at both ends.
    assert_eq!(step_sleep(15, -1), 15);
    assert_eq!(step_sleep(0, 1), 0);
    // A non-listed value snaps to the nearest real duration before stepping (and
    // never mis-snaps to the Off sentinel).
    assert_eq!(step_sleep(20, 1), 30);
    assert_eq!(step_sleep(20, -1), 15);
}

#[test]
fn nav_tabs_map_left_to_right() {
    for (i, &tab) in NAV_TABS.iter().enumerate() {
        let r = nav_tab_rect(i as u16);
        let c = Point::new(r.x + r.w / 2, r.y + r.h / 2);
        assert_eq!(hit_nav(c), Some(tab));
    }
    // A tap above the nav bar selects no tab.
    assert_eq!(hit_nav(Point::new(PANEL_W / 2, NAV_TOP - 1)), None);
    // The far corners still resolve to the edge tabs (no dead gap).
    assert_eq!(hit_nav(Point::new(0, NAV_TOP)), Some(NavTab::Home));
    assert_eq!(
        hit_nav(Point::new(PANEL_W - 1, PANEL_H - 1)),
        Some(NavTab::Settings)
    );
}

#[test]
fn list_rows_hit_in_order_and_gaps_miss() {
    let y0 = 40;
    for i in 0..5u16 {
        let r = row_rect(y0, i);
        assert_eq!(hit_list(Point::new(r.x + 2, r.y + r.h / 2), y0, 5), Some(i));
    }
    // The gap between rows 0 and 1 selects nothing.
    let r0 = row_rect(y0, 0);
    assert_eq!(hit_list(Point::new(r0.x + 2, r0.y + r0.h + 1), y0, 5), None);
    // A row index beyond `n` isn't matched.
    assert_eq!(
        hit_list(Point::new(r0.x + 2, row_rect(y0, 6).y + 2), y0, 5),
        None
    );
}

#[test]
fn pager_hits_and_page_count() {
    let center = |r: Rect| Point::new(r.x + r.w / 2, r.y + r.h / 2);
    assert_eq!(hit_pager(center(PAGER_PREV_RECT)), Some(PagerKey::Prev));
    assert_eq!(hit_pager(center(PAGER_NEXT_RECT)), Some(PagerKey::Next));
    // The indicator gap between the two arrows selects nothing.
    assert_eq!(
        hit_pager(Point::new(
            PANEL_W / 2,
            PAGER_PREV_RECT.y + PAGER_PREV_RECT.h / 2
        )),
        None
    );
    // ceil(total / PK_ROWS_MAX), never zero.
    assert_eq!(page_count(0), 1);
    assert_eq!(page_count(1), 1);
    assert_eq!(page_count(PK_ROWS_MAX as u16), 1);
    assert_eq!(page_count(PK_ROWS_MAX as u16 + 1), 2);
    assert_eq!(page_count(62), 13);
}

#[test]
fn rp_row_shows_nickname_over_rpid() {
    let mut r = RpRow {
        id: Label::clamp(b"github.com"),
        nick: Label::default(),
        accounts: 2,
    };
    assert_eq!(r.shown(), "github.com");
    r.nick = Label::clamp(b"Work GitHub");
    assert_eq!(r.shown(), "Work GitHub");
}

#[test]
fn rename_key_centres_hit_their_keys() {
    let c = |r: Rect| Point::new(r.x + r.w / 2, r.y + r.h / 2);
    // T9 char keys (0,0)=1, (0,1)=2, (2,2)=9, (3,1)=0
    assert_eq!(hit_rename(c(t9_key_rect(0, 0))), Some(RenameKey::Char(0)));
    assert_eq!(hit_rename(c(t9_key_rect(0, 1))), Some(RenameKey::Char(1)));
    assert_eq!(hit_rename(c(t9_key_rect(2, 2))), Some(RenameKey::Char(8)));
    assert_eq!(hit_rename(c(t9_key_rect(3, 1))), Some(RenameKey::Char(9)));
    // Backspace (3, 0) and Save (3, 2)
    assert_eq!(hit_rename(c(t9_key_rect(3, 0))), Some(RenameKey::Backspace));
    assert_eq!(hit_rename(c(t9_key_rect(3, 2))), Some(RenameKey::Save));
    // The field area (above the keypad) is not a key.
    assert_eq!(hit_rename(c(RN_FIELD_RECT)), None);
}

#[test]
fn title_edit_and_back_are_disjoint() {
    let c = |r: Rect| Point::new(r.x + r.w / 2, r.y + r.h / 2);
    assert!(hit_title_edit(c(TITLE_EDIT_RECT)));
    assert!(!hit_title_back(c(TITLE_EDIT_RECT)));
    assert!(hit_title_back(c(TITLE_BACK_RECT)));
    assert!(!hit_title_edit(c(TITLE_BACK_RECT)));
}

#[test]
fn t9_groups_are_printable_and_have_distinct_chars() {
    // A T9 char must belong to exactly one group — a duplicate across groups
    // would make `active_group` / `cycle_at` ambiguous on the rename screen.
    let mut seen: [bool; 128] = [false; 128];
    for (gi, group) in T9_GROUPS.iter().enumerate() {
        assert!(!group.is_empty(), "T9 group {gi} is empty");
        assert!(
            group.iter().all(|&b| (0x20..=0x7E).contains(&b)),
            "non-printable in group {gi}"
        );
        for &a in group.iter() {
            assert!(
                !seen[a as usize],
                "duplicate {a:?} appears in two T9 groups"
            );
            seen[a as usize] = true;
        }
    }
}
