// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::ceremony::{CEREMONY_TITLE_BAND, CEREMONY_TITLE_ROLE, centered_clipped};
use super::components;
use super::home::HOME_CARD_TOP;
use super::*;
use crate::{HomeView, PANEL_H, SuccessKind};
use embedded_graphics::{Pixel, geometry::OriginDimensions};

fn has_color(d: &Rec, r: Rect, c: Rgb565) -> bool {
    (r.y..r.y + r.h).any(|y| (r.x..r.x + r.w).any(|x| d.at(x, y) == c))
}

fn has_aa_color(d: &Rec, r: Rect, fg: Rgb565, bg: Rgb565) -> bool {
    (r.y..r.y + r.h).any(|y| {
        (r.x..r.x + r.w).any(|x| {
            let color = d.at(x, y);
            (1..crate::aa::COVERAGE_MAX)
                .any(|coverage| color == crate::aa::blend_coverage(fg, bg, coverage))
        })
    })
}

/// A `DrawTarget` that records into a 240×320 buffer and, like a real panel,
/// clips out-of-bounds pixels — but flags that it had to (`oob`), so a test can
/// assert a screen stayed inside the panel.
struct Rec {
    px: std::vec::Vec<Rgb565>,
    writes: std::vec::Vec<bool>,
    oob: bool,
}

impl Rec {
    fn new() -> Self {
        Self {
            px: std::vec![BG; PANEL_W as usize * PANEL_H as usize],
            writes: std::vec![false; PANEL_W as usize * PANEL_H as usize],
            oob: false,
        }
    }
    fn at(&self, x: u16, y: u16) -> Rgb565 {
        self.px[y as usize * PANEL_W as usize + x as usize]
    }
    fn any_non_bg_in(&self, r: Rect) -> bool {
        (r.y..r.y + r.h).any(|y| (r.x..r.x + r.w).any(|x| self.at(x, y) != BG))
    }
    fn drew_anything(&self) -> bool {
        self.px.iter().any(|&c| c != BG)
    }
    fn reset_writes(&mut self) {
        self.writes.fill(false);
    }
    fn wrote_anything(&self) -> bool {
        self.writes.iter().any(|&wrote| wrote)
    }
    fn wrote_outside(&self, r: Rect) -> bool {
        self.writes.iter().enumerate().any(|(i, &wrote)| {
            let p = Point::new((i % PANEL_W as usize) as u16, (i / PANEL_W as usize) as u16);
            wrote && !r.contains(p)
        })
    }
    fn wrote_in(&self, r: Rect) -> bool {
        self.writes.iter().enumerate().any(|(i, &wrote)| {
            let p = Point::new((i % PANEL_W as usize) as u16, (i / PANEL_W as usize) as u16);
            wrote && r.contains(p)
        })
    }
}

impl OriginDimensions for Rec {
    fn size(&self) -> Size {
        Size::new(PANEL_W as u32, PANEL_H as u32)
    }
}

impl DrawTarget for Rec {
    type Color = Rgb565;
    type Error = core::convert::Infallible;
    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Rgb565>>,
    {
        for Pixel(p, c) in pixels {
            if p.x >= 0
                && p.y >= 0
                && (p.x as u32) < PANEL_W as u32
                && (p.y as u32) < PANEL_H as u32
            {
                let i = p.y as usize * PANEL_W as usize + p.x as usize;
                self.px[i] = c;
                self.writes[i] = true;
            } else {
                self.oob = true;
            }
        }
        Ok(())
    }
}

#[test]
fn splash_fits_and_draws() {
    let mut d = Rec::new();
    render(&mut d, &Screen::Splash).unwrap();
    assert!(!d.oob, "splash drew outside the panel");
    assert!(d.drew_anything());
}

#[test]
fn pin_title_overflow_detection() {
    // short, design titles fit the band; the long applet PIN titles overflow → marquee
    assert!(!pin_title_overflows("Enter PIN"));
    assert!(!pin_title_overflows("Confirm PIN"));
    assert!(pin_title_overflows("OpenPGP Sign PIN"));
    assert!(pin_title_overflows("OpenPGP Admin PIN"));
}

#[test]
fn scope_pin_titles_fit_static() {
    // The credential-scope titles the firmware now shows on every PIN screen
    // must fit the band so the scope reads statically (never marquees away).
    for t in ["Device PIN", "FIDO PIN", "PIV PIN", "PIV PUK"] {
        assert!(!pin_title_overflows(t), "{t} should fit the title band");
    }
}

#[test]
fn pin_marquee_never_touches_chevron_or_lock() {
    let mut d = Rec::new();
    render_pin_title(&mut d, "OpenPGP Sign PIN", 0).unwrap();
    assert!(!d.oob, "marquee drew outside the panel");
    let band = PIN_TITLE_BAND;
    assert!(d.any_non_bg_in(band), "marquee drew nothing in the band");
    // the back-button column (left of the band) must stay clear — the long title can
    // never slide onto the chevron (the reported bug), at any scroll offset.
    let back = Rect::new(PIN_CANCEL_RECT.x, 6, PIN_CANCEL_RECT.w, 28);
    let right = Rect::new(band.x + band.w, 6, PANEL_W - (band.x + band.w), 28);
    for off in [0u32, 40, 120, 400] {
        let mut e = Rec::new();
        render_pin_title(&mut e, "OpenPGP Sign PIN", off).unwrap();
        assert!(
            !e.any_non_bg_in(back),
            "title painted over the back button at off={off}"
        );
        assert!(
            !e.any_non_bg_in(right),
            "title painted past the band at off={off}"
        );
    }
}

#[test]
fn pin_marquee_scrolls_long_but_not_short() {
    let band = PIN_TITLE_BAND;
    let differs = |s: &str, o1: u32, o2: u32| {
        let (mut a, mut b) = (Rec::new(), Rec::new());
        render_pin_title(&mut a, s, o1).unwrap();
        render_pin_title(&mut b, s, o2).unwrap();
        (band.y..band.y + band.h)
            .any(|y| (band.x..band.x + band.w).any(|x| a.at(x, y) != b.at(x, y)))
    };
    assert!(
        differs("OpenPGP Sign PIN", 0, 60),
        "marquee offset must move a long title"
    );
    assert!(
        !differs("Enter PIN", 0, 500),
        "a fitting title must stay static (centred)"
    );
}

#[test]
fn locked_screen_fits_and_draws() {
    let mut d = Rec::new();
    render(&mut d, &Screen::Locked).unwrap();
    assert!(!d.oob, "locked screen drew outside the panel");
    assert!(d.drew_anything());
    // The lock circle (surface fill) + accent glyph sit in the upper-middle band.
    assert!(
        d.any_non_bg_in(Rect::new(0, 96, PANEL_W, 80)),
        "lock circle / glyph missing"
    );
}

#[test]
fn pin_blocked_screen_fits_and_warns() {
    let mut d = Rec::new();
    render_pin_blocked(&mut d).unwrap();
    assert!(!d.oob, "pin-blocked screen drew outside the panel");
    // The "PIN blocked" heading is painted in the danger colour.
    assert!(
        has_color(&d, Rect::new(0, 176, PANEL_W, 28), theme::DANGER),
        "danger 'PIN blocked' heading missing"
    );
}

#[test]
fn every_home_status_fits_and_draws_with_nav() {
    for status in [
        StatusKind::Boot,
        StatusKind::Idle,
        StatusKind::Processing,
        StatusKind::Touch,
    ] {
        let mut d = Rec::new();
        render(
            &mut d,
            &Screen::Home(HomeView {
                status,
                pin_set: true,
                passkeys: 12,
            }),
        )
        .unwrap();
        assert!(!d.oob, "home {status:?} drew outside the panel");
        assert!(d.drew_anything(), "home {status:?} drew nothing");
        // The bottom nav is always present on a tab; Home is the active one.
        assert!(
            has_color(&d, crate::nav_tab_rect(0), theme::ACCENT),
            "home nav tab not accented on {status:?}"
        );
    }
}

#[test]
fn home_fact_change_repaints_only_the_typed_card() {
    let previous = HomeView {
        status: StatusKind::Idle,
        pin_set: false,
        passkeys: 1234,
    };
    let next = HomeView {
        status: StatusKind::Idle,
        pin_set: true,
        passkeys: 7,
    };
    let mut actual = Rec::new();
    render(&mut actual, &Screen::Home(previous)).unwrap();
    actual.reset_writes();
    render_home_change(&mut actual, &previous, &next).unwrap();

    let mut expected = Rec::new();
    render(&mut expected, &Screen::Home(next)).unwrap();
    assert_eq!(
        actual.px, expected.px,
        "partial Home card differs from a full paint"
    );

    let first = crate::row_rect(HOME_CARD_TOP, 0);
    let last = crate::row_rect(HOME_CARD_TOP, 2);
    let card = Rect::new(first.x, first.y, first.w, last.y + last.h - first.y);
    assert!(actual.wrote_anything());
    assert!(
        !actual.wrote_outside(card),
        "Home fact change touched stable chrome"
    );
    assert!(
        !actual.wrote_in(first),
        "Home fact change repainted the unchanged USB row"
    );
}

#[test]
fn hidden_home_facts_and_identical_views_do_not_draw() {
    let previous = HomeView {
        status: StatusKind::Processing,
        pin_set: false,
        passkeys: 2,
    };
    let next = HomeView {
        passkeys: 99,
        ..previous
    };
    let mut d = Rec::new();
    render(&mut d, &Screen::Home(previous)).unwrap();
    d.reset_writes();
    render_home_change(&mut d, &previous, &next).unwrap();
    assert!(
        !d.wrote_anything(),
        "a hidden Home fact rebuilt visible components"
    );
    render_home_change(&mut d, &next, &next).unwrap();
    assert!(
        !d.wrote_anything(),
        "an identical Home view produced damage"
    );
}

#[test]
fn home_mode_change_repaints_content_but_preserves_chrome() {
    let previous = HomeView {
        status: StatusKind::Idle,
        pin_set: true,
        passkeys: 12,
    };
    let next = HomeView {
        status: StatusKind::Touch,
        ..previous
    };
    let mut actual = Rec::new();
    render(&mut actual, &Screen::Home(previous)).unwrap();
    actual.reset_writes();
    render_home_change(&mut actual, &previous, &next).unwrap();

    let mut expected = Rec::new();
    render(&mut expected, &Screen::Home(next)).unwrap();
    assert_eq!(
        actual.px, expected.px,
        "partial Home mode change differs from a full paint"
    );
    let content = Rect::new(0, STATUS_BAR_H, PANEL_W, NAV_TOP - STATUS_BAR_H);
    assert!(
        !actual.wrote_outside(content),
        "Home mode change touched fixed chrome"
    );
}

#[test]
fn passkeys_list_paints_rows_in_their_hit_rects() {
    let rows = [
        RpRow {
            id: Label::clamp(b"github.com"),
            nick: Label::default(),
            accounts: 2,
        },
        RpRow {
            id: Label::clamp(b"google.com"),
            nick: Label::default(),
            accounts: 1,
        },
    ];
    let mut d = Rec::new();
    render_passkeys_list(&mut d, &rows, 0, 2).unwrap();
    assert!(!d.oob, "list drew outside the panel");
    // Each RP row is a card in the exact rect hit_list maps a tap to.
    for i in 0..rows.len() as u16 {
        assert!(
            has_color(&d, crate::row_rect(PK_LIST_TOP, i), theme::ROW_BG),
            "row {i} card missing from its hit rect"
        );
    }
    assert!(has_color(&d, crate::nav_tab_rect(1), theme::ACCENT));
}

#[test]
fn passkeys_page_damage_preserves_title_and_navigation() {
    let stable = RpRow {
        id: Label::clamp(b"stable.example"),
        nick: Label::default(),
        accounts: 1,
    };
    let previous = [
        stable,
        RpRow {
            id: Label::clamp(b"first.example"),
            nick: Label::default(),
            accounts: 12,
        },
    ];
    let next = [
        stable,
        RpRow {
            id: Label::clamp(b"second.example"),
            nick: Label::clamp(b"Work"),
            accounts: 1,
        },
    ];
    let mut actual = Rec::new();
    render_passkeys_list(&mut actual, &previous, 0, 7).unwrap();
    actual.reset_writes();
    render_passkeys_page(&mut actual, &previous, 0, 7, &next, 1, 7).unwrap();

    let mut expected = Rec::new();
    render_passkeys_list(&mut expected, &next, 1, 7).unwrap();
    assert_eq!(
        actual.px, expected.px,
        "partial Passkeys page differs from a full paint"
    );
    assert!(actual.wrote_anything());
    assert!(
        !actual.wrote_outside(PAGED_BODY_RECT),
        "Passkeys page change touched fixed title or navigation"
    );
    assert!(
        !actual.wrote_in(crate::row_rect(PK_LIST_TOP, 0)),
        "Passkeys page change repainted an unchanged typed row"
    );
}

#[test]
fn passkeys_list_empty_state_draws() {
    let mut d = Rec::new();
    render_passkeys_list(&mut d, &[], 0, 0).unwrap();
    assert!(!d.oob && d.drew_anything());
    assert!(has_color(&d, crate::nav_tab_rect(1), theme::ACCENT));
}

#[test]
fn service_detail_paints_accounts_and_back_affordance() {
    let accounts = [
        AccountRow {
            name: Label::clamp(b"alex@example.com"),
            protected: true,
        },
        AccountRow {
            name: Label::clamp(b"alex.dev"),
            protected: false,
        },
    ];
    let title = Label::clamp(b"github.com");
    let mut d = Rec::new();
    render_service(&mut d, &title, true, &accounts, 0, 2).unwrap();
    assert!(!d.oob, "detail drew outside the panel");
    // The back chevron paints in TITLE_BACK_RECT — where hit_title_back maps a tap.
    assert!(
        has_color(&d, crate::TITLE_BACK_RECT, theme::ACCENT),
        "back chevron missing from its title-bar hit rect"
    );
    // The pencil edit affordance paints in TITLE_EDIT_RECT (the rename entry).
    assert!(
        d.any_non_bg_in(crate::TITLE_EDIT_RECT),
        "edit affordance missing from its title-bar hit rect"
    );
    for i in 0..accounts.len() as u16 {
        assert!(d.any_non_bg_in(crate::row_rect(PK_LIST_TOP, i)));
    }
}

#[test]
fn service_title_clips_a_wide_nickname_in_panel() {
    // A max-length wide nickname (24 'W') must be clipped to the title strip, not
    // overrun off-panel or under the edit pencil (TITLE_EDIT_RECT).
    let accounts = [AccountRow {
        name: Label::clamp(b"alex@example.com"),
        protected: false,
    }];
    let wide = Label::clamp(&[b'W'; 24]);
    let mut d = Rec::new();
    render_service(&mut d, &wide, false, &accounts, 0, 1).unwrap();
    assert!(!d.oob, "wide service title drew outside the panel");
    // The pencil's region still gets its glyph (the title didn't paint over it... the
    // clip ends before it).
    assert!(d.any_non_bg_in(crate::TITLE_EDIT_RECT));
}

#[test]
fn passkey_manager_keeps_the_registrable_domain_suffix() {
    // A wide attacker-chosen rpId whose registrable domain is the tail: the passkey list row
    // and the service-detail title must keep the suffix (head-ellipsis, title_is_rp=true / no
    // nickname) rather than head-first-cut it (as a user-chosen nickname would). Rendering the
    // domain path vs the head-keep path must therefore paint different title/row pixels — the
    // suffix-hiding regression this guards would render them identically.
    let mut src = [b'a'; 60]; // > LABEL_MAX, so clamp_domain drops the head, keeps the tail
    src[47..].copy_from_slice(b".attacker.com");
    let rp = Label::clamp_domain(&src);
    assert!(rp.truncated && rp.as_str().ends_with(".attacker.com"));
    let accounts = [AccountRow {
        name: Label::clamp(b"victim@corp.example"),
        protected: false,
    }];

    // Service-detail title: domain (suffix-kept) must differ from the head-kept rendering.
    let mut dom = Rec::new();
    render_service(&mut dom, &rp, true, &accounts, 0, 1).unwrap();
    let mut head = Rec::new();
    render_service(&mut head, &rp, false, &accounts, 0, 1).unwrap();
    assert!(!dom.oob && !head.oob, "wide rpId title overran the panel");
    let title_differs = (0..PANEL_W).any(|x| (24..48).any(|y| dom.at(x, y) != head.at(x, y)));
    assert!(
        title_differs,
        "service-detail title must keep the registrable-domain suffix (head-ellipsis), not head-cut it"
    );

    // Passkey list row: a row showing the rpId (no nickname) must likewise differ from one
    // whose identical text is treated as a head-keep nickname.
    let rp_row = RpRow {
        id: rp,
        nick: Label::default(),
        accounts: 1,
    };
    let nick_row = RpRow {
        id: Label::default(),
        nick: rp,
        accounts: 1,
    };
    let mut list_rp = Rec::new();
    render_passkeys_list(&mut list_rp, &[rp_row], 0, 1).unwrap();
    let mut list_nick = Rec::new();
    render_passkeys_list(&mut list_nick, &[nick_row], 0, 1).unwrap();
    assert!(
        !list_rp.oob && !list_nick.oob,
        "wide rpId row overran the panel"
    );
    let row = crate::row_rect(PK_LIST_TOP, 0);
    let row_differs = (0..PANEL_W)
        .any(|x| (row.y..row.y + row.h).any(|y| list_rp.at(x, y) != list_nick.at(x, y)));
    assert!(
        row_differs,
        "passkey list row must keep the registrable-domain suffix for an rpId, not head-cut it"
    );
}

#[test]
fn ellipsized_force_mark_marks_a_fitting_label() {
    // A Label clamped at LABEL_MAX fits the box but is a prefix of a longer
    // original; on a trust screen (the RP on the Approve pad) it must still read
    // as truncated. force_mark appends the marker even when the text fits, so a
    // padded look-alike id cannot present a complete-looking prefix.
    let clip = Rect::new(0, 0, PANEL_W, 24);
    let at = EgPoint::new(0, 16);
    let rightmost = |d: &Rec| {
        (0..PANEL_W)
            .rev()
            .find(|&x| (0..24).any(|y| d.at(x, y) != BG))
    };

    let mut plain = Rec::new();
    text_left_ellipsized(
        &mut plain,
        "google.com",
        at,
        Role::Strong,
        theme::TEXT,
        clip,
        false,
    )
    .unwrap();
    let mut marked = Rec::new();
    text_left_ellipsized(
        &mut marked,
        "google.com",
        at,
        Role::Strong,
        theme::TEXT,
        clip,
        true,
    )
    .unwrap();

    assert!(plain.drew_anything() && marked.drew_anything());
    assert!(
        rightmost(&marked) > rightmost(&plain),
        "force_mark must append a visible truncation marker even when the text fits"
    );
}

#[test]
fn centered_clipped_marks_a_truncated_fitting_label() {
    // #5: the Add-passkey (makeCredential) screen draws the rp via centered_clipped
    // with `right = true` (it is a domain). A clamped rp id (Label.truncated) whose
    // tail fits the clip must not render as a complete-looking centred string — with
    // `mark` set it routes through the head-ellipsized path so the marker appears, the
    // same anti-phishing guarantee the Approve screen already had.
    let clip = Rect::new(0, 0, PANEL_W, 24);
    let leftmost = |d: &Rec| (0..PANEL_W).find(|&x| (0..24).any(|y| d.at(x, y) != BG));

    let mut plain = Rec::new();
    centered_clipped(
        &mut plain,
        "paypal.com",
        MIDX,
        16,
        Role::Strong,
        theme::TEXT,
        clip,
        false,
        true,
    )
    .unwrap();
    let mut marked = Rec::new();
    centered_clipped(
        &mut marked,
        "paypal.com",
        MIDX,
        16,
        Role::Strong,
        theme::TEXT,
        clip,
        true,
        true,
    )
    .unwrap();

    assert!(plain.drew_anything() && marked.drew_anything());
    // Unmarked + fits → centred (starts well right of the edge); marked → left-
    // aligned + ellipsized (starts at the clip edge), so the marker is shown.
    assert!(
        leftmost(&marked).unwrap() < leftmost(&plain).unwrap(),
        "a truncated (marked) label must render ellipsized, not centred-complete"
    );
}

#[test]
fn oath_screens_mark_a_truncated_credential_name() {
    // Audit run-33 marked the passkey screens but stopped there. An OATH credential
    // label is host-chosen too, and its list is likewise where the owner audits what
    // is stored — so a name already clipped to LABEL_MAX must not present itself as
    // whole just because the clipped prefix happens to fit the row.
    let plain = Label::clamp(b"acme");
    let mut marked = plain;
    marked.truncated = true;

    let row_of = |name: Label| OathRow {
        name,
        hotp: false,
        touch: false,
    };
    let mut list_plain = Rec::new();
    render_oath(&mut list_plain, &[row_of(plain)], 0, 1).unwrap();
    let mut list_marked = Rec::new();
    render_oath(&mut list_marked, &[row_of(marked)], 0, 1).unwrap();
    let row = crate::row_rect(PK_LIST_TOP, 0);
    assert!(
        (0..PANEL_W)
            .any(|x| (row.y..row.y + row.h).any(|y| list_plain.at(x, y) != list_marked.at(x, y))),
        "a clipped OATH name must render with its truncation marker in the list"
    );

    let view_of = |name: Label| OathDetailView {
        name,
        ..Default::default()
    };
    let mut det_plain = Rec::new();
    render_oath_cred(&mut det_plain, &view_of(plain)).unwrap();
    let mut det_marked = Rec::new();
    render_oath_cred(&mut det_marked, &view_of(marked)).unwrap();
    assert!(
        (0..PANEL_W).any(|x| (24..48).any(|y| det_plain.at(x, y) != det_marked.at(x, y))),
        "a clipped OATH name must render with its truncation marker in the detail title"
    );
}

#[test]
fn right_ellipsized_keeps_the_suffix_unlike_left() {
    // A domain wider than the clip: the head-ellipsis (right) variant keeps the
    // registrable-domain suffix while the tail-ellipsis (left) variant keeps the
    // padded prefix — so the two must render different content, and neither may
    // overrun the clip.
    let clip = Rect::new(0, 0, 100, 24); // narrow enough to force truncation
    let at = EgPoint::new(0, 16);
    let wide = "aaaaaaaaaaaaaaaaaaaaaaaa.attacker.com";
    let mut left = Rec::new();
    text_left_ellipsized(&mut left, wide, at, Role::Strong, theme::TEXT, clip, false).unwrap();
    let mut right = Rec::new();
    text_right_ellipsized(&mut right, wide, at, Role::Strong, theme::TEXT, clip, false).unwrap();
    assert!(left.drew_anything() && right.drew_anything());
    assert!(!left.oob && !right.oob, "ellipsized text overran the clip");
    let differ = (0..clip.w).any(|x| (0..24).any(|y| left.at(x, y) != right.at(x, y)));
    assert!(
        differ,
        "head-ellipsis (suffix kept) must differ from tail-ellipsis (prefix kept)"
    );
}

#[test]
fn applet_detail_screens_fit_and_clip_max_values() {
    // OATH credential detail.
    let mut d = Rec::new();
    render_oath_cred(
        &mut d,
        &OathDetailView {
            name: Label::clamp(b"GitHub:alice"),
            hotp: false,
            algo: Label::clamp(b"SHA1"),
            digits: 6,
            period: 30,
            touch: false,
        },
    )
    .unwrap();
    assert!(!d.oob && d.drew_anything(), "oath detail off-panel");
    assert!(has_color(&d, crate::TITLE_BACK_RECT, theme::ACCENT));

    // Cardholder detail with EVERY free-form field at the label cap must stay on-panel
    // (the regression the value column would hit if it were right-anchored + unclipped).
    let max = Label::clamp(&[b'W'; 64]);
    let mut d = Rec::new();
    render_openpgp_cardholder(
        &mut d,
        &CardholderView {
            name: max,
            login: max,
            url: max,
            lang: Label::clamp(b"en"),
            any: true,
        },
    )
    .unwrap();
    assert!(!d.oob, "cardholder detail drew outside the panel");
    assert!(d.drew_anything());

    // Empty cardholder shows the hint without overrun.
    let mut d = Rec::new();
    render_openpgp_cardholder(&mut d, &CardholderView::default()).unwrap();
    assert!(!d.oob && d.drew_anything());

    // Retired & F9 list: F9, a populated retired slot, and the generate action row.
    let rows = [
        PivExtraRow {
            slot: 0xF9,
            present: true,
            cert: true,
            algo: Label::clamp(b"NIST P-384"),
            generate: false,
        },
        PivExtraRow {
            slot: 0x82,
            present: true,
            cert: false,
            algo: Label::clamp(b"RSA 2048"),
            generate: false,
        },
        PivExtraRow {
            generate: true,
            ..Default::default()
        },
    ];
    let mut d = Rec::new();
    render_piv_extra(&mut d, &rows, 0, rows.len() as u16).unwrap();
    assert!(!d.oob, "retired/F9 list drew outside the panel");
    assert!(has_color(&d, crate::TITLE_BACK_RECT, theme::ACCENT));
    for i in 0..rows.len() as u16 {
        assert!(d.any_non_bg_in(crate::row_rect(PK_LIST_TOP, i)));
    }

    // Keygen algorithm chooser + the hold-to-generate confirm + the RSA "generating" screen.
    let mut d = Rec::new();
    render_piv_keygen_pick(&mut d, 0x82).unwrap();
    assert!(!d.oob && d.drew_anything(), "keygen pick off-panel");
    let mut d = Rec::new();
    render_piv_keygen_confirm(&mut d, 0x82, "NIST P-256").unwrap();
    assert!(!d.oob, "keygen confirm drew outside the panel");
    // The hold button paints in DEL_HOLD_RECT, where hold_to_confirm reads the gesture.
    assert!(has_color(&d, crate::DEL_HOLD_RECT, theme::ACCENT_FILL));
    // It must stay a chrome-less modal: no status bar, so the top-left PK_BACK_RECT cancel
    // chevron has nothing ("RS-Key" / battery) painted behind it (the y=6 overlap fix).
    assert!(
        !d.any_non_bg_in(Rect::new(PANEL_W - 36, 2, 30, 18)),
        "generate-confirm must be chrome-less (no status bar behind the cancel chevron)"
    );
    // The RSA size sub-picker and the "generating" screen (shown while the search runs).
    let mut d = Rec::new();
    render_piv_keygen_rsa_pick(&mut d, 0x82).unwrap();
    assert!(!d.oob && d.drew_anything(), "RSA size picker off-panel");
    let mut d = Rec::new();
    render_piv_keygen_working(&mut d).unwrap();
    assert!(
        !d.oob && d.drew_anything(),
        "keygen working screen off-panel"
    );
}

#[test]
fn rename_screen_paints_wheel_and_save() {
    let mut d = Rec::new();
    render_rename(&mut d, "work", Some(b'a'), Some(1)).unwrap();
    assert!(!d.oob, "rename drew outside the panel");
    assert!(d.drew_anything());
    // The back chevron cancels.
    assert!(has_color(&d, crate::TITLE_BACK_RECT, theme::ACCENT));
    // Each T9 key paints something in its own tap target (including the Save key).
    for row in 0..4u16 {
        for col in 0..3u16 {
            let r = crate::t9_key_rect(row, col);
            assert!(d.any_non_bg_in(r), "T9 key ({row},{col}) painted nothing");
        }
    }
}

#[test]
fn rename_space_pending_stays_in_panel() {
    // Pending space char takes the underline draw path — still in-bounds.
    let mut d = Rec::new();
    render_rename(&mut d, "", Some(b' '), None).unwrap();
    assert!(!d.oob, "rename(space) drew outside the panel");
    assert!(d.drew_anything());
}

#[test]
fn rename_long_value_is_clipped_to_the_field() {
    let long = "abcdefghijklmnopqrstuvwx";
    let mut d = Rec::new();
    render_rename(&mut d, long, Some(b'z'), None).unwrap();
    assert!(!d.oob, "rename(long) drew outside the panel");
}

#[test]
fn passkeys_list_shows_nickname_over_rpid() {
    let rows = [RpRow {
        id: Label::clamp(b"github.com"),
        nick: Label::clamp(b"Work GitHub"),
        accounts: 2,
    }];
    let mut d = Rec::new();
    render_passkeys_list(&mut d, &rows, 0, 1).unwrap();
    assert!(!d.oob && d.drew_anything());
}

/// The Confirm-Delete screen paints its hold control in `DEL_HOLD_RECT` and the
/// cancel chevron in `PK_BACK_RECT` (both in the decline colour) — exactly the
/// regions `hit_del_hold` / `hit_pk_back` map a tap to — with the rp + account on
/// screen so the user sees what they are removing.
#[test]
fn onboard_paints_buttons_in_their_hit_rects() {
    let mut d = Rec::new();
    render(&mut d, &Screen::Onboard).unwrap();
    assert!(!d.oob, "onboard drew outside the panel");
    // The primary Set-a-PIN button is filled in its hit rect; the secondary
    // Continue-without is a muted outline in its own rect — the two regions
    // `hit_onboard` maps a tap to.
    assert!(
        has_color(&d, crate::ONBOARD_SET_RECT, theme::ACCENT_FILL),
        "Set-a-PIN button not in its rect"
    );
    assert!(
        has_color(&d, crate::ONBOARD_SKIP_RECT, theme::MUTED),
        "Continue-without outline not in its rect"
    );
}

#[test]
fn onboard_button_labels_fit_their_buttons() {
    // Both captions are centred inside their button rect; the long secondary one
    // must fit so it never overruns the button or clips.
    assert!(font::width("Set a PIN", Role::Strong).unwrap() <= crate::ONBOARD_SET_RECT.w as u32);
    assert!(
        font::width("Continue without PIN", Role::Body).unwrap()
            <= crate::ONBOARD_SKIP_RECT.w as u32
    );
}

#[test]
fn onboard_body_text_clears_the_set_button() {
    // The body lines sit above the primary button; the strip just above the button must
    // stay background — a body line that descends into it overlaps "Set a PIN" (the
    // reported bug). 6 px is wider than the Body font's descent.
    let mut d = Rec::new();
    render(&mut d, &Screen::Onboard).unwrap();
    let gap = Rect::new(0, crate::ONBOARD_SET_RECT.y - 6, PANEL_W, 6);
    assert!(
        !d.any_non_bg_in(gap),
        "onboard body text overlaps the Set-a-PIN button"
    );
}

#[test]
fn confirm_delete_paints_hold_and_cancel_in_their_hit_rects() {
    let rp = Label::clamp(b"github.com");
    let account = Label::clamp(b"alex@example.com");
    let mut d = Rec::new();
    render_confirm_delete(&mut d, &rp, &account).unwrap();
    assert!(!d.oob, "confirm-delete drew outside the panel");
    assert!(
        has_color(&d, crate::DEL_HOLD_RECT, theme::DANGER_FILL),
        "Hold-to-delete not in its rect"
    );
    assert!(
        has_color(&d, crate::PK_BACK_RECT, theme::DENY),
        "cancel chevron not in its rect"
    );
}

/// The Factory-Reset confirm screen paints its hold control in `DEL_HOLD_RECT`
/// and the cancel chevron in `PK_BACK_RECT` (both in the decline colour) — the
/// regions `hit_del_hold` / `hit_pk_back` map a tap to.
#[test]
fn confirm_factory_reset_paints_hold_and_cancel_in_their_hit_rects() {
    let mut d = Rec::new();
    render_confirm_factory_reset(&mut d).unwrap();
    assert!(!d.oob, "confirm-factory-reset drew outside the panel");
    assert!(
        has_color(&d, crate::DEL_HOLD_RECT, theme::DANGER_FILL),
        "Hold-to-reset not in its rect"
    );
    assert!(
        has_color(&d, crate::PK_BACK_RECT, theme::DENY),
        "cancel chevron not in its rect"
    );
}

/// The factory-reset confirm is a destructive ceremony: its warning reads danger red,
/// never the amber of a recoverable caution.
#[test]
fn factory_reset_warns_in_danger_red_not_amber() {
    let mut d = Rec::new();
    render_confirm_factory_reset(&mut d).unwrap();
    let band = Rect::new(MIDX as u16 - 30, 44, 60, 62); // the warning disc + triangle
    assert!(
        has_color(&d, band, theme::DANGER),
        "factory-reset warning must be danger red"
    );
    assert!(
        !has_color(&d, band, theme::WARN),
        "factory-reset warning must not use the amber caution colour"
    );
}

/// Home's idle status card shows three rows — USB, device PIN, passkeys — each a
/// bordered card, the live-data rows the design calls for.
#[test]
fn home_idle_paints_the_three_status_rows() {
    let mut d = Rec::new();
    render(
        &mut d,
        &Screen::Home(HomeView {
            status: StatusKind::Idle,
            pin_set: true,
            passkeys: 7,
        }),
    )
    .unwrap();
    assert!(!d.oob, "home idle drew outside the panel");
    for i in 0..3u16 {
        let r = crate::row_rect(HOME_CARD_TOP, i);
        assert!(
            has_color(&d, r, theme::ROW_BG),
            "home status row {i} not painted"
        );
        assert!(
            has_color(&d, r, theme::BORDER_CARD),
            "home status row {i} missing its card border"
        );
    }
}

/// Around the centred success circle — comfortably covers the mark glyph at any
/// pop scale, well clear of the heading band below it.
const SUCCESS_BAND: Rect = Rect::new(96, 88, 48, 52);

/// Every success kind paints its mark in the circle, stays in-panel, and uses the
/// design's colour (green check for approve/delete, grey rotate for the wipe).
#[test]
fn success_screens_fit_and_mark_their_kind() {
    for (kind, mark) in [
        (SuccessKind::Approved, theme::SUCCESS),
        (SuccessKind::Deleted, theme::SUCCESS),
        (SuccessKind::Wiped, theme::GREY),
        (SuccessKind::Generated, theme::SUCCESS),
    ] {
        let mut d = Rec::new();
        render_success(&mut d, kind, false).unwrap();
        render_success_circle(&mut d, kind, 100).unwrap();
        assert!(!d.oob, "{kind:?} success drew outside the panel");
        assert!(d.drew_anything(), "{kind:?} success drew nothing");
        let fill = super::reset::success_visuals(kind).1;
        assert!(
            has_aa_color(&d, SUCCESS_BAND, mark, fill),
            "{kind:?} success mark colour missing from the circle"
        );
    }
}

/// The wipe screen is deliberately grey (it restarts), never the green success
/// check used by approve/delete — so the two read as different outcomes.
#[test]
fn wiped_success_is_grey_not_green() {
    let mut d = Rec::new();
    render_success(&mut d, SuccessKind::Wiped, false).unwrap();
    render_success_circle(&mut d, SuccessKind::Wiped, 100).unwrap();
    assert!(
        !has_color(&d, SUCCESS_BAND, theme::SUCCESS),
        "wipe screen must not use the green success colour"
    );
}

/// The wait-for-Done variant paints the primary Done button in the exact region
/// `hit_success_done` maps a tap to.
#[test]
fn success_done_button_in_its_hit_rect() {
    let mut d = Rec::new();
    render_success(&mut d, SuccessKind::Deleted, true).unwrap();
    assert!(!d.oob, "success-with-Done drew outside the panel");
    assert!(
        has_color(&d, crate::DEL_HOLD_RECT, theme::ACCENT_FILL),
        "Done button not painted in its hit rect"
    );
    assert!(crate::hit_success_done(crate::Point::new(120, 270)));
    assert!(!crate::hit_success_done(crate::Point::new(0, 0)));
}

/// Every pop frame — including the 1.06 overshoot — stays inside the fixed circle
/// box, so a frame never spills onto the heading below or off the panel.
#[test]
fn success_pop_frames_stay_in_box() {
    for pct in [40u16, 55, 85, 100, 106] {
        let mut d = Rec::new();
        render_success_circle(&mut d, SuccessKind::Approved, pct).unwrap();
        assert!(!d.oob, "pop frame {pct}% drew outside the panel");
        assert!(
            !d.any_non_bg_in(Rect::new(0, 170, PANEL_W, 60)),
            "pop frame {pct}% bled into the heading / button area"
        );
    }
}

/// The core security property: the Hold-to-approve control lives in `ALLOW_RECT`
/// (in the approve colour) and Deny in `DENY_RECT` (in the deny colour) — exactly
/// the regions `hit_confirm` maps a tap to — with the sanitized rp id on screen.
#[test]
fn confirm_paints_deny_and_hold_in_their_hit_rects() {
    let p = ConfirmPrompt::new("Sign in?", b"github.com", b"alice");
    let mut d = Rec::new();
    render(&mut d, &Screen::Confirm(p)).unwrap();
    assert!(!d.oob, "confirm drew outside the panel");
    // Deny carries the deny colour in DENY_RECT; Hold the approve colour in
    // ALLOW_RECT — paint and hit-test share the rect.
    assert!(
        has_color(&d, DENY_RECT, theme::DENY),
        "Deny not in its rect"
    );
    assert!(
        has_color(&d, ALLOW_RECT, theme::APPROVE),
        "Hold not in its rect"
    );
    // The two never overlap (disjoint by construction).
    assert!(!has_color(&d, DENY_RECT, theme::APPROVE));
}

#[test]
fn confirm_buttons_stay_below_the_prompt_band() {
    // No approve/deny-coloured paint strays above the button band, so a tap in the
    // prompt area can never land on a button.
    let p = ConfirmPrompt::new("Register key?", b"example.org", b"");
    let mut d = Rec::new();
    render(&mut d, &Screen::Confirm(p)).unwrap();
    let row = crate::BTN_BAND_TOP - 1;
    assert!((0..PANEL_W).all(|x| {
        let c = d.at(x, row);
        c != theme::APPROVE && c != theme::DENY
    }));
}

/// The re-skinned approve screen must stay on-panel even with the empty rp a
/// generic OpenPGP/PIV touch confirm carries (no service header) — no panic, no OOB.
#[test]
fn confirm_with_empty_rp_stays_on_panel() {
    let p = ConfirmPrompt::new("Sign with key?", b"", b"");
    let mut d = Rec::new();
    render(&mut d, &Screen::Confirm(p)).unwrap();
    assert!(!d.oob, "empty-rp confirm drew outside the panel");
}

/// Every trusted-consent title the firmware can raise, from the `Confirm::titled` /
/// `Confirm::new` / `Confirm::register` call sites plus the two that pass their title
/// indirectly (`rsk-fido`'s vendor `gate`, `rsk-openpgp`'s UIF match).
/// [`ceremony_title_census_is_complete`] fails if a direct call site grows one that is
/// not listed here.
const CEREMONY_TITLES: &[&str] = &[
    "Allow host PIN entry?",
    "Allow host access?",
    "Always list passkeys?",
    "Attestation sign?",
    "Authenticate?",
    "Challenge-response?",
    "Change LED?",
    "Change audit logging?",
    "Clear attestation key?",
    "Confirm?",
    "Decrypt data?",
    "Erase everything?",
    "Erase this identity?",
    "Export secret seed?",
    "Factory reset device?",
    "Import attestation key?",
    "Load seed from host?",
    "Lock OTP page 58?",
    "Lock device?",
    "Read audit log?",
    "Reboot to BOOTSEL?",
    "Register key?",
    "Remove device lock?",
    "Replace device seed?",
    "Replace this identity?",
    "Require anti-rollback?",
    "Seal backup forever?",
    "Set OATH PIN?",
    "Show OATH code?",
    "Sign audit log?",
    "Sign data?",
    "Sign in?",
    "Use PIV key?",
    "Use this key?",
    "Verify OATH code?",
    "Write device cert?",
    "Write device config?",
    "Write test counter?",
];

/// Titles still wider than [`CEREMONY_TITLE_BAND`]. Empty, and it must stay that way:
/// on a title-only prompt the title is the whole of what the owner is approving, and an
/// ellipsized sentence is two shortenings away from reading as another prompt. A ratchet
/// — shorten a title and drop it from here; never add to it.
const CEREMONY_TITLES_TOO_WIDE: &[&str] = &[];

#[test]
fn ceremony_titles_fit_the_title_band() {
    for t in CEREMONY_TITLES {
        let w = font::width(t, CEREMONY_TITLE_ROLE).expect("consent titles are ASCII");
        assert_eq!(
            w > CEREMONY_TITLE_BAND.w as u32,
            CEREMONY_TITLES_TOO_WIDE.contains(t),
            "{t:?} measures {w}px against the {}px band",
            CEREMONY_TITLE_BAND.w
        );
    }
    // A reworded title must not leave its old spelling behind on the pending list.
    for t in CEREMONY_TITLES_TOO_WIDE {
        assert!(
            CEREMONY_TITLES.contains(t),
            "{t:?} is no longer a consent title"
        );
    }
}

/// The census is hand-maintained, so guard the way it fails silently: a consent title
/// added anywhere under `crates/` or `firmware/` that nobody lists above would never be
/// measured. Titles reached through a helper (`gate`, the UIF match) are not literals at
/// the call site and stay hand-listed.
#[test]
fn ceremony_title_census_is_complete() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let mut found = std::vec::Vec::new();
    for dir in ["crates", "firmware/src"] {
        scan_confirm_titles(&root.join(dir), &mut found);
    }
    // Both trees must actually have been walked, or the loop below passes on nothing.
    // The firmware anchor was "Change LED?" until the vendor applet moved into
    // `crates/rsk-vendor`; with both anchors in one tree the walk over the other
    // proves nothing, so it follows the code.
    for anchor in ["Lock OTP page 58?", "Allow host PIN entry?"] {
        assert!(found.iter().any(|t| t == anchor), "scan missed {anchor:?}");
    }
    for t in &found {
        assert!(
            CEREMONY_TITLES.contains(&t.as_str()),
            "consent title {t:?} is missing from CEREMONY_TITLES"
        );
    }
}

/// Collect the string-literal title argument of every `Confirm::titled(` / `Confirm::new(`
/// under `dir`, recursively. Test and proof siblings are skipped: their titles are
/// fixtures, not screens the firmware can raise.
fn scan_confirm_titles(dir: &std::path::Path, out: &mut std::vec::Vec<std::string::String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        let name = e.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            scan_confirm_titles(&path, out);
            continue;
        }
        if !name.ends_with(".rs") || name.ends_with("_tests.rs") || name.ends_with("_kani.rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path).unwrap_or_default();
        for anchor in ["Confirm::titled(", "Confirm::new("] {
            for (i, m) in src.match_indices(anchor) {
                // The title may sit on the next line (rustfmt wraps the 3-arg form).
                let tail = src[i + m.len()..].trim_start();
                if let Some(rest) = tail.strip_prefix('"')
                    && let Some(end) = rest.find('"')
                {
                    out.push(rest[..end].into());
                }
            }
        }
    }
}

/// A title too wide for its band must be ellipsized inside the panel, never painted
/// past the edge — the ellipsis backstop under [`CEREMONY_TITLES_TOO_WIDE`].
#[test]
fn confirm_keeps_a_wide_title_on_panel() {
    for t in CEREMONY_TITLES_TOO_WIDE {
        let mut d = Rec::new();
        render(&mut d, &Screen::Confirm(ConfirmPrompt::new(t, b"", b""))).unwrap();
        assert!(!d.oob, "{t:?} painted outside the panel");
    }
}

/// Add-passkey reuses the same band: Cancel in `DENY_RECT`, Save filled in
/// `ALLOW_RECT`.
#[test]
fn add_passkey_paints_cancel_and_save_in_their_hit_rects() {
    let rp = Label::clamp(b"github.com");
    let account = Label::clamp(b"alex@example.com");
    let mut d = Rec::new();
    render_add_passkey(&mut d, &rp, &account).unwrap();
    assert!(!d.oob, "add-passkey drew outside the panel");
    assert!(
        has_color(&d, DENY_RECT, theme::DENY),
        "Cancel not in its rect"
    );
    assert!(
        has_color(&d, ALLOW_RECT, theme::ACCENT_FILL),
        "Save not in its rect"
    );
}

/// A long, attacker-influenced rp / account on the add-passkey screen must never
/// overrun the trusted panel — the `centered_clipped` fallback keeps it bounded.
#[test]
fn add_passkey_clips_a_wide_rp_and_account() {
    let rp = Label::clamp(&[b'a'; 48]);
    let account = Label::clamp(b"login.corp.example-company.com");
    let mut d = Rec::new();
    render_add_passkey(&mut d, &rp, &account).unwrap();
    assert!(!d.oob, "wide add-passkey rp/account overran the panel");
}

#[test]
fn confirm_delete_clips_a_wide_rp_and_account() {
    // The delete-confirmation identity must clip like the approve/add screens, so a
    // padded look-alike rpId cannot overflow the card unmarked (anti-phishing).
    let rp = Label::clamp(&[b'W'; 48]);
    let account = Label::clamp(b"login.corp.example-company.com");
    let mut d = Rec::new();
    render_confirm_delete(&mut d, &rp, &account).unwrap();
    assert!(!d.oob, "wide delete-confirm rp/account overran the card");
}

#[test]
fn pin_pad_fits_and_paints_keys_in_their_hit_rects() {
    let mut d = Rec::new();
    render(&mut d, &Screen::Pin(PinPad::new(4))).unwrap();
    assert!(!d.oob, "pin pad drew outside the panel");
    // The OK key is filled in its own hit rect (the key you see is the key you tap).
    let ok = pin_key_rect(2, 3);
    assert_eq!(d.at(ok.x + crate::PIN_KEY_W / 2, ok.y + 3), ALLOW_FILL);
    assert!(d.any_non_bg_in(ok));
    // A digit key carries paint; Cancel is the low-emphasis outline in the deny colour.
    assert!(d.any_non_bg_in(pin_key_rect(0, 0)));
    assert!(has_color(&d, PIN_CANCEL_RECT, theme::DENY));
    // Four entered digits paint cyan masked dots in the band above the grid.
    assert!(has_color(&d, Rect::new(0, 48, PANEL_W, 24), theme::ACCENT));
    // The reveal (eye) toggle is painted in its hit rect.
    assert!(
        has_color(&d, crate::PIN_EYE_RECT, theme::FAINT),
        "reveal eye not drawn on the pad"
    );
}

#[test]
fn pin_reveal_shows_digits_not_dots() {
    // The full masked-entry band (covers the dot row and the eye).
    let band = Rect::new(0, 44, PANEL_W, 32);
    // Masked: accent dots, no revealed digits.
    let mut masked = Rec::new();
    render_pin_dots(&mut masked, 4, 0, None).unwrap();
    assert!(!masked.oob);
    assert!(
        has_color(&masked, band, theme::ACCENT),
        "masked entry must show accent dots"
    );
    // Revealed: the typed digits in the secondary text colour, and no accent dots.
    let mut shown = Rec::new();
    render_pin_dots(&mut shown, 4, 0, Some(b"1234")).unwrap();
    assert!(!shown.oob);
    assert!(
        has_color(&shown, band, theme::TEXT_2),
        "revealed entry must show the typed digits"
    );
    assert!(
        !has_color(&shown, band, theme::ACCENT),
        "revealed entry must not also show masked dots"
    );
}

#[test]
fn pin_long_entry_marks_overflow() {
    let band = Rect::new(0, 44, PANEL_W, 32);
    // A PIN within the row draws no overflow marker.
    let mut short = Rec::new();
    render_pin_dots(&mut short, 4, 0, None).unwrap();
    assert!(
        !has_color(&short, band, theme::CAPTION),
        "no overflow marker for a short PIN"
    );
    // A PIN longer than the row (e.g. the 63-digit CTAP max) caps the dots and marks
    // the rest with a "+" (caption colour) — and never draws outside the panel.
    let mut long = Rec::new();
    render_pin_dots(&mut long, 63, 0, None).unwrap();
    assert!(!long.oob, "a long PIN must not draw outside the panel");
    assert!(
        has_color(&long, band, theme::CAPTION),
        "overflow marker missing for a long PIN"
    );
}

#[test]
fn pin_caption_paints_below_the_grid_in_the_danger_colour() {
    // A wrong-PIN re-prompt carries a danger-coloured caption in the strip under the
    // last key row (grid bottom is y300; the caption sits in 300..320).
    let mut d = Rec::new();
    let pad = PinPad::with_caption(
        0,
        "Enter PIN",
        Some(PinCaption::WrongPin { retries_left: 3 }),
    );
    render(&mut d, &Screen::Pin(pad)).unwrap();
    assert!(!d.oob, "caption drew outside the panel");
    assert!(
        has_color(&d, Rect::new(0, 301, PANEL_W, PANEL_H - 301), theme::DANGER),
        "wrong-PIN caption must paint in the danger colour below the grid"
    );
    // A fresh prompt (no caption) leaves that strip blank.
    let mut clean = Rec::new();
    render(&mut clean, &Screen::Pin(PinPad::new(0))).unwrap();
    assert!(
        !has_color(
            &clean,
            Rect::new(0, 301, PANEL_W, PANEL_H - 301),
            theme::DANGER
        ),
        "a fresh pad must not show a caption"
    );
}

#[test]
fn pin_dots_partial_update_leaves_keys_intact() {
    let mut d = Rec::new();
    render(&mut d, &Screen::Pin(PinPad::new(2))).unwrap();
    let ok = pin_key_rect(2, 3);
    let key_px = d.at(ok.x + crate::PIN_KEY_W / 2, ok.y + 3);
    // A partial dots update touches only the entry band, never the keys.
    render_pin_dots(&mut d, 5, 0, None).unwrap();
    assert!(!d.oob);
    assert_eq!(
        d.at(ok.x + crate::PIN_KEY_W / 2, ok.y + 3),
        key_px,
        "the static keys must survive a partial dots update"
    );
    // The band still carries dots for the new digit count.
    assert!((48..72).any(|y| (0..PANEL_W).any(|x| d.at(x, y) != BG)));
}

#[test]
fn pin_placeholders_outline_the_expected_minimum() {
    let band = Rect::new(0, 48, PANEL_W, 24);
    // An empty pad expecting 6 digits already outlines them — dim placeholder rings,
    // no filled accent dot yet.
    let mut empty = Rec::new();
    render(&mut empty, &Screen::Pin(PinPad::new(0).expecting(6))).unwrap();
    assert!(!empty.oob);
    assert!(
        has_color(&empty, band, theme::CAPTION),
        "an empty pad must outline the expected digits"
    );
    assert!(
        !has_color(&empty, band, theme::ACCENT),
        "no digit entered yet, so no filled dot"
    );
    // Two of six entered: the row carries both filled (accent) and outlined (dim) dots.
    let mut some = Rec::new();
    render(&mut some, &Screen::Pin(PinPad::new(2).expecting(6))).unwrap();
    assert!(has_color(&some, band, theme::ACCENT), "entered digits fill");
    assert!(
        has_color(&some, band, theme::CAPTION),
        "the remaining placeholders stay outlined"
    );
}

#[test]
fn pin_info_caption_paints_muted_not_danger() {
    // The strip under the grid (grid bottom is y300; the caption sits in 301..320).
    let strip = Rect::new(0, 301, PANEL_W, PANEL_H - 301);
    for hint in [
        PinCaption::TriesRemaining { left: 7 },
        PinCaption::ChoosePin,
        PinCaption::Reenter,
    ] {
        let mut d = Rec::new();
        render(
            &mut d,
            &Screen::Pin(PinPad::with_caption(0, "Enter PIN", Some(hint))),
        )
        .unwrap();
        assert!(!d.oob);
        assert!(
            has_color(&d, strip, MUTED),
            "an informational hint must paint muted"
        );
        assert!(
            !has_color(&d, strip, theme::DANGER),
            "an informational hint must not use the danger colour"
        );
    }
}

fn view(page: SettingsPage) -> SettingsView {
    SettingsView {
        page,
        brightness: 3,
        timeout_secs: 30,
        sleep_secs: 60,
        version: 0x078A,
        chipid: 0x0123_4567_89ab_cdef,
        device_pin_set: true,
        fido_pin_set: true,
        backup_sealed: true,
        scramble_pin: false,
    }
}

#[test]
fn every_settings_page_fits_and_draws() {
    for page in [
        SettingsPage::Root,
        SettingsPage::Display,
        SettingsPage::Brightness,
        SettingsPage::Timeout,
        SettingsPage::Sleep,
        SettingsPage::Security,
    ] {
        let mut d = Rec::new();
        render(&mut d, &Screen::Settings(view(page))).unwrap();
        assert!(!d.oob, "settings {page:?} drew outside the panel");
        assert!(d.drew_anything(), "settings {page:?} drew nothing");
    }
}

#[test]
fn firmware_screen_fits_and_draws() {
    // The Firmware screen is a hold sub-flow (rendered directly, not via the settings
    // dispatch); it must paint its version + serial + hold button inside the panel under
    // both secure-boot states (the copy branches on the real fuse).
    for secure_boot in [true, false] {
        let mut d = Rec::new();
        render_firmware(&mut d, 0x07B6, 0x8e0f_f6ae_ae0b_c470, secure_boot).unwrap();
        assert!(
            !d.oob,
            "firmware screen (sb={secure_boot}) drew outside the panel"
        );
        assert!(
            d.drew_anything(),
            "firmware screen (sb={secure_boot}) drew nothing"
        );
    }
    // The notice shown the instant the hold commits must also fit.
    let mut n = Rec::new();
    render_rebooting(&mut n).unwrap();
    assert!(!n.oob, "rebooting notice drew outside the panel");
    assert!(n.drew_anything(), "rebooting notice drew nothing");
}

#[test]
fn security_page_paints_every_row_under_either_pin_state() {
    for pin_set in [false, true] {
        let mut v = view(SettingsPage::Security);
        v.device_pin_set = pin_set;
        v.fido_pin_set = !pin_set;
        let mut d = Rec::new();
        render(&mut d, &Screen::Settings(v)).unwrap();
        assert!(
            !d.oob,
            "security (pin_set={pin_set}) drew outside the panel"
        );
        // Every Security row (Device PIN, FIDO PIN, PIV PIN, Audit log, Backup, Factory
        // reset) is painted in the rect `hit_security` maps its tap to; the bottom row
        // (now six) must stay on-panel (the `!oob` check above).
        for i in 0..crate::SECURITY_ROWS {
            assert!(
                d.any_non_bg_in(settings_row_rect(i)),
                "security row {i} unpainted (pin_set={pin_set})"
            );
        }
    }
}

#[test]
fn piv_pin_menu_paints_four_rows_on_panel() {
    let mut d = Rec::new();
    render_piv_pin_menu(&mut d).unwrap();
    assert!(!d.oob && d.drew_anything(), "PIV PIN menu off-panel");
    // The four op rows (Change PIN / Change PUK / Unblock PIN / Protect mgmt key) each
    // paint where `hit_list(_, PIV_KEYGEN_PICK_TOP, _)` maps a tap.
    for i in 0..4u16 {
        assert!(
            d.any_non_bg_in(crate::row_rect(PIV_KEYGEN_PICK_TOP, i)),
            "PIV PIN menu row {i} unpainted"
        );
    }
}

/// Each PIV-PIN-menu row's full label must fit the width [`row_body`] leaves after it
/// lays out the (right-aligned) trailing caption + chevron — else the label is ellipsised
/// to nothing while only the caption shows (the "Protect mgmt key" regression: a 159 px
/// caption left its 128 px label 1 px). Mirrors `row_body`'s geometry; the row table must
/// match [`render_piv_pin_menu`].
#[test]
fn piv_pin_menu_labels_fit_beside_their_captions() {
    let r0 = crate::row_rect(PIV_KEYGEN_PICK_TOP, 0);
    let (row_x, row_w) = (r0.x as i32, r0.w as i32);
    // (label, trailing caption) — must mirror render_piv_pin_menu.
    let rows: [(&str, Option<&str>); 4] = [
        ("Change PIN", None),
        ("Change PUK", None),
        ("Unblock PIN", Some("with PUK")),
        ("Protect mgmt key", None),
    ];
    for (label, cap) in rows {
        let label_x = row_x + 28; // row_body's label inset
        let mut right = row_x + row_w - 8 - 12; // row edge, minus the chevron these rows draw
        right -= match cap {
            Some(c) => 4 + font::width(c, Role::Body).unwrap() as i32 + ROW_TRAILING_GAP,
            None => ROW_TRAILING_GAP,
        };
        let avail = right - label_x;
        let lw = font::width(label, Role::Body).unwrap() as i32;
        assert!(
            lw <= avail,
            "PIV PIN menu label '{label}' ({lw} px) clipped to {avail} px by its caption"
        );
    }
}

#[test]
fn backup_screen_paints_every_state_inside_the_panel() {
    // (sealed, has_seed, exportable, can_reveal): the status states plus the
    // window-open state that shows the on-device action buttons.
    let states = [
        BackupView {
            sealed: false,
            has_seed: true,
            exportable: true,
            can_reveal: true,
        },
        BackupView {
            sealed: true,
            has_seed: true,
            exportable: true,
            can_reveal: false,
        },
        BackupView {
            sealed: false,
            has_seed: false,
            exportable: true,
            can_reveal: false,
        },
        BackupView {
            sealed: true,
            has_seed: true,
            exportable: false,
            can_reveal: false,
        },
    ];
    for v in states {
        let mut d = Rec::new();
        render_backup(&mut d, &v).unwrap();
        assert!(!d.oob, "backup {v:?} drew outside the panel");
        assert!(d.drew_anything(), "backup {v:?} painted nothing");
        // When the actions are offered, both buttons are painted in their hit rects.
        if v.can_reveal {
            assert!(
                d.any_non_bg_in(crate::BACKUP_REVEAL_RECT),
                "reveal button unpainted"
            );
            assert!(
                d.any_non_bg_in(crate::BACKUP_SEAL_RECT),
                "seal button unpainted"
            );
        }
    }
}

#[test]
fn seed_phrase_and_gates_paint_inside_the_panel() {
    // A full 24-word phrase, both pages, plus the reveal/seal gate screens.
    let words: [&str; 24] = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
        "abuse", "access", "accident", "zoo", "zone", "zero", "youth", "yellow", "wrist", "write",
        "wrong", "yard", "year", "wealth", "weapon",
    ];
    for page in 0..2u16 {
        let mut d = Rec::new();
        render_seed_phrase(&mut d, &words, page, 2).unwrap();
        assert!(!d.oob, "seed phrase page {page} drew outside the panel");
        assert!(d.drew_anything(), "seed phrase page {page} painted nothing");
    }
    for kind in [RevealKind::Phrase, RevealKind::Shares] {
        let mut d = Rec::new();
        render_reveal_warning(&mut d, kind).unwrap();
        assert!(!d.oob && d.drew_anything());
    }
    let mut d = Rec::new();
    render_seal_confirm(&mut d).unwrap();
    assert!(!d.oob && d.drew_anything());

    // The recovery-format chooser, the SLIP-39 share picker, and a share page must all
    // paint inside the panel.
    let mut d = Rec::new();
    render_backup_format(&mut d).unwrap();
    assert!(
        !d.oob && d.drew_anything(),
        "format chooser drew outside the panel"
    );
    let mut d = Rec::new();
    render_share_picker(&mut d, 2, 3).unwrap();
    assert!(
        !d.oob && d.drew_anything(),
        "share picker drew outside the panel"
    );
    let share: [&str; 33] = ["academic"; 33];
    for page in 0..3u16 {
        let mut d = Rec::new();
        render_slip39_share(&mut d, &share, 1, 3, page, 3).unwrap();
        assert!(!d.oob, "share page {page} drew outside the panel");
        assert!(d.drew_anything(), "share page {page} painted nothing");
    }
}

#[test]
fn audit_log_paints_rows_with_kind_coloured_dots() {
    let rows = [
        AuditRow {
            kind: AuditKind::Login,
            secs_ago: Some(120),
        },
        AuditRow {
            kind: AuditKind::Register,
            secs_ago: Some(3600),
        },
        AuditRow {
            kind: AuditKind::Denied,
            secs_ago: None,
        },
    ];
    let mut d = Rec::new();
    render_audit_log(&mut d, &rows, 0, 3, true).unwrap();
    assert!(!d.oob, "audit log drew outside the panel");
    // Each row's status dot is painted in its kind colour, inside its row rect.
    for (i, c) in [theme::SUCCESS, theme::ACCENT, theme::DANGER]
        .into_iter()
        .enumerate()
    {
        assert!(
            has_color(&d, crate::row_rect(crate::PK_LIST_TOP, i as u16), c),
            "row {i} status-dot colour missing"
        );
    }
}

#[test]
fn audit_log_empty_shows_placeholder_and_no_rows() {
    let mut d = Rec::new();
    render_audit_log(&mut d, &[], 0, 0, true).unwrap();
    assert!(!d.oob, "empty audit log drew outside the panel");
    assert!(d.drew_anything(), "empty audit log drew nothing");
    // No row card is painted when there are no events.
    assert!(
        !d.any_non_bg_in(crate::row_rect(crate::PK_LIST_TOP, 0)),
        "empty audit log painted a row card"
    );
}

/// Whether `d` painted exactly `s`, in `role`/`color`, centred on `cy` — a pixel-exact
/// check against a reference frame, so a test can pin *wording* and not merely that
/// something was drawn.
fn shows_centered(d: &Rec, s: &str, cy: i32, role: Role, color: Rgb565) -> bool {
    let mut want = Rec::new();
    font::centered(&mut want, s, EgPoint::new(MIDX, cy), role, color, BG).unwrap();
    ((cy - 12) as u16..(cy + 12) as u16).all(|y| (0..PANEL_W).all(|x| d.at(x, y) == want.at(x, y)))
}

/// The empty screen must not say "No activity yet" on a device that was never watching:
/// journalling is off by default, so the two states have to read differently — the
/// distinction between "I saw nothing" and "I was not looking".
#[test]
fn audit_log_empty_wording_tracks_the_logging_flag() {
    let mut on = Rec::new();
    render_audit_log(&mut on, &[], 0, 0, true).unwrap();
    assert!(
        shows_centered(&on, "No activity yet", 160, Role::Body, MUTED),
        "an enabled, idle journal must read as no activity"
    );

    let mut off = Rec::new();
    render_audit_log(&mut off, &[], 0, 0, false).unwrap();
    assert!(!off.oob, "logging-off audit log drew outside the panel");
    assert!(
        shows_centered(&off, "Logging is off", 160, Role::Body, theme::WARN),
        "a device that was never recording must say so, in WARN"
    );
    assert!(
        shows_centered(
            &off,
            "Nothing is being recorded",
            184,
            Role::MonoSmall,
            theme::CAPTION
        ),
        "the logging-off caption is missing"
    );
}

#[test]
fn multi_page_list_shows_pager_in_its_hit_rects() {
    // A full page of a 3-page list (13 events): mid-list, so both arrows are active.
    let rows = [AuditRow {
        kind: AuditKind::Login,
        secs_ago: Some(60),
    }; crate::PK_ROWS_MAX];
    let mut d = Rec::new();
    render_audit_log(&mut d, &rows, 1, 13, true).unwrap();
    assert!(!d.oob, "paged audit log drew outside the panel");
    assert!(
        has_aa_color(&d, crate::PAGER_PREV_RECT, theme::ACCENT, BG),
        "prev arrow missing from its hit rect"
    );
    assert!(
        has_aa_color(&d, crate::PAGER_NEXT_RECT, theme::ACCENT, BG),
        "next arrow missing from its hit rect"
    );
}

#[test]
fn pager_dims_the_unavailable_end_arrow() {
    let rows = [AuditRow {
        kind: AuditKind::Login,
        secs_ago: Some(60),
    }; crate::PK_ROWS_MAX];
    // First page of 3: prev is dimmed, next is active.
    let mut d = Rec::new();
    render_audit_log(&mut d, &rows, 0, 13, true).unwrap();
    assert!(
        has_aa_color(&d, crate::PAGER_PREV_RECT, theme::CAPTION, BG),
        "prev not dimmed on the first page"
    );
    assert!(
        has_aa_color(&d, crate::PAGER_NEXT_RECT, theme::ACCENT, BG),
        "next not active on the first page"
    );
    // Last page (2 of 3): next is dimmed.
    let mut d2 = Rec::new();
    render_audit_log(&mut d2, &rows[..3], 2, 13, true).unwrap();
    assert!(
        has_aa_color(&d2, crate::PAGER_NEXT_RECT, theme::CAPTION, BG),
        "next not dimmed on the last page"
    );
}

#[test]
fn single_page_list_shows_footer_not_pager() {
    let rows = [AuditRow {
        kind: AuditKind::Login,
        secs_ago: Some(60),
    }; 3];
    let mut d = Rec::new();
    render_audit_log(&mut d, &rows, 0, 3, true).unwrap();
    // One page → no pager: the prev-arrow region (left, clear of the right-aligned
    // item-count footer) stays background.
    assert!(
        !d.any_non_bg_in(crate::PAGER_PREV_RECT),
        "single-page list painted a pager arrow"
    );
}

#[test]
fn fmt_ago_buckets_units() {
    let mut b = [0u8; 8];
    assert_eq!(fmt_ago(0, &mut b), "now");
    assert_eq!(fmt_ago(59, &mut b), "now");
    assert_eq!(fmt_ago(60, &mut b), "1m");
    assert_eq!(fmt_ago(125, &mut b), "2m");
    assert_eq!(fmt_ago(3_600, &mut b), "1h");
    assert_eq!(fmt_ago(86_400, &mut b), "1d");
    assert_eq!(fmt_ago(6 * 86_400, &mut b), "6d");
    assert_eq!(fmt_ago(604_800, &mut b), "1w");
}

#[test]
fn settings_root_paints_every_row_in_its_hit_rect() {
    let mut d = Rec::new();
    render(&mut d, &Screen::Settings(view(SettingsPage::Root))).unwrap();
    for i in 0..crate::SETTINGS_ROWS {
        assert!(
            d.any_non_bg_in(settings_row_rect(i)),
            "root row {i} unpainted"
        );
    }
}

#[test]
fn settings_display_paints_every_row_in_its_hit_rect() {
    let mut d = Rec::new();
    render(&mut d, &Screen::Settings(view(SettingsPage::Display))).unwrap();
    for i in 0..crate::DISPLAY_ROWS {
        assert!(
            d.any_non_bg_in(settings_row_rect(i)),
            "display row {i} unpainted"
        );
    }
}

#[test]
fn adjust_pages_paint_controls_in_their_hit_rects() {
    for page in [
        SettingsPage::Brightness,
        SettingsPage::Timeout,
        SettingsPage::Sleep,
    ] {
        let mut d = Rec::new();
        render(&mut d, &Screen::Settings(view(page))).unwrap();
        assert!(d.any_non_bg_in(ADJ_MINUS_RECT), "{page:?} minus unpainted");
        assert!(d.any_non_bg_in(ADJ_PLUS_RECT), "{page:?} plus unpainted");
        // Back is now the title-bar chevron (no bottom slab), in its hit rect.
        assert!(
            has_color(&d, crate::TITLE_BACK_RECT, theme::ACCENT),
            "{page:?} back chevron unpainted"
        );
    }
}

#[test]
fn brightness_bar_lights_more_segments_at_higher_levels() {
    // The bar band is just above the −/+ controls; a higher level fills more of it.
    let band = Rect::new(0, 96, PANEL_W, 28);
    let count_lit = |level: u8| {
        let mut v = view(SettingsPage::Brightness);
        v.brightness = level;
        let mut d = Rec::new();
        render(&mut d, &Screen::Settings(v)).unwrap();
        (band.x..band.x + band.w)
            .filter(|&x| (band.y..band.y + band.h).any(|y| d.at(x, y) == ALLOW_FILL))
            .count()
    };
    assert!(
        count_lit(4) > count_lit(1),
        "more brightness must light more bar"
    );
}

#[test]
fn header_row_and_nav_draw_within_bounds() {
    let mut d = Rec::new();
    render_header(&mut d, "Settings", true, Some(Glyph::Shield)).unwrap();
    let r = crate::row_rect(40, 0);
    components::rect_card(&mut d, r).unwrap();
    components::rect_row(&mut d, r, Glyph::Lock, "PIN", Some(("OK", theme::OK)), true).unwrap();
    render_nav(&mut d, NavTab::Settings).unwrap();
    assert!(!d.oob, "design-system widgets drew outside the panel");
    // The list-row card fills its rect (sampled on the flat top span).
    assert_eq!(d.at(r.x + r.w / 2, r.y + 3), theme::ROW_BG);
}

/// A row label far too long for its slot is clipped clear of the trailing value —
/// the proportional-font regression that made "webauthn.io" touch "4 accounts".
#[test]
fn long_row_label_is_clipped_clear_of_the_trailing_value() {
    let r = crate::row_rect(40, 0);
    let txt = "4 accounts";
    let mut d = Rec::new();
    components::rect_card(&mut d, r).unwrap();
    components::rect_row(
        &mut d,
        r,
        Glyph::Globe,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        Some((txt, theme::MUTED)),
        true,
    )
    .unwrap();
    assert!(!d.oob);
    // Reconstruct the trailing value's left edge; the ROW_TRAILING_GAP-wide seam to
    // its left must be free of the (white) label text.
    let right_x = r.x as i32 + r.w as i32 - 8 - 12;
    let value_left = (right_x - 4) - font::width(txt, Role::Body).unwrap() as i32;
    for x in (value_left - ROW_TRAILING_GAP).max(0)..value_left {
        for y in r.y..r.y + r.h {
            assert_ne!(
                d.at(x as u16, y),
                theme::TEXT,
                "label not clipped clear of the trailing value at x={x}"
            );
        }
    }
}

/// The two-tier chrome paints within its strips and, with `back`, the title-bar
/// chevron lands in `TITLE_BACK_RECT` (where `hit_title_back` maps a tap).
#[test]
fn chrome_bars_draw_in_their_strips() {
    let mut d = Rec::new();
    status_bar(&mut d).unwrap();
    title_bar(&mut d, "Passkeys", theme::ACCENT, true).unwrap();
    assert!(!d.oob, "chrome drew outside the panel");
    // The status strip carries the RS-Key wordmark + USB indicator.
    assert!(
        d.any_non_bg_in(Rect::new(0, 0, PANEL_W, STATUS_BAR_H)),
        "status bar painted nothing"
    );
    // The back chevron lands in its title-bar hit rect.
    assert!(
        has_color(&d, crate::TITLE_BACK_RECT, theme::ACCENT),
        "back chevron not in TITLE_BACK_RECT"
    );
}

#[test]
fn nav_accents_only_the_active_tab() {
    let mut d = Rec::new();
    render_nav(&mut d, NavTab::Settings).unwrap();
    let has =
        |r: Rect, c: Rgb565| (r.y..r.y + r.h).any(|y| (r.x..r.x + r.w).any(|x| d.at(x, y) == c));
    assert!(
        has(crate::nav_tab_rect(3), theme::ACCENT),
        "active tab not accented"
    );
    assert!(
        !has(crate::nav_tab_rect(0), theme::ACCENT),
        "inactive tab accented"
    );
    assert!(
        !(NAV_TOP + 1..PANEL_H).any(|y| (0..PANEL_W).any(|x| d.at(x, y) == BG)),
        "nav icon or caption stamped the page background over the bar"
    );
}

#[test]
fn applet_screens_paint_inside_the_panel() {
    use crate::{PgpSlotRow, PivSlotRow};
    let mut d = Rec::new();
    render_apps(
        &mut d,
        &AppsView {
            openpgp_keys: 2,
            piv_slots: 1,
            oath_codes: 5,
        },
    )
    .unwrap();
    assert!(!d.oob && d.drew_anything(), "apps chooser");

    let pgp = OpenpgpView {
        slots: [
            PgpSlotRow {
                present: true,
                algo: Label::clamp(b"Ed25519"),
                touch: true,
            },
            PgpSlotRow {
                present: true,
                algo: Label::clamp(b"Cv25519"),
                touch: false,
            },
            PgpSlotRow::default(),
        ],
        cardholder_name: Label::clamp(b"Alice Dev"),
        sig_count: 42,
        pw1: 3,
        pw3: 3,
    };
    let mut d = Rec::new();
    render_openpgp(&mut d, &pgp).unwrap();
    assert!(!d.oob, "openpgp overview spilled");

    // A max-length host-controlled cardholder name on the OVERVIEW row must stay
    // on-panel: the "Card holder" value is right-anchored, so an unclipped long
    // name would overrun left off the panel (the row_body trailing-clip guard).
    let mut wide = pgp;
    wide.cardholder_name = Label::clamp(&[b'W'; 64]);
    let mut d = Rec::new();
    render_openpgp(&mut d, &wide).unwrap();
    assert!(!d.oob, "openpgp overview cardholder name overran the panel");

    let mut d = Rec::new();
    render_openpgp_cardholder(
        &mut d,
        &CardholderView {
            name: Label::clamp(b"Alice Dev"),
            login: Label::clamp(b"alice"),
            url: Label::clamp(b"https://keys.example.org/very/long/path/alice"),
            lang: Label::clamp(b"en"),
            any: true,
        },
    )
    .unwrap();
    assert!(!d.oob && d.drew_anything(), "openpgp cardholder spilled");

    let mut d = Rec::new();
    render_openpgp_cardholder(&mut d, &CardholderView::default()).unwrap();
    assert!(!d.oob && d.drew_anything(), "openpgp cardholder empty");

    let mut d = Rec::new();
    render_openpgp_key(
        &mut d,
        &PgpKeyView {
            slot: 0,
            present: true,
            algo: Label::clamp(b"Ed25519"),
            touch: true,
            created: true,
            fingerprint: [0xAB; 20],
            has_fp: true,
        },
    )
    .unwrap();
    assert!(!d.oob, "openpgp key detail spilled");

    // The empty-slot branch must also paint inside the panel.
    let mut d = Rec::new();
    render_openpgp_key(
        &mut d,
        &PgpKeyView {
            slot: 2,
            present: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!d.oob && d.drew_anything(), "openpgp empty slot");

    let piv = PivView {
        slots: [
            PivSlotRow {
                slot: 0x9A,
                present: true,
                cert: true,
                algo: Label::clamp(b"NIST P-256"),
            },
            PivSlotRow {
                slot: 0x9C,
                present: false,
                cert: true,
                algo: Label::default(),
            },
            PivSlotRow {
                slot: 0x9D,
                ..Default::default()
            },
            PivSlotRow {
                slot: 0x9E,
                ..Default::default()
            },
        ],
        extra: 3,
        pin: 1,
        puk: 0,
    };
    let mut d = Rec::new();
    render_piv(&mut d, &piv).unwrap();
    assert!(!d.oob, "piv overview spilled");

    // The "Retired & F9" screen: F9, a retired key, a cert-only retired slot, and the
    // trailing generate action — plus an empty-state and a retired/F9 slot detail.
    let extra = [
        PivExtraRow {
            slot: 0xF9,
            present: true,
            cert: true,
            algo: Label::clamp(b"NIST P-384"),
            generate: false,
        },
        PivExtraRow {
            slot: 0x82,
            present: true,
            cert: false,
            algo: Label::clamp(b"NIST P-256"),
            generate: false,
        },
        PivExtraRow {
            slot: 0x95,
            present: false,
            cert: true,
            algo: Label::default(),
            generate: false,
        },
        PivExtraRow {
            generate: true,
            ..Default::default()
        },
    ];
    let mut d = Rec::new();
    render_piv_extra(&mut d, &extra, 0, 4).unwrap();
    assert!(!d.oob && d.drew_anything(), "piv extra list spilled");
    let mut d = Rec::new();
    render_piv_extra(&mut d, &[], 0, 0).unwrap();
    assert!(!d.oob && d.drew_anything(), "piv extra empty");

    let mut d = Rec::new();
    render_piv_slot(
        &mut d,
        &PivSlotView {
            slot: 0x82,
            present: true,
            algo: Label::clamp(b"NIST P-256"),
            pin_policy: Label::clamp(b"Once"),
            touch_policy: Label::clamp(b"Always"),
            origin: Label::clamp(b"Generated"),
            cert: true,
        },
    )
    .unwrap();
    assert!(!d.oob, "retired slot detail spilled");

    let mut d = Rec::new();
    render_piv_keygen_pick(&mut d, 0x82).unwrap();
    assert!(!d.oob && d.drew_anything(), "keygen pick spilled");
    let mut d = Rec::new();
    render_piv_keygen_confirm(&mut d, 0x82, "NIST P-256").unwrap();
    assert!(!d.oob && d.drew_anything(), "keygen confirm spilled");

    let mut d = Rec::new();
    render_piv_protect_confirm(&mut d).unwrap();
    assert!(!d.oob && d.drew_anything(), "protect-mgm confirm spilled");

    let mut d = Rec::new();
    render_piv_slot(
        &mut d,
        &PivSlotView {
            slot: 0x9D,
            present: true,
            cert: false,
            algo: Label::clamp(b"RSA 2048"),
            pin_policy: Label::clamp(b"Once"),
            touch_policy: Label::clamp(b"Always"),
            origin: Label::clamp(b"Imported"),
        },
    )
    .unwrap();
    assert!(!d.oob, "piv slot detail spilled");

    let mut d = Rec::new();
    render_piv_slot(
        &mut d,
        &PivSlotView {
            slot: 0x9E,
            present: false,
            cert: false,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!d.oob && d.drew_anything(), "piv empty slot");

    let oath = [
        OathRow {
            name: Label::clamp(b"GitHub:alex"),
            hotp: false,
            touch: true,
        },
        OathRow {
            name: Label::clamp(b"AWS root"),
            hotp: true,
            touch: false,
        },
    ];
    let mut d = Rec::new();
    render_oath(&mut d, &oath, 0, 2).unwrap();
    assert!(!d.oob, "oath list spilled");
    let mut d = Rec::new();
    render_oath(&mut d, &[], 0, 0).unwrap();
    assert!(!d.oob && d.drew_anything(), "oath empty");

    let mut d = Rec::new();
    render_oath_cred(
        &mut d,
        &OathDetailView {
            name: Label::clamp(b"GitHub:alex"),
            hotp: false,
            algo: Label::clamp(b"SHA1"),
            digits: 6,
            period: 30,
            touch: true,
        },
    )
    .unwrap();
    assert!(!d.oob && d.drew_anything(), "oath cred detail spilled");
    let mut d = Rec::new();
    render_oath_cred(
        &mut d,
        &OathDetailView {
            name: Label::clamp(b"AWS"),
            hotp: true,
            algo: Label::clamp(b"SHA256"),
            digits: 8,
            period: 0,
            touch: false,
        },
    )
    .unwrap();
    assert!(!d.oob && d.drew_anything(), "oath hotp detail spilled");
}

#[test]
fn apps_chooser_accents_the_apps_tab() {
    let mut d = Rec::new();
    render_apps(&mut d, &AppsView::default()).unwrap();
    let has =
        |r: Rect, c: Rgb565| (r.y..r.y + r.h).any(|y| (r.x..r.x + r.w).any(|x| d.at(x, y) == c));
    assert!(
        has(crate::nav_tab_rect(2), theme::ACCENT),
        "Apps tab not accented"
    );
}

#[test]
fn hold_fill_grows_left_to_right_with_a_flat_edge() {
    // The wash painted by the fill is the base's lighter `hold_overlay` — for the blue
    // base that is HOLD_ON_BLUE. Count wash pixels along the horizontal centre line.
    let wash = theme::HOLD_ON_BLUE;
    let r = Rect::new(20, 200, 120, 60);
    let yc = r.y + r.h / 2;
    let lit = |num: u16| {
        let mut d = Rec::new();
        render_hold_fill(&mut d, r, "Hold", 0, num, 10, theme::APPROVE).unwrap();
        (r.x..r.x + r.w).filter(|&x| d.at(x, yc) == wash).count()
    };
    assert!(
        lit(8) > lit(2),
        "more hold progress must fill more of the button"
    );
    // The advancing edge is flat (only the left corners are rounded), so the wash
    // reaches the top row right up to its right edge — a rounded-all-corners fill
    // would leave that corner empty (the artifact this guards against).
    let mut d = Rec::new();
    render_hold_fill(&mut d, r, "Hold", 0, 5, 10, theme::APPROVE).unwrap();
    let w = r.w / 2; // num/den = 5/10
    assert_eq!(d.at(r.x + w - 3, r.y + 2), wash);
}

#[test]
fn hold_fill_repaints_only_the_new_strip_and_matches_one_step() {
    let r = Rect::new(20, 200, 120, 60);
    let mut incremental = Rec::new();
    render_hold_button(&mut incremental, r, "Hold", theme::APPROVE).unwrap();
    for (previous, next) in [(0, 2), (2, 5), (5, 10)] {
        render_hold_fill(
            &mut incremental,
            r,
            "Hold",
            previous,
            next,
            10,
            theme::APPROVE,
        )
        .unwrap();
    }

    let mut one_step = Rec::new();
    render_hold_button(&mut one_step, r, "Hold", theme::APPROVE).unwrap();
    render_hold_fill(&mut one_step, r, "Hold", 0, 10, 10, theme::APPROVE).unwrap();
    assert_eq!(incremental.px, one_step.px);

    incremental.reset_writes();
    render_hold_fill(&mut incremental, r, "Hold", 4, 5, 10, theme::APPROVE).unwrap();
    let strip = Rect::new(r.x + 48, r.y, 12, r.h);
    assert!(incremental.wrote_anything());
    assert!(!incremental.wrote_outside(strip));

    incremental.reset_writes();
    render_hold_fill(&mut incremental, r, "Hold", 5, 5, 10, theme::APPROVE).unwrap();
    assert!(!incremental.wrote_anything());
}

/// Regression: `render_pin_dots` must clear the "+" overflow marker and the 10th
/// dot when `entered` drops. The old per-dot clear was centred on each circle, so
/// it left the "+" (drawn at x 184) and dot 10's right tail behind on a delete —
/// a shortened PIN still read as long.
#[test]
fn pin_dots_clear_strip_erases_overflow_and_tenth_dot_on_delete() {
    use crate::render_pin_dots;
    // ENTRY_* are private to render/pin.rs; mirror them here so the edge test does
    // not force a wider re-export. Keep in sync with render/pin.rs.
    const ENTRY_X0: u16 = 24;
    const ENTRY_MAX_SHOWN: u16 = 10;
    const ENTRY_STEP: u16 = 16;

    // Dot i is a 12×12 circle at top-left (24 + i·16, 54). The "+" overflow marker
    // draws to the right of the last dot (x 184..). Use boxes, not point probes, so
    // the test does not pin a glyph baseline.
    let dot10 = Rect::new(ENTRY_X0 + 9 * ENTRY_STEP, 54, 12, 12); // i = 9, the 10th dot.
    let plus = Rect::new(ENTRY_X0 + ENTRY_MAX_SHOWN * ENTRY_STEP, 48, 20, 24);

    // 11 entered → both the 10th dot and the "+" paint; drop to 9 → both erase.
    let mut d = Rec::new();
    render_pin_dots(&mut d, 11, 8, None).unwrap();
    assert!(
        d.any_non_bg_in(dot10),
        "setup: the 10th dot should paint before delete"
    );
    assert!(
        d.any_non_bg_in(plus),
        "setup: the '+' overflow marker should paint before delete"
    );
    render_pin_dots(&mut d, 9, 8, None).unwrap();
    assert!(
        !d.any_non_bg_in(dot10),
        "10th dot not erased on delete — stale tail reads as a longer PIN"
    );
    assert!(
        !d.any_non_bg_in(plus),
        "stale '+' marker left after delete — shortened PIN still read as long"
    );
}

/// Audit run-36: `rsk_openpgp::info` returns `CH_FIELD_MAX = LABEL_MAX + 1` bytes for
/// the sole purpose of letting `Label::clamp` set `truncated`, and
/// `firmware/src/display/applets.rs` static-asserts that relationship — then this
/// screen passed `force_mark: false` and threw the flag away. A 48-byte clip of a
/// longer, narrow-glyph value fits the 212 px box, so the fast path painted it with
/// no ellipsis and it read as the whole thing: the registrable domain on screen was
/// not the one stored. Assert the panel actually differs.
#[test]
fn a_truncated_cardholder_value_paints_its_marker() {
    let narrow = Label::clamp(&[b'i'; 48]); // 48 bytes, fits the box, NOT truncated
    let mut clipped = Label::clamp(&[b'i'; 64]); // clipped at the cap
    assert!(clipped.truncated, "the fixture must actually be truncated");
    clipped.truncated = true;

    let view = |f: Label| CardholderView {
        name: Label::clamp(b"Alice"),
        login: Label::clamp(b"alice"),
        url: f,
        lang: Label::clamp(b"en"),
        any: true,
    };

    let mut whole = Rec::new();
    render_openpgp_cardholder(&mut whole, &view(narrow)).unwrap();
    let mut cut = Rec::new();
    render_openpgp_cardholder(&mut cut, &view(clipped)).unwrap();

    assert!(
        whole.px != cut.px,
        "a clipped cardholder value painted identically to a whole one"
    );
    assert!(!cut.oob, "the marker drew outside the panel");
}
