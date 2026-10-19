// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use core::convert::Infallible;

use embedded_graphics::{
    Pixel, draw_target::DrawTarget, geometry::OriginDimensions, pixelcolor::Rgb565,
    primitives::Rectangle,
};

use super::*;

/// A 240×135 recording target (same shape as `keys_tests`' `Rec`): clips
/// out-of-bounds pixels but flags that it had to, so a test can assert a menu
/// page stayed inside the touchless panel.
struct Rec {
    px: std::vec::Vec<Rgb565>,
    wrote: std::vec::Vec<bool>,
    oob: bool,
}

impl Rec {
    fn new() -> Self {
        Self {
            px: std::vec![BG; KEYS_W as usize * KEYS_H as usize],
            wrote: std::vec![false; KEYS_W as usize * KEYS_H as usize],
            oob: false,
        }
    }
    fn at(&self, x: u16, y: u16) -> Rgb565 {
        self.px[y as usize * KEYS_W as usize + x as usize]
    }
    fn any_ink_in(&self, r: Rect) -> bool {
        (r.y..r.y + r.h).any(|y| (r.x..r.x + r.w).any(|x| self.at(x, y) != BG))
    }
    fn any_color_in(&self, r: Rect, c: Rgb565) -> bool {
        (r.y..r.y + r.h).any(|y| (r.x..r.x + r.w).any(|x| self.at(x, y) == c))
    }
}

impl OriginDimensions for Rec {
    fn size(&self) -> embedded_graphics::geometry::Size {
        embedded_graphics::geometry::Size::new(KEYS_W.into(), KEYS_H.into())
    }
}

impl DrawTarget for Rec {
    type Color = Rgb565;
    type Error = Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Rgb565>>,
    {
        for Pixel(p, c) in pixels {
            if p.x >= 0 && p.y >= 0 && (p.x as u32) < KEYS_W as u32 && (p.y as u32) < KEYS_H as u32
            {
                let i = p.y as usize * KEYS_W as usize + p.x as usize;
                self.px[i] = c;
                self.wrote[i] = true;
            } else {
                self.oob = true;
            }
        }
        Ok(())
    }

    fn fill_solid(&mut self, area: &Rectangle, color: Rgb565) -> Result<(), Self::Error> {
        for py in area.top_left.y..area.top_left.y + area.size.height as i32 {
            for px in area.top_left.x..area.top_left.x + area.size.width as i32 {
                if px >= 0 && py >= 0 && (px as u32) < KEYS_W as u32 && (py as u32) < KEYS_H as u32
                {
                    let i = py as usize * KEYS_W as usize + px as usize;
                    self.px[i] = color;
                    self.wrote[i] = true;
                } else {
                    self.oob = true;
                }
            }
        }
        Ok(())
    }

    fn clear(&mut self, color: Rgb565) -> Result<(), Self::Error> {
        self.px.fill(color);
        self.wrote.fill(true);
        Ok(())
    }
}

const ROW: for<'a> fn(&'a str, &'a str, Tone) -> KeysMenuRow<'a> =
    |left, right, tone| KeysMenuRow {
        left,
        right,
        tone,
        emph: false,
    };

/// Full rows for a section-less four-row page (the common listing shape).
fn four_rows() -> [KeysMenuRow<'static>; 4] {
    [
        ROW("9A AUTHENTICATION", "RSA-2048", Tone::Plain),
        ROW("9C CARD AUTH", "EC-P384", Tone::Plain),
        ROW("9D DIGITAL SIG", "empty", Tone::Plain),
        ROW("9E KEY MGMT", "empty", Tone::Plain),
    ]
}

/// The vertical text bands of one menu page (all row centres from `keys_menu`).
const TITLE_BAND: Rect = Rect::new(0, 3, KEYS_W, 26); // title glyphs 3..=28
const ROW0_BAND: Rect = Rect::new(0, 31, KEYS_W, 18); // 40 - 9 .. 40 + 9
const ROW3_BAND: Rect = Rect::new(0, 88, KEYS_W, 18); // 97 - 9 .. 97 + 9
const HINT_BAND: Rect = Rect::new(0, 108, KEYS_W, 18); // 117 - 9 .. 117 + 9

#[test]
fn page_paints_bands_inside_the_panel() {
    let mut d = Rec::new();
    let rows = four_rows();
    render_keys_menu_page(&mut d, "PIV", 0, 1, &rows).unwrap();
    assert!(!d.oob, "menu page painted outside the keys panel");
    // Dark surface — no full-panel wash.
    assert_eq!(d.at(0, 0), BG);
    assert_eq!(d.at(KEYS_W - 1, 0), BG);
    assert_eq!(d.at(0, KEYS_H - 1), BG);
    assert_eq!(d.at(KEYS_W - 1, KEYS_H - 1), BG);
    // Each band carries ink: title, first and last body row, hint foot.
    assert!(d.any_ink_in(TITLE_BAND), "title band blank");
    assert!(d.any_ink_in(ROW0_BAND), "first row band blank");
    assert!(d.any_ink_in(ROW3_BAND), "last row band blank");
    assert!(d.any_ink_in(HINT_BAND), "hint band blank");
    // The bands are separated by ink-free gutters (2 px at every seam).
    assert!(
        !d.any_ink_in(Rect::new(0, 29, KEYS_W, 2)),
        "title/row0 gutter inked"
    );
    assert!(
        !d.any_ink_in(Rect::new(0, 86, KEYS_W, 2)),
        "row2/row3 gutter inked"
    );
    assert!(
        !d.any_ink_in(Rect::new(0, 106, KEYS_W, 2)),
        "last row/hint gutter inked"
    );
}

#[test]
fn empty_page_keeps_title_hint_and_blank_body() {
    let mut d = Rec::new();
    render_keys_menu_page(&mut d, "OATH", 0, 1, &[]).unwrap();
    assert!(!d.oob);
    assert!(d.any_ink_in(TITLE_BAND), "title band blank");
    assert!(d.any_ink_in(HINT_BAND), "hint band blank");
    assert!(
        !d.any_ink_in(Rect::new(0, 30, KEYS_W, 78)),
        "body bands inked on an empty page"
    );
}

#[test]
fn value_tones_paint_their_theme_colours() {
    let rows = [
        ROW("A", "OK", Tone::Good),
        ROW("B", "CAREFUL", Tone::Warn),
        ROW("C", "LOW", Tone::Bad),
        ROW("D", "plain", Tone::Plain),
    ];
    let mut d = Rec::new();
    render_keys_menu_page(&mut d, "OVERVIEW", 0, 1, &rows).unwrap();
    assert!(
        d.any_color_in(ROW0_BAND, theme::SUCCESS),
        "Good value not in success"
    );
    assert!(
        d.any_color_in(Rect::new(0, 49, KEYS_W, 18), theme::WARN),
        "Warn value not in warn"
    );
    assert!(
        d.any_color_in(Rect::new(0, 68, KEYS_W, 18), theme::DANGER),
        "Bad value not in danger"
    );
    assert!(
        d.any_color_in(ROW3_BAND, theme::GREY),
        "Plain value not in grey"
    );
}

#[test]
fn overwide_label_stops_at_the_value_column() {
    // A 60-char label (~500 px at Body) against a value that leaves little room:
    // the label's ink must end at its clip (the value column minus the gap), and
    // the value's own ink must sit at the right margin.
    let long = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGH"; // 60
    let rows = [ROW(long, "TOTP 6", Tone::Plain)];
    let mut d = Rec::new();
    render_keys_menu_page(&mut d, "OATH", 0, 1, &rows).unwrap();
    assert!(!d.oob);
    let value_w = font::width("TOTP 6", Role::Mono).unwrap();
    let value_x0 = (KEYS_W - KEYS_INSET) as i32 - value_w as i32;
    let clip_end = KEYS_INSET as i32 + value_x0 - KEYS_INSET as i32 - COL_GAP_PX;
    // The label's clip ends before the value column: no FG ink past clip_end
    // in the row band (the ellipsis is drawn *inside* the clip).
    assert!(
        !d.any_color_in(Rect::new(clip_end as u16, 31, 4, 18), FG),
        "label ink crossed the clip edge into the gap"
    );
    // The label did reach its clip edge — something was drawn (incl. the ellipsis).
    assert!(
        d.any_color_in(
            Rect::new(clip_end.saturating_sub(24) as u16, 31, 24, 18),
            FG
        ),
        "label ink never reached the value column"
    );
    // The value still reads at the right margin in its tone.
    assert!(
        d.any_color_in(Rect::new(KEYS_W - KEYS_INSET - 40, 31, 40, 18), theme::GREY),
        "value ink missing from the right margin"
    );
}

#[test]
fn page_indicator_and_title_share_the_title_band() {
    // Two pages: indicator "2/2" must be drawn right-aligned while the title is
    // left-aligned — both in the title band, ink near both margins.
    let rows = four_rows();
    let mut d = Rec::new();
    render_keys_menu_page(&mut d, "OPENPGP", 1, 2, &rows).unwrap();
    assert!(!d.oob);
    assert!(
        d.any_ink_in(Rect::new(0, 3, 100, 26)),
        "title ink missing from the left of the title band"
    );
    assert!(
        d.any_ink_in(Rect::new(KEYS_W - 80, 3, 80, 26)),
        "page indicator ink missing from the right of the title band"
    );
}

#[test]
fn slice_and_page_counts_agree() {
    // Empty, exact, ragged, and page beyond the end all converge.
    assert_eq!(keys_menu_page_slice(0, 0), (0, 0));
    assert_eq!(keys_menu_page_slice(4, 0), (0, 4));
    assert_eq!(keys_menu_page_slice(5, 0), (0, 4));
    assert_eq!(keys_menu_page_slice(5, 1), (4, 1));
    assert_eq!(keys_menu_page_slice(9, 0), (0, 4));
    assert_eq!(keys_menu_page_slice(9, 2), (8, 1));
    // Out-of-range page clamps to the last page (render can't show a blank).
    assert_eq!(keys_menu_page_slice(9, 9), (8, 1));
    assert_eq!(keys_menu_page_slice(9, usize::MAX), (8, 1));
}

#[test]
fn emphasised_row_paints_its_label_in_the_tone() {
    // The SETTINGS select cursor: an `emph` row's label takes the value tone
    // (green) instead of the plain foreground, so the whole row reads as the
    // current one.
    let rows = [KeysMenuRow {
        left: "SCREEN DIRECTION",
        right: "180",
        tone: Tone::Good,
        emph: true,
    }];
    let mut d = Rec::new();
    render_keys_menu_page(&mut d, "SETTINGS", 0, 1, &rows).unwrap();
    assert!(!d.oob);
    // The label band (left of the value column) carries the success green.
    assert!(
        d.any_color_in(Rect::new(12, 31, 100, 18), theme::SUCCESS),
        "emph label not painted in the tone"
    );
    // And the value column too.
    assert!(
        d.any_color_in(
            Rect::new(KEYS_W - KEYS_INSET - 40, 31, 40, 18),
            theme::SUCCESS
        ),
        "emph value not painted in the tone"
    );
}

#[test]
fn overwide_title_stops_at_the_page_indicator() {
    // A detail page titles its frame with a device-supplied name (a relying
    // party), which can overrun the gauge: the title must ellipsize at the
    // indicator's left edge instead of painting under it.
    let long = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGH"; // 60
    let mut d = Rec::new();
    render_keys_menu_page(&mut d, long, 0, 1, &[]).unwrap();
    assert!(!d.oob);
    let ind_w = font::width("1/1", Role::Mono).unwrap() as u16;
    let clip_end = KEYS_W - KEYS_INSET - ind_w - COL_GAP_PX as u16;
    assert!(
        !d.any_color_in(Rect::new(clip_end, 3, 4, 26), FG),
        "title ink crossed into the indicator gap"
    );
    assert!(
        d.any_color_in(Rect::new(clip_end.saturating_sub(24), 3, 24, 26), FG),
        "title ink never reached its clip"
    );
}

#[test]
fn plain_row_keeps_its_label_in_foreground() {
    let rows = [KeysMenuRow {
        left: "MENU DELAY",
        right: "30S",
        tone: Tone::Good,
        emph: false,
    }];
    let mut d = Rec::new();
    render_keys_menu_page(&mut d, "SETTINGS", 0, 1, &rows).unwrap();
    // A non-emph row: the value is green but the label stays foreground —
    // that is what tells a *current value* from a *selected row*.
    assert!(
        d.any_color_in(Rect::new(12, 31, 120, 18), FG),
        "plain label lost its foreground colour"
    );
    assert!(
        !d.any_color_in(Rect::new(12, 31, 120, 18), theme::SUCCESS),
        "plain label painted green"
    );
}
