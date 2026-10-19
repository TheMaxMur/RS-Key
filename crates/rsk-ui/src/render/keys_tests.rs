// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use core::convert::Infallible;

use embedded_graphics::{
    Pixel, draw_target::DrawTarget, geometry::OriginDimensions, pixelcolor::Rgb565,
    primitives::Rectangle,
};

use super::*;

/// A 240×135 recording target: like the touch panel's `Rec`, it clips
/// out-of-bounds pixels but flags that it had to (`oob`), so a test can assert a
/// keys screen stayed inside its (smaller) panel.
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

const KINDS: [StatusKind; 4] = [
    StatusKind::Idle,
    StatusKind::Processing,
    StatusKind::Touch,
    StatusKind::Boot,
];

#[test]
fn status_pages_paint_one_centred_row_in_their_status_colour() {
    for kind in KINDS {
        let ink = status_face(kind).0;
        let mut d = Rec::new();
        render_keys_status(&mut d, kind).unwrap();
        assert!(!d.oob, "{kind:?} painted outside the keys panel");
        // Dark surface — no full-panel wash.
        assert_eq!(d.at(0, 0), BG, "{kind:?} corner not dark");
        assert_eq!(d.at(KEYS_W - 1, KEYS_H - 1), BG);
        // The coloured glyph+word row sits on the vertical middle.
        assert!(
            d.any_ink_in(Rect::new(0, KEYS_H / 2 - 20, KEYS_W, 40)),
            "{kind:?} row missing from the middle band"
        );
        assert!(
            (0..KEYS_H).any(|y| (0..KEYS_W).any(|x| d.at(x, y) == ink)),
            "{kind:?} status colour not painted"
        );
    }
}

#[test]
fn checking_page_is_one_bare_word_in_accent() {
    // The boot-check page paints the bare word (no leading glyph, like the
    // Working/Ready pages) in the working ink, centred on the dark surface.
    let mut d = Rec::new();
    render_keys_checking(&mut d).unwrap();
    assert!(!d.oob, "checking page painted outside the keys panel");
    assert_eq!(d.at(0, 0), BG, "checking surface is not the panel BG");
    assert_eq!(d.at(KEYS_W - 1, KEYS_H - 1), BG);
    assert!(
        d.any_ink_in(Rect::new(0, KEYS_H / 2 - 20, KEYS_W, 40)),
        "checking word missing from the middle band"
    );
    assert!(
        (0..KEYS_H).any(|y| (0..KEYS_W).any(|x| d.at(x, y) == theme::ACCENT)),
        "checking word not painted in accent"
    );
}

#[test]
fn animated_phases_change_the_frame() {
    // Working's arc steps every phase; Ready/Starting breathe. Awaiting-touch
    // is deliberately static (a ceremony paints over it anyway).
    for (kind, a, b) in [
        (StatusKind::Processing, 0u32, 1u32),
        (StatusKind::Processing, 0, 6),
        (StatusKind::Idle, 0, 4),
        (StatusKind::Boot, 0, 4),
    ] {
        let mut x = Rec::new();
        render_keys_status_phase(&mut x, kind, a).unwrap();
        assert!(!x.oob, "{kind:?} phase {a} painted outside the keys panel");
        let mut y = Rec::new();
        render_keys_status_phase(&mut y, kind, b).unwrap();
        assert!(!y.oob, "{kind:?} phase {b} painted outside the keys panel");
        assert_ne!(
            x.px, y.px,
            "{kind:?} phases {a} and {b} rendered identically"
        );
    }
    let mut p0 = Rec::new();
    render_keys_status_phase(&mut p0, StatusKind::Touch, 0).unwrap();
    let mut p5 = Rec::new();
    render_keys_status_phase(&mut p5, StatusKind::Touch, 5).unwrap();
    assert_eq!(p0.px, p5.px, "Touch must not animate");
}

#[test]
fn partial_animation_steps_advance_without_escaping_the_panel() {
    // The in-place steps repaint only their regions; verify they stay in bounds
    // and actually change pixels between phases.
    let mut a = Rec::new();
    render_keys_status(&mut a, StatusKind::Processing).unwrap();
    render_keys_status_step(&mut a, StatusKind::Processing, 0).unwrap();
    let mut b = Rec::new();
    render_keys_status(&mut b, StatusKind::Processing).unwrap();
    render_keys_status_step(&mut b, StatusKind::Processing, 5).unwrap();
    assert!(!a.oob && !b.oob, "processing step escaped the panel");
    assert_ne!(a.px, b.px, "processing breathe phases identical");

    for kind in [StatusKind::Idle, StatusKind::Boot] {
        let mut x = Rec::new();
        render_keys_status(&mut x, kind).unwrap();
        render_keys_status_step(&mut x, kind, 0).unwrap();
        let mut y = Rec::new();
        render_keys_status(&mut y, kind).unwrap();
        render_keys_status_step(&mut y, kind, 4).unwrap();
        assert!(!x.oob && !y.oob, "{kind:?} breathe escaped the panel");
        assert_ne!(x.px, y.px, "{kind:?} breathe phases identical");
    }
}

#[test]
fn decision_pages_paint_one_centred_row_in_their_status_colour() {
    // Approve paints its success colour, decline its danger colour — one row
    // (glyph + word) centred vertically on the dark surface.
    for (approved, ink) in [(true, theme::SUCCESS), (false, theme::DANGER)] {
        let mut d = Rec::new();
        render_keys_decision(&mut d, approved).unwrap();
        assert!(!d.oob, "decision painted outside the keys panel");
        assert_eq!(d.at(0, 0), BG, "decision surface is not the panel BG");
        assert_eq!(d.at(KEYS_W - 1, KEYS_H - 1), BG);
        // The row sits on the vertical middle of the panel…
        assert!(
            d.any_ink_in(Rect::new(0, KEYS_H / 2 - 20, KEYS_W, 40)),
            "decision row missing from the middle band"
        );
        // …and nothing (glyph or word) bleeds into the top or bottom quarters.
        assert!(
            !d.any_ink_in(Rect::new(0, 0, KEYS_W, KEYS_H / 2 - 22)),
            "row too high"
        );
        assert!(
            !d.any_ink_in(Rect::new(0, KEYS_H / 2 + 22, KEYS_W, KEYS_H / 2 - 22)),
            "row too low"
        );
        // The status colour is actually on screen.
        assert!(
            (0..KEYS_H).any(|y| (0..KEYS_W).any(|x| d.at(x, y) == ink)),
            "status colour not painted"
        );
    }
}

#[test]
fn confirm_renders_title_subject_and_hints() {
    let prompt = ConfirmPrompt::new("Sign in?", b"example.com", b"alice");
    let mut d = Rec::new();
    render_keys_confirm(&mut d, &prompt).unwrap();
    assert!(!d.oob, "confirm painted outside the keys panel");
    // Title band (device-controlled operation name).
    assert!(d.any_ink_in(Rect::new(0, 8, KEYS_W, 22)), "title missing");
    // The relying-party line.
    assert!(
        d.any_ink_in(Rect::new(KEYS_INSET, 52, KEYS_TEXT_W, 20)),
        "relying-party line missing"
    );
    // The account line.
    assert!(
        d.any_ink_in(Rect::new(KEYS_INSET, 72, KEYS_TEXT_W, 18)),
        "account line missing"
    );
    // The gesture hints at the foot.
    assert!(
        d.any_ink_in(Rect::new(0, 100, KEYS_W, 34)),
        "gesture hints missing"
    );
}

#[test]
fn confirm_without_account_skips_the_account_line() {
    let prompt = ConfirmPrompt::new("Sign in?", b"example.com", b"");
    let mut d = Rec::new();
    render_keys_confirm(&mut d, &prompt).unwrap();
    // The account line's band is empty when the request carries no account.
    assert!(
        !d.any_ink_in(Rect::new(KEYS_INSET, 74, KEYS_TEXT_W, 10)),
        "empty account still painted"
    );
}

#[test]
fn overlong_rp_stays_inside_its_clip() {
    // A 64-byte source is clamped to LABEL_MAX tail bytes with `truncated` set;
    // the renderer must head-truncate and never paint past the text clip.
    let long = [b'z'; 64];
    let prompt = ConfirmPrompt::new("Sign in?", &long, b"");
    assert!(prompt.primary.truncated, "64-byte rp must be clamped");
    let mut d = Rec::new();
    render_keys_confirm(&mut d, &prompt).unwrap();
    assert!(!d.oob, "long rp painted outside the panel");
    // Ink exists in the rp band…
    assert!(d.any_ink_in(Rect::new(KEYS_INSET, 52, KEYS_TEXT_W, 20)));
    // …and nothing was drawn in the left margin at the rp band's height — the
    // head-truncated line must stay inside its clip (the title and hint lines
    // legitimately paint outside this band, hence the row range below).
    let escaped = (52..72).any(|y| (0..KEYS_INSET).any(|x| d.at(x, y) != BG));
    assert!(!escaped, "long rp escaped its clip");
}
