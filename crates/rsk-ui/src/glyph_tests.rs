// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use embedded_graphics::{
    Pixel,
    geometry::{OriginDimensions, Size},
    prelude::RgbColor,
    primitives::Rectangle,
};

/// The canonical sizes every glyph is authored at — the sizes the UI paints most, where
/// crispness matters. Off-canonical requests scale from the nearest of these. Kept in
/// sync with the `size` fields of every `GLYPH_*` table below and the symmetry test.
const CANON: [u16; 6] = [14, 16, 18, 20, 36, 44];

/// The mirror axes a glyph's art is authored symmetric about, asserted by the symmetry
/// test: `v` = left–right (about the vertical centre line), `h` = top–bottom. A
/// directional glyph that still has a symmetric skeleton lists only the axis it keeps
/// (the chevron's `>` is top–bottom symmetric); a glyph with a directional mark on a
/// symmetric base (the check in a ring, the clock hands, the rotate arrow, the key, the
/// pencil, the crescent, the terminal caret) claims neither, so the test does not flag it.
struct Sym {
    v: bool,
    h: bool,
}

fn sym(g: Glyph) -> Sym {
    use Glyph::*;
    match g {
        Chevron | Backspace => Sym { v: false, h: true },
        Lock | Home | Shield | Warn | Usb | User => Sym { v: true, h: false },
        Sun | Globe | Gear | Eye | Lifebuoy | Cpu | Apps => Sym { v: true, h: true },
        _ => Sym { v: false, h: false },
    }
}

/// A tiny recording target: tracks whether anything was drawn and whether any
/// pixel fell outside its bounds (a glyph must stay inside its box).
struct Rec {
    w: i32,
    h: i32,
    drew: bool,
    partial: bool,
    oob: bool,
}

impl OriginDimensions for Rec {
    fn size(&self) -> Size {
        Size::new(self.w as u32, self.h as u32)
    }
}

impl DrawTarget for Rec {
    type Color = Rgb565;
    type Error = core::convert::Infallible;
    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Rgb565>>,
    {
        for Pixel(p, color) in pixels {
            if p.x < 0 || p.y < 0 || p.x >= self.w || p.y >= self.h {
                self.oob = true;
            } else {
                self.drew = true;
                self.partial |= color != Rgb565::BLACK && color != Rgb565::WHITE;
            }
        }
        Ok(())
    }
}

const ALL: [Glyph; 24] = [
    Glyph::Usb,
    Glyph::Check,
    Glyph::Backspace,
    Glyph::CheckCircle,
    Glyph::Lock,
    Glyph::Key,
    Glyph::Home,
    Glyph::Gear,
    Glyph::Chevron,
    Glyph::Back,
    Glyph::Shield,
    Glyph::Globe,
    Glyph::Warn,
    Glyph::Sun,
    Glyph::Clock,
    Glyph::Moon,
    Glyph::Rotate,
    Glyph::Edit,
    Glyph::Eye,
    Glyph::Lifebuoy,
    Glyph::Cpu,
    Glyph::Apps,
    Glyph::Terminal,
    Glyph::User,
];

#[test]
fn fixed_masks_match_the_original_sampler_exactly() {
    for glyph in ALL {
        for size in FIXED_SIZES {
            let bitmap = pick(table(glyph), size);
            let Some(coverage) = fixed_coverage(glyph, size) else {
                continue;
            };
            let actual: std::vec::Vec<u8> = coverage.collect();
            assert_eq!(actual.len(), usize::from(size) * usize::from(size));
            for y in 0..i32::from(size) {
                for x in 0..i32::from(size) {
                    assert_eq!(
                        actual[y as usize * usize::from(size) + x as usize],
                        scaled_coverage(bitmap, x, y, i32::from(size)),
                        "{glyph:?}@{size} differs at ({x},{y})"
                    );
                }
            }
        }
    }
}

/// Every glyph carries exactly the canonical sizes, and each bitmap is a square grid
/// of `size` rows × `size` columns over the `'#'`/`'.'` alphabet — the invariant the
/// blitter and the symmetry test both rely on.
#[test]
fn every_bitmap_is_square_and_canonical() {
    for g in ALL {
        let tbl = table(g);
        let sizes: std::vec::Vec<u16> = tbl.iter().map(|b| b.size).collect();
        assert_eq!(
            sizes, CANON,
            "{g:?} does not carry exactly the canonical sizes"
        );
        for b in tbl {
            let n = b.size as usize;
            assert_eq!(b.rows.len(), n, "{g:?}@{} wrong row count", b.size);
            for (y, r) in b.rows.iter().enumerate() {
                assert_eq!(r.len(), n, "{g:?}@{} row {y} wrong width", b.size);
                assert!(
                    r.bytes().all(|c| c == b'#' || c == b'.'),
                    "{g:?}@{} row {y} has a non-#/. char",
                    b.size
                );
            }
        }
    }
}

#[test]
fn every_glyph_paints_inside_its_box() {
    // Box at (4,4) size 16 inside a 24×24 target: every glyph must paint and
    // never spill outside the 24×24 bounds.
    for g in ALL {
        let mut d = Rec {
            w: 24,
            h: 24,
            drew: false,
            partial: false,
            oob: false,
        };
        draw(
            &mut d,
            g,
            Point::new(4, 4),
            16,
            Rgb565::WHITE,
            Rgb565::BLACK,
        )
        .unwrap();
        assert!(d.drew, "{g:?} drew nothing");
        assert!(d.partial, "{g:?} has no antialiased pixel");
        assert!(!d.oob, "{g:?} drew outside its 24×24 box");
    }
}

#[test]
fn nav_size_glyphs_also_fit() {
    // The bottom-nav tabs render at 20px — still inside the box.
    for g in [Glyph::Home, Glyph::Key, Glyph::Gear] {
        let mut d = Rec {
            w: 28,
            h: 28,
            drew: false,
            partial: false,
            oob: false,
        };
        draw(
            &mut d,
            g,
            Point::new(4, 4),
            20,
            Rgb565::WHITE,
            Rgb565::BLACK,
        )
        .unwrap();
        assert!(d.drew && !d.oob, "{g:?} did not fit at nav size");
    }
}

/// Off-canonical sizes (12, 22, 28, 32, 38, 40) are blitted scaled from the nearest
/// canonical bitmap; the scale must still paint inside its box at every one.
#[test]
fn off_canonical_sizes_stay_in_box() {
    for g in ALL {
        for s in [12u16, 22, 28, 32, 38, 40] {
            let pad = 6;
            let side = s as i32 + 2 * pad;
            let mut d = Rec {
                w: side,
                h: side,
                drew: false,
                partial: false,
                oob: false,
            };
            draw(
                &mut d,
                g,
                Point::new(pad as u16, pad as u16),
                s,
                Rgb565::WHITE,
                Rgb565::BLACK,
            )
            .unwrap();
            assert!(d.drew && !d.oob, "{g:?}@{s} scaled outside its box");
        }
    }
}

struct Transactions {
    draw: usize,
    contiguous: usize,
}

impl OriginDimensions for Transactions {
    fn size(&self) -> Size {
        Size::new(32, 32)
    }
}

impl DrawTarget for Transactions {
    type Color = Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Rgb565>>,
    {
        self.draw += 1;
        let _ = pixels.into_iter().count();
        Ok(())
    }

    fn fill_contiguous<I>(&mut self, area: &Rectangle, colors: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Rgb565>,
    {
        self.contiguous += 1;
        assert_eq!(
            colors.into_iter().count() as u32,
            area.size.width * area.size.height
        );
        Ok(())
    }
}

#[test]
fn a_glyph_uses_one_contiguous_write() {
    let mut target = Transactions {
        draw: 0,
        contiguous: 0,
    };
    draw(
        &mut target,
        Glyph::Key,
        Point::new(4, 4),
        20,
        Rgb565::WHITE,
        Rgb565::BLACK,
    )
    .unwrap();
    assert_eq!(target.draw, 0);
    assert_eq!(target.contiguous, 1);
}

struct Grid {
    n: usize,
    px: std::vec::Vec<u8>,
}
impl Grid {
    fn new(n: usize) -> Self {
        Self {
            n,
            px: std::vec![0; n * n],
        }
    }
}
impl OriginDimensions for Grid {
    fn size(&self) -> Size {
        Size::new(self.n as u32, self.n as u32)
    }
}
impl DrawTarget for Grid {
    type Color = Rgb565;
    type Error = core::convert::Infallible;
    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Rgb565>>,
    {
        for Pixel(p, color) in pixels {
            if p.x >= 0 && p.y >= 0 && (p.x as usize) < self.n && (p.y as usize) < self.n {
                self.px[p.y as usize * self.n + p.x as usize] = color.r();
            }
        }
        Ok(())
    }
}

/// Each glyph must be authored mirror-symmetric about the axes [`sym`] claims for it,
/// at every canonical size — this is what guards against the "crooked" look. On an even
/// box there is no true centre column, so a 1px centred stroke can't be mirror-exact;
/// the centre band (the column/row that maps to its own neighbour) is exempt. Glyphs
/// with a directional mark claim no axis, so the mark is not flagged. Checked only at
/// canonical sizes — that is where the art is authored; off-canonical scaling is
/// best-effort and not part of the symmetry contract.
#[test]
fn glyphs_respect_their_symmetry_axes() {
    for g in ALL {
        let sy = sym(g);
        if !sy.v && !sy.h {
            continue;
        }
        for s in CANON {
            let s = s as usize;
            let mut grid = Grid::new(s);
            draw(
                &mut grid,
                g,
                Point::new(0, 0),
                s as u16,
                Rgb565::WHITE,
                Rgb565::BLACK,
            )
            .unwrap();
            let center = |a: usize| (a as i32 - (s as i32 - 1 - a as i32)).abs() <= 1;
            for y in 0..s {
                for x in 0..s {
                    if sy.v && !center(x) {
                        assert!(
                            grid.px[y * s + x].abs_diff(grid.px[y * s + (s - 1 - x)]) <= 2,
                            "{g:?} at {s}px not left-right symmetric (row {y}, col {x})"
                        );
                    }
                    if sy.h && !center(y) {
                        assert!(
                            grid.px[y * s + x].abs_diff(grid.px[(s - 1 - y) * s + x]) <= 2,
                            "{g:?} at {s}px not top-bottom symmetric (row {y}, col {x})"
                        );
                    }
                }
            }
        }
    }
}
