// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use embedded_graphics::{
    Pixel,
    geometry::{OriginDimensions, Size},
    prelude::RgbColor,
    primitives::Rectangle,
};

struct Rec {
    pixels: std::vec::Vec<Rgb565>,
}

impl Rec {
    fn new() -> Self {
        Self {
            pixels: std::vec![Rgb565::BLACK; 320 * 80],
        }
    }
}

impl OriginDimensions for Rec {
    fn size(&self) -> Size {
        Size::new(320, 80)
    }
}

impl DrawTarget for Rec {
    type Color = Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Rgb565>>,
    {
        for Pixel(point, color) in pixels {
            if point.x >= 0 && point.y >= 0 && point.x < 320 && point.y < 80 {
                self.pixels[point.y as usize * 320 + point.x as usize] = color;
            }
        }
        Ok(())
    }
}

#[test]
fn every_role_renders_partial_coverage() {
    for role in [
        Role::Ready,
        Role::Heading,
        Role::Strong,
        Role::Body,
        Role::BodyStrong,
        Role::Mono,
        Role::MonoSmall,
    ] {
        let mut target = Rec::new();
        centered(
            &mut target,
            "Ag",
            EgPoint::new(160, 40),
            role,
            Rgb565::WHITE,
            Rgb565::BLACK,
        )
        .unwrap();
        assert!(
            target.pixels.contains(&Rgb565::WHITE),
            "{role:?} has no full ink"
        );
        assert!(
            target
                .pixels
                .iter()
                .any(|color| *color != Rgb565::BLACK && *color != Rgb565::WHITE),
            "{role:?} has no partial coverage"
        );
    }
}

#[test]
fn metrics_cover_ascii_em_dash_and_fallback() {
    for role in [Role::Ready, Role::Heading, Role::Body, Role::Mono] {
        assert!(width(" !~\u{2014}", role).unwrap() > 0);
        assert_eq!(width("\u{2603}", role), width("?", role));
    }

    let mut fallback = Rec::new();
    let mut question = Rec::new();
    left(
        &mut fallback,
        "\u{2603}",
        EgPoint::new(20, 40),
        Role::Body,
        Rgb565::WHITE,
        Rgb565::BLACK,
    )
    .unwrap();
    left(
        &mut question,
        "?",
        EgPoint::new(20, 40),
        Role::Body,
        Rgb565::WHITE,
        Rgb565::BLACK,
    )
    .unwrap();
    assert_eq!(fallback.pixels, question.pixels);
}

#[test]
fn middle_dot_has_its_own_glyph() {
    let mut dot = Rec::new();
    let mut question = Rec::new();
    left(
        &mut dot,
        "\u{00B7}",
        EgPoint::new(20, 40),
        Role::Body,
        Rgb565::WHITE,
        Rgb565::BLACK,
    )
    .unwrap();
    left(
        &mut question,
        "?",
        EgPoint::new(20, 40),
        Role::Body,
        Rgb565::WHITE,
        Rgb565::BLACK,
    )
    .unwrap();
    assert_ne!(dot.pixels, question.pixels);
}

#[test]
fn width_includes_the_last_glyph_overhang() {
    let font = font(Role::Heading);
    let glyph = font.glyphs[glyph_index('g')];
    assert!(glyph.left as i16 + glyph.width as i16 > glyph.advance as i16);
    assert_eq!(
        width("Ag", Role::Heading),
        Some(
            u32::from(font.glyphs[glyph_index('A')].advance)
                + (glyph.left as u32 + u32::from(glyph.width))
        )
    );
}

#[test]
fn split_background_uses_each_surface() {
    let mut target = Rec::new();
    centered_split(
        &mut target,
        "Hold",
        EgPoint::new(160, 40),
        Role::Body,
        Rgb565::WHITE,
        Rgb565::RED,
        Rgb565::BLUE,
        160,
    )
    .unwrap();
    assert!(target.pixels.iter().any(|color| color.r() > color.b()));
    assert!(target.pixels.iter().any(|color| color.b() > color.r()));
}

fn sparse_left(target: &mut Rec, text: &str, at: EgPoint, role: Role, color: Rgb565, bg: Rgb565) {
    let font = font(role);
    let baseline = at.y + (i32::from(font.ascent) - i32::from(font.descent)) / 2;
    let mut pen_x = at.x;
    for char in text.chars() {
        let glyph = font.glyphs[glyph_index(char)];
        let x = pen_x + i32::from(glyph.left);
        let y = baseline + i32::from(glyph.top);
        let width = usize::from(glyph.width);
        let height = usize::from(glyph.height);
        target
            .draw_iter((0..height).flat_map(|row| {
                (0..width).filter_map(move |column| {
                    let alpha = coverage(font, glyph, row * width + column);
                    (alpha > 0).then(|| {
                        Pixel(
                            EgPoint::new(x + column as i32, y + row as i32),
                            blend_coverage(color, bg, alpha),
                        )
                    })
                })
            }))
            .unwrap();
        pen_x += i32::from(glyph.advance);
    }
}

#[test]
fn contiguous_text_matches_the_sparse_renderer() {
    for role in [
        Role::Ready,
        Role::Heading,
        Role::Strong,
        Role::Body,
        Role::BodyStrong,
        Role::Mono,
        Role::MonoSmall,
    ] {
        let mut contiguous = Rec::new();
        let mut sparse = Rec::new();
        left(
            &mut contiguous,
            "Ready )j&?!",
            EgPoint::new(40, 40),
            role,
            Rgb565::WHITE,
            Rgb565::BLACK,
        )
        .unwrap();
        sparse_left(
            &mut sparse,
            "Ready )j&?!",
            EgPoint::new(40, 40),
            role,
            Rgb565::WHITE,
            Rgb565::BLACK,
        );
        assert_eq!(contiguous.pixels, sparse.pixels, "{role:?}");
    }
}

#[test]
fn aligned_and_clipped_text_matches_the_sparse_renderer() {
    let text = "Clipped )j&?!";
    for role in [Role::Heading, Role::Body, Role::MonoSmall] {
        let text_width = width(text, role).unwrap() as i32;
        for (alignment, at) in [
            (Alignment::Center, EgPoint::new(18, 40)),
            (Alignment::Right, EgPoint::new(82, 40)),
        ] {
            let start_x = match alignment {
                Alignment::Center => at.x - text_width / 2,
                Alignment::Right => at.x - text_width,
                Alignment::Left => unreachable!(),
            };
            let mut contiguous = Rec::new();
            let mut sparse = Rec::new();
            draw(
                &mut contiguous,
                text,
                at,
                role,
                Rgb565::WHITE,
                Background::Solid(Rgb565::BLACK),
                alignment,
            )
            .unwrap();
            sparse_left(
                &mut sparse,
                text,
                EgPoint::new(start_x, at.y),
                role,
                Rgb565::WHITE,
                Rgb565::BLACK,
            );
            assert_eq!(contiguous.pixels, sparse.pixels, "{role:?}");
        }
    }
}

struct Transactions {
    draw: usize,
    contiguous: usize,
}

impl OriginDimensions for Transactions {
    fn size(&self) -> Size {
        Size::new(320, 80)
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
fn a_text_run_uses_one_contiguous_write() {
    let mut target = Transactions {
        draw: 0,
        contiguous: 0,
    };
    left(
        &mut target,
        "Fast pages",
        EgPoint::new(20, 40),
        Role::Body,
        Rgb565::WHITE,
        Rgb565::BLACK,
    )
    .unwrap();
    assert_eq!(target.draw, 0);
    assert_eq!(target.contiguous, 1);
}

/// Adjacent glyph boxes overlap: 8 of the 97 glyphs have a negative left bearing and
/// 28 carry ink past their advance. So a later glyph's faint fringe lands on an
/// earlier glyph's solid stroke, and taking the later coverage instead of the greater
/// punches a near-background pixel into it. Adding a glyph must never lighten what
/// the prefix already drew.
#[test]
fn a_following_glyph_never_lightens_the_one_before_it() {
    for (role, pair) in [
        (Role::Heading, "\\j"),
        (Role::Heading, "(j"),
        (Role::Ready, "()"),
        (Role::Strong, "_j"),
        (Role::BodyStrong, "gj"),
    ] {
        let at = EgPoint::new(20, 40);
        let mut alone = Rec::new();
        let mut both = Rec::new();
        left(
            &mut alone,
            &pair[..1],
            at,
            role,
            Rgb565::WHITE,
            Rgb565::BLACK,
        )
        .unwrap();
        left(&mut both, pair, at, role, Rgb565::WHITE, Rgb565::BLACK).unwrap();
        // White on black, so the green channel *is* the coverage, monotonically.
        let dimmed = alone
            .pixels
            .iter()
            .zip(&both.pixels)
            .enumerate()
            .find(|(_, (a, b))| b.g() < a.g());
        assert!(
            dimmed.is_none(),
            "{role:?} {pair:?}: the second glyph lightened a pixel the first had drawn: {:?}",
            dimmed.map(|(i, (a, b))| (i % 320, i / 320, a.g(), b.g()))
        );
    }
}

/// The rename keypad's labels are drawn from this atlas, and a char that is not in it
/// renders as `?` — which is how the space key came to read "SPACE". "Is it ASCII" was
/// the wrong rule for that: the atlas is ASCII plus three, and the space key wants one
/// of the three. Ask the atlas instead.
#[test]
fn every_t9_key_label_has_its_own_glyph() {
    let fallback = glyph_index('?');
    for (digit, letters) in crate::T9_KEY_LABELS {
        for char in digit.chars().chain(letters.chars()) {
            assert!(
                char == '?' || glyph_index(char) != fallback,
                "T9 label {digit:?}/{letters:?} uses {char:?}, which is not in the atlas"
            );
        }
    }
}
