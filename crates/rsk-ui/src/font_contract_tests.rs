// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

struct Blits {
    size: Size,
    areas: std::vec::Vec<Rectangle>,
    draws: usize,
}

impl Blits {
    fn new(width: u32, height: u32) -> Self {
        Self {
            size: Size::new(width, height),
            areas: std::vec::Vec::new(),
            draws: 0,
        }
    }
}

impl OriginDimensions for Blits {
    fn size(&self) -> Size {
        self.size
    }
}

impl DrawTarget for Blits {
    type Color = Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, _pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Rgb565>>,
    {
        self.draws += 1;
        Ok(())
    }

    fn fill_contiguous<I>(&mut self, area: &Rectangle, _colors: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Rgb565>,
    {
        // Dispatch is the oracle; consuming a malformed giant raster would stall it.
        self.areas.push(*area);
        Ok(())
    }
}

#[test]
fn a_full_width_text_row_clips_the_last_glyph_before_its_alpha_buffer_end() {
    let mut target = Rec::new();
    left(
        &mut target,
        &"A".repeat(46),
        EgPoint::new(0, 40),
        Role::Mono,
        Rgb565::WHITE,
        Rgb565::BLACK,
    )
    .unwrap();
    assert!(target.pixels.contains(&Rgb565::WHITE));
}

#[test]
fn split_text_preserves_each_surfaces_constant_color_channel() {
    let mut target = Rec::new();
    for row in target.pixels.chunks_mut(320) {
        row[..160].fill(Rgb565::RED);
        row[160..].fill(Rgb565::BLUE);
    }
    centered_split(
        &mut target,
        "O",
        EgPoint::new(160, 40),
        Role::Body,
        Rgb565::WHITE,
        Rgb565::RED,
        Rgb565::BLUE,
        160,
    )
    .unwrap();
    assert!(target.pixels.iter().any(|color| color.g() > 0));
    for row in target.pixels.chunks(320) {
        assert!(row[..160].iter().all(|color| color.r() == 31));
        assert!(row[160..].iter().all(|color| color.b() == 31));
    }
}

#[test]
fn one_body_glyph_keeps_its_actual_bounding_box() {
    let mut target = Blits::new(320, 80);
    left(
        &mut target,
        "A",
        EgPoint::new(20, 40),
        Role::Body,
        Rgb565::WHITE,
        Rgb565::BLACK,
    )
    .unwrap();
    assert_eq!(target.draws, 0);
    assert_eq!(
        target.areas,
        [Rectangle::new(EgPoint::new(20, 36), Size::new(8, 9))]
    );
}

#[test]
fn a_body_glyph_touching_the_top_edge_still_emits_ink() {
    let mut target = Rec::new();
    left(
        &mut target,
        "A",
        EgPoint::new(20, 4),
        Role::Body,
        Rgb565::WHITE,
        Rgb565::BLACK,
    )
    .unwrap();
    assert!(target.pixels.iter().any(|color| color.g() > 0));
}

#[test]
fn fully_clipped_text_dispatches_no_raster_without_consuming_it() {
    let mut target = Blits::new(320, 80);
    left(
        &mut target,
        "A",
        EgPoint::new(20, 100),
        Role::Body,
        Rgb565::WHITE,
        Rgb565::BLACK,
    )
    .unwrap();
    assert!(target.areas.is_empty());
    assert_eq!(target.draws, 0);
}

#[test]
fn wholly_left_clipped_runs_do_not_spend_placed_glyph_capacity() {
    let mut target = Blits::new(320, 80);
    left(
        &mut target,
        &"A".repeat(129),
        EgPoint::new(-2000, 40),
        Role::Body,
        Rgb565::WHITE,
        Rgb565::BLACK,
    )
    .unwrap();
    assert!(target.areas.is_empty());
}

#[test]
fn boundary_touching_glyphs_do_not_spend_placed_glyph_capacity() {
    for (width, at) in [
        (1024, EgPoint::new(0, 4)),
        (1024, EgPoint::new(-8, 4)),
        (1040, EgPoint::new(0, 84)),
        (1040, EgPoint::new(0, -5)),
    ] {
        let mut target = Blits::new(width, 80);
        left(
            &mut target,
            &"A".repeat(129),
            at,
            Role::Body,
            Rgb565::WHITE,
            Rgb565::BLACK,
        )
        .unwrap();
        assert_eq!(target.draws, 0);
        if at.y == 4 {
            assert_eq!(target.areas.len(), 1);
        } else {
            assert!(target.areas.is_empty());
        }
    }
}
