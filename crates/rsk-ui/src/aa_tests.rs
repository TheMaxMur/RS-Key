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
    side: usize,
    pixels: std::vec::Vec<Rgb565>,
    oob: bool,
}

impl Rec {
    fn new(side: usize, color: Rgb565) -> Self {
        Self {
            side,
            pixels: std::vec![color; side * side],
            oob: false,
        }
    }

    fn at(&self, x: usize, y: usize) -> Rgb565 {
        self.pixels[y * self.side + x]
    }
}

impl OriginDimensions for Rec {
    fn size(&self) -> Size {
        Size::new(self.side as u32, self.side as u32)
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
            if point.x < 0
                || point.y < 0
                || point.x >= self.side as i32
                || point.y >= self.side as i32
            {
                self.oob = true;
            } else {
                self.pixels[point.y as usize * self.side + point.x as usize] = color;
            }
        }
        Ok(())
    }
}

#[test]
fn blend_has_exact_endpoints_and_intermediate_coverage() {
    assert_eq!(
        blend_coverage(Rgb565::WHITE, Rgb565::BLACK, 0),
        Rgb565::BLACK
    );
    assert_eq!(
        blend_coverage(Rgb565::WHITE, Rgb565::BLACK, 15),
        Rgb565::WHITE
    );
    let middle = blend_coverage(Rgb565::WHITE, Rgb565::BLACK, 7);
    assert_ne!(middle, Rgb565::BLACK);
    assert_ne!(middle, Rgb565::WHITE);
}

#[test]
fn circle_and_rounded_rect_have_aa_edges_inside_their_boxes() {
    let mut circle_target = Rec::new(24, Rgb565::BLACK);
    filled_circle(
        &mut circle_target,
        EgPoint::new(4, 4),
        16,
        Rgb565::WHITE,
        Rgb565::BLACK,
    )
    .unwrap();
    assert!(!circle_target.oob);
    assert_eq!(circle_target.at(3, 12), Rgb565::BLACK);
    assert!(
        circle_target
            .pixels
            .iter()
            .any(|color| *color != Rgb565::BLACK && *color != Rgb565::WHITE)
    );

    let mut rounded = Rec::new(24, Rgb565::BLACK);
    rounded_rect(
        &mut rounded,
        Rect::new(2, 5, 20, 14),
        10,
        Some(Rgb565::WHITE),
        Some((Rgb565::RED, 1)),
        Rgb565::BLACK,
    )
    .unwrap();
    assert!(!rounded.oob);
    assert_eq!(rounded.at(1, 12), Rgb565::BLACK);
    assert_eq!(rounded.at(12, 12), Rgb565::WHITE);
    assert!(
        rounded.pixels.iter().any(|color| *color != Rgb565::BLACK
            && *color != Rgb565::WHITE
            && *color != Rgb565::RED)
    );

    let mut outline = Rec::new(24, Rgb565::BLACK);
    rounded_rect(
        &mut outline,
        Rect::new(2, 5, 20, 14),
        10,
        None,
        Some((Rgb565::RED, 1)),
        Rgb565::BLACK,
    )
    .unwrap();
    assert_eq!(outline.at(12, 12), Rgb565::BLACK);
}

fn rounded_coverage_slow(rect: Rect, diameter: u32, px: i32, py: i32) -> u8 {
    let mut coverage = 0;
    for sy in 0..SAMPLES {
        for sx in 0..SAMPLES {
            let x = px * SAMPLE_SCALE + sx * 2 + 1;
            let y = py * SAMPLE_SCALE + sy * 2 + 1;
            coverage += u8::from(rounded_sample(rect, diameter, x, y));
        }
    }
    coverage
}

#[test]
fn rounded_rect_fast_path_matches_all_samples() {
    for (rect, diameter) in [
        (Rect::new(0, 0, 20, 14), 10),
        (Rect::new(3, 7, 216, 126), 11),
        (Rect::new(5, 9, 41, 41), 17),
    ] {
        for py in i32::from(rect.y).saturating_sub(1)..=i32::from(rect.y + rect.h) {
            for px in i32::from(rect.x).saturating_sub(1)..=i32::from(rect.x + rect.w) {
                assert_eq!(
                    rounded_coverage(rect, diameter, px, py),
                    rounded_coverage_slow(rect, diameter, px, py),
                    "rect={rect:?}, diameter={diameter}, pixel=({px},{py})"
                );
            }
        }
    }
}

fn legacy_rounded_rect(
    target: &mut Rec,
    rect: Rect,
    diameter: u32,
    fill: Option<Rgb565>,
    border: Option<(Rgb565, u16)>,
    bg: Rgb565,
) {
    for py in i32::from(rect.y)..i32::from(rect.y + rect.h) {
        for px in i32::from(rect.x)..i32::from(rect.x + rect.w) {
            let outer = rounded_coverage_slow(rect, diameter, px, py);
            let color = if let Some((stroke, width)) = border {
                let inner = inset(rect, width);
                let inner_diameter = diameter.saturating_sub(u32::from(width) * 2);
                let inner_coverage = rounded_coverage_slow(inner, inner_diameter, px, py);
                if let Some(fill) = fill {
                    blend_three(fill, stroke, bg, inner_coverage, outer)
                } else {
                    blend_coverage(stroke, bg, outer.saturating_sub(inner_coverage))
                }
            } else if let Some(fill) = fill {
                blend_coverage(fill, bg, outer)
            } else {
                bg
            };
            target.pixels[py as usize * target.side + px as usize] = color;
        }
    }
}

#[test]
fn rounded_rect_spans_match_the_original_pixels_exactly() {
    let bg = Rgb565::new(2, 4, 6);
    let fill = Rgb565::new(27, 51, 11);
    let stroke = Rgb565::new(30, 7, 24);
    for diameter in [6, 8, 9, 10, 11, 16, 17] {
        for (fill, border) in [
            (Some(fill), None),
            (Some(fill), Some((stroke, 1))),
            (Some(fill), Some((stroke, 2))),
            (None, Some((stroke, 1))),
            (None, Some((stroke, 2))),
            (None, None),
        ] {
            let rect = Rect::new(3, 5, 41, 29);
            let mut expected = Rec::new(48, Rgb565::BLUE);
            legacy_rounded_rect(&mut expected, rect, diameter, fill, border, bg);
            let mut actual = Rec::new(48, Rgb565::BLUE);
            rounded_rect(&mut actual, rect, diameter, fill, border, bg).unwrap();
            assert_eq!(
                actual.pixels, expected.pixels,
                "diameter={diameter}, fill={fill:?}, border={border:?}"
            );
        }
    }
}

#[test]
fn status_ring_mask_matches_all_distance_samples() {
    let generated = std::hint::black_box(ring_sample_mask::<50, 3, 2500>());
    let diameter = 50;
    let width = 3;
    let center = diameter as i32 * SAMPLE_SCALE / 2;
    let inner = center - width as i32 * SAMPLE_SCALE;
    for y in 0..diameter as usize {
        for x in 0..diameter as usize {
            let mut expected = 0u16;
            for sy in 0..SAMPLES {
                for sx in 0..SAMPLES {
                    let px = x as i32 * SAMPLE_SCALE + sx * 2 + 1 - center;
                    let py = y as i32 * SAMPLE_SCALE + sy * 2 + 1 - center;
                    let distance = px * px + py * py;
                    if distance <= center * center && distance > inner * inner {
                        expected |= 1 << (sy * SAMPLES + sx);
                    }
                }
            }
            assert_eq!(fixed_ring_samples(diameter, width, x, y), Some(expected));
            assert_eq!(generated[y * diameter as usize + x], expected);
        }
    }
}

#[test]
fn status_arc_phase_table_matches_every_sample() {
    let generated = std::hint::black_box(status_arc_coverages());
    let center = 50 * SAMPLE_SCALE / 2;
    for phase in 0..STATUS_ARC_PHASES {
        let start = STATUS_ARC_BASE_DEG + phase as i32 * STATUS_ARC_STEP_DEG;
        for y in 0..50usize {
            for x in 0..50usize {
                let samples = RING_50_3[y * 50 + x];
                let mut ring = 0u8;
                let mut arc = 0u8;
                for sy in 0..SAMPLES {
                    for sx in 0..SAMPLES {
                        let bit = 1 << (sy * SAMPLES + sx);
                        if samples & bit != 0 {
                            let px = x as i32 * SAMPLE_SCALE + sx * 2 + 1 - center;
                            let py = y as i32 * SAMPLE_SCALE + sy * 2 + 1 - center;
                            ring += 1;
                            arc += u8::from(angle_in_arc(px, py, start, 270));
                        }
                    }
                }
                assert_eq!(
                    fixed_ring_arc_coverage(50, 3, start, 270, x, y),
                    Some((min_coverage(arc), min_coverage(ring)))
                );
                assert_eq!(
                    generated[phase * STATUS_ARC_PIXELS + y * 50 + x],
                    (min_coverage(ring) << 4) | min_coverage(arc)
                );
            }
        }
    }
    assert_eq!(fixed_ring_arc_coverage(50, 3, -89, 270, 0, 0), None);
}

#[test]
fn generated_round_masks_and_spans_match_the_geometry_oracle() {
    let masks = std::hint::black_box(rounded_masks());
    let spans = std::hint::black_box(rounded_spans());
    for diameter in 1..=ROUND_MASK_SIDE {
        let rect = Rect::new(0, 0, diameter as u16, diameter as u16);
        for y in 0..diameter {
            for x in 0..diameter {
                let expected = circle_coverage(
                    x as i32,
                    y as i32,
                    diameter as i32 * SAMPLE_SCALE / 2,
                    diameter as i32 * SAMPLE_SCALE / 2,
                    diameter as i32 * SAMPLE_SCALE / 2,
                );
                assert_eq!(
                    masks[diameter * ROUND_MASK_SIDE * ROUND_MASK_SIDE + y * ROUND_MASK_SIDE + x],
                    expected
                );
            }
            if y < diameter.div_ceil(2) {
                let expected = (0..diameter.div_ceil(2))
                    .find(|&x| {
                        rounded_coverage_slow(rect, diameter as u32, x as i32, y as i32) == 16
                    })
                    .unwrap_or(diameter.div_ceil(2));
                assert_eq!(usize::from(spans[diameter * ROUND_MASK_SIDE + y]), expected);
            }
        }
    }
}

#[test]
fn generated_circle_masks_match_supersampled_geometry() {
    let mask = std::hint::black_box(circle_mask::<12, 144>());
    for y in 0..12 {
        for x in 0..12 {
            assert_eq!(
                mask[y * 12 + x],
                circle_coverage(x as i32, y as i32, 48, 48, 48)
            );
        }
    }
}

#[test]
fn zero_sized_shapes_write_nothing_and_zero_radius_rectangles_are_solid() {
    let mut target = Rec::new(24, Rgb565::BLACK);
    rounded_rect(
        &mut target,
        Rect::new(0, 0, 0, 10),
        0,
        Some(Rgb565::WHITE),
        None,
        Rgb565::BLACK,
    )
    .unwrap();
    fill_rect(&mut target, Rect::new(0, 0, 10, 0), Rgb565::WHITE).unwrap();
    filled_circle(
        &mut target,
        EgPoint::new(0, 0),
        0,
        Rgb565::WHITE,
        Rgb565::BLACK,
    )
    .unwrap();
    assert!(target.pixels.iter().all(|&pixel| pixel == Rgb565::BLACK));
    rounded_rect(
        &mut target,
        Rect::new(2, 2, 10, 10),
        0,
        Some(Rgb565::WHITE),
        None,
        Rgb565::BLACK,
    )
    .unwrap();
    assert_eq!(target.at(2, 2), Rgb565::WHITE);
    assert_eq!(target.at(11, 11), Rgb565::WHITE);
    assert_eq!(target.at(12, 12), Rgb565::BLACK);
    assert!(!rounded_sample(Rect::new(0, 0, 0, 0), 0, 0, 0));
    assert!(rounded_sample(Rect::new(0, 0, 1, 1), 0, 1, 1));
    assert_eq!(rounded_coverage(Rect::new(0, 0, 0, 0), 0, 0, 0), 0);
    assert_eq!(fixed_rounded_coverage(Rect::new(0, 0, 1, 1), 0, 0, 0), 16);
}

#[test]
fn ring_arc_draws_track_mark_and_partial_pixels() {
    let mut target = Rec::new(32, Rgb565::BLACK);
    ring_arc(
        &mut target,
        EgPoint::new(16, 16),
        24,
        3,
        -90,
        270,
        Rgb565::BLUE,
        Rgb565::RED,
        Rgb565::BLACK,
    )
    .unwrap();
    assert!(target.pixels.contains(&Rgb565::BLUE));
    assert!(target.pixels.contains(&Rgb565::RED));
    assert!(
        target.pixels.iter().any(|color| *color != Rgb565::BLACK
            && *color != Rgb565::BLUE
            && *color != Rgb565::RED)
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DrawError;

struct Fails;

impl OriginDimensions for Fails {
    fn size(&self) -> Size {
        Size::new(32, 32)
    }
}

impl DrawTarget for Fails {
    type Color = Rgb565;
    type Error = DrawError;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Rgb565>>,
    {
        if pixels.into_iter().next().is_some() {
            Err(DrawError)
        } else {
            Ok(())
        }
    }
}

#[test]
fn shape_reports_target_errors() {
    assert_eq!(
        filled_circle(
            &mut Fails,
            EgPoint::new(4, 4),
            12,
            Rgb565::WHITE,
            Rgb565::BLACK,
        ),
        Err(DrawError)
    );
}

struct Transactions {
    draw: usize,
    contiguous: usize,
    solid: usize,
}

impl OriginDimensions for Transactions {
    fn size(&self) -> Size {
        Size::new(64, 64)
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

    fn fill_solid(&mut self, _area: &Rectangle, _color: Rgb565) -> Result<(), Self::Error> {
        self.solid += 1;
        Ok(())
    }
}

#[test]
fn shapes_use_contiguous_masks_and_solid_spans() {
    let mut target = Transactions {
        draw: 0,
        contiguous: 0,
        solid: 0,
    };
    filled_circle(
        &mut target,
        EgPoint::new(2, 2),
        16,
        Rgb565::WHITE,
        Rgb565::BLACK,
    )
    .unwrap();
    circle(
        &mut target,
        EgPoint::new(2, 2),
        16,
        2,
        Rgb565::WHITE,
        Rgb565::BLACK,
    )
    .unwrap();
    rounded_rect(
        &mut target,
        Rect::new(2, 2, 24, 16),
        8,
        Some(Rgb565::WHITE),
        None,
        Rgb565::BLACK,
    )
    .unwrap();
    ring_arc(
        &mut target,
        EgPoint::new(20, 20),
        16,
        2,
        -90,
        270,
        Rgb565::BLUE,
        Rgb565::WHITE,
        Rgb565::BLACK,
    )
    .unwrap();
    assert_eq!(target.draw, 0);
    assert_eq!(target.contiguous, 5);
    assert_eq!(target.solid, 1);
}

#[test]
fn circular_strokes_remain_symmetric_for_uncached_inner_diameters() {
    for diameter in [12u32, 17, 39, 58] {
        for width in [1, 3, 7] {
            let side = diameter as usize + 4;
            let mut target = Rec::new(side, Rgb565::BLACK);
            circle(
                &mut target,
                EgPoint::new(2, 2),
                diameter,
                width,
                Rgb565::WHITE,
                Rgb565::BLACK,
            )
            .unwrap();
            assert!(!target.oob);
            assert_eq!(target.at(0, 0), Rgb565::BLACK);
            let d = diameter as usize;
            for y in 0..d {
                for x in 0..d {
                    let pixel = target.at(x + 2, y + 2);
                    assert_eq!(pixel, target.at(d - 1 - x + 2, y + 2));
                    assert_eq!(pixel, target.at(x + 2, d - 1 - y + 2));
                    assert_eq!(pixel, target.at(y + 2, x + 2));
                }
            }
        }
    }
}

#[test]
fn a_complete_arc_matches_its_circle_at_every_rotation() {
    for diameter in [24u32, 50] {
        let side = diameter as usize + 4;
        let top_left = EgPoint::new(2, 2);
        let center = EgPoint::new(2 + diameter as i32 / 2, 2 + diameter as i32 / 2);
        let mut expected = Rec::new(side, Rgb565::BLACK);
        circle(
            &mut expected,
            top_left,
            diameter,
            3,
            Rgb565::WHITE,
            Rgb565::BLACK,
        )
        .unwrap();
        for start in [-90, -89, 0, 13, 360] {
            let mut target = Rec::new(side, Rgb565::BLACK);
            ring_arc(
                &mut target,
                center,
                diameter,
                3,
                start,
                360,
                Rgb565::RED,
                Rgb565::WHITE,
                Rgb565::BLACK,
            )
            .unwrap();
            assert!(!target.oob);
            assert_eq!(
                target.pixels, expected.pixels,
                "diameter={diameter}, start={start}"
            );
        }
    }
}
