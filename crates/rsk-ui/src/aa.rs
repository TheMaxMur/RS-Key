// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Integer coverage drawing for the direct-write RGB565 panel.

use embedded_graphics::{
    draw_target::DrawTarget,
    geometry::{Point as EgPoint, Size},
    pixelcolor::Rgb565,
    prelude::RgbColor,
    primitives::Rectangle,
};

use crate::Rect;

const SAMPLES: i32 = 4;
const SAMPLE_SCALE: i32 = SAMPLES * 2;
/// Maximum value for the four-bit coverage scale.
pub const COVERAGE_MAX: u8 = 15;

/// Blend one 4-bit coverage value over a known surface colour.
pub fn blend_coverage(fg: Rgb565, bg: Rgb565, coverage: u8) -> Rgb565 {
    let coverage = coverage.min(COVERAGE_MAX) as u32;
    if coverage == 0 {
        return bg;
    }
    if coverage == COVERAGE_MAX as u32 {
        return fg;
    }
    let inverse = COVERAGE_MAX as u32 - coverage;
    let r = (fg.r() as u32 * coverage + bg.r() as u32 * inverse + 7) / 15;
    let g = (fg.g() as u32 * coverage + bg.g() as u32 * inverse + 7) / 15;
    let b = (fg.b() as u32 * coverage + bg.b() as u32 * inverse + 7) / 15;
    Rgb565::new(r as u8, g as u8, b as u8)
}

fn blend_three(
    front: Rgb565,
    middle: Rgb565,
    bg: Rgb565,
    front_coverage: u8,
    total_coverage: u8,
) -> Rgb565 {
    let total = total_coverage.min(15) as u32;
    let front_coverage = front_coverage.min(total as u8) as u32;
    let middle_coverage = total - front_coverage;
    let background_coverage = 15 - total;
    let mix = |front_channel: u8, middle_channel: u8, bg_channel: u8| {
        ((u32::from(front_channel) * front_coverage
            + u32::from(middle_channel) * middle_coverage
            + u32::from(bg_channel) * background_coverage
            + 7)
            / 15) as u8
    };
    Rgb565::new(
        mix(front.r(), middle.r(), bg.r()),
        mix(front.g(), middle.g(), bg.g()),
        mix(front.b(), middle.b(), bg.b()),
    )
}

fn circle_coverage(px: i32, py: i32, cx: i32, cy: i32, radius: i32) -> u8 {
    let mut coverage = 0;
    let radius_sq = radius * radius;
    for sy in 0..SAMPLES {
        for sx in 0..SAMPLES {
            let x = px * SAMPLE_SCALE + sx * 2 + 1 - cx;
            let y = py * SAMPLE_SCALE + sy * 2 + 1 - cy;
            coverage += u8::from(x * x + y * y <= radius_sq);
        }
    }
    coverage
}

fn rounded_sample(rect: Rect, diameter: u32, x: i32, y: i32) -> bool {
    if rect.w == 0 || rect.h == 0 {
        return false;
    }
    let left = rect.x as i32 * SAMPLE_SCALE;
    let top = rect.y as i32 * SAMPLE_SCALE;
    let right = (rect.x as i32 + rect.w as i32) * SAMPLE_SCALE;
    let bottom = (rect.y as i32 + rect.h as i32) * SAMPLE_SCALE;
    if x < left || x >= right || y < top || y >= bottom {
        return false;
    }
    let radius = (diameter as i32 * SAMPLE_SCALE / 2)
        .min((right - left) / 2)
        .min((bottom - top) / 2);
    if radius == 0 {
        return true;
    }
    let cx = x.clamp(left + radius, right - radius);
    let cy = y.clamp(top + radius, bottom - radius);
    let dx = x - cx;
    let dy = y - cy;
    dx * dx + dy * dy <= radius * radius
}

fn rounded_coverage(rect: Rect, diameter: u32, px: i32, py: i32) -> u8 {
    if rect.w == 0 || rect.h == 0 {
        return 0;
    }
    let left = i32::from(rect.x) * SAMPLE_SCALE;
    let top = i32::from(rect.y) * SAMPLE_SCALE;
    let right = (i32::from(rect.x) + i32::from(rect.w)) * SAMPLE_SCALE;
    let bottom = (i32::from(rect.y) + i32::from(rect.h)) * SAMPLE_SCALE;
    let sample_left = px * SAMPLE_SCALE + 1;
    let sample_top = py * SAMPLE_SCALE + 1;
    let sample_right = sample_left + (SAMPLES - 1) * 2;
    let sample_bottom = sample_top + (SAMPLES - 1) * 2;
    if sample_right < left || sample_left >= right || sample_bottom < top || sample_top >= bottom {
        return 0;
    }
    let radius = (diameter as i32 * SAMPLE_SCALE / 2)
        .min((right - left) / 2)
        .min((bottom - top) / 2);
    if radius == 0
        || (sample_left >= left + radius && sample_right <= right - radius)
        || (sample_top >= top + radius && sample_bottom <= bottom - radius)
    {
        return (SAMPLES * SAMPLES) as u8;
    }

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

fn inset(rect: Rect, amount: u16) -> Rect {
    Rect::new(
        rect.x.saturating_add(amount),
        rect.y.saturating_add(amount),
        rect.w.saturating_sub(amount.saturating_mul(2)),
        rect.h.saturating_sub(amount.saturating_mul(2)),
    )
}

/// Draw a filled circle. The fringe stays inside its diameter box.
pub fn filled_circle<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    top_left: EgPoint,
    diameter: u32,
    fill: Rgb565,
    bg: Rgb565,
) -> Result<(), D::Error> {
    if diameter == 0 {
        return Ok(());
    }
    let d = diameter as i32;
    let cx = (top_left.x * 2 + d) * SAMPLE_SCALE / 2;
    let cy = (top_left.y * 2 + d) * SAMPLE_SCALE / 2;
    let radius = d * SAMPLE_SCALE / 2;
    let area = Rectangle::new(top_left, Size::new(diameter, diameter));
    t.fill_contiguous(
        &area,
        (top_left.y..top_left.y + d).flat_map(|py| {
            (top_left.x..top_left.x + d).map(move |px| {
                let coverage = circle_coverage(px, py, cx, cy, radius);
                blend_coverage(fill, bg, coverage)
            })
        }),
    )
}

/// Draw a circle outline with an inside-aligned stroke.
pub fn circle<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    top_left: EgPoint,
    diameter: u32,
    width: u32,
    color: Rgb565,
    bg: Rgb565,
) -> Result<(), D::Error> {
    if diameter == 0 || width == 0 {
        return Ok(());
    }
    let d = diameter as i32;
    let cx = (top_left.x * 2 + d) * SAMPLE_SCALE / 2;
    let cy = (top_left.y * 2 + d) * SAMPLE_SCALE / 2;
    let outer = d * SAMPLE_SCALE / 2;
    let inner = (outer - width as i32 * SAMPLE_SCALE).max(0);
    let area = Rectangle::new(top_left, Size::new(diameter, diameter));
    t.fill_contiguous(
        &area,
        (top_left.y..top_left.y + d).flat_map(|py| {
            (top_left.x..top_left.x + d).map(move |px| {
                let outer_coverage = circle_coverage(px, py, cx, cy, outer);
                let inner_coverage = circle_coverage(px, py, cx, cy, inner);
                let coverage = outer_coverage.saturating_sub(inner_coverage);
                blend_coverage(color, bg, coverage)
            })
        }),
    )
}

/// Draw a rounded rectangle with an optional fill and inside border.
#[allow(clippy::too_many_arguments)]
pub fn rounded_rect<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    rect: Rect,
    corner_diameter: u32,
    fill: Option<Rgb565>,
    border: Option<(Rgb565, u16)>,
    bg: Rgb565,
) -> Result<(), D::Error> {
    if rect.w == 0 || rect.h == 0 {
        return Ok(());
    }
    let area = Rectangle::new(
        EgPoint::new(i32::from(rect.x), i32::from(rect.y)),
        Size::new(u32::from(rect.w), u32::from(rect.h)),
    );
    t.fill_contiguous(
        &area,
        (rect.y as i32..(rect.y + rect.h) as i32).flat_map(|py| {
            (rect.x as i32..(rect.x + rect.w) as i32).map(move |px| {
                let outer = rounded_coverage(rect, corner_diameter, px, py);
                let mut color = bg;
                if let Some((stroke, width)) = border {
                    let inner = inset(rect, width);
                    let inner_diameter = corner_diameter.saturating_sub(u32::from(width) * 2);
                    let inner_coverage = rounded_coverage(inner, inner_diameter, px, py);
                    if let Some(fill) = fill {
                        color = blend_three(fill, stroke, bg, inner_coverage, outer);
                    } else {
                        let coverage = outer.saturating_sub(inner_coverage);
                        color = blend_coverage(stroke, color, coverage);
                    }
                } else if let Some(fill) = fill {
                    color = blend_coverage(fill, color, outer);
                }
                color
            })
        }),
    )
}

fn angle_deg(x: i32, y: i32) -> i32 {
    if x == 0 && y == 0 {
        return 0;
    }
    let ax = x.abs();
    let ay = y.abs();
    let first = if ax >= ay {
        ay * 45 / ax.max(1)
    } else {
        90 - ax * 45 / ay.max(1)
    };
    match (x >= 0, y >= 0) {
        (true, true) => first,
        (false, true) => 180 - first,
        (false, false) => 180 + first,
        (true, false) => 360 - first,
    }
}

fn angle_in_arc(x: i32, y: i32, start_deg: i32, sweep_deg: u16) -> bool {
    (angle_deg(x, y) - start_deg).rem_euclid(360) < i32::from(sweep_deg.min(360))
}

/// Draw a ring track and its arc in one pass, including the shared AA fringe.
#[allow(clippy::too_many_arguments)]
pub fn ring_arc<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    center: EgPoint,
    diameter: u32,
    width: u32,
    start_deg: i32,
    sweep_deg: u16,
    track: Rgb565,
    mark: Rgb565,
    bg: Rgb565,
) -> Result<(), D::Error> {
    if diameter == 0 || width == 0 {
        return Ok(());
    }
    let d = diameter as i32;
    let left = center.x - d / 2;
    let top = center.y - d / 2;
    let cx = center.x * SAMPLE_SCALE;
    let cy = center.y * SAMPLE_SCALE;
    let outer = d * SAMPLE_SCALE / 2;
    let inner = (outer - width as i32 * SAMPLE_SCALE).max(0);
    let outer_sq = outer * outer;
    let inner_sq = inner * inner;
    let area = Rectangle::new(EgPoint::new(left, top), Size::new(diameter, diameter));
    t.fill_contiguous(
        &area,
        (top..top + d).flat_map(|py| {
            (left..left + d).map(move |px| {
                let mut ring = 0u8;
                let mut arc = 0u8;
                for sy in 0..SAMPLES {
                    for sx in 0..SAMPLES {
                        let x = px * SAMPLE_SCALE + sx * 2 + 1 - cx;
                        let y = py * SAMPLE_SCALE + sy * 2 + 1 - cy;
                        let distance = x * x + y * y;
                        if distance <= outer_sq && distance > inner_sq {
                            ring += 1;
                            arc += u8::from(angle_in_arc(x, y, start_deg, sweep_deg));
                        }
                    }
                }
                blend_three(mark, track, bg, arc, ring)
            })
        }),
    )
}

#[cfg(test)]
#[path = "aa_tests.rs"]
mod tests;
