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

const ROUND_MASK_SIDE: usize = 16;
const ROUND_MASK_LEN: usize = 17 * ROUND_MASK_SIDE * ROUND_MASK_SIDE;
const ROUND_SPAN_LEN: usize = 17 * ROUND_MASK_SIDE;

const fn rounded_masks() -> [u8; ROUND_MASK_LEN] {
    let mut masks = [0u8; ROUND_MASK_LEN];
    let mut diameter = 1usize;
    while diameter <= ROUND_MASK_SIDE {
        let radius = diameter as i32 * SAMPLE_SCALE / 2;
        let mut y = 0usize;
        while y < diameter {
            let mut x = 0usize;
            while x < diameter {
                let mut coverage = 0u8;
                let mut sy = 0;
                while sy < SAMPLES {
                    let mut sx = 0;
                    while sx < SAMPLES {
                        let px = x as i32 * SAMPLE_SCALE + sx * 2 + 1 - radius;
                        let py = y as i32 * SAMPLE_SCALE + sy * 2 + 1 - radius;
                        coverage += (px * px + py * py <= radius * radius) as u8;
                        sx += 1;
                    }
                    sy += 1;
                }
                masks[diameter * ROUND_MASK_SIDE * ROUND_MASK_SIDE + y * ROUND_MASK_SIDE + x] =
                    coverage;
                x += 1;
            }
            y += 1;
        }
        diameter += 1;
    }
    masks
}

const ROUND_MASKS: [u8; ROUND_MASK_LEN] = rounded_masks();

const fn rounded_spans() -> [u8; ROUND_SPAN_LEN] {
    let mut spans = [0u8; ROUND_SPAN_LEN];
    let mut diameter = 1usize;
    while diameter <= ROUND_MASK_SIDE {
        let half = diameter.div_ceil(2);
        let mut y = 0;
        while y < half {
            let mut x = 0;
            while x < half
                && ROUND_MASKS
                    [diameter * ROUND_MASK_SIDE * ROUND_MASK_SIDE + y * ROUND_MASK_SIDE + x]
                    < (SAMPLES * SAMPLES) as u8
            {
                x += 1;
            }
            spans[diameter * ROUND_MASK_SIDE + y] = x as u8;
            y += 1;
        }
        diameter += 1;
    }
    spans
}

const ROUND_SPANS: [u8; ROUND_SPAN_LEN] = rounded_spans();

const fn circle_mask<const DIAMETER: usize, const LEN: usize>() -> [u8; LEN] {
    let mut mask = [0u8; LEN];
    let center = DIAMETER as i32 * SAMPLE_SCALE / 2;
    let radius_sq = center * center;
    let mut index = 0;
    while index < LEN {
        let x = index % DIAMETER;
        let y = index / DIAMETER;
        let mut value = 0u8;
        let mut sy = 0;
        while sy < SAMPLES {
            let mut sx = 0;
            while sx < SAMPLES {
                let px = x as i32 * SAMPLE_SCALE + sx * 2 + 1 - center;
                let py = y as i32 * SAMPLE_SCALE + sy * 2 + 1 - center;
                value += (px * px + py * py <= radius_sq) as u8;
                sx += 1;
            }
            sy += 1;
        }
        mask[index] = value;
        index += 1;
    }
    mask
}

static CIRCLE_6: [u8; 36] = circle_mask::<6, 36>();
static CIRCLE_8: [u8; 64] = circle_mask::<8, 64>();
static CIRCLE_10: [u8; 100] = circle_mask::<10, 100>();
static CIRCLE_12: [u8; 144] = circle_mask::<12, 144>();
static CIRCLE_39: [u8; 1521] = circle_mask::<39, 1521>();
static CIRCLE_58: [u8; 3364] = circle_mask::<58, 3364>();
static CIRCLE_61: [u8; 3721] = circle_mask::<61, 3721>();
static CIRCLE_64: [u8; 4096] = circle_mask::<64, 4096>();
static CIRCLE_70: [u8; 4900] = circle_mask::<70, 4900>();
static CIRCLE_72: [u8; 5184] = circle_mask::<72, 5184>();
static CIRCLE_76: [u8; 5776] = circle_mask::<76, 5776>();

const fn ring_sample_mask<const DIAMETER: usize, const WIDTH: usize, const LEN: usize>()
-> [u16; LEN] {
    let mut mask = [0u16; LEN];
    let center = DIAMETER as i32 * SAMPLE_SCALE / 2;
    let outer_sq = center * center;
    let inner = center - WIDTH as i32 * SAMPLE_SCALE;
    let inner_sq = inner * inner;
    let mut index = 0;
    while index < LEN {
        let pixel_x = index % DIAMETER;
        let pixel_y = index / DIAMETER;
        let mut sy = 0;
        while sy < SAMPLES {
            let mut sx = 0;
            while sx < SAMPLES {
                let x = pixel_x as i32 * SAMPLE_SCALE + sx * 2 + 1 - center;
                let y = pixel_y as i32 * SAMPLE_SCALE + sy * 2 + 1 - center;
                let distance = x * x + y * y;
                if distance <= outer_sq && distance > inner_sq {
                    mask[index] |= 1 << (sy * SAMPLES + sx);
                }
                sx += 1;
            }
            sy += 1;
        }
        index += 1;
    }
    mask
}

const RING_50_3: [u16; 2500] = ring_sample_mask::<50, 3, 2500>();
const STATUS_ARC_BASE_DEG: i32 = -90;
const STATUS_ARC_STEP_DEG: i32 = 24;
const STATUS_ARC_PHASES: usize = 15;
const STATUS_ARC_PIXELS: usize = 50 * 50;

const fn status_arc_coverages() -> [u8; STATUS_ARC_PHASES * STATUS_ARC_PIXELS] {
    let mut out = [0; STATUS_ARC_PHASES * STATUS_ARC_PIXELS];
    let center = 50 * SAMPLE_SCALE / 2;
    let mut phase = 0;
    while phase < STATUS_ARC_PHASES {
        let start = STATUS_ARC_BASE_DEG + phase as i32 * STATUS_ARC_STEP_DEG;
        let mut index = 0;
        while index < STATUS_ARC_PIXELS {
            let samples = RING_50_3[index];
            let pixel_x = index % 50;
            let pixel_y = index / 50;
            let mut ring = 0u8;
            let mut arc = 0u8;
            let mut sy = 0;
            while sy < SAMPLES {
                let mut sx = 0;
                while sx < SAMPLES {
                    let bit = 1 << (sy * SAMPLES + sx);
                    if samples & bit != 0 {
                        let x = pixel_x as i32 * SAMPLE_SCALE + sx * 2 + 1 - center;
                        let y = pixel_y as i32 * SAMPLE_SCALE + sy * 2 + 1 - center;
                        ring += 1;
                        arc += angle_in_arc(x, y, start, 270) as u8;
                    }
                    sx += 1;
                }
                sy += 1;
            }
            out[phase * STATUS_ARC_PIXELS + index] = (min_coverage(ring) << 4) | min_coverage(arc);
            index += 1;
        }
        phase += 1;
    }
    out
}

static STATUS_ARC_COVERAGES: [u8; STATUS_ARC_PHASES * STATUS_ARC_PIXELS] = status_arc_coverages();

const fn min_coverage(value: u8) -> u8 {
    if value > COVERAGE_MAX {
        COVERAGE_MAX
    } else {
        value
    }
}

fn fixed_circle_coverage(diameter: u32, x: usize, y: usize) -> Option<u8> {
    let index = y * diameter as usize + x;
    match diameter {
        6 => Some(CIRCLE_6[index]),
        8 => Some(CIRCLE_8[index]),
        10 => Some(CIRCLE_10[index]),
        12 => Some(CIRCLE_12[index]),
        39 => Some(CIRCLE_39[index]),
        58 => Some(CIRCLE_58[index]),
        61 => Some(CIRCLE_61[index]),
        64 => Some(CIRCLE_64[index]),
        70 => Some(CIRCLE_70[index]),
        72 => Some(CIRCLE_72[index]),
        76 => Some(CIRCLE_76[index]),
        _ => None,
    }
}

fn fixed_ring_samples(diameter: u32, width: u32, x: usize, y: usize) -> Option<u16> {
    match (diameter, width) {
        (50, 3) => Some(RING_50_3[y * 50 + x]),
        _ => None,
    }
}

fn fixed_ring_arc_coverage(
    diameter: u32,
    width: u32,
    start_deg: i32,
    sweep_deg: u16,
    x: usize,
    y: usize,
) -> Option<(u8, u8)> {
    if diameter != 50 || width != 3 || sweep_deg != 270 {
        return None;
    }
    let delta = start_deg.wrapping_sub(STATUS_ARC_BASE_DEG).rem_euclid(360);
    if delta % STATUS_ARC_STEP_DEG != 0 {
        return None;
    }
    let phase = delta as usize / STATUS_ARC_STEP_DEG as usize;
    let packed = STATUS_ARC_COVERAGES[phase * STATUS_ARC_PIXELS + y * 50 + x];
    Some((packed & 0x0f, packed >> 4))
}

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

    if diameter <= ROUND_MASK_SIDE as u32
        && u32::from(rect.w) >= diameter
        && u32::from(rect.h) >= diameter
    {
        let local_x = (px - i32::from(rect.x)).min(i32::from(rect.x + rect.w - 1) - px) as usize;
        let local_y = (py - i32::from(rect.y)).min(i32::from(rect.y + rect.h - 1) - py) as usize;
        let corner = diameter.div_ceil(2) as usize;
        if local_x < corner && local_y < corner {
            return ROUND_MASKS[diameter as usize * ROUND_MASK_SIDE * ROUND_MASK_SIDE
                + local_y * ROUND_MASK_SIDE
                + local_x];
        }
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

fn fixed_round_supported(rect: Rect, diameter: u32) -> bool {
    if diameter > ROUND_MASK_SIDE as u32 {
        return false;
    }
    let half = diameter.div_ceil(2);
    u32::from(rect.w) >= half * 2 && u32::from(rect.h) >= half * 2
}

fn fixed_rounded_coverage(rect: Rect, diameter: u32, px: u16, py: u16) -> u8 {
    if rect.w == 0
        || rect.h == 0
        || px < rect.x
        || py < rect.y
        || px >= rect.x + rect.w
        || py >= rect.y + rect.h
    {
        return 0;
    }
    if diameter == 0 {
        return (SAMPLES * SAMPLES) as u8;
    }
    let local_x = (px - rect.x).min(rect.x + rect.w - 1 - px) as usize;
    let local_y = (py - rect.y).min(rect.y + rect.h - 1 - py) as usize;
    let half = diameter.div_ceil(2) as usize;
    if local_x >= half || local_y >= half {
        return (SAMPLES * SAMPLES) as u8;
    }
    let full_start = usize::from(ROUND_SPANS[diameter as usize * ROUND_MASK_SIDE + local_y]);
    if local_x >= full_start {
        return (SAMPLES * SAMPLES) as u8;
    }
    ROUND_MASKS[diameter as usize * ROUND_MASK_SIDE * ROUND_MASK_SIDE
        + local_y * ROUND_MASK_SIDE
        + local_x]
}

fn fill_rect<D: DrawTarget<Color = Rgb565>>(
    target: &mut D,
    rect: Rect,
    color: Rgb565,
) -> Result<(), D::Error> {
    if rect.w == 0 || rect.h == 0 {
        return Ok(());
    }
    target.fill_solid(
        &Rectangle::new(
            EgPoint::new(i32::from(rect.x), i32::from(rect.y)),
            Size::new(u32::from(rect.w), u32::from(rect.h)),
        ),
        color,
    )
}

fn rounded_color(
    rect: Rect,
    diameter: u32,
    fill: Option<Rgb565>,
    border: Option<(Rgb565, u16)>,
    bg: Rgb565,
    px: u16,
    py: u16,
) -> Rgb565 {
    let outer = fixed_rounded_coverage(rect, diameter, px, py);
    if let Some((stroke, width)) = border {
        let inner = inset(rect, width);
        let inner_diameter = diameter.saturating_sub(u32::from(width) * 2);
        let inner_coverage = fixed_rounded_coverage(inner, inner_diameter, px, py);
        if let Some(fill) = fill {
            blend_three(fill, stroke, bg, inner_coverage, outer)
        } else {
            blend_coverage(stroke, bg, outer.saturating_sub(inner_coverage))
        }
    } else if let Some(fill) = fill {
        blend_coverage(fill, bg, outer)
    } else {
        bg
    }
}

fn straight_color(
    fill: Option<Rgb565>,
    border: Option<(Rgb565, u16)>,
    bg: Rgb565,
    inside_inner: bool,
) -> Rgb565 {
    if let Some((stroke, _)) = border {
        if inside_inner {
            fill.unwrap_or(bg)
        } else {
            stroke
        }
    } else {
        fill.unwrap_or(bg)
    }
}

fn fill_fixed_middle<D: DrawTarget<Color = Rgb565>>(
    target: &mut D,
    rect: Rect,
    diameter: u32,
    fill: Option<Rgb565>,
    border: Option<(Rgb565, u16)>,
    bg: Rgb565,
) -> Result<(), D::Error> {
    let half = diameter.div_ceil(2) as u16;
    let middle = Rect::new(rect.x, rect.y + half, rect.w, rect.h - half * 2);
    if let Some((stroke, width)) = border {
        fill_rect(
            target,
            Rect::new(middle.x, middle.y, width, middle.h),
            stroke,
        )?;
        fill_rect(
            target,
            Rect::new(middle.x + width, middle.y, middle.w - width * 2, middle.h),
            fill.unwrap_or(bg),
        )?;
        fill_rect(
            target,
            Rect::new(middle.x + middle.w - width, middle.y, width, middle.h),
            stroke,
        )
    } else {
        fill_rect(target, middle, fill.unwrap_or(bg))
    }
}

fn fill_fixed_strips<D: DrawTarget<Color = Rgb565>>(
    target: &mut D,
    rect: Rect,
    diameter: u32,
    fill: Option<Rgb565>,
    border: Option<(Rgb565, u16)>,
    bg: Rgb565,
) -> Result<(), D::Error> {
    let half = diameter.div_ceil(2) as u16;
    if half == 0 {
        return Ok(());
    }
    for bottom in [false, true] {
        let strip = Rect::new(
            rect.x,
            if bottom {
                rect.y + rect.h - half
            } else {
                rect.y
            },
            rect.w,
            half,
        );
        let area = Rectangle::new(
            EgPoint::new(i32::from(strip.x), i32::from(strip.y)),
            Size::new(u32::from(strip.w), u32::from(strip.h)),
        );
        target.fill_contiguous(
            &area,
            (strip.y..strip.y + strip.h).flat_map(|py| {
                (strip.x..strip.x + strip.w).map(move |px| {
                    let local_x = (px - rect.x).min(rect.x + rect.w - 1 - px);
                    if local_x < half {
                        rounded_color(rect, diameter, fill, border, bg, px, py)
                    } else if let Some((_, width)) = border {
                        let inner = inset(rect, width);
                        let inside_inner = px >= inner.x
                            && py >= inner.y
                            && px < inner.x + inner.w
                            && py < inner.y + inner.h;
                        straight_color(fill, border, bg, inside_inner)
                    } else {
                        fill.unwrap_or(bg)
                    }
                })
            }),
        )?;
    }
    Ok(())
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
                let coverage = fixed_circle_coverage(
                    diameter,
                    (px - top_left.x) as usize,
                    (py - top_left.y) as usize,
                )
                .unwrap_or_else(|| circle_coverage(px, py, cx, cy, radius));
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
                let x = (px - top_left.x) as usize;
                let y = (py - top_left.y) as usize;
                let outer_coverage = fixed_circle_coverage(diameter, x, y)
                    .unwrap_or_else(|| circle_coverage(px, py, cx, cy, outer));
                let inner_diameter = diameter.saturating_sub(width * 2);
                let inner_coverage = if width <= diameter
                    && x >= width as usize
                    && y >= width as usize
                    && x < (diameter - width) as usize
                    && y < (diameter - width) as usize
                {
                    fixed_circle_coverage(inner_diameter, x - width as usize, y - width as usize)
                        .unwrap_or_else(|| circle_coverage(px, py, cx, cy, inner))
                } else {
                    circle_coverage(px, py, cx, cy, inner)
                };
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
    let half = corner_diameter.div_ceil(2) as u16;
    let border_supported = border
        .is_none_or(|(_, width)| width <= half && width.saturating_mul(2) <= rect.w.min(rect.h));
    if fixed_round_supported(rect, corner_diameter) && border_supported {
        if fill.is_none() && border.is_none() {
            return fill_rect(t, rect, bg);
        }
        fill_fixed_middle(t, rect, corner_diameter, fill, border, bg)?;
        return fill_fixed_strips(t, rect, corner_diameter, fill, border, bg);
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

const fn angle_deg(x: i32, y: i32) -> i32 {
    if x == 0 && y == 0 {
        return 0;
    }
    let ax = x.abs();
    let ay = y.abs();
    let first = if ax >= ay {
        ay * 45 / ax
    } else {
        90 - ax * 45 / ay
    };
    match (x >= 0, y >= 0) {
        (true, true) => first,
        (false, true) => 180 - first,
        (false, false) => 180 + first,
        (true, false) => 360 - first,
    }
}

const fn angle_in_arc(x: i32, y: i32, start_deg: i32, sweep_deg: u16) -> bool {
    let sweep = if sweep_deg > 360 { 360 } else { sweep_deg };
    (angle_deg(x, y) - start_deg).rem_euclid(360) < sweep as i32
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
                if let Some((arc, ring)) = fixed_ring_arc_coverage(
                    diameter,
                    width,
                    start_deg,
                    sweep_deg,
                    (px - left) as usize,
                    (py - top) as usize,
                ) {
                    return blend_three(mark, track, bg, arc, ring);
                }
                let mut ring = 0u8;
                let mut arc = 0u8;
                let fixed =
                    fixed_ring_samples(diameter, width, (px - left) as usize, (py - top) as usize);
                for sy in 0..SAMPLES {
                    for sx in 0..SAMPLES {
                        let bit = 1 << (sy * SAMPLES + sx);
                        let x = px * SAMPLE_SCALE + sx * 2 + 1 - cx;
                        let y = py * SAMPLE_SCALE + sy * 2 + 1 - cy;
                        let distance = x * x + y * y;
                        let in_ring = fixed
                            .map(|samples| samples & bit != 0)
                            .unwrap_or(distance <= outer_sq && distance > inner_sq);
                        if in_ring {
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
