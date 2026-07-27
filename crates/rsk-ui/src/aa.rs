// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Anti-aliased drawing for the ST7789 panel. Integer math only (no_std, no libm).

use embedded_graphics::{
    Pixel,
    draw_target::DrawTarget,
    geometry::Point as EgPoint,
    pixelcolor::Rgb565,
    prelude::{Drawable, RgbColor},
    primitives::Rectangle,
};

use crate::theme;

const FP: u32 = 16;
const FP_ONE: i64 = 1 << FP;
const FP_HALF: i64 = FP_ONE / 2;
const AA_BAND: i64 = FP_ONE + FP_HALF;

const ALPHA: [u8; 32] = [
    255, 247, 239, 231, 223, 215, 207, 199, 191, 183, 175, 167, 159, 151, 143, 135, 128, 120,
    112, 104, 96, 88, 80, 72, 64, 56, 48, 40, 32, 24, 16, 8,
];

/// Anti-aliased filled circle. Takes top-left and diameter (same API as
/// embedded-graphics `Circle::new`), so call sites stay unchanged.
pub fn filled_circle<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    top_left: EgPoint,
    diameter: u32,
    fill: Rgb565,
) -> Result<(), D::Error> {
    let cx = top_left.x + diameter as i32 / 2;
    let cy = top_left.y + diameter as i32 / 2;
    let r = i64::from(diameter) << (FP - 1);
    let r_inner = r - AA_BAND;
    let r_outer = r + AA_BAND;
    let r_inner_sq = r_inner * r_inner;
    let r_outer_sq = r_outer * r_outer;

    let r2 = diameter as i32 / 2 + 3;
    let min_x = cx - r2;
    let max_x = cx + r2;
    let min_y = cy - r2;
    let max_y = cy + r2;

    for py in min_y..=max_y {
        for px in min_x..=max_x {
            let dx = i64::from(px - cx) << FP;
            let dy = i64::from(py - cy) << FP;
            let d2 = dx * dx + dy * dy;

            let color = if d2 <= r_inner_sq {
                fill
            } else if d2 >= r_outer_sq {
                continue;
            } else {
                let frac = (d2 - r_inner_sq) as u64 * 32 / (r_outer_sq - r_inner_sq) as u64;
                let a = ALPHA[frac.min(31) as usize];
                blend(fill, theme::BG, a)
            };

            Pixel(EgPoint::new(px, py), color).draw(t)?;
        }
    }
    Ok(())
}

/// Anti-aliased filled rounded rectangle. Same API as
/// `RoundedRectangle::with_equal_corners(rect, size)`.
pub fn filled_rounded_rect<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    bounds: Rectangle,
    corner_radius: u32,
    fill: Rgb565,
) -> Result<(), D::Error> {
    let bx = bounds.top_left.x;
    let by = bounds.top_left.y;
    let bw = bounds.size.width as i32;
    let bh = bounds.size.height as i32;
    let cr_u = corner_radius as i32;
    let cr = i64::from(corner_radius) << FP;
    let cr_inner = cr - AA_BAND;
    let cr_outer = cr + AA_BAND;
    let cr_inner_sq = cr_inner * cr_inner;
    let cr_outer_sq = cr_outer * cr_outer;

    let c_tl_x = i64::from(bx + cr_u) << FP;
    let c_tl_y = i64::from(by + cr_u) << FP;
    let c_tr_x = i64::from(bx + bw - cr_u) << FP;
    let c_bl_y = i64::from(by + bh - cr_u) << FP;

    let straight_x0 = bx + cr_u;
    let straight_x1 = bx + bw - cr_u;
    let straight_y0 = by + cr_u;
    let straight_y1 = by + bh - cr_u;

    for py in by..by + bh {
        for px in bx..bx + bw {
            if (px >= straight_x0 && px < straight_x1) || (py >= straight_y0 && py < straight_y1) {
                Pixel(EgPoint::new(px, py), fill).draw(t)?;
                continue;
            }

            let pxf = i64::from(px) << FP;
            let pyf = i64::from(py) << FP;

            let d2 = if px < straight_x0 && py < straight_y0 {
                (pxf - c_tl_x).pow(2) + (pyf - c_tl_y).pow(2)
            } else if px >= straight_x1 && py < straight_y0 {
                (pxf - c_tr_x).pow(2) + (pyf - c_tl_y).pow(2)
            } else if px < straight_x0 && py >= straight_y1 {
                (pxf - c_tl_x).pow(2) + (pyf - c_bl_y).pow(2)
            } else if px >= straight_x1 && py >= straight_y1 {
                (pxf - c_tr_x).pow(2) + (pyf - c_bl_y).pow(2)
            } else {
                continue;
            };

            let color = if d2 <= cr_inner_sq {
                fill
            } else if d2 >= cr_outer_sq {
                continue;
            } else {
                let frac = (d2 - cr_inner_sq) as u64 * 32 / (cr_outer_sq - cr_inner_sq) as u64;
                let a = ALPHA[frac.min(31) as usize];
                blend(fill, theme::BG, a)
            };

            Pixel(EgPoint::new(px, py), color).draw(t)?;
        }
    }
    Ok(())
}

fn blend(fg: Rgb565, bg: Rgb565, alpha: u8) -> Rgb565 {
    if alpha == 0 { return bg; }
    if alpha == 255 { return fg; }
    let a = alpha as u32;
    let inv = 255 - a;
    let r = (fg.r() as u32 * a + bg.r() as u32 * inv) / 255;
    let g = (fg.g() as u32 * a + bg.g() as u32 * inv) / 255;
    let b = (fg.b() as u32 * a + bg.b() as u32 * inv) / 255;
    Rgb565::new(r as u8, g as u8, b as u8)
}
