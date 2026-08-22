// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Four-bit IBM Plex text for the direct-write trusted display.

use embedded_graphics::{
    draw_target::DrawTarget,
    geometry::{Point as EgPoint, Size},
    pixelcolor::Rgb565,
    primitives::Rectangle,
};

use crate::aa::blend_coverage;

/// A typographic role from the display design.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// IBM Plex Sans SemiBold, 30 px.
    Ready,
    /// IBM Plex Sans SemiBold, 19 px.
    Heading,
    /// IBM Plex Sans SemiBold, 18 px.
    Strong,
    /// IBM Plex Sans Regular, 13 px.
    Body,
    /// IBM Plex Sans SemiBold, 13 px.
    BodyStrong,
    /// IBM Plex Mono Regular, 12 px.
    Mono,
    /// IBM Plex Mono Regular, 11 px.
    MonoSmall,
}

#[derive(Clone, Copy)]
struct Glyph {
    advance: u8,
    left: i8,
    top: i8,
    width: u8,
    height: u8,
    offset: u32,
}

#[derive(Clone, Copy)]
struct Font {
    ascent: u8,
    descent: u8,
    glyphs: &'static [Glyph; 97],
    data: &'static [u8],
}

#[path = "../../../third_party/ibm-plex/font_data.rs"]
mod generated;

const fn font(role: Role) -> Font {
    match role {
        Role::Ready => generated::READY,
        Role::Heading => generated::HEADING,
        Role::Strong => generated::STRONG,
        Role::Body => generated::BODY,
        Role::BodyStrong => generated::BODY_STRONG,
        Role::Mono => generated::MONO,
        Role::MonoSmall => generated::MONO_SMALL,
    }
}

const fn glyph_index(char: char) -> usize {
    if char == '\u{2014}' {
        95
    } else if char == '\u{00B7}' {
        96
    } else if char >= ' ' && char <= '~' {
        char as usize - ' ' as usize
    } else {
        '?' as usize - ' ' as usize
    }
}

fn coverage(font: Font, glyph: Glyph, index: usize) -> u8 {
    let packed = font.data[glyph.offset as usize + index / 2];
    if index.is_multiple_of(2) {
        packed >> 4
    } else {
        packed & 0x0F
    }
}

#[derive(Clone, Copy)]
enum Alignment {
    Left,
    Center,
    Right,
}

#[derive(Clone, Copy)]
enum Background {
    Solid(Rgb565),
    Split {
        left: Rgb565,
        right: Rgb565,
        split_x: i32,
    },
}

impl Background {
    fn at(self, x: i32) -> Rgb565 {
        match self {
            Self::Solid(color) => color,
            Self::Split {
                left,
                right,
                split_x,
            } => {
                if x < split_x {
                    left
                } else {
                    right
                }
            }
        }
    }
}

fn draw<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    text: &str,
    at: EgPoint,
    role: Role,
    color: Rgb565,
    bg: Background,
    alignment: Alignment,
) -> Result<(), D::Error> {
    let font = font(role);
    let text_width = width(text, role).unwrap_or(0) as i32;
    let start_x = match alignment {
        Alignment::Left => at.x,
        Alignment::Center => at.x - text_width / 2,
        Alignment::Right => at.x - text_width,
    };
    let baseline = at.y + (i32::from(font.ascent) - i32::from(font.descent)) / 2;
    let mut pen_x = start_x;
    let mut left = i32::MAX;
    let mut top = i32::MAX;
    let mut right = i32::MIN;
    let mut bottom = i32::MIN;
    for char in text.chars() {
        let glyph = font.glyphs[glyph_index(char)];
        let x = pen_x + i32::from(glyph.left);
        let y = baseline + i32::from(glyph.top);
        if glyph.width > 0 && glyph.height > 0 {
            left = left.min(x);
            top = top.min(y);
            right = right.max(x + i32::from(glyph.width));
            bottom = bottom.max(y + i32::from(glyph.height));
        }
        pen_x += i32::from(glyph.advance);
    }
    if left >= right || top >= bottom {
        return Ok(());
    }

    let area = Rectangle::new(
        EgPoint::new(left, top),
        Size::new((right - left) as u32, (bottom - top) as u32),
    );
    t.fill_contiguous(
        &area,
        (top..bottom).flat_map(|py| {
            (left..right).map(move |px| {
                let mut alpha = 0;
                let mut pen_x = start_x;
                for char in text.chars() {
                    let glyph = font.glyphs[glyph_index(char)];
                    let x = pen_x + i32::from(glyph.left);
                    let y = baseline + i32::from(glyph.top);
                    if px >= x
                        && px < x + i32::from(glyph.width)
                        && py >= y
                        && py < y + i32::from(glyph.height)
                    {
                        let column = (px - x) as usize;
                        let row = (py - y) as usize;
                        // Glyph boxes overlap -- 8 of the 97 have a negative left
                        // bearing, 28 carry ink past their advance -- so the pair
                        // composites, and the greater coverage wins, not the later.
                        let index = row * usize::from(glyph.width) + column;
                        alpha = alpha.max(coverage(font, glyph, index));
                    }
                    pen_x += i32::from(glyph.advance);
                }
                blend_coverage(color, bg.at(px), alpha)
            })
        }),
    )
}

/// Draw horizontally centred and vertically centred text.
pub fn centered<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    text: &str,
    at: EgPoint,
    role: Role,
    color: Rgb565,
    bg: Rgb565,
) -> Result<(), D::Error> {
    draw(
        t,
        text,
        at,
        role,
        color,
        Background::Solid(bg),
        Alignment::Center,
    )
}

/// Draw centred text over a vertical split between two known surfaces.
#[allow(clippy::too_many_arguments)]
pub(crate) fn centered_split<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    text: &str,
    at: EgPoint,
    role: Role,
    color: Rgb565,
    left_bg: Rgb565,
    right_bg: Rgb565,
    split_x: i32,
) -> Result<(), D::Error> {
    draw(
        t,
        text,
        at,
        role,
        color,
        Background::Split {
            left: left_bg,
            right: right_bg,
            split_x,
        },
        Alignment::Center,
    )
}

/// Draw left-aligned and vertically centred text.
pub fn left<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    text: &str,
    at: EgPoint,
    role: Role,
    color: Rgb565,
    bg: Rgb565,
) -> Result<(), D::Error> {
    draw(
        t,
        text,
        at,
        role,
        color,
        Background::Solid(bg),
        Alignment::Left,
    )
}

/// Draw right-aligned and vertically centred text.
pub fn right<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    text: &str,
    at: EgPoint,
    role: Role,
    color: Rgb565,
    bg: Rgb565,
) -> Result<(), D::Error> {
    draw(
        t,
        text,
        at,
        role,
        color,
        Background::Solid(bg),
        Alignment::Right,
    )
}

/// Return the integer horizontal extent of `text` from its pen origin.
pub fn width(text: &str, role: Role) -> Option<u32> {
    let font = font(role);
    let mut pen = 0u32;
    let mut right = 0u32;
    for char in text.chars() {
        let glyph = font.glyphs[glyph_index(char)];
        right = right.max(
            pen.saturating_add_signed(i32::from(glyph.left))
                .saturating_add(u32::from(glyph.width)),
        );
        pen = pen.saturating_add(u32::from(glyph.advance));
    }
    Some(pen.max(right))
}

#[cfg(test)]
#[path = "font_tests.rs"]
mod tests;
