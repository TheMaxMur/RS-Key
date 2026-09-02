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

const MAX_PLACED_GLYPHS: usize = 128;
const MAX_TEXT_ROW: usize = 320;

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
    glyphs: &'static [Glyph; 98],
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
    } else if char == '\u{2423}' {
        97
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

#[derive(Clone, Copy)]
struct PlacedGlyph {
    glyph: Glyph,
    x: i32,
    y: i32,
}

struct TextRaster {
    font: Font,
    placed: [PlacedGlyph; MAX_PLACED_GLYPHS],
    placed_len: usize,
    left: i32,
    top: i32,
    width: usize,
    height: usize,
    x: usize,
    y: usize,
    alpha: [u8; MAX_TEXT_ROW],
    background_left: [Rgb565; 16],
    background_right: [Rgb565; 16],
    split_x: i32,
}

impl TextRaster {
    fn prepare_row(&mut self) {
        self.alpha[..self.width].fill(0);
        let screen_y = self.top + self.y as i32;
        for placed in &self.placed[..self.placed_len] {
            let glyph = placed.glyph;
            let glyph_y = screen_y - placed.y;
            if glyph_y < 0 || glyph_y >= i32::from(glyph.height) {
                continue;
            }
            let row = glyph_y as usize * usize::from(glyph.width);
            for glyph_x in 0..usize::from(glyph.width) {
                let screen_x = placed.x + glyph_x as i32;
                if screen_x >= self.left && screen_x < self.left + self.width as i32 {
                    let x = (screen_x - self.left) as usize;
                    self.alpha[x] = self.alpha[x].max(coverage(self.font, glyph, row + glyph_x));
                }
            }
        }
    }
}

impl Iterator for TextRaster {
    type Item = Rgb565;

    fn next(&mut self) -> Option<Self::Item> {
        if self.y == self.height {
            return None;
        }
        if self.x == 0 {
            self.prepare_row();
        }
        let alpha = usize::from(self.alpha[self.x]);
        let color = if self.left + (self.x as i32) < self.split_x {
            self.background_left[alpha]
        } else {
            self.background_right[alpha]
        };
        self.x += 1;
        if self.x == self.width {
            self.x = 0;
            self.y += 1;
        }
        Some(color)
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
    let text_width = match alignment {
        Alignment::Left => 0,
        Alignment::Center | Alignment::Right => width(text, role).unwrap_or(0) as i32,
    };
    let start_x = match alignment {
        Alignment::Left => at.x,
        Alignment::Center => at.x - text_width / 2,
        Alignment::Right => at.x - text_width,
    };
    let baseline = at.y + (i32::from(font.ascent) - i32::from(font.descent)) / 2;
    let clip = t.bounding_box();
    let clip_right = clip.top_left.x + clip.size.width as i32;
    let clip_bottom = clip.top_left.y + clip.size.height as i32;
    let dummy = PlacedGlyph {
        glyph: font.glyphs[0],
        x: 0,
        y: 0,
    };
    let mut placed = [dummy; MAX_PLACED_GLYPHS];
    let mut placed_len = 0;
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
        let visible = x < clip_right
            && x + i32::from(glyph.width) > clip.top_left.x
            && y < clip_bottom
            && y + i32::from(glyph.height) > clip.top_left.y;
        if visible {
            assert!(placed_len < placed.len(), "text glyph capacity exceeded");
            placed[placed_len] = PlacedGlyph { glyph, x, y };
            placed_len += 1;
        }
        pen_x += i32::from(glyph.advance);
    }
    if left >= right || top >= bottom {
        return Ok(());
    }

    left = left.max(clip.top_left.x);
    top = top.max(clip.top_left.y);
    right = right.min(clip_right).min(left + MAX_TEXT_ROW as i32);
    bottom = bottom.min(clip_bottom);
    if left >= right || top >= bottom {
        return Ok(());
    }

    let mut background_left = [Rgb565::new(0, 0, 0); 16];
    let mut background_right = [Rgb565::new(0, 0, 0); 16];
    let (left_bg, right_bg, split_x) = match bg {
        Background::Solid(color) => (color, color, i32::MAX),
        Background::Split {
            left,
            right,
            split_x,
        } => (left, right, split_x),
    };
    for alpha in 0..16 {
        background_left[alpha] = blend_coverage(color, left_bg, alpha as u8);
        background_right[alpha] = blend_coverage(color, right_bg, alpha as u8);
    }

    let area = Rectangle::new(
        EgPoint::new(left, top),
        Size::new((right - left) as u32, (bottom - top) as u32),
    );
    t.fill_contiguous(
        &area,
        TextRaster {
            font,
            placed,
            placed_len,
            left,
            top,
            width: (right - left) as usize,
            height: (bottom - top) as usize,
            x: 0,
            y: 0,
            alpha: [0; MAX_TEXT_ROW],
            background_left,
            background_right,
            split_x,
        },
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
