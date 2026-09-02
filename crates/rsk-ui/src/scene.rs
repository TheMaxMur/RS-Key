// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Compact retained frames for the framebuffer-less panel.

use core::hash::Hasher;

use embedded_graphics::{
    Pixel,
    draw_target::DrawTarget,
    geometry::{Dimensions, Point, Size},
    pixelcolor::{IntoStorage, Rgb565, RgbColor, raw::RawU16},
    primitives::Rectangle,
};
use siphasher::sip128::{Hasher128, SipHasher24};

use crate::{PANEL_H, PANEL_W, Rect};

/// Height of one composited DMA band.
pub const BAND_H: u16 = 8;
/// Bytes in one full-width RGB565 band.
pub const BAND_BYTES: usize = PANEL_W as usize * BAND_H as usize * 2;

/// Maximum rows that fit in one fixed DMA buffer at `width` pixels.
pub const fn dma_band_height(width: u16) -> u16 {
    if width == 0 {
        return 0;
    }
    let rows = BAND_BYTES / (width as usize * 2);
    if rows > PANEL_H as usize {
        PANEL_H
    } else {
        rows as u16
    }
}
/// Damage tiles keep local changes small without using a full framebuffer.
pub const DAMAGE_TILE: u16 = 32;
pub const DAMAGE_COLS: usize = PANEL_W.div_ceil(DAMAGE_TILE) as usize;
pub const DAMAGE_ROWS: usize = PANEL_H.div_ceil(DAMAGE_TILE) as usize;
pub const DAMAGE_TILES: usize = DAMAGE_COLS * DAMAGE_ROWS;
/// Per-boot key for the keyed damage tags.
pub type DamageKey = [u64; 2];
/// Collision-resistant tag for one damage tile.
pub type DamageTag = u128;

const DAMAGE_DOMAIN: &[u8; 8] = b"RSK-DMG1";

// A complete scene lives in a Frame on the stack. Raster operations store their
// geometry once, then one-byte palette/run tokens. The total stays below 16 KiB.
const STREAM_CAPACITY: usize = 12 * 1024;
const OP_SOLID: u8 = 0;
const OP_RASTER: u8 = 1;
const OP_BACKGROUND: u8 = 2;
const SOLID_BYTES: usize = 9;
const RASTER_HEADER: usize = 13;
const RASTER_PALETTE: usize = 31;
const RUN_SHORT_MAX: u16 = 7;
const RUN_LONG_MAX: u16 = RUN_SHORT_MAX + 1 + u8::MAX as u16;
const BAND_ROWS: usize = PANEL_H.div_ceil(BAND_H) as usize;
const CHECKPOINT_CAPACITY: usize = 256;
const DAMAGE_RECT_CAPACITY: usize = 64;
const NO_RECORD: u16 = u16::MAX;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Command {
    opcode: u8,
    rect: Rect,
    color: Rgb565,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PendingRun {
    x: u8,
    y: u16,
    width: u8,
    color: u16,
}

impl PendingRun {
    fn command(self) -> Command {
        Command {
            opcode: OP_SOLID,
            rect: Rect::new(u16::from(self.x), self.y, u16::from(self.width), 1),
            color: RawU16::new(self.color).into(),
        }
    }
}

/// A retained scene could not represent the complete frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SceneError {
    /// The fixed retained stream had no space for the next operation.
    Capacity,
}

#[derive(Clone, Copy)]
struct RasterState {
    x: u16,
    y: u16,
    width: u16,
    pixels: u32,
    position: u32,
    palette: usize,
    token: usize,
    end: usize,
    run_color: u16,
    run_left: u16,
}

struct RasterEncoder {
    palette: [u16; RASTER_PALETTE],
    write: usize,
    token_start: usize,
    palette_len: usize,
    last_index: Option<u8>,
    last_color: u16,
    run_length: u16,
    pixels: u32,
    checkpoint_pixels: u32,
}

/// A retained, ordered stream of solid rectangles and row-major raster runs.
pub struct Scene {
    stream: [u8; STREAM_CAPACITY],
    tile_tags: [DamageTag; DAMAGE_TILES],
    checkpoints: [u16; CHECKPOINT_CAPACITY],
    band_first: [u16; BAND_ROWS],
    band_end: [u16; BAND_ROWS],
    pending: Option<PendingRun>,
    background: Rgb565,
    stream_len: u16,
    checkpoint_len: u16,
    command_count: u16,
    records_valid: bool,
    tags_valid: bool,
    error: Option<SceneError>,
}

const _: () = assert!(core::mem::size_of::<Scene>() <= 16 * 1024);

impl Default for Scene {
    fn default() -> Self {
        Self {
            stream: [0; STREAM_CAPACITY],
            tile_tags: [0; DAMAGE_TILES],
            checkpoints: [0; CHECKPOINT_CAPACITY],
            band_first: [NO_RECORD; BAND_ROWS],
            band_end: [0; BAND_ROWS],
            pending: None,
            background: Rgb565::BLACK,
            stream_len: 0,
            checkpoint_len: 0,
            command_count: 0,
            records_valid: false,
            tags_valid: false,
            error: None,
        }
    }
}

impl RasterEncoder {
    fn new(token_start: usize, checkpoint_pixels: u32) -> Self {
        Self {
            palette: [0; RASTER_PALETTE],
            write: token_start,
            token_start,
            palette_len: 0,
            last_index: None,
            last_color: 0,
            run_length: 0,
            pixels: 0,
            checkpoint_pixels,
        }
    }

    fn palette_index(&mut self, color: u16) -> Option<u8> {
        if let Some(index) = self.palette[..self.palette_len]
            .iter()
            .position(|entry| *entry == color)
        {
            return Some(index as u8);
        }
        if self.palette_len == self.palette.len() {
            return None;
        }
        let index = self.palette_len;
        self.palette[index] = color;
        self.palette_len += 1;
        Some(index as u8)
    }

    fn flush_run(&mut self, scene: &mut Scene) -> Result<(), SceneError> {
        if self.run_length == 0 {
            return Ok(());
        }
        scene.finish_run(
            &mut self.write,
            self.last_index,
            self.last_color,
            self.run_length,
        )?;
        self.run_length = 0;
        Ok(())
    }

    fn push(&mut self, scene: &mut Scene, color: u16) -> Result<(), SceneError> {
        if self.pixels != 0 && self.pixels.is_multiple_of(self.checkpoint_pixels) {
            self.flush_run(scene)?;
            scene.push_checkpoint(self.write - self.token_start)?;
        }
        self.pixels += 1;
        if self.run_length != 0 && color == self.last_color && self.run_length < u16::MAX {
            self.run_length += 1;
            return Ok(());
        }
        self.flush_run(scene)?;
        let index = self.palette_index(color);
        self.last_index = index;
        self.last_color = color;
        self.run_length = 1;
        Ok(())
    }
}

impl Scene {
    pub fn reset(&mut self) {
        self.pending = None;
        self.background = Rgb565::BLACK;
        self.stream_len = 0;
        self.checkpoint_len = 0;
        self.command_count = 0;
        self.band_first.fill(NO_RECORD);
        self.band_end.fill(0);
        self.records_valid = false;
        self.tags_valid = false;
        self.error = None;
    }

    pub fn command_count(&self) -> usize {
        usize::from(self.command_count) + usize::from(self.pending.is_some())
    }

    pub fn error(&self) -> Option<SceneError> {
        self.error
    }

    fn capacity_error<T>(&mut self) -> Result<T, SceneError> {
        self.error = Some(SceneError::Capacity);
        Err(SceneError::Capacity)
    }

    fn check_error(&self) -> Result<(), SceneError> {
        self.error.map_or(Ok(()), Err)
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), SceneError> {
        let start = usize::from(self.stream_len);
        let Some(end) = start.checked_add(bytes.len()) else {
            return self.capacity_error();
        };
        if end > self.stream.len() {
            return self.capacity_error();
        }
        self.stream[start..end].copy_from_slice(bytes);
        self.stream_len = end as u16;
        Ok(())
    }

    fn push_solid(&mut self, rect: Rect, color: Rgb565) -> Result<(), SceneError> {
        self.check_error()?;
        if rect.w == 0 || rect.h == 0 {
            return Ok(());
        }
        self.records_valid = false;
        self.tags_valid = false;
        let [color_high, color_low] = color.into_storage().to_be_bytes();
        let [y_low, y_high] = rect.y.to_le_bytes();
        let [height_low, height_high] = (rect.h - 1).to_le_bytes();
        self.append(&[
            OP_SOLID,
            rect.x as u8,
            y_low,
            y_high,
            (rect.w - 1) as u8,
            height_low,
            height_high,
            color_high,
            color_low,
        ])?;
        self.command_count = self.command_count.saturating_add(1);
        Ok(())
    }

    fn flush_pending(&mut self) -> Result<(), SceneError> {
        self.check_error()?;
        if let Some(run) = self.pending.take() {
            let command = run.command();
            self.push_solid(command.rect, command.color)?;
        }
        Ok(())
    }

    fn push_pixel(&mut self, x: u16, y: u16, color: Rgb565) -> Result<(), SceneError> {
        self.check_error()?;
        self.records_valid = false;
        self.tags_valid = false;
        let raw = color.into_storage();
        if let Some(run) = self.pending.as_mut()
            && run.color == raw
            && run.y == y
            && u16::from(run.x) + u16::from(run.width) == x
            && u16::from(run.width) < PANEL_W
        {
            run.width += 1;
            return Ok(());
        }
        self.flush_pending()?;
        self.pending = Some(PendingRun {
            x: x as u8,
            y,
            width: 1,
            color: raw,
        });
        Ok(())
    }

    fn finish_run(
        &mut self,
        write: &mut usize,
        palette_index: Option<u8>,
        color: u16,
        mut length: u16,
    ) -> Result<(), SceneError> {
        while length != 0 {
            let part = length.min(RUN_LONG_MAX);
            let needed =
                usize::from(part > RUN_SHORT_MAX) + 1 + usize::from(palette_index.is_none()) * 2;
            if *write + needed > self.stream.len() {
                return self.capacity_error();
            }
            let index = palette_index.unwrap_or(RASTER_PALETTE as u8);
            if part <= RUN_SHORT_MAX {
                self.stream[*write] = index << 3 | (part as u8 - 1);
                *write += 1;
            } else {
                self.stream[*write] = index << 3 | RUN_SHORT_MAX as u8;
                self.stream[*write + 1] = (part - RUN_SHORT_MAX - 1) as u8;
                *write += 2;
            }
            if palette_index.is_none() {
                let [high, low] = color.to_be_bytes();
                self.stream[*write] = high;
                self.stream[*write + 1] = low;
                *write += 2;
            }
            self.command_count = self.command_count.saturating_add(1);
            length -= part;
        }
        Ok(())
    }

    fn push_checkpoint(&mut self, offset: usize) -> Result<(), SceneError> {
        let index = usize::from(self.checkpoint_len);
        if index == self.checkpoints.len() {
            return self.capacity_error();
        }
        self.checkpoints[index] = offset as u16;
        self.checkpoint_len += 1;
        Ok(())
    }

    fn rollback_raster(&mut self, stream_len: usize, command_count: u16, checkpoint_len: u16) {
        self.stream_len = stream_len as u16;
        self.command_count = command_count;
        self.checkpoint_len = checkpoint_len;
    }

    fn encode_raster<I: IntoIterator<Item = Rgb565>>(
        &mut self,
        area: &Rectangle,
        colors: I,
        bounds: (i32, i32, i32, i32),
        encoder: &mut RasterEncoder,
    ) -> Result<(), SceneError> {
        let (left, top, right, bottom) = bounds;
        let mut source = colors.into_iter();
        if area.top_left.x == left
            && area.top_left.y == top
            && area.top_left.x + area.size.width as i32 == right
            && area.top_left.y + area.size.height as i32 == bottom
        {
            let pixels = area.size.width as usize * area.size.height as usize;
            for color in source.by_ref().take(pixels) {
                encoder.push(self, color.into_storage())?;
            }
            return encoder.flush_run(self);
        }
        'rows: for oy in 0..area.size.height {
            for ox in 0..area.size.width {
                let Some(color) = source.next() else {
                    break 'rows;
                };
                let x = area.top_left.x + ox as i32;
                let y = area.top_left.y + oy as i32;
                if x < left || x >= right || y < top || y >= bottom {
                    continue;
                }
                encoder.push(self, color.into_storage())?;
            }
        }
        encoder.flush_run(self)
    }

    fn push_raster<I: IntoIterator<Item = Rgb565>>(
        &mut self,
        area: &Rectangle,
        colors: I,
    ) -> Result<(), SceneError> {
        self.flush_pending()?;
        self.records_valid = false;
        self.tags_valid = false;
        let left = area.top_left.x.max(0).min(i32::from(PANEL_W));
        let top = area.top_left.y.max(0).min(i32::from(PANEL_H));
        let right = (area.top_left.x + area.size.width as i32)
            .max(0)
            .min(i32::from(PANEL_W));
        let bottom = (area.top_left.y + area.size.height as i32)
            .max(0)
            .min(i32::from(PANEL_H));
        if left >= right || top >= bottom {
            return Ok(());
        }

        let start = usize::from(self.stream_len);
        let command_start = self.command_count;
        let checkpoint_start = self.checkpoint_len;
        let token_start = start + RASTER_HEADER;
        if token_start > self.stream.len() {
            let error = self.capacity_error::<()>().unwrap_err();
            self.rollback_raster(start, command_start, checkpoint_start);
            return Err(error);
        }
        let checkpoint_pixels = (right - left) as u32 * u32::from(BAND_H);
        let mut encoder = RasterEncoder::new(token_start, checkpoint_pixels);
        if let Err(error) =
            self.encode_raster(area, colors, (left, top, right, bottom), &mut encoder)
        {
            self.rollback_raster(start, command_start, checkpoint_start);
            return Err(error);
        }
        if encoder.pixels == 0 {
            self.rollback_raster(start, command_start, checkpoint_start);
            return Ok(());
        }

        let token_bytes = encoder.write - token_start;
        let palette_bytes = encoder.palette_len * 2;
        if encoder.write + palette_bytes > self.stream.len() {
            let error = self.capacity_error::<()>().unwrap_err();
            self.rollback_raster(start, command_start, checkpoint_start);
            return Err(error);
        }
        self.stream
            .copy_within(token_start..encoder.write, token_start + palette_bytes);
        for (index, color) in encoder.palette[..encoder.palette_len].iter().enumerate() {
            let [high, low] = color.to_be_bytes();
            self.stream[token_start + index * 2] = high;
            self.stream[token_start + index * 2 + 1] = low;
        }
        let [y_low, y_high] = (top as u16).to_le_bytes();
        let count = encoder.pixels.to_le_bytes();
        let token_count = (token_bytes as u16).to_le_bytes();
        let checkpoint = checkpoint_start.to_le_bytes();
        self.stream[start..token_start].copy_from_slice(&[
            OP_RASTER,
            left as u8,
            y_low,
            y_high,
            (right - left - 1) as u8,
            count[0],
            count[1],
            count[2],
            encoder.palette_len as u8,
            token_count[0],
            token_count[1],
            checkpoint[0],
            checkpoint[1],
        ]);
        self.stream_len = (encoder.write + palette_bytes) as u16;
        Ok(())
    }

    fn finalize_records(&mut self) -> Result<(), SceneError> {
        self.flush_pending()?;
        if self.records_valid {
            return Ok(());
        }
        self.band_first.fill(NO_RECORD);
        self.band_end.fill(0);
        let mut offset = 0;
        while offset < usize::from(self.stream_len) {
            let (rect, end) = self.record_bounds(offset);
            let first = usize::from(rect.y / BAND_H);
            let last = usize::from((rect.y + rect.h - 1) / BAND_H);
            for band in first..=last {
                if self.band_first[band] == NO_RECORD {
                    self.band_first[band] = offset as u16;
                }
                self.band_end[band] = end as u16;
            }
            offset = end;
        }
        self.records_valid = true;
        Ok(())
    }

    /// Flush the last sparse run and authenticate every damage tile in one scan.
    pub fn finalize(&mut self, key: DamageKey) -> Result<(), SceneError> {
        self.finalize_records()?;
        let mut tags: [SipHasher24; DAMAGE_TILES] = core::array::from_fn(|index| {
            let mut tag = SipHasher24::new_with_keys(key[0], key[1]);
            tag.write(DAMAGE_DOMAIN);
            tag.write(&(index as u16).to_le_bytes());
            tag
        });
        for row in 0..DAMAGE_ROWS {
            for column in 0..DAMAGE_COLS {
                let tile = damage_tile(column, row);
                tag_command(
                    &mut tags[row * DAMAGE_COLS + column],
                    OP_BACKGROUND,
                    tile,
                    self.background,
                );
            }
        }
        for command in self.commands() {
            let rect = command.rect;
            let first_column = usize::from(rect.x / DAMAGE_TILE);
            let last_column = usize::from((rect.x + rect.w - 1) / DAMAGE_TILE);
            let first_row = usize::from(rect.y / DAMAGE_TILE);
            let last_row = usize::from((rect.y + rect.h - 1) / DAMAGE_TILE);
            for row in first_row..=last_row {
                for column in first_column..=last_column {
                    let tile = damage_tile(column, row);
                    if let Some(hit) = intersection(rect, tile) {
                        tag_command(
                            &mut tags[row * DAMAGE_COLS + column],
                            command.opcode,
                            hit,
                            command.color,
                        );
                    }
                }
            }
        }
        for (out, tag) in self.tile_tags.iter_mut().zip(tags.iter()) {
            *out = tag.finish128().into();
        }
        self.tags_valid = true;
        Ok(())
    }

    fn record_bounds(&self, offset: usize) -> (Rect, usize) {
        let bytes = &self.stream[offset..usize::from(self.stream_len)];
        match bytes[0] {
            OP_SOLID => (decode_solid(bytes).rect, offset + SOLID_BYTES),
            OP_RASTER => {
                let width = u16::from(bytes[4]) + 1;
                let pixels = u32::from_le_bytes([bytes[5], bytes[6], bytes[7], 0]);
                let rows = pixels.div_ceil(u32::from(width)) as u16;
                let palette_bytes = usize::from(bytes[8]) * 2;
                let token_bytes = usize::from(u16::from_le_bytes([bytes[9], bytes[10]]));
                (
                    Rect::new(
                        u16::from(bytes[1]),
                        u16::from_le_bytes([bytes[2], bytes[3]]),
                        width,
                        rows,
                    ),
                    offset + RASTER_HEADER + palette_bytes + token_bytes,
                )
            }
            _ => unreachable!(),
        }
    }

    fn commands(&self) -> Commands<'_> {
        Commands {
            scene: self,
            offset: 0,
            raster: None,
            pending: self.pending,
        }
    }

    /// Replay a retained frame on a regular draw target.
    pub fn replay<D: DrawTarget<Color = Rgb565>>(&self, target: &mut D) -> Result<(), D::Error> {
        self.replay_rect(target, Rect::new(0, 0, PANEL_W, PANEL_H))
    }

    /// Replay only `rect`, restoring its scene background before its commands.
    pub fn replay_rect<D: DrawTarget<Color = Rgb565>>(
        &self,
        target: &mut D,
        rect: Rect,
    ) -> Result<(), D::Error> {
        let Some(rect) = intersection(rect, Rect::new(0, 0, PANEL_W, PANEL_H)) else {
            return Ok(());
        };
        target.fill_solid(&eg_rect(rect), self.background)?;
        for command in self.commands() {
            let Some(hit) = intersection(command.rect, rect) else {
                continue;
            };
            target.fill_solid(&eg_rect(hit), command.color)?;
        }
        Ok(())
    }

    fn record_damage_rects(
        &self,
        out: &mut [Rect; DAMAGE_RECT_CAPACITY],
    ) -> Result<usize, SceneError> {
        assert!(
            self.records_valid,
            "scene must be finalized before presentation"
        );
        let mut len = 0;
        let mut offset = 0;
        while offset < usize::from(self.stream_len) {
            let bytes = &self.stream[offset..usize::from(self.stream_len)];
            match bytes[0] {
                OP_SOLID => {
                    add_damage_rect(out, &mut len, decode_solid(bytes).rect)?;
                    offset += SOLID_BYTES;
                }
                OP_RASTER => {
                    let x = u16::from(bytes[1]);
                    let y = u16::from_le_bytes([bytes[2], bytes[3]]);
                    let width = u16::from(bytes[4]) + 1;
                    let pixels = u32::from_le_bytes([bytes[5], bytes[6], bytes[7], 0]);
                    let full_rows = (pixels / u32::from(width)) as u16;
                    let remainder = (pixels % u32::from(width)) as u16;
                    if full_rows != 0 {
                        add_damage_rect(out, &mut len, Rect::new(x, y, width, full_rows))?;
                    }
                    if remainder != 0 {
                        add_damage_rect(out, &mut len, Rect::new(x, y + full_rows, remainder, 1))?;
                    }
                    let palette_bytes = usize::from(bytes[8]) * 2;
                    let token_bytes = usize::from(u16::from_le_bytes([bytes[9], bytes[10]]));
                    offset += RASTER_HEADER + palette_bytes + token_bytes;
                }
                _ => unreachable!(),
            }
        }
        Ok(len)
    }

    /// Return the authenticated tag of one finalized damage tile.
    pub fn tile_tag(&self, column: usize, row: usize) -> DamageTag {
        assert!(
            self.tags_valid,
            "scene must be finalized before presentation"
        );
        self.tile_tags[row * DAMAGE_COLS + column]
    }

    /// Find changed tiles and join adjacent tiles into panel update rectangles.
    pub fn damage_rects(
        &self,
        previous: &[DamageTag; DAMAGE_TILES],
        previous_valid: bool,
        tags: &mut [DamageTag; DAMAGE_TILES],
        out: &mut [Rect; DAMAGE_TILES],
    ) -> usize {
        let mut dirty = [false; DAMAGE_TILES];
        for row in 0..DAMAGE_ROWS {
            for column in 0..DAMAGE_COLS {
                let index = row * DAMAGE_COLS + column;
                tags[index] = self.tile_tag(column, row);
                dirty[index] = !previous_valid || tags[index] != previous[index];
            }
        }

        let mut len = 0;
        for row in 0..DAMAGE_ROWS {
            let mut column = 0;
            while column < DAMAGE_COLS {
                if !dirty[row * DAMAGE_COLS + column] {
                    column += 1;
                    continue;
                }
                let start = column;
                while column < DAMAGE_COLS && dirty[row * DAMAGE_COLS + column] {
                    column += 1;
                }
                let x = start as u16 * DAMAGE_TILE;
                let y = row as u16 * DAMAGE_TILE;
                let width = ((column - start) as u16 * DAMAGE_TILE).min(PANEL_W - x);
                let height = DAMAGE_TILE.min(PANEL_H - y);
                if let Some(previous) = out[..len]
                    .iter_mut()
                    .find(|rect| rect.x == x && rect.w == width && rect.y + rect.h == y)
                {
                    previous.h += height;
                } else {
                    out[len] = Rect::new(x, y, width, height);
                    len += 1;
                }
            }
        }
        len
    }

    /// Compose one part of a damage rectangle directly as big-endian RGB565.
    pub fn raster_band(&self, rect: Rect, y: u16, height: u16, out: &mut [u8]) {
        assert!(
            self.records_valid,
            "scene must be finalized before presentation"
        );
        let band = Rect::new(rect.x, y, rect.w, height.min(rect.y + rect.h - y));
        let needed = usize::from(band.w) * usize::from(band.h) * 2;
        fill_color(&mut out[..needed], self.background);
        if band.w == 0 || band.h == 0 {
            return;
        }

        let first_band = usize::from(band.y / BAND_H);
        let last_band = usize::from((band.y + band.h - 1) / BAND_H);
        let mut first = NO_RECORD;
        let mut end = 0u16;
        for index in first_band..=last_band {
            if self.band_first[index] != NO_RECORD {
                first = first.min(self.band_first[index]);
                end = end.max(self.band_end[index]);
            }
        }
        if first == NO_RECORD {
            return;
        }

        let mut offset = usize::from(first);
        while offset < usize::from(end) {
            let bytes = &self.stream[offset..usize::from(self.stream_len)];
            match bytes[0] {
                OP_SOLID => {
                    paint_command(decode_solid(bytes), band, out);
                    offset += SOLID_BYTES;
                }
                OP_RASTER => {
                    offset = self.raster_record(offset, band, out);
                }
                _ => unreachable!(),
            }
        }
    }

    fn raster_record(&self, offset: usize, band: Rect, out: &mut [u8]) -> usize {
        let bytes = &self.stream[offset..usize::from(self.stream_len)];
        let x = u16::from(bytes[1]);
        let y = u16::from_le_bytes([bytes[2], bytes[3]]);
        let width = u16::from(bytes[4]) + 1;
        let pixels = u32::from_le_bytes([bytes[5], bytes[6], bytes[7], 0]);
        let palette_len = usize::from(bytes[8]);
        let token_bytes = usize::from(u16::from_le_bytes([bytes[9], bytes[10]]));
        let checkpoint_start = u16::from_le_bytes([bytes[11], bytes[12]]);
        let palette = offset + RASTER_HEADER;
        let token_start = palette + palette_len * 2;
        let end = token_start + token_bytes;
        let rows = pixels.div_ceil(u32::from(width)) as u16;
        let top = band.y.max(y);
        let bottom = (band.y + band.h).min(y + rows);
        if top >= bottom || x >= band.x + band.w || x + width <= band.x {
            return end;
        }

        let first_pixel = u32::from(top - y) * u32::from(width);
        let last_pixel = pixels.min(u32::from(bottom - y) * u32::from(width));
        let (mut token, mut position) =
            self.raster_seek(checkpoint_start, token_start, width, first_pixel);
        while token < end && position < last_pixel {
            let value = self.stream[token];
            token += 1;
            let palette_index = usize::from(value >> 3);
            let mut run = u16::from(value & 7) + 1;
            if value & 7 == RUN_SHORT_MAX as u8 {
                run += u16::from(self.stream[token]);
                token += 1;
            }
            let color = if palette_index == RASTER_PALETTE {
                let color = u16::from_be_bytes([self.stream[token], self.stream[token + 1]]);
                token += 2;
                color
            } else {
                u16::from_be_bytes([
                    self.stream[palette + palette_index * 2],
                    self.stream[palette + palette_index * 2 + 1],
                ])
            };
            let run_end = position + u32::from(run);
            let mut visible = position.max(first_pixel);
            let visible_end = run_end.min(last_pixel);
            while visible < visible_end {
                let column = (visible % u32::from(width)) as u16;
                let length = (visible_end - visible)
                    .min(u32::from(width - column))
                    .min(u32::from(u16::MAX)) as u16;
                paint_command(
                    Command {
                        opcode: OP_RASTER,
                        rect: Rect::new(
                            x + column,
                            y + (visible / u32::from(width)) as u16,
                            length,
                            1,
                        ),
                        color: RawU16::new(color).into(),
                    },
                    band,
                    out,
                );
                visible += u32::from(length);
            }
            position = run_end;
        }
        end
    }

    fn raster_seek(
        &self,
        checkpoint_start: u16,
        token_start: usize,
        width: u16,
        first_pixel: u32,
    ) -> (usize, u32) {
        let interval = u32::from(width) * u32::from(BAND_H);
        let checkpoint = first_pixel / interval;
        if checkpoint == 0 {
            return (token_start, 0);
        }
        let index = usize::from(checkpoint_start) + checkpoint as usize - 1;
        debug_assert!(index < usize::from(self.checkpoint_len));
        (
            token_start + usize::from(self.checkpoints[index]),
            checkpoint * interval,
        )
    }
}

fn decode_solid(bytes: &[u8]) -> Command {
    Command {
        opcode: OP_SOLID,
        rect: Rect::new(
            u16::from(bytes[1]),
            u16::from_le_bytes([bytes[2], bytes[3]]),
            u16::from(bytes[4]) + 1,
            u16::from_le_bytes([bytes[5], bytes[6]]) + 1,
        ),
        color: RawU16::new(u16::from_be_bytes([bytes[7], bytes[8]])).into(),
    }
}

fn paint_command(command: Command, band: Rect, out: &mut [u8]) {
    let Some(hit) = intersection(command.rect, band) else {
        return;
    };
    for py in hit.y..hit.y + hit.h {
        let row = usize::from(py - band.y) * usize::from(band.w);
        let start = (row + usize::from(hit.x - band.x)) * 2;
        let end = start + usize::from(hit.w) * 2;
        fill_color(&mut out[start..end], command.color);
    }
}

fn fill_color(out: &mut [u8], color: Rgb565) {
    if let Some(template) = crate::page_templates::row(color.into_storage()) {
        for chunk in out.chunks_mut(template.len()) {
            chunk.copy_from_slice(&template[..chunk.len()]);
        }
        return;
    }
    let bytes = color.into_storage().to_be_bytes();
    for pixel in out.as_chunks_mut::<2>().0 {
        pixel.copy_from_slice(&bytes);
    }
}

fn damage_tile(column: usize, row: usize) -> Rect {
    Rect::new(
        column as u16 * DAMAGE_TILE,
        row as u16 * DAMAGE_TILE,
        DAMAGE_TILE.min(PANEL_W - column as u16 * DAMAGE_TILE),
        DAMAGE_TILE.min(PANEL_H - row as u16 * DAMAGE_TILE),
    )
}

fn tag_command(tag: &mut SipHasher24, opcode: u8, hit: Rect, color: Rgb565) {
    let color = color.into_storage();
    tag.write(&[
        opcode,
        hit.x as u8,
        (hit.y & 0xff) as u8,
        (hit.y >> 8) as u8,
        hit.w as u8,
        hit.h as u8,
        (color >> 8) as u8,
        color as u8,
    ]);
}

struct Commands<'a> {
    scene: &'a Scene,
    offset: usize,
    raster: Option<RasterState>,
    pending: Option<PendingRun>,
}

impl Iterator for Commands<'_> {
    type Item = Command;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(mut raster) = self.raster.take() {
                if raster.run_left == 0 {
                    let token = self.scene.stream[raster.token];
                    raster.token += 1;
                    let palette_index = usize::from(token >> 3);
                    raster.run_left = u16::from(token & 7) + 1;
                    if token & 7 == RUN_SHORT_MAX as u8 {
                        raster.run_left += u16::from(self.scene.stream[raster.token]);
                        raster.token += 1;
                    }
                    if palette_index == RASTER_PALETTE {
                        raster.run_color = u16::from_be_bytes([
                            self.scene.stream[raster.token],
                            self.scene.stream[raster.token + 1],
                        ]);
                        raster.token += 2;
                    } else {
                        raster.run_color = u16::from_be_bytes([
                            self.scene.stream[raster.palette + palette_index * 2],
                            self.scene.stream[raster.palette + palette_index * 2 + 1],
                        ]);
                    }
                }
                let column = (raster.position % u32::from(raster.width)) as u16;
                let width = raster
                    .run_left
                    .min(raster.width - column)
                    .min(u16::try_from(raster.pixels).unwrap_or(u16::MAX));
                let command = Command {
                    opcode: OP_RASTER,
                    rect: Rect::new(
                        raster.x + column,
                        raster.y + (raster.position / u32::from(raster.width)) as u16,
                        width,
                        1,
                    ),
                    color: RawU16::new(raster.run_color).into(),
                };
                raster.position += u32::from(width);
                raster.pixels -= u32::from(width);
                raster.run_left -= width;
                if raster.pixels == 0 {
                    debug_assert_eq!(raster.run_left, 0);
                    debug_assert_eq!(raster.token, raster.end);
                    self.offset = raster.end;
                } else {
                    self.raster = Some(raster);
                }
                return Some(command);
            }

            if self.offset == usize::from(self.scene.stream_len) {
                return self.pending.take().map(PendingRun::command);
            }
            let bytes = &self.scene.stream[self.offset..usize::from(self.scene.stream_len)];
            match bytes[0] {
                OP_SOLID => {
                    self.offset += SOLID_BYTES;
                    return Some(decode_solid(bytes));
                }
                OP_RASTER => {
                    let palette_len = usize::from(bytes[8]);
                    let token_bytes = usize::from(u16::from_le_bytes([bytes[9], bytes[10]]));
                    let token = self.offset + RASTER_HEADER + palette_len * 2;
                    self.raster = Some(RasterState {
                        x: u16::from(bytes[1]),
                        y: u16::from_le_bytes([bytes[2], bytes[3]]),
                        width: u16::from(bytes[4]) + 1,
                        pixels: u32::from_le_bytes([bytes[5], bytes[6], bytes[7], 0]),
                        position: 0,
                        palette: self.offset + RASTER_HEADER,
                        token,
                        end: token + token_bytes,
                        run_color: 0,
                        run_left: 0,
                    });
                }
                _ => unreachable!(),
            }
        }
    }
}

fn intersection(a: Rect, b: Rect) -> Option<Rect> {
    let left = a.x.max(b.x);
    let top = a.y.max(b.y);
    let right = (a.x + a.w).min(b.x + b.w);
    let bottom = (a.y + a.h).min(b.y + b.h);
    (left < right && top < bottom).then(|| Rect::new(left, top, right - left, bottom - top))
}

fn eg_rect(rect: Rect) -> Rectangle {
    Rectangle::new(
        Point::new(i32::from(rect.x), i32::from(rect.y)),
        Size::new(u32::from(rect.w), u32::from(rect.h)),
    )
}

fn add_damage_rect(
    out: &mut [Rect; DAMAGE_RECT_CAPACITY],
    len: &mut usize,
    mut rect: Rect,
) -> Result<(), SceneError> {
    let mut index = 0;
    while index < *len {
        if let Some(joined) = rectangular_union(rect, out[index]) {
            rect = joined;
            *len -= 1;
            out[index] = out[*len];
            index = 0;
        } else {
            index += 1;
        }
    }
    if *len == out.len() {
        return Err(SceneError::Capacity);
    }
    out[*len] = rect;
    *len += 1;
    Ok(())
}

fn rectangular_union(a: Rect, b: Rect) -> Option<Rect> {
    let left = a.x.min(b.x);
    let top = a.y.min(b.y);
    let right = (a.x + a.w).max(b.x + b.w);
    let bottom = (a.y + a.h).max(b.y + b.h);
    let joined = Rect::new(left, top, right - left, bottom - top);
    let overlap = intersection(a, b)
        .map(|rect| u32::from(rect.w) * u32::from(rect.h))
        .unwrap_or(0);
    let area = u32::from(a.w) * u32::from(a.h) + u32::from(b.w) * u32::from(b.h) - overlap;
    (area == u32::from(joined.w) * u32::from(joined.h)).then_some(joined)
}

impl Dimensions for Scene {
    fn bounding_box(&self) -> Rectangle {
        Rectangle::new(Point::zero(), Size::new(PANEL_W.into(), PANEL_H.into()))
    }
}

impl DrawTarget for Scene {
    type Color = Rgb565;
    type Error = SceneError;

    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        pixels: I,
    ) -> Result<(), Self::Error> {
        for Pixel(point, color) in pixels {
            if point.x >= 0
                && point.y >= 0
                && point.x < i32::from(PANEL_W)
                && point.y < i32::from(PANEL_H)
            {
                self.push_pixel(point.x as u16, point.y as u16, color)?;
            }
        }
        Ok(())
    }

    fn fill_contiguous<I: IntoIterator<Item = Rgb565>>(
        &mut self,
        area: &Rectangle,
        colors: I,
    ) -> Result<(), Self::Error> {
        self.push_raster(area, colors)
    }

    fn fill_solid(&mut self, area: &Rectangle, color: Rgb565) -> Result<(), Self::Error> {
        self.flush_pending()?;
        let left = area.top_left.x.max(0).min(i32::from(PANEL_W));
        let top = area.top_left.y.max(0).min(i32::from(PANEL_H));
        let right = (area.top_left.x + area.size.width as i32)
            .max(0)
            .min(i32::from(PANEL_W));
        let bottom = (area.top_left.y + area.size.height as i32)
            .max(0)
            .min(i32::from(PANEL_H));
        if left < right && top < bottom {
            self.push_solid(
                Rect::new(
                    left as u16,
                    top as u16,
                    (right - left) as u16,
                    (bottom - top) as u16,
                ),
                color,
            )?;
        }
        Ok(())
    }

    fn clear(&mut self, color: Rgb565) -> Result<(), Self::Error> {
        self.check_error()?;
        self.pending = None;
        self.background = color;
        self.stream_len = 0;
        self.checkpoint_len = 0;
        self.command_count = 0;
        self.band_first.fill(NO_RECORD);
        self.band_end.fill(0);
        self.records_valid = false;
        self.tags_valid = false;
        Ok(())
    }
}

/// A panel that can present a completed retained frame.
pub trait FrameTarget: DrawTarget<Color = Rgb565> {
    /// Return the secret per-boot key used to authenticate damage tags.
    fn damage_key(&self) -> DamageKey;

    /// Present a finalized complete scene and report transport success.
    fn present_scene(&mut self, scene: &Scene) -> bool;

    /// Present finalized semantic damage and report transport success.
    fn present_damage(&mut self, scene: &Scene, rects: &[Rect]) -> bool
    where
        Self: Sized,
    {
        for rect in rects {
            if scene.replay_rect(self, *rect).is_err() {
                return false;
            }
        }
        true
    }
}

/// A draw target that records one frame and presents it when the value drops.
pub struct Frame<'a, P: FrameTarget> {
    panel: &'a mut P,
    scene: Scene,
}

impl<'a, P: FrameTarget> Frame<'a, P> {
    pub fn new(panel: &'a mut P) -> Self {
        Self {
            panel,
            scene: Scene::default(),
        }
    }
}

impl<P: FrameTarget> Drop for Frame<'_, P> {
    fn drop(&mut self) {
        let key = self.panel.damage_key();
        self.scene
            .finalize(key)
            .expect("retained scene capacity exceeded");
        assert!(
            self.panel.present_scene(&self.scene),
            "retained scene presentation failed"
        );
    }
}

impl<P: FrameTarget> Dimensions for Frame<'_, P> {
    fn bounding_box(&self) -> Rectangle {
        self.scene.bounding_box()
    }
}

impl<P: FrameTarget> DrawTarget for Frame<'_, P> {
    type Color = Rgb565;
    type Error = SceneError;

    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        pixels: I,
    ) -> Result<(), Self::Error> {
        self.scene.draw_iter(pixels)
    }

    fn fill_contiguous<I: IntoIterator<Item = Rgb565>>(
        &mut self,
        area: &Rectangle,
        colors: I,
    ) -> Result<(), Self::Error> {
        self.scene.fill_contiguous(area, colors)
    }

    fn fill_solid(&mut self, area: &Rectangle, color: Rgb565) -> Result<(), Self::Error> {
        self.scene.fill_solid(area, color)
    }

    fn clear(&mut self, color: Rgb565) -> Result<(), Self::Error> {
        self.scene.clear(color)
    }
}

/// A draw target that records one semantic repaint and presents its exact damage.
pub struct DamageFrame<'a, P: FrameTarget> {
    panel: &'a mut P,
    scene: Scene,
}

impl<'a, P: FrameTarget> DamageFrame<'a, P> {
    pub fn new(panel: &'a mut P) -> Self {
        let scene = Scene {
            background: crate::theme::PANEL_BG,
            ..Scene::default()
        };
        Self { panel, scene }
    }
}

impl<P: FrameTarget> Drop for DamageFrame<'_, P> {
    fn drop(&mut self) {
        self.scene
            .finalize_records()
            .expect("retained damage capacity exceeded");
        let mut rects = [Rect::new(0, 0, 0, 0); DAMAGE_RECT_CAPACITY];
        let len = self
            .scene
            .record_damage_rects(&mut rects)
            .expect("retained damage rectangle capacity exceeded");
        if len == 0 {
            return;
        }
        assert!(
            self.panel.present_damage(&self.scene, &rects[..len]),
            "retained damage presentation failed"
        );
    }
}

impl<P: FrameTarget> Dimensions for DamageFrame<'_, P> {
    fn bounding_box(&self) -> Rectangle {
        self.scene.bounding_box()
    }
}

impl<P: FrameTarget> DrawTarget for DamageFrame<'_, P> {
    type Color = Rgb565;
    type Error = SceneError;

    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        pixels: I,
    ) -> Result<(), Self::Error> {
        self.scene.draw_iter(pixels)
    }

    fn fill_contiguous<I: IntoIterator<Item = Rgb565>>(
        &mut self,
        area: &Rectangle,
        colors: I,
    ) -> Result<(), Self::Error> {
        self.scene.fill_contiguous(area, colors)
    }

    fn fill_solid(&mut self, area: &Rectangle, color: Rgb565) -> Result<(), Self::Error> {
        self.scene.fill_solid(area, color)
    }

    fn clear(&mut self, color: Rgb565) -> Result<(), Self::Error> {
        self.scene.clear(color)?;
        self.scene
            .push_solid(Rect::new(0, 0, PANEL_W, PANEL_H), color)
    }
}

#[cfg(test)]
#[path = "scene_tests.rs"]
mod tests;
