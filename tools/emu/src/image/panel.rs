// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! ST7789 GRAM behind the board's PIO serial pins.

const CLK: u64 = 1 << 10;
const MOSI: u64 = 1 << 11;
const CS: u64 = 1 << 13;
const DC: u64 = 1 << 14;
const RESET: u64 = 1 << 15;
const SLPIN: u8 = 0x10;
const SLPOUT: u8 = 0x11;
const NORON: u8 = 0x13;
const INVOFF: u8 = 0x20;
const INVON: u8 = 0x21;
const DISPOFF: u8 = 0x28;
const DISPON: u8 = 0x29;
const CASET: u8 = 0x2A;
const RASET: u8 = 0x2B;
const RAMWR: u8 = 0x2C;
const MADCTL: u8 = 0x36;
const COLMOD: u8 = 0x3A;
const RGB565: u8 = 0x55;
const MV: u8 = 1 << 5;
const MX: u8 = 1 << 6;
const MY: u8 = 1 << 7;
pub const WIDTH: usize = 240;
pub const HEIGHT: usize = 320;

pub struct Panel {
    pub pixels: Vec<u16>,
    pub sleeping: bool,
    pub enabled: bool,
    pub inverted: bool,
    pub writes: u64,
    pub bytes: u64,
    previous: u64,
    bits: u8,
    shift: u8,
    command: u8,
    params: Vec<u8>,
    columns: (usize, usize),
    rows: (usize, usize),
    cursor: (usize, usize),
    high: Option<u8>,
    format: u8,
    madctl: u8,
    pub error: Option<String>,
}

impl Default for Panel {
    fn default() -> Self {
        Self {
            pixels: vec![0; WIDTH * HEIGHT],
            sleeping: true,
            enabled: false,
            inverted: false,
            writes: 0,
            bytes: 0,
            previous: 0,
            bits: 0,
            shift: 0,
            command: 0,
            params: Vec::new(),
            columns: (0, WIDTH - 1),
            rows: (0, HEIGHT - 1),
            cursor: (0, 0),
            high: None,
            format: 0,
            madctl: 0,
            error: None,
        }
    }
}

impl Panel {
    pub fn sample(&mut self, pins: u64) {
        if pins & RESET == 0 {
            if self.previous & RESET != 0 {
                *self = Self::default();
            }
        } else if pins & CS != 0 {
            self.bits = 0;
            self.shift = 0;
        } else if pins & CLK != 0 && self.previous & CLK == 0 {
            self.shift = (self.shift << 1) | u8::from(pins & MOSI != 0);
            self.bits += 1;
            if self.bits == 8 {
                self.byte(pins & DC != 0, self.shift);
                self.bits = 0;
                self.shift = 0;
            }
        }
        self.previous = pins;
    }

    fn byte(&mut self, data: bool, byte: u8) {
        if self.error.is_some() {
            return;
        }
        self.bytes += 1;
        if !data {
            let expected = match self.command {
                CASET | RASET => 4,
                MADCTL | COLMOD => 1,
                _ => 0,
            };
            if self.params.len() != expected || self.high.is_some() {
                self.error = Some("incomplete ST7789 command or pixel".into());
            }
            self.command = byte;
            self.params.clear();
            self.high = None;
            match byte {
                SLPIN => self.sleeping = true,
                SLPOUT => self.sleeping = false,
                INVOFF => self.inverted = false,
                INVON => self.inverted = true,
                DISPOFF => self.enabled = false,
                DISPON => self.enabled = true,
                RAMWR => self.cursor = (self.columns.0, self.rows.0),
                NORON | CASET | RASET | MADCTL | COLMOD => {}
                _ => self.error = Some(format!("unsupported ST7789 command {byte:#04x}")),
            }
            return;
        }
        if self.command != RAMWR {
            let expected = match self.command {
                MADCTL | COLMOD => 1,
                CASET | RASET => 4,
                _ => 0,
            };
            if self.params.len() >= expected {
                self.error = Some("excess ST7789 parameter".into());
                return;
            }
            self.params.push(byte);
        }
        match self.command {
            MADCTL => {
                self.madctl = byte;
                if byte & !(MV | MX | MY) != 0 {
                    self.error = Some("unsupported ST7789 scan/color order".into());
                }
            }
            COLMOD => self.format = byte,
            CASET | RASET => {
                if let Ok(bytes) = <&[u8; 4]>::try_from(self.params.as_slice()) {
                    let first = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
                    let last = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
                    let bound = match (self.command, self.madctl & MV != 0) {
                        (CASET, false) | (RASET, true) => WIDTH,
                        _ => HEIGHT,
                    };
                    if first > last || last >= bound {
                        self.error = Some("ST7789 window leaves the panel".into());
                        return;
                    }
                    if self.command == CASET {
                        self.columns = (first, last);
                    } else {
                        self.rows = (first, last);
                    }
                }
            }
            RAMWR => {
                if self.format != RGB565 {
                    self.error = Some("ST7789 pixel format is not RGB565".into());
                    return;
                }
                if let Some(high) = self.high.take() {
                    self.pixel(u16::from_be_bytes([high, byte]));
                } else {
                    self.high = Some(byte);
                }
            }
            _ => self.error = Some("unexpected ST7789 parameter".into()),
        }
    }

    fn pixel(&mut self, color: u16) {
        let (mut x, mut y) = self.cursor;
        if self.madctl & MV != 0 {
            core::mem::swap(&mut x, &mut y);
        }
        if x >= WIDTH || y >= HEIGHT || self.columns.0 > self.columns.1 || self.rows.0 > self.rows.1
        {
            self.error = Some("ST7789 window leaves the panel".into());
            return;
        }
        if self.madctl & MX != 0 {
            x = WIDTH - 1 - x;
        }
        if self.madctl & MY != 0 {
            y = HEIGHT - 1 - y;
        }
        self.pixels[y * WIDTH + x] = color;
        self.writes += 1;
        if self.cursor.0 < self.columns.1 {
            self.cursor.0 += 1;
        } else {
            self.cursor.0 = self.columns.0;
            self.cursor.1 = if self.cursor.1 < self.rows.1 {
                self.cursor.1 + 1
            } else {
                self.rows.0
            };
        }
    }

    pub fn status(&self) -> String {
        format!(
            "width={WIDTH} height={HEIGHT} sleeping={} enabled={} inverted={} madctl={} writes={} bytes={}",
            self.sleeping, self.enabled, self.inverted, self.madctl, self.writes, self.bytes
        )
    }

    pub fn read(&self) -> String {
        use std::fmt::Write;
        let mut output = String::with_capacity(WIDTH * HEIGHT * 4);
        for pixel in &self.pixels {
            write!(output, "{pixel:04x}").unwrap();
        }
        output
    }
}

#[cfg(test)]
#[path = "panel_tests.rs"]
mod tests;
