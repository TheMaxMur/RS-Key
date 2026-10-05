// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The status-only panel: a 240×135 ST7789 LCD driven straight off the board's
//! hardware SPI, showing the device's own status (build, chip id, USB, uptime).
//!
//! This is NOT the trusted display. It has no touch controller, so it offers no
//! Approve/Deny and no on-panel PIN entry — user presence stays on the BOOTSEL
//! button and every ceremony the host runs is unchanged. The panel is a status
//! indicator in the place an addressable LED would otherwise sit, for boards
//! whose screen is a plain 1.14" SPI module (the reference is ALIENTEK's
//! RP2350A small-system board, whose panel is an ST7789V2 wired to SPI1).
//!
//! Everything drawn here is device-owned: the build counter, the chip serial, an
//! attach flag and uptime. No host-supplied string reaches this screen, so there
//! is nothing to sanitise and no `rsk_ui::Label` in the path.

use core::cell::RefCell;
use core::convert::Infallible;

use embassy_rp::gpio::Output;
use embassy_rp::peripherals::SPI1;
use embassy_rp::spi::{Blocking, Spi};
use embassy_time::{Duration, Instant, Timer, block_for};
use embedded_graphics::{
    Pixel,
    draw_target::DrawTarget,
    geometry::{Dimensions, Point as EgPoint, Size},
    pixelcolor::{IntoStorage, Rgb565},
    primitives::Rectangle,
};
use rsk_ui::font::{self, Role};
use rsk_ui::theme;

/// The 1.14" panel's visible area in landscape (MADCTL below swaps the axes).
const PANEL_W: u16 = 240;
/// The panel's height in landscape.
const PANEL_H: u16 = 135;
/// Column (CASET) offset: the 240-px axis is centred in the controller's 320-px
/// GRAM, 40 on each side. A vertical one-pixel bar at the far edge means this is
/// off by one on the *other* axis, not this one.
const COL_OFFSET: u16 = 40;
/// Row (RASET) offset: the 135-px axis fills 52+135+53 = 240 of the GRAM, so one
/// edge has 52 spare rows and the other 53. `53` matches the ALIENTEK demo; if
/// the image is shifted a row, this is the value to change to 52.
const ROW_OFFSET: u16 = 53;
/// MADCTL for landscape with the panel's native RGB order (`MV|MX|ML`), the
/// value ALIENTEK's own ST7789V2 initialisation uses.
const MADCTL: u8 = 0x70;
/// One full panel row of RGB565 pixels.
const ROW_BYTES: usize = PANEL_W as usize * 2;
/// Vertical centre of the subtitle / presence-banner band.
const PROMPT_Y: u16 = 50;
/// Height of that band. Kept clear of the title above (ends at y=37) and the
/// first value line below (starts at y=63), and it is the one band the presence
/// banner and the idle subtitle share, so neither ever leaves the other's pixels.
const PROMPT_BAND: u16 = 24;

/// The device facts the screen shows. `Copy`, no secrets: the build counter comes
/// from `main` and the chip id is the same serial the USB descriptor publishes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Info {
    pub version: u16,
    pub chipid: u64,
}

/// A rendered frame's inputs, so the loop repaints only on a change.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Status {
    version: u16,
    chipid: u64,
    usb: bool,
    uptime_s: u32,
}

/// The write-only ST7789 over hardware SPI. Blocking writes are fine here: the
/// screen repaints at most once a second, and a full frame is ~13 ms at 40 MHz.
pub struct Panel {
    spi: Spi<'static, SPI1, Blocking>,
    cs: Output<'static>,
    dc: Output<'static>,
    /// The backlight, driven and held at its ON level for the device's lifetime.
    /// Dropping an embassy `Output` disconnects the pad, so the field owns it.
    bl: Output<'static>,
}

impl Panel {
    /// Wake, initialise and paint the first frame, then light the backlight. The
    /// panel stays dark through init (the GPIO starts low), so there is no white
    /// flash before the first paint.
    pub fn new(
        spi: Spi<'static, SPI1, Blocking>,
        cs: Output<'static>,
        dc: Output<'static>,
        bl: Output<'static>,
        info: Info,
    ) -> Self {
        let mut panel = Self { spi, cs, dc, bl };
        panel.init();
        panel.paint(
            &Status {
                version: info.version,
                chipid: info.chipid,
                usb: false,
                uptime_s: 0,
            },
            None,
        );
        // The reference board switches the backlight with a PNP high-side
        // transistor (S8550: emitter to 3V3, base pulled up by R8, base driven
        // through R10 from this pin), so a LOW base is what lights it — `Level::High`
        // holds it dark through init and this releases it once the first frame is up,
        // so there is no white flash.
        panel.bl.set_low();
        panel
    }

    fn command(&mut self, cmd: u8, params: &[u8]) {
        self.cs.set_low();
        self.dc.set_low();
        let _ = self.spi.blocking_write(&[cmd]);
        if !params.is_empty() {
            self.dc.set_high();
            let _ = self.spi.blocking_write(params);
        }
        self.cs.set_high();
    }

    /// Open a RAM-write window in panel coordinates, adding the GRAM offsets. The
    /// caller streams exactly `w * h` pixels and then calls [`Self::end_window`].
    fn begin_window(&mut self, x: u16, y: u16, w: u16, h: u16) {
        let x0 = x + COL_OFFSET;
        let x1 = x0 + w - 1;
        let y0 = y + ROW_OFFSET;
        let y1 = y0 + h - 1;
        self.cs.set_low();
        self.dc.set_low();
        let _ = self.spi.blocking_write(&[0x2A]);
        self.dc.set_high();
        let _ = self
            .spi
            .blocking_write(&[(x0 >> 8) as u8, x0 as u8, (x1 >> 8) as u8, x1 as u8]);
        self.dc.set_low();
        let _ = self.spi.blocking_write(&[0x2B]);
        self.dc.set_high();
        let _ = self
            .spi
            .blocking_write(&[(y0 >> 8) as u8, y0 as u8, (y1 >> 8) as u8, y1 as u8]);
        self.dc.set_low();
        let _ = self.spi.blocking_write(&[0x2C]);
        self.dc.set_high();
    }

    fn end_window(&mut self) {
        self.cs.set_high();
    }

    /// Write one horizontal run of RGB565 pixels as a single one-row window.
    fn write_run(&mut self, start: EgPoint, used: usize, row: &[u8]) {
        if used == 0 {
            return;
        }
        self.begin_window(start.x as u16, start.y as u16, (used / 2) as u16, 1);
        let _ = self.spi.blocking_write(&row[..used]);
        self.end_window();
    }

    /// The ALIENTEK RP2350A panel's ST7789V2 sequence, verbatim (there is no GPIO
    /// reset on that board, so a software reset stands in), with inversion on.
    fn init(&mut self) {
        block_for(Duration::from_millis(120));
        self.command(0x01, &[]); // software reset
        block_for(Duration::from_millis(150));
        self.command(0x11, &[]); // sleep out
        block_for(Duration::from_millis(120));
        self.command(0x36, &[MADCTL]);
        self.command(0x3A, &[0x05]); // 16-bit RGB565
        self.command(0xB2, &[0x0C, 0x0C, 0x00, 0x33, 0x33]); // porch
        self.command(0xB7, &[0x35]); // gate control
        self.command(0xBB, &[0x19]); // VCOM
        self.command(0xC0, &[0x2C]); // power control 1
        self.command(0xC2, &[0x01]); // power control 2
        self.command(0xC3, &[0x12]); // power control 3
        self.command(0xC4, &[0x20]); // power control 4
        self.command(0xC6, &[0x01]); // VCOM control
        self.command(0xD0, &[0xA4, 0xA1]); // power control 5
        self.command(
            0xE0,
            &[
                0xD0, 0x04, 0x0D, 0x11, 0x13, 0x2B, 0x3F, 0x54, 0x4C, 0x18, 0x0D, 0x0B, 0x1F, 0x23,
            ],
        ); // gamma +
        self.command(
            0xE1,
            &[
                0xD0, 0x04, 0x0C, 0x11, 0x13, 0x2C, 0x3F, 0x44, 0x51, 0x2F, 0x1F, 0x1F, 0x20, 0x23,
            ],
        ); // gamma -
        self.command(0x21, &[]); // inversion on
        self.command(0x29, &[]); // display on
        block_for(Duration::from_millis(20));
    }

    /// Clear the whole panel to `color`.
    fn clear(&mut self, color: Rgb565) -> Result<(), Infallible> {
        self.fill_solid(
            &Rectangle::new(EgPoint::zero(), Size::new(PANEL_W.into(), PANEL_H.into())),
            color,
        )
    }

    /// Repaint one text line. Clearing the line's own row band first is what makes
    /// a redraw idempotent: `font::left` paints only the glyphs it places, so a
    /// shorter string would otherwise leave the tail of the old one behind.
    fn line(&mut self, text: &str, y: u16, band: u16, role: Role, color: Rgb565) {
        let top = y - band / 2;
        let _ = self.fill_solid(
            &Rectangle::new(
                EgPoint::new(0, top as i32),
                Size::new(PANEL_W.into(), band.into()),
            ),
            theme::BG,
        );
        let _ = font::left(
            self,
            text,
            EgPoint::new(12, y as i32),
            role,
            color,
            theme::BG,
        );
    }

    /// The subtitle / presence banner. One band, two faces: the idle caption, or —
    /// while the device is waiting for a button press — a filled bar asking for it.
    ///
    /// The banner says only *that* a press is wanted. It never renders anything from
    /// the applet's `Confirm`, so a relying party can't be painted here, and this
    /// panel stays what it is: an indicator in the LED's place, not a consent surface.
    fn prompt(&mut self, on: bool) {
        let (fill, text, role, fg) = if on {
            (theme::WARN, "PRESS THE KEY", Role::BodyStrong, theme::BG)
        } else {
            (theme::BG, "status panel", Role::MonoSmall, theme::MUTED)
        };
        let top = PROMPT_Y - PROMPT_BAND / 2;
        let _ = self.fill_solid(
            &Rectangle::new(
                EgPoint::new(0, top as i32),
                Size::new(PANEL_W.into(), PROMPT_BAND.into()),
            ),
            fill,
        );
        let _ = font::left(
            self,
            text,
            EgPoint::new(12, PROMPT_Y as i32),
            role,
            fg,
            fill,
        );
    }

    /// Repaint the screen for `st`, touching only the lines whose text changed. The
    /// idle key changes one field a second (the uptime), and rewriting one 240×14
    /// band is invisible where clearing the whole panel first reads as a blink.
    fn paint(&mut self, st: &Status, prev: Option<&Status>) {
        let full = prev.is_none_or(|p| p.version != st.version || p.chipid != st.chipid);
        if full {
            let _ = self.clear(theme::BG);
            self.line("RS-Key", 26, 22, Role::Heading, theme::TEXT);
            self.prompt(false);
            let mut line = Line::new();
            self.line(
                line.push_str("FW 0x")
                    .push_hex(u64::from(st.version), 4)
                    .as_str(),
                70,
                14,
                Role::Mono,
                theme::TEXT_2,
            );
            let mut line = Line::new();
            self.line(
                line.push_str("Chip ").push_hex(st.chipid, 16).as_str(),
                86,
                14,
                Role::Mono,
                theme::TEXT_2,
            );
        }
        if full || prev.is_none_or(|p| p.usb != st.usb) {
            let (usb, color) = if st.usb {
                ("USB connected", theme::SUCCESS)
            } else {
                ("USB idle", theme::MUTED)
            };
            self.line(usb, 110, 16, Role::BodyStrong, color);
        }
        if full || prev.is_none_or(|p| p.uptime_s != st.uptime_s) {
            let mut line = Line::new();
            self.line(
                line.push_str("Up ")
                    .push_u32(st.uptime_s)
                    .push_str("s")
                    .as_str(),
                126,
                14,
                Role::MonoSmall,
                theme::FAINT,
            );
        }
    }
}

impl Dimensions for Panel {
    fn bounding_box(&self) -> Rectangle {
        Rectangle::new(EgPoint::zero(), Size::new(PANEL_W.into(), PANEL_H.into()))
    }
}

impl DrawTarget for Panel {
    type Color = Rgb565;
    type Error = Infallible;

    /// Write pixel runs: the renderer's text path uses `fill_contiguous`, but a
    /// primitive that draws pixel-by-pixel lands here, so merge horizontal runs
    /// into single windows rather than opening one per pixel.
    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        pixels: I,
    ) -> Result<(), Self::Error> {
        let mut row = [0u8; ROW_BYTES];
        let mut start = EgPoint::zero();
        let mut previous = EgPoint::new(-2, -2);
        let mut used = 0usize;
        for Pixel(point, color) in pixels {
            if point.x < 0
                || point.y < 0
                || point.x >= i32::from(PANEL_W)
                || point.y >= i32::from(PANEL_H)
            {
                continue;
            }
            if used != 0 && (point.y != previous.y || point.x != previous.x + 1) {
                self.write_run(start, used, &row);
                used = 0;
            }
            if used == 0 {
                start = point;
            }
            let bytes = color.into_storage().to_be_bytes();
            row[used] = bytes[0];
            row[used + 1] = bytes[1];
            used += 2;
            previous = point;
        }
        self.write_run(start, used, &row);
        Ok(())
    }

    /// Blit a rectangle of colours, one window per visible row. The source is
    /// walked in `area` row-major order (the embedded-graphics contract) so a
    /// clipped area still consumes its colours in step.
    fn fill_contiguous<I: IntoIterator<Item = Rgb565>>(
        &mut self,
        area: &Rectangle,
        colors: I,
    ) -> Result<(), Self::Error> {
        let left = area.top_left.x.max(0);
        let top = area.top_left.y.max(0);
        let right = (area.top_left.x + area.size.width as i32).min(i32::from(PANEL_W));
        let bottom = (area.top_left.y + area.size.height as i32).min(i32::from(PANEL_H));
        if left >= right || top >= bottom {
            return Ok(());
        }
        let mut source = colors.into_iter();
        let mut row = [0u8; ROW_BYTES];
        for ay in 0..area.size.height as i32 {
            let y = area.top_left.y + ay;
            let mut used = 0usize;
            for ax in 0..area.size.width as i32 {
                let Some(color) = source.next() else { break };
                let x = area.top_left.x + ax;
                if x < left || x >= right || y < top || y >= bottom {
                    continue;
                }
                let bytes = color.into_storage().to_be_bytes();
                row[used] = bytes[0];
                row[used + 1] = bytes[1];
                used += 2;
            }
            if used != 0 {
                self.begin_window(left as u16, y as u16, (used / 2) as u16, 1);
                let _ = self.spi.blocking_write(&row[..used]);
                self.end_window();
            }
        }
        Ok(())
    }

    /// Fill a solid rectangle: one window, then the same row streamed per line.
    fn fill_solid(&mut self, area: &Rectangle, color: Rgb565) -> Result<(), Self::Error> {
        let left = area.top_left.x.max(0);
        let top = area.top_left.y.max(0);
        let right = (area.top_left.x + area.size.width as i32).min(i32::from(PANEL_W));
        let bottom = (area.top_left.y + area.size.height as i32).min(i32::from(PANEL_H));
        if left >= right || top >= bottom {
            return Ok(());
        }
        let bytes = color.into_storage().to_be_bytes();
        let mut row = [0u8; ROW_BYTES];
        for pixel in row.as_chunks_mut::<2>().0 {
            pixel.copy_from_slice(&bytes);
        }
        let width_bytes = (right - left) as usize * 2;
        self.begin_window(
            left as u16,
            top as u16,
            (right - left) as u16,
            (bottom - top) as u16,
        );
        for _ in 0..(bottom - top) {
            let _ = self.spi.blocking_write(&row[..width_bytes]);
        }
        self.end_window();
        Ok(())
    }
}

/// The ambient status screen. Repaints on any change, and only the line(s) that
/// changed: an idle key rewrites one 240×14 band a second for the uptime, so a
/// later value never reads as a blanked-then-redrawn screen.
#[embassy_executor::task]
pub async fn status_task(panel: &'static RefCell<Panel>, info: Info) {
    let mut last: Option<Status> = None;
    loop {
        let status = Status {
            version: info.version,
            chipid: info.chipid,
            usb: crate::usb_attach::elapsed_ms() > 0,
            uptime_s: (Instant::now().as_millis() / 1000) as u32,
        };
        if last.as_ref() != Some(&status) {
            panel.borrow_mut().paint(&status, last.as_ref());
            last = Some(status);
        }
        Timer::after_millis(500).await;
    }
}

/// The panel's presence backend: the button the key already uses, with a banner on
/// the screen for as long as the wait lasts.
///
/// The banner is drawn **from inside the wait**, not from [`status_task`], because
/// the wait blocks the thread executor: the status task cannot run while a press is
/// being asked for, so a prompt driven from the ambient loop would only ever appear
/// after the press it was asking for. Drawing here costs nothing else — the panel is
/// a status indicator, it shows no operation and no relying party, and
/// `shows_confirm` keeps its `false` default, so CTAP semantics (including the
/// `authenticatorReset` power-up window exemption) stay exactly a button key's.
pub struct PanelPresence {
    panel: &'static RefCell<Panel>,
    inner: crate::presence::ButtonPresence,
}

impl PanelPresence {
    pub fn new(panel: &'static RefCell<Panel>, inner: crate::presence::ButtonPresence) -> Self {
        Self { panel, inner }
    }

    /// One non-blocking sample, for the worker's typed-ticket button watcher.
    pub fn poll_pressed(&mut self) -> bool {
        self.inner.poll_pressed()
    }
}

impl rsk_sdk::UserPresence for PanelPresence {
    fn request(&mut self, confirm: rsk_sdk::Confirm<'_>) -> rsk_sdk::Presence {
        self.panel.borrow_mut().prompt(true);
        let result = self.inner.request(confirm);
        self.panel.borrow_mut().prompt(false);
        result
    }

    fn request_ceremony(&mut self, confirm: rsk_sdk::Confirm<'_>) -> rsk_sdk::Presence {
        self.panel.borrow_mut().prompt(true);
        let result = self.inner.request_ceremony(confirm);
        self.panel.borrow_mut().prompt(false);
        result
    }
}

/// A fixed-capacity text line, so the screen composes strings without a heap.
struct Line {
    buf: [u8; 40],
    len: usize,
}

impl Line {
    fn new() -> Self {
        Self {
            buf: [0; 40],
            len: 0,
        }
    }

    fn push_str(&mut self, s: &str) -> &mut Self {
        let bytes = s.as_bytes();
        let n = bytes.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
        self
    }

    fn push_hex(&mut self, value: u64, digits: usize) -> &mut Self {
        for i in (0..digits).rev() {
            let nibble = ((value >> (i * 4)) & 0xF) as u8;
            let ch = if nibble < 10 {
                b'0' + nibble
            } else {
                b'A' + nibble - 10
            };
            if self.len < self.buf.len() {
                self.buf[self.len] = ch;
                self.len += 1;
            }
        }
        self
    }

    fn push_u32(&mut self, mut value: u32) -> &mut Self {
        let mut digits = [0u8; 10];
        let mut n = 0;
        loop {
            digits[n] = b'0' + (value % 10) as u8;
            value /= 10;
            n += 1;
            if value == 0 {
                break;
            }
        }
        for i in (0..n).rev() {
            if self.len < self.buf.len() {
                self.buf[self.len] = digits[i];
                self.len += 1;
            }
        }
        self
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?")
    }
}
