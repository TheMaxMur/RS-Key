// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Raw ST7789 transport for retained frames and small direct redraws.

use core::convert::Infallible;

use embassy_futures::{block_on, poll_once};
use embassy_rp::dma::{Channel, ChannelInstance};
use embassy_rp::gpio::{Level, Output};
use embassy_rp::interrupt::typelevel::Binding;
use embassy_rp::peripherals::{DMA_CH0, PIO0};
use embassy_rp::pio::{
    Common, Config as PioConfig, Direction, FifoJoin, LoadedProgram, PioPin, ShiftDirection,
    StateMachine,
};
use embassy_rp::{Peri, dma};
use embassy_time::{Duration, block_for};
use embedded_graphics::{
    Pixel,
    draw_target::DrawTarget,
    geometry::{OriginDimensions, Point as EgPoint, Size},
    pixelcolor::{IntoStorage, Rgb565, RgbColor},
    primitives::Rectangle,
};
use mipidsi::options::{ColorInversion, ColorOrder};

const DIRECT_CHUNK_BYTES: usize = rsk_ui::PANEL_W as usize * 2;
const SOLID_CHUNK_BYTES: usize = DIRECT_CHUNK_BYTES * 2;
const PANEL_PIXEL_FORMAT_RGB565: u8 = 0x55;

/// TX-only mode-0 PIO transport. Two instructions generate one clock period.
pub(crate) struct PioDisplayTx {
    sm: StateMachine<'static, PIO0, 0>,
    dma: Channel<'static>,
    _program: LoadedProgram<'static, PIO0>,
}

impl PioDisplayTx {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        common: &mut Common<'static, PIO0>,
        mut sm: StateMachine<'static, PIO0, 0>,
        clk: Peri<'static, impl PioPin>,
        mosi: Peri<'static, impl PioPin>,
        dma: Peri<'static, DMA_CH0>,
        irq: impl Binding<<DMA_CH0 as ChannelInstance>::Interrupt, dma::InterruptHandler<DMA_CH0>>
        + 'static,
        frequency: u32,
    ) -> Self {
        let program = embassy_rp::pio::program::pio_asm!(
            ".side_set 1",
            ".wrap_target",
            "out pins, 1 side 0",
            "nop side 1",
            ".wrap",
        );
        let program = common.load_program(&program.program);
        let mut clk = common.make_pio_pin(clk);
        let mosi = common.make_pio_pin(mosi);
        clk.set_output_inversion(false);

        let mut config = PioConfig::default();
        config.use_program(&program, &[&clk]);
        config.set_out_pins(&[&mosi]);
        config.shift_out.auto_fill = true;
        config.shift_out.direction = ShiftDirection::Left;
        config.shift_out.threshold = 8;
        config.fifo_join = FifoJoin::TxOnly;
        // One bit per two instructions at divider 1, so the wire rate is clk_sys/2.
        // `BUILD_DISPLAY_SYS_CLOCK_HZ`'s const assert already refuses a board file
        // that breaks the ratio; this is the backstop for a second caller.
        assert_eq!(
            embassy_rp::clocks::clk_sys_freq(),
            frequency * 2,
            "the display PIO clocks at half clk_sys and sets no divider"
        );
        config.clock_divider = 1u8.into();
        sm.set_config(&config);
        sm.set_pins(Level::Low, &[&clk, &mosi]);
        sm.set_pin_dirs(Direction::Out, &[&clk, &mosi]);
        sm.set_enable(true);

        Self {
            sm,
            dma: Channel::new(dma, irq),
            _program: program,
        }
    }

    fn blocking_write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            let value = u32::from_be_bytes([*byte, 0, 0, 0]);
            while !self.sm.tx().try_push(value) {}
            // Clear an earlier empty-FIFO latch so flush observes this byte.
            self.sm.tx().stalled();
        }
        self.flush();
    }

    async fn write(&mut self, bytes: &[u8]) {
        // A gap between DMA bands can latch a stall before the final band.
        self.sm.tx().stalled();
        let mut dma = self.dma.reborrow();
        self.sm.tx().dma_push(&mut dma, bytes, false).await;
    }

    fn flush(&mut self) {
        while !self.sm.tx().empty() {}
        while !self.sm.tx().stalled() {}
    }
}

/// The write-only panel after initialization. Complete frames use retained
/// commands and two DMA bands; small animations use the raw direct path.
pub(crate) struct Panel {
    spi: PioDisplayTx,
    cs: Output<'static>,
    dc: Output<'static>,
    // Keep the panel out of reset. Dropping an embassy GPIO output disconnects it.
    _rst: Output<'static>,
    // GRAM window offset for partial-glass modules: the visible glass sits away
    // from the GRAM origin, so every CASET/RASET window is shifted by it (the
    // Waveshare GEEK demo uses 40/53 in landscape). 0 for a full-glass panel.
    win_off: (u16, u16),
    damage_key: rsk_ui::scene::DamageKey,
    tile_tags: [rsk_ui::scene::DamageTag; rsk_ui::scene::DAMAGE_TILES],
    tags_valid: bool,
}

impl OriginDimensions for Panel {
    fn size(&self) -> Size {
        Size::new(rsk_ui::PANEL_W.into(), rsk_ui::PANEL_H.into())
    }
}

impl Panel {
    // Panel construction needs all fixed hardware parts and display options.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        spi: PioDisplayTx,
        cs: Output<'static>,
        dc: Output<'static>,
        rst: Output<'static>,
        damage_key: rsk_ui::scene::DamageKey,
        invert: ColorInversion,
        color_order: ColorOrder,
        madctl_scan: u8,
        win_off: (u16, u16),
    ) -> Self {
        let mut panel = Self {
            spi,
            cs,
            dc,
            _rst: rst,
            win_off,
            damage_key,
            tile_tags: [0; rsk_ui::scene::DAMAGE_TILES],
            tags_valid: false,
        };
        // GRAM is blanked inside `reset_and_init`, before display-on — see
        // that function's note.
        panel.reset_and_init(invert, color_order, madctl_scan);
        panel
    }

    fn command(&mut self, command: u8, params: &[u8]) {
        self.cs.set_low();
        self.dc.set_low();
        self.spi.blocking_write(&[command]);
        if !params.is_empty() {
            self.dc.set_high();
            self.spi.blocking_write(params);
        }
        self.cs.set_high();
    }

    fn reset_and_init(&mut self, invert: ColorInversion, color_order: ColorOrder, madctl_scan: u8) {
        self._rst.set_low();
        block_for(Duration::from_micros(10));
        self._rst.set_high();
        block_for(Duration::from_millis(150));
        // MADCTL = the board's scan-direction bits (MY|MX|MV — 0 for the touch
        // build's portrait panel, 0x70 for the GEEK's landscape 1.14") plus the
        // BGR bit from the colour order.
        self.command(
            0x36,
            &[madctl_scan
                | if matches!(color_order, ColorOrder::Bgr) {
                    0x08
                } else {
                    0
                }],
        );
        // The remainder is the Waveshare ST7789V2 init register set: the porch /
        // gate / VCOM / gamma defaults that place a *partial* glass (240×135,
        // 135×240, …) on this controller's larger GRAM. Omitting them leaves the
        // panel's display window on the controller defaults, which misplace the
        // frame and clip it (measured on the RP2350-GEEK: content shifted and
        // cut at the top/left). The touch board's 240×320 glass shows these
        // settings' full-GRAM defaults the same either way.
        self.command(0x3A, &[PANEL_PIXEL_FORMAT_RGB565]);
        self.command(0xB2, &[0x0C, 0x0C, 0x00, 0x33, 0x33]); // porch control
        self.command(0xB7, &[0x35]); // gate control
        self.command(0xBB, &[0x19]); // VCOM setting
        self.command(0xC0, &[0x2C]); // LCM control
        self.command(0xC2, &[0x01]); // VDV and VRH command enable
        self.command(0xC3, &[0x12]); // VRH set
        self.command(0xC4, &[0x20]); // VDV set
        self.command(0xC6, &[0x0F]); // frame rate control
        self.command(0xD0, &[0xA4, 0xA1]); // power control 1
        self.command(
            0xE0,
            &[
                0xD0, 0x04, 0x0D, 0x11, 0x13, 0x2B, 0x3F, 0x54, 0x4C, 0x18, 0x0D, 0x0B, 0x1F, 0x23,
            ],
        ); // positive gamma
        self.command(
            0xE1,
            &[
                0xD0, 0x04, 0x0C, 0x11, 0x13, 0x2C, 0x3F, 0x44, 0x51, 0x2F, 0x1F, 0x1F, 0x20, 0x23,
            ],
        ); // negative gamma
        self.command(
            if matches!(invert, ColorInversion::Inverted) {
                0x21
            } else {
                0x20
            },
            &[],
        );
        self.command(0x11, &[]); // sleep out
        block_for(Duration::from_millis(120));
        // Blank GRAM while the display is still OFF: a freshly-powered GRAM
        // shows a random pattern the moment display-on lands, and no amount of
        // post-on clearing can hide that first frame. Written to black here,
        // the first on-frame is already clean (measured on the GEEK).
        let all = Rectangle::new(
            EgPoint::zero(),
            Size::new(rsk_ui::PANEL_W.into(), rsk_ui::PANEL_H.into()),
        );
        let _ = self.fill_solid(&all, Rgb565::BLACK);
        self.command(0x29, &[]); // display on
        block_for(Duration::from_millis(120));
    }

    fn begin_window(&mut self, rect: rsk_ui::Rect) {
        let (ox, oy) = self.win_off;
        let right = rect.x + rect.w - 1 + ox;
        let bottom = rect.y + rect.h - 1 + oy;
        let left = rect.x + ox;
        let top = rect.y + oy;
        self.cs.set_low();
        self.dc.set_low();
        self.spi.blocking_write(&[0x2A]);
        self.dc.set_high();
        self.spi.blocking_write(&[
            (left >> 8) as u8,
            left as u8,
            (right >> 8) as u8,
            right as u8,
        ]);
        self.dc.set_low();
        self.spi.blocking_write(&[0x2B]);
        self.dc.set_high();
        self.spi.blocking_write(&[
            (top >> 8) as u8,
            top as u8,
            (bottom >> 8) as u8,
            bottom as u8,
        ]);
        self.dc.set_low();
        self.spi.blocking_write(&[0x2C]);
        self.dc.set_high();
    }

    fn end_window(&mut self) {
        self.spi.flush();
        self.cs.set_high();
    }

    fn present_rect(&mut self, scene: &rsk_ui::scene::Scene, rect: rsk_ui::Rect) {
        let mut band_a = [0; rsk_ui::scene::BAND_BYTES];
        let mut band_b = [0; rsk_ui::scene::BAND_BYTES];
        let max_band_height = rsk_ui::scene::dma_band_height(rect.w);
        let mut height_a = max_band_height.min(rect.h);
        scene.raster_band(rect, rect.y, height_a, &mut band_a);
        self.begin_window(rect);
        let mut y = rect.y + height_a;

        loop {
            let len_a = usize::from(rect.w) * usize::from(height_a) * 2;
            let has_b = y < rect.y + rect.h;
            let height_b;
            {
                let future = self.spi.write(&band_a[..len_a]);
                let mut transfer = core::pin::pin!(future);
                let first = poll_once(transfer.as_mut());
                height_b = if has_b {
                    let height = max_band_height.min(rect.y + rect.h - y);
                    scene.raster_band(rect, y, height, &mut band_b);
                    height
                } else {
                    0
                };
                match first {
                    core::task::Poll::Ready(()) => {}
                    core::task::Poll::Pending => block_on(transfer.as_mut()),
                }
            }
            if !has_b {
                break;
            }
            y += height_b;

            let len_b = usize::from(rect.w) * usize::from(height_b) * 2;
            let has_a = y < rect.y + rect.h;
            let next_height_a;
            {
                let future = self.spi.write(&band_b[..len_b]);
                let mut transfer = core::pin::pin!(future);
                let first = poll_once(transfer.as_mut());
                next_height_a = if has_a {
                    let height = max_band_height.min(rect.y + rect.h - y);
                    scene.raster_band(rect, y, height, &mut band_a);
                    height
                } else {
                    0
                };
                match first {
                    core::task::Poll::Ready(()) => {}
                    core::task::Poll::Pending => block_on(transfer.as_mut()),
                }
            }
            if !has_a {
                break;
            }
            height_a = next_height_a;
            y += height_a;
        }

        self.end_window();
    }
}

impl rsk_ui::scene::FrameTarget for Panel {
    fn damage_key(&self) -> rsk_ui::scene::DamageKey {
        self.damage_key
    }

    fn present_scene(&mut self, scene: &rsk_ui::scene::Scene) -> bool {
        let previous_valid = self.tags_valid;
        self.tags_valid = false;
        let mut next_tags = [0; rsk_ui::scene::DAMAGE_TILES];
        let mut rects = [rsk_ui::Rect::new(0, 0, 0, 0); rsk_ui::scene::DAMAGE_TILES];
        let len = scene.damage_rects(&self.tile_tags, previous_valid, &mut next_tags, &mut rects);
        for rect in &rects[..len] {
            self.present_rect(scene, *rect);
        }
        self.tile_tags = next_tags;
        self.tags_valid = true;
        true
    }

    fn present_damage(&mut self, scene: &rsk_ui::scene::Scene, rects: &[rsk_ui::Rect]) -> bool {
        self.tags_valid = false;
        for rect in rects {
            self.present_rect(scene, *rect);
        }
        true
    }
}

impl DrawTarget for Panel {
    type Color = Rgb565;
    type Error = Infallible;

    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        pixels: I,
    ) -> Result<(), Self::Error> {
        self.tags_valid = false;
        let mut row = [0; DIRECT_CHUNK_BYTES];
        let mut start = EgPoint::zero();
        let mut previous = EgPoint::new(-2, -2);
        let mut used = 0;
        for Pixel(point, color) in pixels {
            if point.x < 0
                || point.y < 0
                || point.x >= i32::from(rsk_ui::PANEL_W)
                || point.y >= i32::from(rsk_ui::PANEL_H)
            {
                continue;
            }
            if used != 0 && (point.y != previous.y || point.x != previous.x + 1) {
                let rect = rsk_ui::Rect::new(start.x as u16, start.y as u16, used as u16 / 2, 1);
                self.begin_window(rect);
                block_on(self.spi.write(&row[..used]));
                self.end_window();
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
        if used != 0 {
            let rect = rsk_ui::Rect::new(start.x as u16, start.y as u16, used as u16 / 2, 1);
            self.begin_window(rect);
            block_on(self.spi.write(&row[..used]));
            self.end_window();
        }
        Ok(())
    }

    fn fill_contiguous<I: IntoIterator<Item = Rgb565>>(
        &mut self,
        area: &Rectangle,
        colors: I,
    ) -> Result<(), Self::Error> {
        self.tags_valid = false;
        let left = area.top_left.x.max(0).min(i32::from(rsk_ui::PANEL_W));
        let top = area.top_left.y.max(0).min(i32::from(rsk_ui::PANEL_H));
        let right = (area.top_left.x + area.size.width as i32)
            .max(0)
            .min(i32::from(rsk_ui::PANEL_W));
        let bottom = (area.top_left.y + area.size.height as i32)
            .max(0)
            .min(i32::from(rsk_ui::PANEL_H));
        if left >= right || top >= bottom {
            return Ok(());
        }
        let rect = rsk_ui::Rect::new(
            left as u16,
            top as u16,
            (right - left) as u16,
            (bottom - top) as u16,
        );
        let mut source = colors.into_iter();
        let mut ox = 0;
        let mut oy = 0;
        let mut source_done = false;
        let mut fill = |buffer: &mut [u8]| {
            let mut used = 0;
            while !source_done && oy < area.size.height && used + 2 <= buffer.len() {
                let Some(color) = source.next() else {
                    source_done = true;
                    break;
                };
                let x = area.top_left.x + ox as i32;
                let y = area.top_left.y + oy as i32;
                ox += 1;
                if ox == area.size.width {
                    ox = 0;
                    oy += 1;
                }
                if x < left || x >= right || y < top || y >= bottom {
                    continue;
                }
                let bytes = color.into_storage().to_be_bytes();
                buffer[used] = bytes[0];
                buffer[used + 1] = bytes[1];
                used += 2;
            }
            (used, source_done || oy == area.size.height)
        };

        let mut chunk_a = [0; DIRECT_CHUNK_BYTES];
        let (mut len_a, first_done) = fill(&mut chunk_a);
        if len_a == 0 {
            return Ok(());
        }
        self.begin_window(rect);
        if first_done {
            block_on(self.spi.write(&chunk_a[..len_a]));
            self.end_window();
            return Ok(());
        }
        let mut chunk_b = [0; DIRECT_CHUNK_BYTES];
        loop {
            let (len_b, done_b);
            {
                let future = self.spi.write(&chunk_a[..len_a]);
                let mut transfer = core::pin::pin!(future);
                let first = poll_once(transfer.as_mut());
                (len_b, done_b) = fill(&mut chunk_b);
                match first {
                    core::task::Poll::Ready(()) => {}
                    core::task::Poll::Pending => block_on(transfer.as_mut()),
                }
            }
            if len_b == 0 {
                break;
            }
            if done_b {
                block_on(self.spi.write(&chunk_b[..len_b]));
                break;
            }

            let (next_len_a, done_a);
            {
                let future = self.spi.write(&chunk_b[..len_b]);
                let mut transfer = core::pin::pin!(future);
                let first = poll_once(transfer.as_mut());
                (next_len_a, done_a) = fill(&mut chunk_a);
                match first {
                    core::task::Poll::Ready(()) => {}
                    core::task::Poll::Pending => block_on(transfer.as_mut()),
                }
            }
            if next_len_a == 0 {
                break;
            }
            if done_a {
                block_on(self.spi.write(&chunk_a[..next_len_a]));
                break;
            }
            len_a = next_len_a;
        }
        self.end_window();
        Ok(())
    }

    fn fill_solid(&mut self, area: &Rectangle, color: Rgb565) -> Result<(), Self::Error> {
        self.tags_valid = false;
        let left = area.top_left.x.max(0).min(i32::from(rsk_ui::PANEL_W));
        let top = area.top_left.y.max(0).min(i32::from(rsk_ui::PANEL_H));
        let right = (area.top_left.x + area.size.width as i32)
            .max(0)
            .min(i32::from(rsk_ui::PANEL_W));
        let bottom = (area.top_left.y + area.size.height as i32)
            .max(0)
            .min(i32::from(rsk_ui::PANEL_H));
        if left >= right || top >= bottom {
            return Ok(());
        }
        let rect = rsk_ui::Rect::new(
            left as u16,
            top as u16,
            (right - left) as u16,
            (bottom - top) as u16,
        );
        let bytes = color.into_storage().to_be_bytes();
        let mut chunk = [0; SOLID_CHUNK_BYTES];
        for pixel in chunk.as_chunks_mut::<2>().0 {
            pixel.copy_from_slice(&bytes);
        }
        self.begin_window(rect);
        let mut remaining = usize::from(rect.w) * usize::from(rect.h) * 2;
        while remaining != 0 {
            let len = remaining.min(chunk.len());
            block_on(self.spi.write(&chunk[..len]));
            remaining -= len;
        }
        self.end_window();
        Ok(())
    }
}
