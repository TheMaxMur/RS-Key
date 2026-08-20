// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! This board's trusted display: the Waveshare RP2350-Touch-LCD-2.8 (ST7789 over
//! SPI1, CST328 touch over I2C1), plus the board verbs the flow asks for.
//!
//! The flow itself — which screen is shown when, the PIN pad, the Approve/Deny
//! wait — is [`rsk_display`], where a host can run it against a window. What is
//! here is the part that is genuinely this board's: bringing the panel and the
//! touch controller up, and the [`rsk_display::Hooks`] impl wiring the backlight
//! PWM, the wake button and the firmware's own globals back in.

use core::cell::RefCell;

use embassy_rp::gpio::{Input, Output};
use embassy_rp::i2c::{Blocking as I2cBlocking, I2c};
use embassy_rp::peripherals::{I2C1, SPI1};
use embassy_rp::pwm::{Config as PwmConfig, Pwm};
use embassy_rp::spi::{Blocking as SpiBlocking, Spi};
use embassy_time::{Delay, Duration, Instant, block_for};
use embedded_hal_bus::spi::ExclusiveDevice;

use mipidsi::interface::SpiInterface;
use mipidsi::models::ST7789;
use mipidsi::options::{ColorInversion, ColorOrder};
use mipidsi::{Builder, Display};

extern crate alloc;
use alloc::boxed::Box;

use rsk_display::{BL_TOP, TouchPad};
use rsk_rsa::RsaKey;

use crate::flash_storage::FlashStorage;
use crate::handler::{FidoRng, Store};

pub use rsk_display::{DeviceInfo, DeviceKeys, UI_YIELD_FLOOR_MS, piv_ref_title};

/// CST328 7-bit I2C address.
const CST328_ADDR: u16 = 0x1A;

/// The fully-built ST7789 panel (write-only, blocking SPI1, no framebuffer).
type Panel = Display<SpiInterface<'static, PanelSpi, Output<'static>>, ST7789, Output<'static>>;
/// The SPI bus + CS presented as one `SpiDevice` for mipidsi.
type PanelSpi = ExclusiveDevice<Spi<'static, SPI1, SpiBlocking>, Output<'static>, Delay>;

/// This board's instance of the flow.
pub type Ui = rsk_display::Ui<'static, Panel, Touch, DisplayHooks, FlashStorage, FidoRng>;
/// The on-screen presence backend over this board's panel.
pub type TouchPresence =
    rsk_display::TouchPresence<'static, Panel, Touch, DisplayHooks, FlashStorage, FidoRng>;

/// The panel's SPI bus + control pins + pixel buffer, bundled so `main` stays
/// within embassy's argument cap when it hands the peripherals over.
pub struct PanelHw {
    pub spi: Spi<'static, SPI1, SpiBlocking>,
    pub cs: Output<'static>,
    pub dc: Output<'static>,
    pub rst: Output<'static>,
    /// GPIO16 backlight, driven as PWM for brightness (constructed at zero duty so
    /// the panel stays dark through init — no white flash).
    pub bl: Pwm<'static>,
    pub buf: &'static mut [u8],
}

/// The CST328 touch controller's I2C bus + reset pin.
pub struct TouchHw {
    pub i2c: I2c<'static, I2C1, I2cBlocking>,
    pub rst: Output<'static>,
}

/// PWM config for the GPIO16 backlight: 8-bit `top`, non-inverted (high = lit), with
/// `duty` as the on-fraction. Shared by `main`'s initial (zero-duty) construction and
/// every live brightness change so the polarity always matches.
pub fn backlight_cfg(duty: u16) -> PwmConfig {
    // `PwmConfig` is `#[non_exhaustive]`, so build from Default and set fields.
    let mut cfg = PwmConfig::default();
    cfg.top = BL_TOP;
    cfg.compare_a = duty.min(BL_TOP);
    cfg
}

/// The CST328 touch controller on I2C1. Owns only the bus; the reset pin is pulsed
/// once during [`build`].
pub struct Touch {
    i2c: I2c<'static, I2C1, I2cBlocking>,
}

impl Touch {
    /// Leave normal reporting mode set after the reset pulse — write register
    /// 0xD109 (REG_MODE_NORMAL) as a 2-byte big-endian address with no payload.
    fn normal_mode(&mut self) {
        let _ = self.i2c.blocking_write(CST328_ADDR, &[0xD1, 0x09]);
    }
}

impl TouchPad for Touch {
    /// Read the first finger's coordinate, if any, then clear the report so the
    /// controller serves the next one. Any I2C error reads as "no touch". The
    /// coordinate is already in panel pixels (the controller is configured at the
    /// panel resolution; HW bringup confirmed the axes need no swap).
    fn read(&mut self) -> Option<rsk_ui::Point> {
        let mut buf = [0u8; 7];
        let pt = match self
            .i2c
            .blocking_write_read(CST328_ADDR, &[0xD0, 0x00], &mut buf)
        {
            Ok(()) => rsk_ui::touch::parse_cst328(&buf),
            Err(_) => None,
        };
        // Clear register 0xD005 (write address + a 0 byte) to ack the report.
        let _ = self.i2c.blocking_write(CST328_ADDR, &[0xD0, 0x05, 0x00]);
        pt
    }
}

/// The board verbs and firmware globals the flow reaches through.
pub struct DisplayHooks {
    /// Backlight on GPIO16, driven as PWM for brightness control and held for the
    /// device's lifetime (dropping it disconnects the pad → black panel).
    bl: Pwm<'static>,
    // The CST328 reset (GPIO17), held so its pad isn't disconnected on drop (an
    // embassy `Output` sets funcsel = Null when dropped); never toggled after build.
    #[allow(dead_code)]
    tp_rst: Output<'static>,
    /// The display-sleep wake button (the board's BAT_PWR / a `WAKE_PIN` GPIO) paired
    /// with its `active_high` polarity, or `None` when `WAKE_PIN=none` (touch-only
    /// wake). Polled while asleep.
    wake_btn: Option<(Input<'static>, bool)>,
}

impl rsk_display::Hooks for DisplayHooks {
    fn set_backlight(&mut self, duty: u16) {
        self.bl.set_config(&backlight_cfg(duty));
    }

    fn wake_pressed(&self) -> bool {
        match &self.wake_btn {
            Some((btn, active_high)) => {
                if *active_high {
                    btn.is_high()
                } else {
                    btn.is_low()
                }
            }
            None => false,
        }
    }

    fn led_status(&self) -> u8 {
        crate::led::status()
    }

    fn set_led_status(&mut self, status: u8) {
        crate::led::set_status(status);
    }

    fn attach_elapsed_ms(&self) -> u64 {
        crate::usb_attach::elapsed_ms()
    }

    fn host_request_pending_after(&self, since: Instant) -> bool {
        crate::worker::host_request_pending_after(since)
    }

    fn host_request_pending(&self) -> bool {
        crate::worker::host_request_pending()
    }

    fn request_reboot(&mut self, bootsel: bool) {
        crate::vendor::request_reboot(bootsel);
    }

    fn reboot_pending(&self) -> bool {
        crate::vendor::reboot_pending()
    }

    fn note_local_pin_changed(&mut self) {
        crate::handler::note_local_pin_changed();
    }

    /// The same worker signal, because its whole effect is what both events need:
    /// end the RAM `pinUvAuthToken` before the next CBOR command. They stay mapped
    /// together only while that holds — a re-key-*specific* side effect added
    /// there would then fire on a failed check too.
    fn note_local_pin_failed(&mut self) {
        crate::handler::note_local_pin_changed();
    }

    fn secure_boot_enabled(&self) -> bool {
        use rsk_rescue::Platform as _;
        // A pure OTP read (no flash / no shared borrow) — true only on a fused,
        // secure-boot device, where the boot ROM actually verifies the image
        // signature on next boot.
        crate::rescue_platform::RescuePlatform
            .secure_boot_status()
            .enabled
    }

    fn set_up_pending(&mut self, pending: bool) {
        crate::presence::set_up_pending(pending);
    }

    fn set_cancel_requested(&mut self, requested: bool) {
        crate::presence::set_cancel_requested(requested);
    }

    fn cancel_requested(&self) -> bool {
        crate::presence::cancel_requested()
    }

    fn presence_timeout_ms(&self) -> u32 {
        crate::presence::presence_timeout_ms()
    }

    fn set_presence_timeout_ms(&mut self, ms: u32) {
        crate::presence::set_presence_timeout_ms(ms);
    }

    fn rsa_search_progress(
        &mut self,
        nbits: usize,
        rng: &mut dyn rsk_openpgp::Rng,
        on_tick: &mut dyn FnMut(),
    ) -> Option<Box<RsaKey>> {
        crate::core1::run_rsa_search_progress(nbits, rng, on_tick)
    }
}

/// Build and initialize the panel + touch from the raw peripherals, then hand them
/// to the flow. Blocking (~200 ms of panel/touch reset) — `main` calls this *after*
/// the USB task is spawned, so the interrupt executor keeps enumerating while these
/// busy-waits run on the thread executor; enumeration is never delayed.
pub fn build(
    panel: PanelHw,
    touch: TouchHw,
    info: DeviceInfo,
    fs: &'static RefCell<Store>,
    keys: DeviceKeys,
    rng: &'static RefCell<FidoRng>,
    wake_btn: Option<(Input<'static>, bool)>,
) -> Ui {
    let PanelHw {
        spi,
        cs,
        dc,
        rst,
        bl,
        buf,
    } = panel;
    let TouchHw {
        i2c,
        rst: mut tp_rst,
    } = touch;

    // The panel is write-only, so the only way `ExclusiveDevice` errors is a
    // CS-toggle programming bug.
    let spi_dev = ExclusiveDevice::new(spi, cs, Delay).unwrap();
    let di = SpiInterface::new(spi_dev, dc, buf);

    // ST7789 240x320 portrait. Inversion and color order from board config.
    let invert = if crate::BUILD_DISPLAY_INVERT_COLORS {
        ColorInversion::Inverted
    } else {
        ColorInversion::Normal
    };
    let color_order = match crate::BUILD_DISPLAY_COLOR_ORDER {
        1 => ColorOrder::Bgr,
        _ => ColorOrder::Rgb,
    };
    let mut delay = Delay;
    let panel = Builder::new(ST7789, di)
        .display_size(rsk_ui::PANEL_W, rsk_ui::PANEL_H)
        .invert_colors(invert)
        .color_order(color_order)
        .reset_pin(rst)
        .init(&mut delay)
        .unwrap();

    // CST328 reset pulse (high → low → high), then normal reporting mode.
    tp_rst.set_high();
    block_for(Duration::from_millis(10));
    tp_rst.set_low();
    block_for(Duration::from_millis(10));
    tp_rst.set_high();
    block_for(Duration::from_millis(50));
    let mut touch = Touch { i2c };
    touch.normal_mode();

    let hooks = DisplayHooks {
        bl,
        tp_rst,
        wake_btn,
    };
    Ui::new(panel, touch, hooks, info, fs, keys, rng)
}

/// The ambient status screen. `#[embassy_executor::task]` cannot be generic, so
/// this monomorphic wrapper is what the spawner takes; the loop itself is
/// [`rsk_display::status_loop`].
#[embassy_executor::task]
pub async fn status_task(ui: &'static RefCell<Ui>) {
    rsk_display::status_loop(ui).await;
}
