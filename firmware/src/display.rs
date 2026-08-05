// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The trusted-display backend for the `display` build: it drives the Waveshare
//! RP2350-Touch-LCD-2.8 (ST7789 over SPI1, CST328 touch over I2C1) and is the
//! `display` build's [`crate::presence::Presence`]. Two roles share one panel:
//!
//! * [`status_task`] mirrors the device status the onboard LED would show (boot /
//!   idle / working), repainting on change — the ambient screen.
//! * [`TouchPresence`] renders the trusted Approve/Deny prompt when an applet asks
//!   for user presence, naming the operation and the *real* relying party, and
//!   block-waits an on-screen tap. A tap on **Allow** confirms; a tap on **Deny**
//!   is a genuine `Declined` (→ `OPERATION_DENIED`) — the BOOTSEL button has no
//!   such gesture. This is the anti-WebUSB-phishing guarantee: a signature can't
//!   be obtained without a physical tap on a screen showing the true rp.
//!
//! The *what to draw*, the untrusted-string sanitizing, the Allow/Deny button
//! geometry and the touch-report parse all live in `rsk-ui` (host-tested + Kani);
//! this file is the thin HAL glue plus the cross-executor wait.
//!
//! Both roles run on the THREAD executor and share the panel through a `'static`
//! `RefCell<Ui>`. They never race for it: `TouchPresence::request` is *synchronous*
//! (the applet call chain is), so while it block-waits a tap the thread executor is
//! occupied and `status_task` cannot run — exactly like the BOOTSEL wait. USB on
//! the interrupt executor preempts the busy-wait throughout, so keepalives keep
//! flowing and a full-frame repaint never stalls enumeration.

use core::cell::RefCell;
use core::sync::atomic::{AtomicU32, Ordering};

use embassy_rp::gpio::{Input, Output};
use embassy_rp::i2c::{Blocking as I2cBlocking, I2c};
use embassy_rp::peripherals::{I2C1, SPI1};
use embassy_rp::pwm::{Config as PwmConfig, Pwm};
use embassy_rp::spi::{Blocking as SpiBlocking, Spi};
use embassy_time::{Delay, Duration, Instant, Timer, block_for};
use embedded_graphics::{
    Pixel,
    draw_target::DrawTarget,
    geometry::{Dimensions, Point as EgPoint, Size},
    pixelcolor::Rgb565,
    prelude::RgbColor,
    primitives::Rectangle,
};
use embedded_hal_bus::spi::ExclusiveDevice;
use zeroize::Zeroize;

use mipidsi::interface::SpiInterface;
use mipidsi::models::ST7789;
use mipidsi::options::{ColorInversion, ColorOrder};
use mipidsi::{Builder, Display};
use rsk_crypto::Device;
use rsk_sdk::Confirm;
use rsk_ui::{
    ALLOW_RECT, AccountRow, AdjustKey, AppEntry, AuditRow, BRIGHTNESS_LEVELS, BackupView, Button,
    ConfirmPrompt, DisplayEntry, HomeView, Label, NavTab, PinCaption, PinKey, PinPad, RootEntry,
    RpRow, Screen, SecurityEntry, SettingsPage, SettingsView, StatusKind, SuccessKind,
};

use crate::handler::{FidoRng, Store};
use crate::led;
use crate::presence::{CANCEL_REQUESTED, PRESENCE_TIMEOUT_MS, UP_PENDING};

mod applets;
mod backup;
mod gates;
mod pin;
mod power;
mod presence;
mod settings;
mod status;
mod touch;

pub(crate) use gates::piv_ref_title;
pub use presence::TouchPresence;
pub use status::status_task;

use settings::EF_DISPLAY;
use touch::Touch;

/// Touch poll cadence during a confirm wait; `block_for` keeps interrupts on, so
/// the high-priority USB executor runs between polls (mirrors the BOOTSEL wait).
const TOUCH_POLL_MS: u64 = 16;
/// Status-spinner arc step per ~100ms status-loop tick (≈1.5s per revolution — the
/// design's ~1.4s request spinner).
const SPIN_STEP_DEG: i32 = 24;

/// Until this ms-since-boot the ambient status loop must not repaint. A modal
/// (PIN pad / Approve-Deny) sets it on exit so a back-to-back hand-off — pad →
/// confirm during one UV ceremony — doesn't flash the idle/working screen in the
/// brief host round-trip gap between the two. After the window the ambient screen
/// repaints as usual (returning to idle).
static AMBIENT_QUIET_UNTIL_MS: AtomicU32 = AtomicU32::new(0);
/// How long to hold the ambient screen back after a modal ends — long enough to
/// cover the platform's next-command round-trip, short enough to feel immediate.
const AMBIENT_QUIET_MS: u32 = 400;

/// Auto-close an open on-device tab / menu (Passkeys / Settings / a Confirm-Delete)
/// after this long *without a tap*, returning to the idle status screen — a privacy
/// backstop so a walked-away device doesn't leave the passkey list (or a menu) on
/// screen indefinitely. It is **not** the host-starvation guard: while a tab is open
/// the worker is parked (single thread executor), but the browse loops poll
/// [`crate::worker::host_request_pending`] and yield the instant a host command
/// arrives, so this bound can be generous (a comfortable browse) without making the
/// host wait for it.
const MENU_INACTIVITY_MS: u64 = 60_000;

/// Minimum time an on-device modal that yields to the host stays open before a queued
/// host command may close it. `REQ` latches until the worker drains it, and the worker
/// cannot run while a modal busy-waits, so without a floor a single queued command shuts
/// the modal on its first poll — and a host repeating any ungated command (getInfo will
/// do) could keep the owner's unlock pad shut indefinitely. The host is receiving
/// keepalives throughout, so a couple of seconds costs it nothing.
const UI_YIELD_FLOOR_MS: u64 = 2_500;

/// How long the user must hold the on-screen approve button before it confirms — long
/// enough that an accidental brush can't approve, short enough to feel responsive. The
/// button fills as the hold builds, and lifting the finger early resets it.
const HOLD_MS: u64 = 800;

/// Auto-dismiss dwell for a success "pop" with no Done button (see [`Ui::show_success`]).
const SUCCESS_POP_MS: u64 = 1100;

/// PIN-title marquee: hold the head of an overflowing title visible this long, then scroll
/// one pixel per [`MARQUEE_MS_PER_PX`] ms (≈45 px/s) so a long title like "OpenPGP Sign
/// PIN" reads in full without colliding with the back chevron.
const MARQUEE_PAUSE_MS: u64 = 800;
const MARQUEE_MS_PER_PX: u64 = 22;
/// Bytes for the 1-bit off-screen mask the marquee composites into (one bit per band
/// pixel: set = title glyph, clear = background). The whole band then blits in a single
/// `fill_contiguous` transaction, so the panel never shows the cleared-then-redrawn flash
/// that a direct per-frame clear+draw produces (the reported flicker).
const MARQUEE_MASK_BYTES: usize =
    (rsk_ui::PIN_TITLE_BAND.w as usize * rsk_ui::PIN_TITLE_BAND.h as usize).div_ceil(8);

/// Backlight PWM `top` (8-bit, like the LED): a brightness level maps to a compare
/// value `0..=BL_TOP`.
const BL_TOP: u16 = 255;

/// Built-in display-sleep timeout (ms), derived from the EF_DISPLAY codec's
/// [`rsk_ui::settings_store::DEFAULT_SLEEP_SECS`]. Runtime-adjustable from the Settings
/// → Display sleep page ([`SLEEP_TIMEOUT_MS`]); `0` there means never sleep.
const DEFAULT_SLEEP_MS: u32 = rsk_ui::settings_store::DEFAULT_SLEEP_SECS as u32 * 1000;
/// Display-sleep timeout in ms, edited live by the menu. `0` = Off (never blanks).
/// Read each tick by the ambient loop; reboot reseeds the default.
static SLEEP_TIMEOUT_MS: AtomicU32 = AtomicU32::new(DEFAULT_SLEEP_MS);

/// ms-since-boot of the last user interaction (touch / wake button) or host ceremony —
/// the display-sleep countdown is measured from here. Bumped by [`note_activity`].
static LAST_ACTIVITY_MS: AtomicU32 = AtomicU32::new(0);

/// ms-since-boot of the last **local** interaction — a touch or the wake button. The
/// auto-lock measures from here, never from [`LAST_ACTIVITY_MS`]: a host ceremony must
/// keep the backlight awake (a long approve prompt must not blank mid-read) but must
/// not postpone the lock, or a loop of ungated presence requests holds the panel
/// unlocked for the whole plugged-in session.
static LAST_LOCAL_MS: AtomicU32 = AtomicU32::new(0);

/// Mark "the user (or host) just did something", resetting the display-sleep countdown.
fn note_activity() {
    LAST_ACTIVITY_MS.store(Instant::now().as_millis() as u32, Ordering::Relaxed);
}

/// Mark a *local* interaction: resets both the sleep countdown and the auto-lock one.
fn note_local_activity() {
    let now = Instant::now().as_millis() as u32;
    LAST_ACTIVITY_MS.store(now, Ordering::Relaxed);
    LAST_LOCAL_MS.store(now, Ordering::Relaxed);
}

/// Device identity shown read-only on the settings Firmware screen + its list row.
pub struct DeviceInfo {
    /// bcdDevice firmware build counter.
    pub version: u16,
    /// RP2350 chip serial (chipid).
    pub chipid: u64,
}

/// The device key material the read-only passkey enumerator needs to load and unbox
/// the resident-credential seed from `EF_KEY_DEV` — the same identity the worker's
/// `Ctx` carries, kept as owned copies so the display task can build a [`Device`] on
/// demand (when the Passkeys tab is open) without holding the seed itself.
pub struct DeviceKeys {
    pub serial_id: [u8; 8],
    pub serial_hash: [u8; 32],
    pub otp_mkek: Option<[u8; 32]>,
}

impl DeviceKeys {
    fn device(&self) -> Device<'_> {
        Device {
            serial_hash: &self.serial_hash,
            serial_id: &self.serial_id,
            otp_key: self.otp_mkek.as_ref(),
        }
    }
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

/// Map a brightness level (`1..=BRIGHTNESS_LEVELS`) to a backlight duty (compare).
fn level_duty(level: u8) -> u16 {
    let l = level.clamp(1, BRIGHTNESS_LEVELS) as u16;
    (l * BL_TOP) / BRIGHTNESS_LEVELS as u16
}

/// The fully-built ST7789 panel (write-only, blocking SPI1, no framebuffer).
type Panel = Display<SpiInterface<'static, PanelSpi, Output<'static>>, ST7789, Output<'static>>;
/// The SPI bus + CS presented as one `SpiDevice` for mipidsi.
type PanelSpi = ExclusiveDevice<Spi<'static, SPI1, SpiBlocking>, Output<'static>, Delay>;

/// A 1-bit off-screen `DrawTarget` over the PIN title band: rsk-ui's `render_pin_title`
/// composites into it (one bit per band pixel — set = a title glyph, clear = background),
/// then the firmware blits the whole band in a single `fill_contiguous`. Because our text
/// is 1-bit (no anti-aliasing) the band is exactly two colours, so a mask captures it
/// losslessly, and the single-transaction blit removes the per-frame clear→draw flash that
/// made the marquee flicker. Coordinates are absolute (panel space) so the generic
/// `render_pin_title` — which draws at the band's real position — lands correctly.
struct BandMask<'a> {
    bits: &'a mut [u8],
    band: Rectangle,
}

impl<'a> BandMask<'a> {
    fn new(bits: &'a mut [u8], band: rsk_ui::Rect) -> Self {
        bits.fill(0);
        Self {
            bits,
            band: Rectangle::new(
                EgPoint::new(band.x as i32, band.y as i32),
                Size::new(band.w as u32, band.h as u32),
            ),
        }
    }
}

impl Dimensions for BandMask<'_> {
    fn bounding_box(&self) -> Rectangle {
        self.band
    }
}

impl DrawTarget for BandMask<'_> {
    type Color = Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        pixels: I,
    ) -> Result<(), Self::Error> {
        let w = self.band.size.width as i32;
        for Pixel(p, c) in pixels {
            let x = p.x - self.band.top_left.x;
            let y = p.y - self.band.top_left.y;
            if x >= 0 && y >= 0 && x < w && (y as u32) < self.band.size.height {
                let idx = y as usize * w as usize + x as usize;
                // The only colours drawn are the background fill and the FG glyph; any
                // non-background pixel is a glyph → set its bit.
                if c != rsk_ui::theme::PANEL_BG {
                    self.bits[idx >> 3] |= 1 << (idx & 7);
                } else {
                    self.bits[idx >> 3] &= !(1 << (idx & 7));
                }
            }
        }
        Ok(())
    }
}

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

/// Panel + touch + the last-painted screen, owned behind a `'static` `RefCell`
/// shared by [`status_task`] and [`TouchPresence`].
pub struct Ui {
    panel: Panel,
    touch: Touch,
    /// Backlight on GPIO16, driven as PWM for brightness control and held for the
    /// device's lifetime (dropping it disconnects the pad → black panel).
    bl: Pwm<'static>,
    // The CST328 reset (GPIO17), held so its pad isn't disconnected on drop (an
    // embassy `Output` sets funcsel = Null when dropped); never toggled after build.
    #[allow(dead_code)]
    tp_rst: Output<'static>,
    /// What is currently on screen, so the status loop only repaints on a change.
    shown: Option<Screen>,
    /// Whether the panel has been seen *untouched* since the current ambient screen
    /// was painted, so the next contact is a deliberate tap on what is now shown.
    /// The CST328 reports level, not edges: without this, a finger still down when a
    /// screen appears is read as a tap on it the same tick. That let the 800 ms hold
    /// approving a host ceremony — or a wake press held past the bounded release
    /// wait — land on `Screen::Onboard`, whose full-width "Continue without PIN"
    /// button covers the exact coordinates of the ceremony's Deny/Allow band, and
    /// silently consume a fresh device's one-time PIN offer (audit run-33). Every
    /// modal flow already debounces on *entry*; this is the ambient screens' end.
    touch_armed: bool,
    /// Read-only identity shown on the settings Firmware screen.
    info: DeviceInfo,
    /// Current backlight level (`1..=BRIGHTNESS_LEVELS`), edited from the menu.
    brightness: u8,
    /// Whether the panel is blanked (backlight off + cleared) by the display-sleep
    /// timeout. A touch or the wake button restores it; a host ceremony wakes it too.
    asleep: bool,
    /// The display-sleep wake button (the board's BAT_PWR / a `WAKE_PIN` GPIO) paired
    /// with its `active_high` polarity, or `None` when `WAKE_PIN=none` (touch-only
    /// wake). Polled while asleep.
    wake_btn: Option<(Input<'static>, bool)>,
    /// Whether the on-device UI is locked (passkeys browser + settings need the device
    /// PIN to reopen). Set at boot or on auto-sleep — both only when a PIN is set; cleared
    /// by a correct on-screen PIN. Gates only the panel UI — host CTAP ceremonies (confirm
    /// / built-in-UV) are unaffected and paint their own prompts over it.
    locked: bool,
    /// The first-run onboarding prompt is active: a fresh, PIN-less device that hasn't yet
    /// offered (and had dismissed) the "set a device PIN?" screen. While set, the idle loop
    /// shows [`Screen::Onboard`] instead of Home and a tap routes to [`Ui::run_onboarding`];
    /// cleared once the user sets a PIN or chooses to continue without one. Mutually
    /// exclusive with `locked` (onboarding only exists when no device PIN is set).
    onboarding: bool,
    /// The persisted "continue without a device PIN" choice ([`rsk_ui::DisplayConfig`]'s
    /// `pin_declined`), held so every `EF_DISPLAY` write preserves it. Set true (and flushed)
    /// when the user dismisses onboarding; a factory reset wipes the record back to false.
    pin_declined: bool,
    /// The shared flash store — the same `RefCell` the worker uses. The Passkeys tab
    /// borrows it to enumerate resident credentials; safe because the worker is parked
    /// (it never holds the borrow across an `.await`) while this thread-executor task
    /// runs.
    fs: &'static RefCell<Store>,
    /// Device identity for unboxing the resident-credential seed on demand.
    keys: DeviceKeys,
    /// The shared DRBG — the same `RefCell` the worker uses. Borrowed only to draw the
    /// randomness an on-device SLIP-39 split needs (the share identifier + Shamir random
    /// shares); the worker is parked while this thread-executor task runs, so no race.
    rng: &'static RefCell<FidoRng>,
    /// 1-bit scratch for the flicker-free PIN-title marquee blit ([`BandMask`]).
    marquee_mask: [u8; MARQUEE_MASK_BYTES],
    /// Cached Home status-card facts (device-PIN-set + resident passkey count), refreshed
    /// by [`Ui::refresh_home_stats`] only at modal boundaries — boot, wake, a closed tab
    /// modal — so the idle Home frame never triggers a per-paint flash enumeration.
    home_pin_set: bool,
    home_passkeys: u16,
}

impl Ui {
    /// Build and initialize the panel + touch from the raw peripherals, show the
    /// boot splash and raise the backlight, and put the CST328 into normal mode.
    /// Blocking (~200 ms of panel/touch reset) — `main` calls this *after* the USB
    /// task is spawned, so the interrupt executor keeps enumerating while these
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
            mut bl,
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
        let mut panel = Builder::new(ST7789, di)
            .display_size(rsk_ui::PANEL_W, rsk_ui::PANEL_H)
            .invert_colors(invert)
            .color_order(color_order)
            .reset_pin(rst)
            .init(&mut delay)
            .unwrap();

        let _ = rsk_ui::render(&mut panel, &Screen::Splash);

        // Restore the persisted display settings before lighting the panel, so it
        // comes up at the saved brightness (no full-bright flash then dim) and the
        // saved sleep timeout. Absent (fresh device) keeps the live defaults.
        let mut dcfg = rsk_ui::DisplayConfig::default();
        {
            let mut buf = [0u8; rsk_ui::DISPLAY_CONF_LEN];
            if let Some(n) = fs.borrow_mut().read(EF_DISPLAY, &mut buf) {
                dcfg.apply_block(&buf[..n.min(buf.len())]);
            }
        }
        SLEEP_TIMEOUT_MS.store(dcfg.sleep_secs as u32 * 1000, Ordering::Relaxed);
        let brightness = dcfg.brightness.clamp(1, BRIGHTNESS_LEVELS);

        // Backlight up to the saved level only now there is something to show (it was
        // built at zero duty, so the panel stayed dark through init — no white flash).
        bl.set_config(&backlight_cfg(level_duty(brightness)));

        // CST328 reset pulse (high → low → high), then normal reporting mode.
        tp_rst.set_high();
        block_for(Duration::from_millis(10));
        tp_rst.set_low();
        block_for(Duration::from_millis(10));
        tp_rst.set_high();
        block_for(Duration::from_millis(50));
        let mut touch = Touch { i2c };
        touch.normal_mode();

        // Boot locked when a device PIN is set: a security key should come up requiring
        // the PIN to reach its on-device UI, not open. Without a PIN there is nothing to
        // unlock with, so it boots open (the lock is a no-op then anyway).
        let locked = rsk_fido::passkeys::device_pin_is_set(&mut fs.borrow_mut());
        // A fresh, PIN-less device that hasn't already had the prompt dismissed comes up on
        // the onboarding screen offering to set a device PIN (declining is remembered in
        // `EF_DISPLAY`, so it's a one-time first-run offer). Mutually exclusive with `locked`.
        let onboarding = !locked && !dcfg.pin_declined;

        Ui {
            panel,
            touch,
            bl,
            tp_rst,
            shown: None,
            touch_armed: false,
            info,
            brightness,
            asleep: false,
            wake_btn,
            locked,
            onboarding,
            pin_declined: dcfg.pin_declined,
            fs,
            keys,
            rng,
            marquee_mask: [0; MARQUEE_MASK_BYTES],
            // Seeded from the cheap PIN bit (== `locked`); the count is filled by the first
            // `refresh_home_stats` before Home is ever painted.
            home_pin_set: locked,
            home_passkeys: 0,
        }
    }

    /// Refresh the Home status-card facts — whether a device PIN is set and how many
    /// resident passkeys are stored — into the cache the idle Home frame reads. Enumerates
    /// flash (the seed-unboxing RP walk), so it runs only at modal boundaries (boot, wake,
    /// a closed tab modal), never per idle frame: a per-paint partition scan would stall the
    /// panel, the lesson the PIV `has_data` lag taught. Borrow-safe like [`Self::load_rps`]
    /// (the worker is parked while this thread-executor task runs).
    fn refresh_home_stats(&mut self) {
        let dev = self.keys.device();
        let mut store = self.fs.borrow_mut();
        self.home_pin_set = rsk_fido::passkeys::device_pin_is_set(&mut store);
        let mut creds = 0u16;
        let _ = rsk_fido::passkeys::for_each_rp(&dev, &mut store, |rp| {
            creds = creds.saturating_add(rp.count as u16);
        });
        self.home_passkeys = creds;
    }

    /// Composite one marquee frame of `title` (scrolled by `off` px) into the 1-bit mask,
    /// then blit the whole title band in a single `fill_contiguous` — no per-frame
    /// clear→draw flash, so the scroll is flicker-free. Only called for titles that
    /// overflow the band; a fitting title is drawn once, centred, by `render`.
    fn render_marquee_frame(&mut self, title: &str, off: u32) {
        let band = rsk_ui::PIN_TITLE_BAND;
        let Self {
            panel,
            marquee_mask,
            ..
        } = self;
        {
            let mut mask = BandMask::new(marquee_mask, band);
            let _ = rsk_ui::render_pin_title(&mut mask, title, off);
        }
        let area = Rectangle::new(
            EgPoint::new(band.x as i32, band.y as i32),
            Size::new(band.w as u32, band.h as u32),
        );
        let n = band.w as usize * band.h as usize;
        let colors = (0..n).map(|i| {
            if marquee_mask[i >> 3] & (1 << (i & 7)) != 0 {
                rsk_ui::theme::TEXT
            } else {
                rsk_ui::theme::PANEL_BG
            }
        });
        let _ = panel.fill_contiguous(&area, colors);
    }

    /// Hand the panel back to the ambient loop on a modal's exit. Closing a tab back to
    /// idle is repainted *immediately* by [`status_task`]'s dispatcher, and a tab → next
    /// tab hand-off renders the new tab directly, so neither needs the ambient-quiet
    /// window (that is only for the pad → confirm gap, set in `confirm_wait` /
    /// `collect_pin`). So this just clears the last-shown marker.
    /// Record a panel-originated action in the on-device audit journal.
    ///
    /// The panel renders the journal as its evidence surface, yet nothing under
    /// `display/` ever wrote to it: an on-screen seed reveal, seal or PIN change
    /// left no entry while every one of their USB equivalents was logged (audit
    /// run-34 #17). Journalling is opt-in and off by default, which caps the
    /// impact but does not remove it — the gap silently omitted the device's
    /// highest-value actions from the log of a user who deliberately turned it on.
    fn journal_local(&self, ev: u8) {
        let dev = self.keys.device();
        let now = crate::usb_attach::elapsed_ms();
        rsk_fido::journal::append_local(&dev, &mut self.fs.borrow_mut(), now, ev, 0);
    }

    fn end_modal(&mut self) {
        self.shown = None;
    }
}
