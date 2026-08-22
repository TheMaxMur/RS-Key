// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The trusted display's *flow*: which screen is shown when, and what a tap on it
//! does. Two roles share one panel:
//!
//! * [`status_loop`] mirrors the device status the onboard LED would show (boot /
//!   idle / working), repainting on change — the ambient screen.
//! * [`TouchPresence`] renders the trusted Approve/Deny prompt when an applet asks
//!   for user presence, naming the operation and the *real* relying party, and
//!   block-waits an on-screen tap. A tap on **Allow** confirms; a tap on **Deny**
//!   is a genuine `Declined` (→ `OPERATION_DENIED`) — the BOOTSEL button has no
//!   such gesture. This is the anti-WebUSB-phishing guarantee: a signature can't
//!   be obtained without a physical tap on a screen showing the true rp.
//!
//! The *what to draw*, the untrusted-string sanitizing, the Allow/Deny button
//! geometry and the touch-report parse live in `rsk-ui` (host-tested + Kani). What
//! is here is the decision layer between them, and it used to live in `firmware/`
//! — so the only thing that could run it was a flashed board with a panel soldered
//! on. The panel and the touch controller are now type parameters (a
//! `DrawTarget<Color = Rgb565>` and a [`TouchPad`]); the few verbs left that are
//! genuinely the board's sit behind [`Hooks`], whose defaults are exact no-ops.
//! The firmware supplies an ST7789 and a CST328; the emulator supplies a window.
//!
//! Both roles run on the THREAD executor and share the panel through a
//! `RefCell<Ui>`. They never race for it: `TouchPresence::request` is *synchronous*
//! (the applet call chain is), so while it block-waits a tap the thread executor is
//! occupied and `status_loop` cannot run — exactly like the BOOTSEL wait. USB on
//! the interrupt executor preempts the busy-wait throughout, so keepalives keep
//! flowing and a full-frame repaint never stalls enumeration.

// Host test builds link `std`: the doubles the flow runs against (a recording
// panel, a scripted touch pad) want a heap and a mutex, and the crates the tests
// borrow from — `rsk-fs`'s RAM storage, `embassy-time`'s `std` driver — are std
// too. The firmware build is untouched, and no test code reaches the image.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

use core::cell::RefCell;
use core::sync::atomic::{AtomicU32, Ordering};

use embassy_time::{Duration, Instant, Timer, block_for};
use embedded_graphics::{
    Pixel,
    draw_target::DrawTarget,
    geometry::{Dimensions, Point as EgPoint, Size},
    pixelcolor::Rgb565,
    prelude::RgbColor,
    primitives::Rectangle,
};
use zeroize::Zeroize;

use rsk_crypto::{Device, FusedKey, FusedRead, read_fused};
use rsk_fs::Fs;
use rsk_sdk::Confirm;
use rsk_ui::{
    ALLOW_RECT, AccountRow, AdjustKey, AppEntry, AuditRow, BRIGHTNESS_LEVELS, BackupView, Button,
    ConfirmPrompt, DisplayEntry, HomeView, Label, NavTab, PinCaption, PinKey, PinPad, RootEntry,
    RpRow, Screen, SecurityEntry, SettingsPage, SettingsView, StatusKind, SuccessKind,
};

mod applets;
mod backup;
mod gates;
mod pin;
mod power;
mod presence;
mod settings;
mod status;
mod touch;

pub use gates::piv_ref_title;
pub use presence::TouchPresence;
pub use status::status_loop;
pub use touch::TouchPad;

use settings::EF_DISPLAY;

/// The board verbs this flow cannot perform itself, plus the firmware globals a
/// ceremony coordinates through. Every method defaults to an exact no-op for a
/// build without that hardware, so an implementation overrides only what it has —
/// the same shape as `rsk_device::Hooks` and `rsk_vendor::Platform`.
pub trait Hooks {
    /// Set the backlight to `duty` (`0..=`[`BL_TOP`]); `0` blanks the panel.
    fn set_backlight(&mut self, _duty: u16) {}
    /// One non-blocking, polarity-corrected sample of the sleep/wake button.
    /// `false` on a board without one (`WAKE_PIN=none`).
    fn wake_pressed(&self) -> bool {
        false
    }
    /// The LED status engine's index, borrowed by a ceremony and restored after it.
    fn led_status(&self) -> u8 {
        rsk_led::STATUS_IDLE
    }
    fn set_led_status(&mut self, _status: u8) {}
    /// Milliseconds since the USB *attach*, so a panel-originated audit entry is
    /// stamped on the same clock as a host-originated one.
    fn attach_elapsed_ms(&self) -> u64 {
        0
    }
    /// Whether a host command has been queued since `since`, so an on-device modal
    /// yields the (single) thread executor instead of starving the host.
    fn host_request_pending_after(&self, _since: Instant) -> bool {
        false
    }
    fn host_request_pending(&self) -> bool {
        false
    }
    /// Queue a warm reboot, optionally into BOOTSEL (Settings → Firmware update).
    fn request_reboot(&mut self, _bootsel: bool) {}
    fn reboot_pending(&self) -> bool {
        false
    }
    /// A device PIN was re-keyed from the panel: the host side must end every
    /// session credential the old PIN authorized (CTAP 2.1 §6.5.5.6).
    fn note_local_pin_changed(&mut self) {}
    /// A clientPIN comparison *failed* at the panel's pad. Same consequence — the
    /// host's outstanding `pinUvAuthToken` ends — for the other reason: the pad's
    /// current-PIN prompt is `changePIN`'s old-PIN check, and over USB that check
    /// drops the token on a mismatch.
    fn note_local_pin_failed(&mut self) {}
    /// Whether the boot ROM actually verifies the image signature (read from OTP),
    /// shown read-only on Settings → Firmware.
    fn secure_boot_enabled(&self) -> bool {
        false
    }
    /// The presence flags a ceremony shares with the CTAPHID transport:
    /// `up_pending` makes the keepalive report `UPNEEDED`, `cancel` is set by the
    /// transport and polled by the wait.
    fn set_up_pending(&mut self, _pending: bool) {}
    fn set_cancel_requested(&mut self, _requested: bool) {}
    fn cancel_requested(&self) -> bool {
        false
    }
    /// The host-configurable presence timeout, in milliseconds. The Settings →
    /// Presence page edits it live and flushes it to the phy record on exit.
    fn presence_timeout_ms(&self) -> u32 {
        30_000
    }
    fn set_presence_timeout_ms(&mut self, _ms: u32) {}
    /// Search for an RSA key on whatever accelerator the board has, calling
    /// `on_tick` often enough to keep the on-screen spinner moving. `None` means
    /// no accelerator *and* no key — the caller reports the failure either way, so
    /// a build without one simply cannot generate from the panel.
    fn rsa_search_progress(
        &mut self,
        _nbits: usize,
        _rng: &mut dyn rsk_sdk::Rng,
        _on_tick: &mut dyn FnMut(),
    ) -> Option<alloc::boxed::Box<rsk_openpgp::keys::RsaKey>> {
        None
    }
}

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

/// How long the Settings menu must go without a tap before an edit is written to
/// flash. Short enough that a change survives the unplug that ends a USB key's
/// session, long enough that a run of −/+ taps is still one write — brightness and
/// display-sleep live in the credential partition, whose whole design is that it
/// fills slowly, so a write per tap would advance its ring toward a cold migration.
const SETTINGS_PERSIST_QUIET_MS: u64 = 1_500;

/// Auto-close an open on-device tab / menu (Passkeys / Settings / a Confirm-Delete)
/// after this long *without a tap*, returning to the idle status screen — a privacy
/// backstop so a walked-away device doesn't leave the passkey list (or a menu) on
/// screen indefinitely. It is **not** the host-starvation guard: while a tab is open
/// the worker is parked (single thread executor), but the browse loops poll
/// [`Hooks::host_request_pending`] and yield the instant a host command
/// arrives, so this bound can be generous (a comfortable browse) without making the
/// host wait for it.
const MENU_INACTIVITY_MS: u64 = 60_000;

/// Minimum time an on-device modal that yields to the host stays open before a queued
/// host command may close it. `REQ` latches until the worker drains it, and the worker
/// cannot run while a modal busy-waits, so without a floor a single queued command shuts
/// the modal on its first poll — and a host repeating any ungated command (getInfo will
/// do) could keep the owner's unlock pad shut indefinitely. The host is receiving
/// keepalives throughout, so a couple of seconds costs it nothing.
pub const UI_YIELD_FLOOR_MS: u64 = 2_500;

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
/// Bytes for the four-bit coverage buffer used by the marquee. The complete band blits
/// in one transaction, so scrolling keeps antialiasing without clear-then-draw flicker.
const MARQUEE_COVERAGE_BYTES: usize =
    (rsk_ui::PIN_TITLE_BAND.w as usize * rsk_ui::PIN_TITLE_BAND.h as usize).div_ceil(2);

/// Backlight PWM `top` (8-bit, like the LED): a brightness level maps to a compare
/// value `0..=BL_TOP`.
pub const BL_TOP: u16 = 255;

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
/// `Ctx` carries. The serials are owned copies; the MKEK is a way to read the fuses,
/// so the display task builds a [`Device`] on demand (when the Passkeys tab is open)
/// while holding neither the seed nor the root key.
pub struct DeviceKeys {
    pub serial_id: [u8; 8],
    pub serial_hash: [u8; 32],
    pub mkek_source: Option<FusedKey>,
}

impl DeviceKeys {
    fn device<'k>(&'k self, mkek: &'k FusedRead) -> Device<'k> {
        Device {
            serial_hash: &self.serial_hash,
            serial_id: &self.serial_id,
            otp_key: mkek.as_deref(),
        }
    }
}

/// Map a brightness level (`1..=BRIGHTNESS_LEVELS`) to a backlight duty (compare).
fn level_duty(level: u8) -> u16 {
    let l = level.clamp(1, BRIGHTNESS_LEVELS) as u16;
    (l * BL_TOP) / BRIGHTNESS_LEVELS as u16
}

/// A four-bit off-screen `DrawTarget` over the PIN title band. Coordinates are absolute,
/// so the generic title renderer lands at the real panel position.
struct BandCoverage<'a> {
    coverage: &'a mut [u8],
    band: Rectangle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UnsupportedBandColor;

impl<'a> BandCoverage<'a> {
    fn new(coverage: &'a mut [u8], band: rsk_ui::Rect) -> Self {
        coverage.fill(0);
        Self {
            coverage,
            band: Rectangle::new(
                EgPoint::new(band.x as i32, band.y as i32),
                Size::new(band.w as u32, band.h as u32),
            ),
        }
    }

    fn encode(color: Rgb565) -> Result<u8, UnsupportedBandColor> {
        (0..=rsk_ui::aa::COVERAGE_MAX)
            .find(|&coverage| {
                rsk_ui::aa::blend_coverage(rsk_ui::theme::TEXT, rsk_ui::theme::PANEL_BG, coverage)
                    == color
            })
            .ok_or(UnsupportedBandColor)
    }

    fn set(&mut self, index: usize, value: u8) {
        let shift = (index & 1) * 4;
        self.coverage[index >> 1] &= !(0x0F << shift);
        self.coverage[index >> 1] |= value << shift;
    }
}

fn packed_coverage(coverage: &[u8], index: usize) -> u8 {
    (coverage[index >> 1] >> ((index & 1) * 4)) & 0x0F
}

impl Dimensions for BandCoverage<'_> {
    fn bounding_box(&self) -> Rectangle {
        self.band
    }
}

impl DrawTarget for BandCoverage<'_> {
    type Color = Rgb565;
    type Error = UnsupportedBandColor;

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
                self.set(idx, Self::encode(c)?);
            }
        }
        Ok(())
    }
}

/// Panel + touch + the last-painted screen, owned behind a `RefCell` shared by
/// [`status_loop`] and [`TouchPresence`].
///
/// `panel` and `touch` are type parameters rather than accessors on [`Hooks`] on
/// purpose: they are named by ~180 sites in this crate, and a field keeps every
/// one of them reading the way it did when this was the firmware's own module.
pub struct Ui<'a, P, T, H, S, R>
where
    P: DrawTarget<Color = Rgb565>,
    T: TouchPad,
    H: Hooks,
    S: rsk_fs::Storage,
{
    panel: P,
    touch: T,
    /// The board verbs and the firmware globals a ceremony coordinates through.
    hooks: H,
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
    fs: &'a RefCell<Fs<S>>,
    /// Device identity for unboxing the resident-credential seed on demand.
    keys: DeviceKeys,
    /// The shared DRBG — the same `RefCell` the worker uses. Borrowed only to draw the
    /// randomness an on-device SLIP-39 split needs (the share identifier + Shamir random
    /// shares); the worker is parked while this thread-executor task runs, so no race.
    rng: &'a RefCell<R>,
    /// Four-bit scratch for the flicker-free PIN-title marquee blit ([`BandCoverage`]).
    marquee_coverage: [u8; MARQUEE_COVERAGE_BYTES],
    /// Cached Home status-card facts (device-PIN-set + resident passkey count), refreshed
    /// by [`Ui::refresh_home_stats`] only at modal boundaries — boot, wake, a closed tab
    /// modal — so the idle Home frame never triggers a per-paint flash enumeration.
    home_pin_set: bool,
    home_passkeys: u16,
}

impl<'a, P, T, H, S, R> Ui<'a, P, T, H, S, R>
where
    P: DrawTarget<Color = Rgb565>,
    T: TouchPad,
    H: Hooks,
    S: rsk_fs::Storage,
    R: rsk_sdk::Rng,
{
    /// Take an already-initialized panel and touch controller, show the boot
    /// splash, restore the persisted display settings and raise the backlight.
    ///
    /// Bringing the hardware *up* — the SPI/mipidsi init, the CST328 reset pulse —
    /// is the caller's: it is the one part that differs between a board and a
    /// window, and it is done by the time the flow is handed them.
    pub fn new(
        mut panel: P,
        touch: T,
        mut hooks: H,
        info: DeviceInfo,
        fs: &'a RefCell<Fs<S>>,
        keys: DeviceKeys,
        rng: &'a RefCell<R>,
    ) -> Self {
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

        // Backlight up to the saved level only now there is something to show (the
        // caller brings the panel up dark, so there is no white flash through init).
        hooks.set_backlight(level_duty(brightness));

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
            hooks,
            shown: None,
            touch_armed: false,
            info,
            brightness,
            asleep: false,
            locked,
            onboarding,
            pin_declined: dcfg.pin_declined,
            fs,
            keys,
            rng,
            marquee_coverage: [0; MARQUEE_COVERAGE_BYTES],
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
        let mkek = read_fused(self.keys.mkek_source);
        let dev = self.keys.device(&mkek);
        let mut store = self.fs.borrow_mut();
        self.home_pin_set = rsk_fido::passkeys::device_pin_is_set(&mut store);
        let mut creds = 0u16;
        let _ = rsk_fido::passkeys::for_each_rp(&dev, &mut store, |rp| {
            creds = creds.saturating_add(rp.count as u16);
        });
        self.home_passkeys = creds;
    }

    /// Composite one marquee frame and blit the whole title band in one transaction.
    /// Only called for titles that overflow the band.
    fn render_marquee_frame(&mut self, title: &str, off: u32) {
        let band = rsk_ui::PIN_TITLE_BAND;
        let Self {
            panel,
            marquee_coverage,
            ..
        } = self;
        let rendered = {
            let mut target = BandCoverage::new(marquee_coverage, band);
            rsk_ui::render_pin_title(&mut target, title, off)
        };
        if rendered.is_err() {
            marquee_coverage.fill(0);
        }
        let area = Rectangle::new(
            EgPoint::new(band.x as i32, band.y as i32),
            Size::new(band.w as u32, band.h as u32),
        );
        let n = band.w as usize * band.h as usize;
        let colors = (0..n).map(|i| {
            rsk_ui::aa::blend_coverage(
                rsk_ui::theme::TEXT,
                rsk_ui::theme::PANEL_BG,
                packed_coverage(marquee_coverage, i),
            )
        });
        let _ = panel.fill_contiguous(&area, colors);
    }

    /// Record a panel-originated action in the on-device audit journal.
    ///
    /// The panel renders the journal as its evidence surface, yet nothing under
    /// `display/` ever wrote to it: an on-screen seed reveal, seal or PIN change
    /// left no entry while every one of their USB equivalents was logged (audit
    /// run-34 #17). Journalling is opt-in and off by default, which caps the
    /// impact but does not remove it — the gap silently omitted the device's
    /// highest-value actions from the log of a user who deliberately turned it on.
    fn journal_local(&self, ev: u8) {
        let mkek = read_fused(self.keys.mkek_source);
        let dev = self.keys.device(&mkek);
        let now = self.hooks.attach_elapsed_ms();
        rsk_fido::journal::append_local(&dev, &mut self.fs.borrow_mut(), now, ev, 0);
    }

    /// Hand the panel back to the ambient loop on a modal's exit. Closing a tab back to
    /// idle is repainted *immediately* by the firmware's `status_task` dispatcher, and a
    /// tab → next tab hand-off renders the new tab directly, so neither needs the ambient-quiet
    /// window (that is only for the pad → confirm gap, set in `confirm_wait` /
    /// `collect_pin`). So this just clears the last-shown marker.
    fn end_modal(&mut self) {
        self.shown = None;
    }
}

#[cfg(test)]
mod tests;
