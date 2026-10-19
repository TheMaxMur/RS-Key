// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The `display-keys` build: a touchless panel (Waveshare RP2350-GEEK) driven by
//! one physical button instead of a touch pad.
//!
//! The panel renders the two things a button key needs of a screen — the ambient
//! status wash (the LED this board does not have) and, when an applet asks for
//! presence, a confirm page naming the pending operation. The button gestures
//! are mapped by [`rsk_device::presence::GestureWait`]: a short press approves,
//! a hold past 800 ms declines (the one-button decline gesture, taught by the
//! confirm page's hint lines). No on-device PIN pad — `uv` stays unadvertised
//! and the host types PINs, exactly like the button-only build.
//!
//! The one browse surface this build has is the no-host idle menu
//! ([`crate::keys_menu`]): when no host has configured the device for 30 s the
//! STARTING wash gives way to a read-only, single-button paged listing of the
//! device's own metadata (see that module). [`status_task`] owns the entry
//! timer; the menu loop itself is synchronous and holds the panel, exactly like
//! a confirm wait below.
//!
//! Everything here is the board half; the layout and the anti-phishing text
//! rules live in `rsk_ui`'s `keys` renderer (host-tested). `status_task` and a
//! confirm wait share the panel through a `RefCell` on the thread executor — a
//! confirm wait is synchronous (the applet call chain is), so while it waits the
//! status task cannot run, exactly like the touch build's `status_task` vs
//! `TouchPresence`. USB on the interrupt executor preempts the busy-wait
//! throughout, so keepalives keep flowing.

use core::cell::RefCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};

use embassy_rp::gpio::Output;
use embassy_time::{Duration, Instant, Timer, block_for};

use rsk_device::presence::{Board, Gesture, GestureWait};
use rsk_ui::{ConfirmPrompt, StatusKind};

use crate::display_panel::Panel;
use crate::handler::Store;
use crate::keys_menu;
use crate::led;
use crate::presence::{self, Button};

/// The panel plus the always-on backlight driver. The backlight is driven as a
/// plain GPIO held high — the button build has no brightness menu, so there is
/// nothing a PWM would buy; holding the `Output` keeps the pad from dropping
/// (an embassy `Output` disconnects its pad on drop → black panel).
pub(crate) struct KeysBoard {
    panel: Panel,
    _bl: Output<'static>,
}

impl KeysBoard {
    pub(crate) fn new(panel: Panel, bl: Output<'static>) -> Self {
        Self { panel, _bl: bl }
    }
}

impl Deref for KeysBoard {
    type Target = Panel;
    fn deref(&self) -> &Panel {
        &self.panel
    }
}

impl DerefMut for KeysBoard {
    fn deref_mut(&mut self) -> &mut Panel {
        &mut self.panel
    }
}

/// The shared panel+backlight cell: `status_task` (ambient) and `KeysPresence`
/// (confirm pages) — never raced (see the module docs).
pub(crate) type SharedPanel = RefCell<KeysBoard>;

/// Ambient wash repaint cadence — same as the touch build's ambient loop, so a
/// status flip shows within ~100 ms.
const POLL_MS: u64 = 100;

/// How long the approve/decline feedback page stays up after a gesture decides,
/// before the ambient wash returns. Long enough to read, short enough that a
/// host ceremony's next screen (or the idle wash) feels immediate.
const DECISION_MS: u64 = 900;

/// Map the LED status engine's index onto the on-screen status (the touch build
/// keeps the same mapping in `rsk_display::status`).
fn status_to_kind(s: u8) -> StatusKind {
    match s {
        rsk_led::STATUS_IDLE => StatusKind::Idle,
        rsk_led::STATUS_PROCESSING => StatusKind::Processing,
        rsk_led::STATUS_TOUCH => StatusKind::Touch,
        _ => StatusKind::Boot,
    }
}

/// Set by [`KeysPresence`] after it has hand-painted the panel (a confirm page,
/// the decision page, the restored wash): the ambient task's `shown` cache does
/// not know about that paint, so the next tick must repaint unconditionally —
/// otherwise a ceremony that ends on the same status the task last drew leaves
/// the restored (stale) frame on screen instead of the live status.
static REPAINT_PENDING: AtomicBool = AtomicBool::new(false);

fn repaint_pending() -> bool {
    REPAINT_PENDING.swap(false, Ordering::AcqRel)
}

/// Force the ambient task's next tick to repaint from the LED engine.
pub(crate) fn request_repaint() {
    REPAINT_PENDING.store(true, Ordering::Release);
}

/// The panel cell the long-running worker hooks draw on, registered by `main`
/// once the panel task is spawned. A `&'static RefCell` cannot itself live in
/// a `Sync` static (the cell is deliberately `!Sync`), so the reference travels
/// as a raw pointer here.
///
/// SAFETY: `register_screen` stores the `&'static` (from `KEY_UI.init`, which
/// lives for the whole run) once during single-threaded boot; `screen()` reads
/// it back only from the worker thread's keygen hook — the same
/// thread-executor exclusivity every `RefCell` in this firmware relies on, so
/// the pointer never crosses executors. (docs/unsafe.md — keygen tick screen
/// handle.)
static SCREEN_PTR: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

pub(crate) fn register_screen(ui: &'static SharedPanel) {
    SCREEN_PTR.store(ui as *const SharedPanel as *mut (), Ordering::Release);
}

fn screen() -> Option<&'static SharedPanel> {
    let ptr = SCREEN_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        return None;
    }
    // SAFETY: see the `SCREEN_PTR` invariant above — the stored pointer is the
    // `&'static` registered during boot, re-read on the same executor.
    Some(unsafe { &*(ptr as *const SharedPanel) })
}

/// Repaint gate for the RSA-keygen progress hook: the search fires the tick
/// once per prime candidate (far more often than a repaint should run), so a
/// step is drawn at most every 100 ms — the same time-gate the touch build's
/// keygen spinner uses, so the search is never slowed by SPI traffic.
const KEYGEN_TICK_MS: u32 = 100;

static KEYGEN_LAST_MS: AtomicU32 = AtomicU32::new(0);
static KEYGEN_PHASE: AtomicU32 = AtomicU32::new(0);

/// RSA keygen on the worker thread holds the thread executor for its whole
/// run, freezing the ambient task — so the busy frame is driven from here,
/// inside the keygen, exactly like the touch build's on_tick spinner.
pub(crate) fn keygen_enter() {
    KEYGEN_PHASE.store(0, Ordering::Relaxed);
    KEYGEN_LAST_MS.store(0, Ordering::Relaxed);
    // Paint the full busy frame up front — the exact frame the ambient task
    // draws for a Processing status, so the keygen busy page and the
    // post-ceremony busy page are one and the same. The worker is between
    // dispatches here, so the panel borrow always succeeds.
    if let Some(ui) = screen()
        && let Ok(mut board) = ui.try_borrow_mut()
    {
        let panel: &mut Panel = &mut board;
        let _ = rsk_ui::render_keys_status(panel, StatusKind::Processing);
    }
}

pub(crate) fn keygen_tick() {
    let now = Instant::now().as_millis() as u32;
    if now.wrapping_sub(KEYGEN_LAST_MS.load(Ordering::Relaxed)) < KEYGEN_TICK_MS {
        return;
    }
    KEYGEN_LAST_MS.store(now, Ordering::Relaxed);
    let phase = KEYGEN_PHASE.fetch_add(1, Ordering::Relaxed);
    let Some(ui) = screen() else {
        return; // keygen before the panel was registered: nothing to drive
    };
    if let Ok(mut board) = ui.try_borrow_mut() {
        let panel: &mut Panel = &mut board;
        // `keygen_enter` painted the frame; each tick steps the breath in place.
        let _ = rsk_ui::render_keys_status_step(panel, StatusKind::Processing, phase);
    }
}

/// Keygen over: hand the panel back to the ambient task, which repaints from
/// the LED engine on its next tick.
pub(crate) fn keygen_leave() {
    request_repaint();
}

/// Ambient status page: repaint when the LED engine's status changes, whenever
/// [`KeysPresence`] signals that it hand-painted the panel, and on each
/// animation step of the current state — the working arc advances every tick,
/// the idle/starting breathe ramps every three. A ceremony holds the thread
/// executor synchronously, so the animation simply freezes while a command is
/// dispatched — it never delays one.
#[embassy_executor::task]
pub(crate) async fn status_task(
    ui: &'static SharedPanel,
    dev: keys_menu::DeviceKeys,
    fs: &'static RefCell<Store>,
    presence: &'static RefCell<presence::Presence>,
) {
    // The panel was just initialised (and blanked to black): show the Starting
    // page at once — the touch build lets its splash linger the same way — so
    // a fresh plug never stares at an empty frame.
    if let Ok(mut board) = ui.try_borrow_mut() {
        let panel: &mut Panel = &mut board;
        let _ = rsk_ui::render_keys_status(panel, StatusKind::Boot);
    }
    Timer::after_millis(600).await;
    let mut shown = Some(StatusKind::Boot);
    let mut phase: u32 = 0;
    let mut breathe_ticks: u32 = 0;
    #[cfg(not(feature = "no-touch"))]
    let mut boot_since: Option<Instant> = None;
    loop {
        let kind = status_to_kind(led::status());
        #[cfg(not(feature = "no-touch"))]
        // The no-host idle menu: once the STARTING wash has held
        // `keys_menu::MENU_ENTRY_MS` without a host configuring the device,
        // hand the panel to the synchronous browse loop (see `keys_menu`). The
        // timer counts from the *first* Boot tick, so the pre-USB hardening
        // lap — up to ~30 s, during which this task cannot poll — is not part
        // of the wait; a configure at any point resets it.
        if kind == StatusKind::Boot {
            let now = Instant::now();
            match boot_since {
                None => boot_since = Some(now),
                Some(t0)
                    if now.saturating_duration_since(t0)
                        >= Duration::from_millis(keys_menu::entry_delay_ms()) =>
                {
                    // The menu paints non-status frames: clear the shown cache
                    // so the wash is repainted the tick after it returns.
                    shown = None;
                    // A confirm wait or the worker can own the panel/presence
                    // mid-tick on the same executor — impossible in practice
                    // while Boot (a confirm only runs inside a dispatch), but
                    // a failed borrow must not wedge the task: keep the elapsed
                    // timestamp and retry next tick.
                    let Ok(mut board) = ui.try_borrow_mut() else {
                        continue;
                    };
                    let panel: &mut Panel = &mut board;
                    let mut guard = presence.borrow_mut();
                    // The browse loop owns the panel and key until a host
                    // configures the device; the next tick then paints the
                    // live status (the timer is reset below either way).
                    keys_menu::browse(panel, &mut guard.button, fs, &dev);
                    drop(guard);
                    boot_since = None;
                    continue;
                }
                _ => {}
            }
        } else {
            boot_since = None;
        }
        if shown != Some(kind) {
            phase = 0;
            breathe_ticks = 0;
        }
        // Advance the animation phase of the current state.
        let advance = match kind {
            // Working breathes a little faster than Ready/Starting.
            StatusKind::Processing => {
                breathe_ticks = breathe_ticks.wrapping_add(1);
                if breathe_ticks.is_multiple_of(2) {
                    phase = phase.wrapping_add(1);
                    true
                } else {
                    false
                }
            }
            StatusKind::Idle | StatusKind::Boot => {
                breathe_ticks = breathe_ticks.wrapping_add(1);
                // One ramp step every three ticks (≈300 ms): the 16-phase ramp
                // then completes a breath in ≈4.8 s — slow enough to feel calm.
                if breathe_ticks.is_multiple_of(3) {
                    phase = phase.wrapping_add(1);
                    true
                } else {
                    false
                }
            }
            StatusKind::Touch => false,
        };
        if shown != Some(kind) || repaint_pending() {
            // A confirm wait owns the panel synchronously; skip its tick and
            // retry next poll rather than block the thread executor behind it.
            // `shown` is only advanced on a successful paint, so a skipped tick
            // retries until it lands. The full frame is drawn once per state;
            // animation steps repaint only their own region below.
            if let Ok(mut board) = ui.try_borrow_mut() {
                let panel: &mut Panel = &mut board;
                let _ = rsk_ui::render_keys_status(panel, kind);
                shown = Some(kind);
            }
        } else if advance {
            // In-place animation step — no full-frame rewrite, so the step
            // cannot tear the panel (see the keys renderer's docs).
            if let Ok(mut board) = ui.try_borrow_mut() {
                let panel: &mut Panel = &mut board;
                let _ = rsk_ui::render_keys_status_step(panel, kind, phase);
            }
        }
        Timer::after_millis(POLL_MS).await;
    }
}

/// The presence backend for the touchless build: paints the confirm page, then
/// waits for a button gesture on the shared arbiter. Satisfies the one
/// `rsk_sdk::UserPresence` every applet asks through, so only the
/// `presence::Presence` alias changes (the worker wiring stays the same).
pub struct KeysPresence {
    ui: &'static SharedPanel,
    #[cfg_attr(feature = "no-touch", allow(dead_code))]
    button: Button,
    #[cfg_attr(feature = "no-touch", allow(dead_code))]
    latch: GestureWait,
}

impl KeysPresence {
    pub(crate) fn new(ui: &'static SharedPanel, button: Button) -> Self {
        Self {
            ui,
            button,
            latch: GestureWait::new(),
        }
    }

    /// Common entry: show the touch status, paint the confirm page (so a press
    /// approves *this* operation, named on screen), wait for the gesture, then
    /// hand the panel back to the ambient task.
    fn confirm_wait(&mut self, confirm: rsk_sdk::Confirm<'_>) -> rsk_sdk::Presence {
        #[cfg(feature = "no-touch")]
        {
            // Automated-test image: no button can be pressed, so confirm at once
            // (the panel may still be initialised, but nothing is drawn on it).
            let _ = confirm;
            return rsk_sdk::Presence::Confirmed;
        }
        #[cfg(not(feature = "no-touch"))]
        {
            let saved = led::status();
            led::set_status(rsk_led::STATUS_TOUCH);
            let prompt = ConfirmPrompt::new(confirm.title, confirm.primary, confirm.secondary);
            // A key still held when the page appears (the tail of an earlier
            // gesture) must not read as a press on it — wait for the release
            // edge before arming the wait.
            wait_confirm_armed(&mut self.button);
            if let Ok(mut board) = self.ui.try_borrow_mut() {
                let panel: &mut Panel = &mut board;
                let _ = rsk_ui::render_keys_confirm(panel, &prompt);
            }
            let outcome = self.latch.wait(presence::arbiter(), &mut self.button);
            // The gesture's outcome gets a short readable page before the
            // ambient wash returns (the touch build's "Approved" pop is the
            // same idea) — so a press does not read as "just went back to
            // working".
            let decided = matches!(outcome, Gesture::Confirmed | Gesture::Declined);
            if decided {
                if let Ok(mut board) = self.ui.try_borrow_mut() {
                    let panel: &mut Panel = &mut board;
                    let _ = rsk_ui::render_keys_decision(panel, outcome == Gesture::Confirmed);
                }
                block_for(Duration::from_millis(DECISION_MS));
            }
            // Hand the live panel back to the ambient task: force its next tick
            // to repaint from the LED engine, whatever its `shown` cache thinks.
            if let Ok(mut board) = self.ui.try_borrow_mut() {
                let panel: &mut Panel = &mut board;
                let _ = rsk_ui::render_keys_status(panel, status_to_kind(saved));
            }
            led::set_status(saved);
            REPAINT_PENDING.store(true, Ordering::Release);
            match outcome {
                Gesture::Confirmed => rsk_sdk::Presence::Confirmed,
                Gesture::Declined => rsk_sdk::Presence::Declined,
                Gesture::Timeout => rsk_sdk::Presence::Timeout,
                Gesture::Cancelled => rsk_sdk::Presence::Cancelled,
            }
        }
    }
}

impl KeysPresence {
    /// The click-counter probe: the worker's idle watcher polls this to type a
    /// slot's Yubico-OTP ticket (N idle clicks → slot N), and the dispatch tail
    /// samples it once to mark a still-held press as consumed. A plain level
    /// sample is correct on both paths — idle clicks happen only while no
    /// ceremony owns the button (a confirm wait runs synchronously inside a
    /// dispatch, so its press can never be counted as an idle click, and the
    /// release of an approved press lands outside the click window).
    pub fn poll_pressed(&mut self) -> bool {
        #[cfg(not(feature = "no-touch"))]
        {
            self.button.pressed()
        }
        #[cfg(feature = "no-touch")]
        {
            // No-touch test image: nothing may wait on the button.
            false
        }
    }
}

impl rsk_sdk::UserPresence for KeysPresence {
    /// A smartcard touch policy (OpenPGP UIF, PIV, OATH, management…): reached
    /// over CCID, which carries no `CTAPHID_CANCEL`, so a cancel is just a
    /// non-confirmation here (the same mapping the button build's `request`).
    fn request(&mut self, confirm: rsk_sdk::Confirm<'_>) -> rsk_sdk::Presence {
        match self.confirm_wait(confirm) {
            rsk_sdk::Presence::Cancelled => rsk_sdk::Presence::Timeout,
            other => other,
        }
    }

    /// A CTAP2 ceremony, which *can* be cancelled mid-wait: report it so the
    /// in-flight command answers `CTAP2_ERR_KEEPALIVE_CANCEL`.
    fn request_ceremony(&mut self, confirm: rsk_sdk::Confirm<'_>) -> rsk_sdk::Presence {
        self.confirm_wait(confirm)
    }

    /// The screen names the operation before the button approves it, so a press
    /// carries *which* operation it approves — CTAP 2.1 §6.6 reset exemption.
    fn shows_confirm(&self) -> bool {
        true
    }
}

/// Bounded release wait before a freshly painted confirm page starts reading
/// presses, so a key still held from an earlier gesture can't confirm the new
/// page the instant it appears. Bounded so a stuck key can't wedge a ceremony.
#[cfg(not(feature = "no-touch"))]
fn wait_confirm_armed(button: &mut Button) {
    let start = Instant::now();
    while button.pressed() {
        if start.elapsed() >= Duration::from_millis(2000) {
            break;
        }
        block_for(Duration::from_millis(16));
    }
}
