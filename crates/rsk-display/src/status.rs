// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The ambient status loop and its status/audit display mappers.

use super::power::BREATHE_TICKS;
use super::*;

/// Repaint cadence for the on-device keygen spinner. The hook fires far more often than this
/// (once per prime candidate); time-gating to ~100ms keeps the panel repaint off the keygen's
/// hot path so the search isn't slowed by SPI traffic.
pub(super) const KEYGEN_SPIN_MS: u64 = 100;

/// Step the live presence/touch timeout to the next/previous menu choice and store
/// it (the seconds → ms atomic the waits read). [`Ui::persist_settings`] writes the
/// new value back to the phy record's `PresenceTimeout` tag on Settings exit, so it
/// survives a reboot (the same tag `rsk hw --touch-timeout` and boot both read).
/// Returns whether the value actually changed, so a no-op tap at a clamp boundary
/// doesn't mark the session dirty (and thus doesn't trigger a redundant flash write).
pub(super) fn adjust_timeout<H: Hooks>(hooks: &mut H, delta: i8) -> bool {
    let cur = (hooks.presence_timeout_ms() / 1000) as u16;
    let next = rsk_ui::step_timeout(cur, delta);
    hooks.set_presence_timeout_ms(next as u32 * 1000);
    next != cur
}

/// Step the display-sleep timeout from the menu (−/+). `0` seconds = Off (never blanks).
/// Returns whether the value actually changed (see [`adjust_timeout`]).
pub(super) fn adjust_sleep(delta: i8) -> bool {
    let cur = (SLEEP_TIMEOUT_MS.load(Ordering::Relaxed) / 1000) as u16;
    let next = rsk_ui::step_sleep(cur, delta);
    SLEEP_TIMEOUT_MS.store(next as u32 * 1000, Ordering::Relaxed);
    next != cur
}

/// Map the LED status engine's index ([`Hooks::led_status`]) onto the on-screen
/// status, so the panel shows the same idle/working/touch state the LED would.
fn status_to_kind(s: u8) -> StatusKind {
    match s {
        rsk_led::STATUS_IDLE => StatusKind::Idle,
        rsk_led::STATUS_PROCESSING => StatusKind::Processing,
        rsk_led::STATUS_TOUCH => StatusKind::Touch,
        _ => StatusKind::Boot,
    }
}

/// Whether a repaint puts a *different surface* under the finger, or only redraws
/// the status glyph on the one already there. Only the former may disarm: the host
/// drives `u.hooks.led_status()` around every dispatch, so counting that as a new screen
/// let a plain CTAP loop disarm the panel on every tick and swallow every tap
/// (audit run-34 #14). A tap on Home means the same thing whatever the glyph says.
fn same_surface(prev: Option<Screen>, next: Screen) -> bool {
    match (prev, next) {
        (Some(Screen::Home(a)), Screen::Home(b)) => {
            // Destructured, so a new `HomeView` field has to be classified here
            // rather than silently joining the ignored half.
            let HomeView {
                status: _,
                pin_set,
                passkeys,
            } = a;
            pin_set == b.pin_set && passkeys == b.passkeys
        }
        (Some(a), b) => a == b,
        (None, _) => false,
    }
}

/// Deadline for the on-device auto-lock. It follows the display-sleep setting so the two
/// stay intuitive, but "Off" (`0`) disables blanking only — a security control must not be
/// switchable off from a display page, so the lock falls back to the built-in default.
fn lock_after_ms(sleep_ms: u32) -> u32 {
    if sleep_ms == 0 {
        super::DEFAULT_SLEEP_MS
    } else {
        sleep_ms
    }
}

/// Apply a pager tap to the current page, clamped to `0..page_count(total)` — a Prev on
/// page 0 or a Next on the last page is a harmless no-op (the arrow is drawn dimmed).
pub(super) fn paged(page: u16, total: u16, k: rsk_ui::PagerKey) -> u16 {
    let last = rsk_ui::page_count(total).saturating_sub(1);
    match k {
        rsk_ui::PagerKey::Prev => page.saturating_sub(1),
        rsk_ui::PagerKey::Next => (page + 1).min(last),
    }
}

/// Map a journal event code to its on-device audit-log display class (the boundary
/// translation, the way an rpId is clamped into a `Label` — rsk-ui has no rsk-fido dep).
pub(super) fn audit_kind(ev: u8) -> rsk_ui::AuditKind {
    use rsk_fido::journal as j;
    use rsk_ui::AuditKind as K;
    match ev {
        j::EV_GET_ASSERT | j::EV_U2F_AUTH => K::Login,
        j::EV_MAKE_CRED | j::EV_U2F_REGISTER => K::Register,
        j::EV_PIN_SET | j::EV_PIN_CHANGE => K::Pin,
        j::EV_PIN_LOCKOUT => K::Denied,
        j::EV_BOOT => K::Boot,
        j::EV_RESET => K::Reset,
        j::EV_LOCK_ENGAGE | j::EV_LOCK_RELEASE => K::Lock,
        j::EV_CFG_MIN_PIN | j::EV_CFG_EA | j::EV_CFG_ALWAYS_UV | j::EV_AUDIT_CFG => K::Config,
        j::EV_BACKUP_EXPORT | j::EV_BACKUP_LOAD | j::EV_BACKUP_FINALIZE => K::Backup,
        _ => K::Other,
    }
}

impl<'a, P, T, H, S, R> Ui<'a, P, T, H, S, R>
where
    P: DrawTarget<Color = Rgb565>,
    T: TouchPad,
    H: Hooks,
    S: rsk_fs::Storage,
    R: rsk_sdk::Rng,
{
    /// Paint `screen` and remember it as the one on the panel. The pair is never
    /// useful apart: a repaint whose `shown` is not updated repaints for ever, and
    /// a `shown` without the repaint makes the loop believe a frame it never drew.
    fn paint(&mut self, screen: Screen) {
        let _ = rsk_ui::render(&mut self.panel, &screen);
        self.shown = Some(screen);
    }

    /// The Home card from the *cached* stats — never a per-frame flash scan. The
    /// callers that need fresh numbers refresh first; that is a decision about
    /// what just happened, not about how Home is built.
    fn home_screen(&self) -> Screen {
        Screen::Home(HomeView {
            status: status_to_kind(self.hooks.led_status()),
            pin_set: self.home_pin_set,
            passkeys: self.home_passkeys,
        })
    }

    /// What the panel stands on when nothing else is happening: the Locked screen
    /// while the on-device UI is locked, the onboarding offer on a fresh PIN-less
    /// device, Home otherwise. `refresh` re-reads the Home card's facts, for the
    /// callers that just left a flow which could have changed them.
    ///
    /// `locked` implies a PIN and `onboarding` implies none, so the two can never
    /// both hold — which is why the post-unlock caller can share this even though
    /// it wrote no onboarding branch of its own.
    fn ambient_screen(&mut self, refresh: bool) -> Screen {
        if self.locked {
            Screen::Locked
        } else if self.onboarding {
            Screen::Onboard
        } else {
            if refresh {
                self.refresh_home_stats();
            }
            self.home_screen()
        }
    }

    /// Blanked for retention: poll only the wake sources. A touch anywhere or the
    /// wake button restores the panel — repainted right away so waking shows the
    /// ambient screen, not the black sleep frame — and the gesture is consumed so
    /// it is not read as a tap on whatever it woke to.
    fn tick_asleep(&mut self) {
        if !(self.touch.read().is_some() || self.wake_pressed()) {
            return;
        }
        self.wake();
        note_local_activity();
        // Woke from sleep: a host ceremony may have added or removed a passkey
        // while the panel was dark, so Home's card is refreshed before painting.
        let screen = self.ambient_screen(true);
        self.paint(screen);
        // Nothing has been touched on this frame yet. The release wait below is
        // bounded, so a finger held through it returns with the contact still
        // down — and since `screen` is unchanged on the next tick there is no
        // repaint to disarm, so `armed_touch` would hand the wake press to the
        // freshly painted screen as a deliberate tap (on a fresh device:
        // "Continue without PIN"). `wait_wake_release` does not cover it — it
        // polls the wake *button*, which a touch-wake never pressed.
        self.touch_armed = false;
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(1000));
        self.wait_wake_release();
    }

    /// Repaint the ambient screen if it changed, then pulse the liveness overlay.
    /// Returns the status the rest of the tick gates on.
    fn ambient_repaint(&mut self, tick: u32, spin: &mut i32, breathe: &mut u8) -> StatusKind {
        let kind = status_to_kind(self.hooks.led_status());
        // Working / awaiting-touch is activity — never sleep mid-operation.
        if kind != StatusKind::Idle {
            note_activity();
        }
        let screen = self.ambient_screen(false);
        if self.shown != Some(screen) {
            let new_surface = !same_surface(self.shown, screen);
            self.paint(screen);
            // A screen that just appeared has not been touched yet. Disarm so a
            // contact already on the panel — the wake press, or the finger still
            // down from the approval hold a host ceremony just ended — cannot be
            // read as a tap on it.
            if new_surface {
                self.touch_armed = false;
            }
        }
        // Liveness: pulse a small region over the (already-painted) frame — the
        // spinner arc while busy, the breathe hint while locked. Both redraw in
        // place (no clear), so they never flicker and the idle frame is untouched.
        match screen {
            Screen::Home(v) if v.status != StatusKind::Idle => {
                *spin = spin.wrapping_add(SPIN_STEP_DEG);
                let _ = rsk_ui::render_status_arc(&mut self.panel, v.status, *spin);
            }
            Screen::Locked if tick.is_multiple_of(BREATHE_TICKS) => {
                *breathe = breathe.wrapping_add(1);
                let _ = rsk_ui::render_locked_breathe(&mut self.panel, *breathe);
            }
            _ => {}
        }
        kind
    }

    /// A tap while locked: any tap opens the unlock pad. Repaint the result at
    /// once — Home if the correct PIN dropped the lock, else Locked — so the pad's
    /// last frame never lingers through `collect_pin`'s ambient-quiet window.
    fn tap_locked(&mut self) {
        self.run_unlock();
        note_local_activity();
        // The power button can sleep from the unlock pad; the panel is then
        // blanked, so leave the repaint to the wake path.
        if !self.asleep {
            let screen = self.ambient_screen(true);
            self.paint(screen);
        }
    }

    /// A tap on a fresh PIN-less device: route it to the onboarding buttons (Set a
    /// PIN / Continue without). Repaint at once — Onboard again if it is still
    /// pending (a missed-button tap or an abandoned set), else Home now that the
    /// offer is resolved. `run_onboarding` refreshes the Home cache on whichever
    /// branch resolves the prompt, so no refresh is wanted here.
    fn tap_onboarding(&mut self, p: rsk_ui::Point) {
        self.run_onboarding(p);
        note_local_activity();
        // Setting a PIN here runs the pad, which the power button can sleep from;
        // skip the repaint when it did (panel blanked).
        if !self.asleep {
            let screen = self.ambient_screen(false);
            self.paint(screen);
        }
    }

    /// A tap on the bottom nav opens a tab. Each tab modal returns the next nav
    /// destination, so the user switches tab→tab directly (e.g. Passkeys →
    /// Settings) without a Home detour.
    fn tap_nav(&mut self, p: rsk_ui::Point) {
        let mut target = rsk_ui::hit_nav(p);
        let opened_tab = matches!(
            target,
            Some(NavTab::Settings | NavTab::Passkeys | NavTab::Apps)
        );
        while let Some(tab) = target {
            target = match tab {
                NavTab::Home => None,
                NavTab::Settings => self.run_settings(),
                NavTab::Passkeys => self.run_passkeys(),
                NavTab::Apps => self.run_apps(),
            };
        }
        note_local_activity(); // a browse session just ended — restart the clock
        // The power button can sleep from inside a tab modal; the panel is then
        // blanked (and locked if a PIN is set), so leave the repaint to the wake
        // path and paint here only awake.
        if self.asleep {
            return;
        }
        if self.locked {
            // The menu closed with the UI locked (a sub-flow slept + locked
            // without blanking is impossible, so this is unreachable today, but
            // keeps Locked from lingering).
            self.paint(Screen::Locked);
        } else if opened_tab && !self.hooks.host_request_pending() {
            // Closing a tab back to idle repaints Home now (not next poll) so it
            // feels instant. Skip if a host command is queued — the worker paints
            // next (no stale flash). The tab modal may have added or deleted a
            // passkey or set the PIN, so refresh the card facts first.
            self.refresh_home_stats();
            let screen = self.ambient_screen(false);
            self.paint(screen);
        }
    }

    /// The wake button and the armed touch. Returns whether this tick handled a
    /// local gesture — those paths bump the activity stamps themselves and may
    /// already have slept or locked, so the deadline check below stands down.
    ///
    /// Input and the auto-lock must not depend on the USB configuration state.
    /// `kind` is a *display* concern (which glyph to paint), and it sits at `Boot`
    /// until a host completes SET_CONFIGURATION — so gating touch on `Idle` left
    /// the panel animating but deaf on charger or battery power.
    /// Processing/Touch stay excluded because a dispatch or ceremony owns the
    /// executor then anyway.
    fn handle_local_input(&mut self, kind: StatusKind) -> bool {
        if !matches!(kind, StatusKind::Idle | StatusKind::Boot) {
            return false;
        }
        if self.wake_pressed() {
            // The wake button doubles as a manual "sleep now" while awake (also
            // locks, like any sleep, when a PIN is set).
            note_local_activity();
            self.enter_sleep();
            self.wait_wake_release();
            return true;
        }
        let Some(p) = self.armed_touch() else {
            return false;
        };
        note_local_activity();
        if self.locked {
            self.tap_locked();
        } else if self.onboarding {
            self.tap_onboarding(p);
        } else {
            self.tap_nav(p);
        }
        true
    }

    /// Sleep and auto-lock, evaluated OUTSIDE the ambient-quiet window and outside
    /// the `kind` gate. They used to sit inside both, and `ceremony_end` pushes the
    /// quiet window 400 ms forward on *every* ceremony exit — so an unauthenticated
    /// `authenticatorSelection` loop postponed the auto-lock indefinitely, which
    /// `power.rs` explicitly promises a host cannot do (audit run-34 #15). Quiet is
    /// a repaint concern; a security deadline is not one a host may hold off.
    fn tick_deadlines(&mut self) {
        // Re-read the clock: a tab/menu modal above can run for many seconds, so
        // the top-of-loop `now` would be stale and underflow against the
        // freshly-bumped activity stamp.
        let now = Instant::now().as_millis() as u32;
        let sleep_ms = SLEEP_TIMEOUT_MS.load(Ordering::Relaxed);
        if sleep_ms != 0 && now.wrapping_sub(LAST_ACTIVITY_MS.load(Ordering::Relaxed)) >= sleep_ms {
            self.enter_sleep();
        } else if now.wrapping_sub(LAST_LOCAL_MS.load(Ordering::Relaxed)) >= lock_after_ms(sleep_ms)
            && self.lock_now()
        {
            // Counted from the last *local* interaction, so neither a host
            // ceremony loop nor "Display sleep: Off" holds the panel unlocked. It
            // only re-arms the lock — blanking stays the sleep setting's business
            // — so repaint the Locked screen now.
            self.paint(Screen::Locked);
        }
    }
}

/// Ambient status screen: after letting the splash linger, repaint the idle/working
/// status whenever [`Hooks::led_status`] changes. The confirm prompt is painted by
/// [`TouchPresence`] (which holds the same [`Ui`]); a synchronous confirm occupies
/// this executor, so this loop never runs mid-confirm and the two never collide on
/// the panel (the `try_borrow_mut` is belt-and-suspenders).
pub async fn status_loop<'a, P, T, H, S, R>(ui: &RefCell<Ui<'a, P, T, H, S, R>>)
where
    P: DrawTarget<Color = Rgb565>,
    T: TouchPad,
    H: Hooks,
    S: rsk_fs::Storage,
    R: rsk_sdk::Rng,
{
    Timer::after_millis(600).await; // let the boot splash linger
    note_local_activity(); // the fresh boot counts as activity, so the sleep clock starts now
    // Prime the Home status-card cache once before the first idle paint (boot has settled
    // the flash; the worker is parked here while this task runs, so the borrow is safe).
    ui.borrow_mut().refresh_home_stats();
    // Liveness animation state: the spinner arc angle (advanced while busy) and the
    // locked-hint breathe phase (advanced every few ticks), plus a tick counter to pace
    // the breathe. These pulse a small region on top of the already-painted frame, so
    // they never trigger a full repaint and can't flicker the idle hot path.
    let mut spin = rsk_ui::STATUS_ARC_START;
    let mut breathe: u8 = 0;
    let mut tick: u32 = 0;
    loop {
        // A Settings → Firmware update queued a reboot: stop driving the panel and just yield
        // so the worker (same thread-mode executor) gets scheduled to scrub the live secrets
        // and reset to BOOTSEL on its next tick. Parking here — before any repaint — keeps the
        // "Rebooting" notice on screen instead of flashing Home over it.
        if ui.borrow().hooks.reboot_pending() {
            Timer::after_millis(10).await;
            continue;
        }
        tick = tick.wrapping_add(1);
        // Wrap-safe deadline checks (millis truncated to u32 wrap every ~49 days).
        let now = Instant::now().as_millis() as u32;
        if let Ok(mut u) = ui.try_borrow_mut() {
            if u.asleep {
                u.tick_asleep();
            } else {
                // Skip the ambient repaint while a modal hand-off is in flight, so the
                // status screen never flickers between the pad and the confirm prompt.
                let quiet_over =
                    now.wrapping_sub(AMBIENT_QUIET_UNTIL_MS.load(Ordering::Relaxed)) as i32 >= 0;
                let local_input = quiet_over && {
                    let kind = u.ambient_repaint(tick, &mut spin, &mut breathe);
                    u.handle_local_input(kind)
                };
                if !local_input && !u.asleep {
                    u.tick_deadlines();
                }
            }
        }
        Timer::after_millis(100).await;
    }
}

#[cfg(test)]
#[path = "status_tests.rs"]
mod tests;
