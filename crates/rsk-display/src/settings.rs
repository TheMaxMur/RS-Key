// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The on-device Settings menu and the persisted display settings.

use super::gates::PinScope;
use super::status::{adjust_sleep, adjust_timeout};
use super::*;

/// Persisted display-settings record: the backlight level and display-sleep timeout
/// edited in Settings → Display, read at boot ([`Ui::new`]) and rewritten on
/// Settings exit ([`Ui::persist_settings`]) so they survive a reboot. In the system
/// config FID range next to `EF_PHY` (`0xE020`) / `EF_META`, outside every applet's
/// reset scope; not reachable by any host APDU. The touch timeout is *not* here — it
/// rides `EF_PHY`'s `PresenceTimeout` tag, the same record `rsk hw --touch-timeout`
/// writes (see [`rsk_ui::DisplayConfig`]).
pub(super) const EF_DISPLAY: u16 = 0xE030;

/// What a Settings page did with a tap. The menu used to carry this as three
/// separate mutable locals — a `repaint` flag, a reassigned `page`, and a `break`
/// per exit — spread across six inline page arms, so what a tap could do was only
/// visible by reading all of them.
enum Nav {
    /// Nothing was hit: no repaint, stay put.
    Idle,
    /// Handled on this page (a knob moved, a sub-modal ran) — repaint it.
    Stay,
    /// Go to another page and paint that.
    Goto(SettingsPage),
    /// Leave the menu, handing the ambient loop its next destination.
    Leave(Option<NavTab>),
}

/// The −/+ of an adjust page, or `None` for Back / a miss — which [`adjust_exit`]
/// then tells apart. Split out because all three adjust pages decode the same two
/// keys and differ only in what they do with the step.
fn adjust_step(p: rsk_ui::Point) -> Option<i8> {
    match rsk_ui::hit_adjust(p) {
        Some(AdjustKey::Minus) => Some(-1),
        Some(AdjustKey::Plus) => Some(1),
        _ => None,
    }
}

/// Back returns to the Display list; anything else on an adjust page is a miss.
fn adjust_exit(p: rsk_ui::Point) -> Nav {
    if matches!(rsk_ui::hit_adjust(p), Some(AdjustKey::Back)) {
        Nav::Goto(SettingsPage::Display)
    } else {
        Nav::Idle
    }
}

/// Display: the back chevron, or a drill-down into one of the three knobs.
fn settings_display(p: rsk_ui::Point) -> Nav {
    if rsk_ui::hit_title_back(p) {
        return Nav::Goto(SettingsPage::Root);
    }
    match rsk_ui::hit_display(p) {
        Some(DisplayEntry::Brightness) => Nav::Goto(SettingsPage::Brightness),
        Some(DisplayEntry::Sleep) => Nav::Goto(SettingsPage::Sleep),
        Some(DisplayEntry::Timeout) => Nav::Goto(SettingsPage::Timeout),
        None => Nav::Idle,
    }
}

/// Display sleep: the blanking deadline, a plain atomic — no `self` in reach of it.
fn settings_sleep(p: rsk_ui::Point, dirty: &mut bool) -> Nav {
    let Some(step) = adjust_step(p) else {
        return adjust_exit(p);
    };
    *dirty |= adjust_sleep(step);
    Nav::Stay
}

impl<'a, P, T, H, S, R> Ui<'a, P, T, H, S, R>
where
    P: DrawTarget<Color = Rgb565>,
    T: TouchPad,
    H: Hooks,
    S: rsk_fs::Storage,
    R: rsk_sdk::Rng,
{
    /// Paint a settings page, snapshotting the live brightness/timeout/identity into
    /// the view. Clears `shown` so the ambient loop repaints once the menu releases
    /// the panel.
    fn render_settings(&mut self, page: SettingsPage) {
        // Read every store-backed flag under ONE borrow: multiple `self.fs.borrow_mut()`
        // temporaries in a single expression all live to the end of the statement, so a
        // second one would panic the RefCell (`already borrowed`).
        let (device_pin_set, fido_pin_set, backup_sealed) = {
            let mut fs = self.fs.borrow_mut();
            (
                rsk_fido::passkeys::device_pin_is_set(&mut fs),
                rsk_fido::passkeys::pin_is_set(&mut fs),
                rsk_fido::passkeys::backup_sealed(&mut fs),
            )
        };
        let view = SettingsView {
            page,
            brightness: self.brightness,
            timeout_secs: (self.hooks.presence_timeout_ms() / 1000) as u16,
            sleep_secs: (SLEEP_TIMEOUT_MS.load(Ordering::Relaxed) / 1000) as u16,
            version: self.info.version,
            chipid: self.info.chipid,
            device_pin_set,
            fido_pin_set,
            backup_sealed,
        };
        let _ = rsk_ui::render(&mut self.panel, &Screen::Settings(view));
        self.shown = None;
    }

    /// The interactive on-device settings menu. Synchronous and busy-waiting like the
    /// confirm / PIN modals, so it owns the panel with the same natural mutual
    /// exclusion against the worker (single thread executor: while this spins, no
    /// applet command is serviced — bounded by [`MENU_INACTIVITY_MS`]). Navigates
    /// Root → sub-pages, applies brightness/timeout live, and hands the panel back to
    /// the ambient status loop on Close / Back or after the inactivity timeout.
    pub(super) fn run_settings(&mut self) -> Option<NavTab> {
        // Render first (so the switch feels instant), then let the opening finger lift
        // before polling so it isn't read as the first menu tap. The Root page now carries
        // the four-tab nav (Settings is a top-level tab), so it returns the next nav
        // destination like the other tabs; sub-pages still exit via their back chevron.
        let mut page = SettingsPage::Root;
        self.render_settings(page);
        self.touch
            .wait_release(Instant::now(), Duration::from_millis(MENU_INACTIVITY_MS));
        let mut last = Instant::now();
        let idle_limit = Duration::from_millis(MENU_INACTIVITY_MS);
        let persist_after = Duration::from_millis(SETTINGS_PERSIST_QUIET_MS);

        // Track whether the user actually changed a knob, so the persist on exit is one
        // flash write per editing session (on every exit path), not one per −/+ tap.
        let mut display_dirty = false;
        let mut presence_dirty = false;

        let next = loop {
            // The power button sleeps from inside the menu too, not just on Home.
            if self.sleep_button_pressed() {
                break None;
            }
            if let Some(p) = self.touch.read() {
                last = Instant::now();
                let repaint = match match page {
                    SettingsPage::Root => self.settings_root(p, &mut last),
                    SettingsPage::Display => settings_display(p),
                    SettingsPage::Security => self.settings_security(p, &mut last),
                    SettingsPage::Brightness => self.settings_brightness(p, &mut display_dirty),
                    SettingsPage::Timeout => self.settings_timeout(p, &mut presence_dirty),
                    SettingsPage::Sleep => settings_sleep(p, &mut display_dirty),
                } {
                    Nav::Leave(next) => break next,
                    Nav::Idle => false,
                    Nav::Stay => true,
                    Nav::Goto(next) => {
                        page = next;
                        true
                    }
                };
                // A sub-modal (e.g. the audit log) may have slept + locked via the power
                // button; if so, unwind without repainting over the now-blanked panel —
                // status_task owns the asleep/Locked state from here.
                if self.asleep {
                    break None;
                }
                // One tap = one action: wait for release (bounded) before the next.
                self.touch.wait_release(last, idle_limit);
                if repaint {
                    self.render_settings(page);
                }
            }
            // Flush an edit that has settled, instead of waiting for the menu to
            // close. A USB key is unplugged, not shut down, so "persist on exit"
            // silently loses a change the user has already watched take effect —
            // and the settings screen is exactly where they decide they are done.
            // One quiet moment still coalesces a run of −/+ taps into a single
            // write, which is what keeps this churn out of the credential pages.
            if (display_dirty || presence_dirty) && last.elapsed() >= persist_after {
                self.persist_settings(display_dirty, presence_dirty);
                display_dirty = false;
                presence_dirty = false;
            }
            // A host command is queued — yield to the parked worker at once, rather
            // than making it wait out the (now generous) inactivity bound.
            if self.hooks.host_request_pending_after(last) || last.elapsed() >= idle_limit {
                break None;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        };

        // Whatever the debounce above has not already written — an edit made in the
        // last moment before Back, a tab switch or the power button.
        self.persist_settings(display_dirty, presence_dirty);
        self.end_modal();
        next
    }

    /// Root: the four-tab nav, or a drill-down into a sub-page.
    fn settings_root(&mut self, p: rsk_ui::Point, last: &mut Instant) -> Nav {
        // The bottom nav switches tabs directly (Settings is a top-level tab now):
        // Home → idle, the others hand off to that tab's modal.
        if let Some(tab) = rsk_ui::hit_nav(p) {
            return match tab {
                NavTab::Settings => Nav::Idle,
                NavTab::Home => Nav::Leave(None),
                NavTab::Passkeys => Nav::Leave(Some(NavTab::Passkeys)),
                NavTab::Apps => Nav::Leave(Some(NavTab::Apps)),
            };
        }
        match rsk_ui::hit_settings_root(p) {
            // Display drills into the brightness / sleep / touch-timeout knobs.
            Some(RootEntry::Display) => Nav::Goto(SettingsPage::Display),
            // Security drills into Set/Change PIN + Factory reset (the destructive
            // reset lives one tap deeper).
            Some(RootEntry::Security) => Nav::Goto(SettingsPage::Security),
            // Firmware: the installed-version + reboot-to-update sub-flow. A
            // completed update hold queues a reboot and returns `true` — leave the
            // menu so the ambient loop can park and hand the executor to the worker,
            // which scrubs + resets. A cancel falls back to this list.
            Some(RootEntry::Firmware) => {
                if self.run_firmware() {
                    return Nav::Leave(None);
                }
                *last = Instant::now();
                Nav::Stay
            }
            None => Nav::Idle,
        }
    }

    /// Security: each row runs its own modal, which may take many seconds — so the
    /// inactivity clock restarts when one returns, not when the tap landed.
    fn settings_security(&mut self, p: rsk_ui::Point, last: &mut Instant) -> Nav {
        if rsk_ui::hit_title_back(p) {
            return Nav::Goto(SettingsPage::Root);
        }
        match rsk_ui::hit_security(p) {
            Some(SecurityEntry::DevicePin) => self.run_set_pin(PinScope::Device),
            Some(SecurityEntry::FidoPin) => self.run_set_pin(PinScope::Fido),
            Some(SecurityEntry::PivPin) => self.run_piv_pins(),
            Some(SecurityEntry::AuditLog) => self.run_auditlog(),
            Some(SecurityEntry::Backup) => self.run_backup(),
            // A confirmed reset queues the reboot and returns `true` — leave at once
            // so nothing runs between the wipe and the reset (`persist_settings`
            // would otherwise re-create EF_DISPLAY, carrying `pin_declined` across
            // the factory reset). A cancel falls back to this page.
            Some(SecurityEntry::FactoryReset) => {
                if self.run_factory_reset() {
                    return Nav::Leave(None);
                }
            }
            None => return Nav::Idle,
        }
        *last = Instant::now();
        Nav::Stay
    }

    /// Brightness: −/+ applies live, and only a value that actually moved marks the
    /// session dirty — a tap at a clamp boundary must not cost a flash write.
    fn settings_brightness(&mut self, p: rsk_ui::Point, dirty: &mut bool) -> Nav {
        let Some(step) = adjust_step(p) else {
            return adjust_exit(p);
        };
        let was = self.brightness;
        self.set_brightness(rsk_ui::step_brightness(self.brightness, step));
        *dirty |= self.brightness != was;
        Nav::Stay
    }

    /// Touch timeout: the presence wait, which rides `EF_PHY` rather than
    /// `EF_DISPLAY` — hence its own dirty flag.
    fn settings_timeout(&mut self, p: rsk_ui::Point, dirty: &mut bool) -> Nav {
        let Some(step) = adjust_step(p) else {
            return adjust_exit(p);
        };
        *dirty |= adjust_timeout(&mut self.hooks, step);
        Nav::Stay
    }

    /// Persist the display settings the user edited so they survive a reboot. Called
    /// once on Settings exit (every exit path — Back, a tab switch, the inactivity
    /// timeout, the power button), not per −/+ tap, so a tweak costs one flash write
    /// rather than one per step. Brightness + display-sleep live in `EF_DISPLAY`; the
    /// touch timeout shares `EF_PHY`'s `PresenceTimeout` tag with
    /// `rsk hw --touch-timeout`, so it is read-modify-written there (preserving the
    /// other phy fields) to keep a single source of truth — last writer wins, and an
    /// on-panel edit snaps to the menu's choices, so it overwrites a custom value a
    /// host set. Synchronous, like the other display-task flash writes — the worker is
    /// parked while this runs.
    fn persist_settings(&mut self, save_display: bool, save_presence: bool) {
        if save_display {
            self.save_display_config();
        }
        if save_presence {
            let secs = (self.hooks.presence_timeout_ms() / 1000) as u8;
            let mut fs = self.fs.borrow_mut();
            let mut phy = rsk_rescue::phy::load(&mut fs).unwrap_or_default();
            phy.presence_timeout = Some(secs);
            let _ = rsk_rescue::phy::save(&mut fs, &phy);
        }
    }

    /// Write the live display settings (brightness + sleep) plus the persisted
    /// `pin_declined` flag to `EF_DISPLAY` in one record. Every `EF_DISPLAY` write goes
    /// through here so the onboarding flag is never dropped by a brightness/sleep save (and
    /// vice-versa) — the record carries all three fields. Synchronous; the worker is parked.
    pub(super) fn save_display_config(&mut self) {
        let cfg = rsk_ui::DisplayConfig {
            brightness: self.brightness,
            sleep_secs: (SLEEP_TIMEOUT_MS.load(Ordering::Relaxed) / 1000) as u16,
            pin_declined: self.pin_declined,
        };
        let _ = self.fs.borrow_mut().put(EF_DISPLAY, &cfg.encode());
    }
}

#[cfg(test)]
#[path = "settings_tests.rs"]
mod tests;
