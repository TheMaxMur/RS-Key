// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Display sleep/wake, backlight brightness, and the wake/power button.

use super::*;

/// The locked-hint breathe advances one shade every this many ~100ms status-loop ticks, so
/// the 8-shade ramp cycles in ~2.4s (the design's breathe period).
pub(super) const BREATHE_TICKS: u32 = 3;

impl Ui {
    /// Apply a brightness level (`1..=BRIGHTNESS_LEVELS`) to the backlight PWM and
    /// remember it for the menu's gauge.
    pub(super) fn set_brightness(&mut self, level: u8) {
        self.brightness = level.clamp(1, BRIGHTNESS_LEVELS);
        self.bl
            .set_config(&backlight_cfg(level_duty(self.brightness)));
    }

    /// Blank the panel after the inactivity timeout: backlight off, then clear the
    /// glass to black. A *static* image is what burns into the IPS panel, so dropping
    /// it entirely (not just dimming) is the retention guard. Idempotent.
    fn sleep(&mut self) {
        if self.asleep {
            return;
        }
        self.bl.set_config(&backlight_cfg(0));
        let _ = self.panel.clear(Rgb565::BLACK);
        self.shown = None;
        self.asleep = true;
    }

    /// Restore the panel from sleep: backlight back to the saved brightness; the caller
    /// (the ambient loop, or a host ceremony) repaints. Idempotent.
    pub(super) fn wake(&mut self) {
        if !self.asleep {
            return;
        }
        self.bl
            .set_config(&backlight_cfg(level_duty(self.brightness)));
        self.asleep = false;
        self.shown = None;
    }

    /// One non-blocking touch sample that only reports a contact the user began on
    /// the screen now showing. The panel reports level, not edges, so a finger still
    /// down when an ambient screen is painted would otherwise be judged as a tap on
    /// it — see [`Ui::touch_armed`]. Seeing the panel untouched arms the next tap.
    pub(super) fn armed_touch(&mut self) -> Option<rsk_ui::Point> {
        match self.touch.read() {
            None => {
                self.touch_armed = true;
                None
            }
            Some(p) if self.touch_armed => Some(p),
            // Still the contact that predates this screen: ignore, stay disarmed.
            Some(_) => None,
        }
    }

    /// One non-blocking sample of the wake button (if wired), honouring its polarity.
    pub(super) fn wake_pressed(&self) -> bool {
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

    /// Enter display sleep, additionally locking the on-device UI when a device PIN is
    /// set — so a walked-away device requires the PIN to browse passkeys / settings on
    /// wake. Without a PIN there is nothing to unlock with, so it only blanks.
    ///
    /// Called from host-ceremony screens too (the built-in-UV pad, an Approve/Deny prompt),
    /// where the worker still holds `fs` borrowed for the whole command — so read the
    /// PIN-set bit with `try_borrow_mut` and fall back to the cached `home_pin_set` rather
    /// than double-borrowing. That fallback is accurate: a device PIN can't change mid-
    /// ceremony, and it stays fresh past an on-device set (see [`Ui::run_set_pin`]).
    pub(super) fn enter_sleep(&mut self) {
        let pin_set = match self.fs.try_borrow_mut() {
            Ok(mut fs) => rsk_fido::passkeys::device_pin_is_set(&mut fs),
            Err(_) => self.home_pin_set,
        };
        if pin_set {
            self.locked = true;
        }
        self.sleep();
    }

    /// Re-arm the on-device lock without blanking, for the auto-lock deadline that runs
    /// independently of display sleep. Sleep is a display setting the user may switch
    /// off; the lock is a security control, so it must not be switchable off with it —
    /// nor postponable by a host, which is why its deadline counts from the last *local*
    /// interaction. That second half was not true until run-34 #15: the deadline was
    /// only *evaluated* inside the ambient-quiet window, which every ceremony exit
    /// pushes 400 ms forward, so a loop of unauthenticated `authenticatorSelection`
    /// starved it. `status_task` now evaluates it outside that window.
    /// No-op without a device PIN (nothing to unlock with).
    pub(super) fn lock_now(&mut self) -> bool {
        if self.locked {
            return false;
        }
        let pin_set = match self.fs.try_borrow_mut() {
            Ok(mut fs) => rsk_fido::passkeys::device_pin_is_set(&mut fs),
            Err(_) => self.home_pin_set,
        };
        if pin_set {
            self.locked = true;
        }
        pin_set
    }

    /// Block until the wake button is released (bounded), so a single press toggles
    /// sleep exactly once rather than oscillating while the button is held down.
    pub(super) fn wait_wake_release(&self) {
        let start = Instant::now();
        while self.wake_pressed() {
            if start.elapsed() >= Duration::from_millis(2000) {
                break;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
    }

    /// Poll the sleep/wake button from inside a modal: if pressed, sleep now (auto-locking
    /// like any sleep), wait for release, and return `true` so the caller abandons its wait
    /// and unwinds to the now-asleep [`status_task`]. Called from every blocking on-device
    /// loop — browse modals, the PIN pad, hold-to-confirm, and the host Approve/Deny prompts
    /// — so the power button sleeps the device from *any* screen, not just Home. Each caller
    /// must, after a `true`, either return itself or check `self.asleep` so the sleep
    /// propagates up (a parent loop that keeps polling a blanked panel reads touches blind).
    pub(super) fn sleep_button_pressed(&mut self) -> bool {
        if self.wake_pressed() {
            self.enter_sleep();
            self.wait_wake_release();
            true
        } else {
            false
        }
    }
}
