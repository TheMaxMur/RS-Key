// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The idle click gesture: N clicks of the presence button while nothing is in
//! flight type slot N's Yubico-OTP ticket over the keyboard interface.
//!
//! It shares one physical button with every consent ceremony, so the rule that
//! matters is the one this module exists to hold: **a press a ceremony consumed
//! is not a click**. The counter runs on the falling edge, and a touch wait can
//! return with the finger still down — so clearing the accumulated state when a
//! dispatch ends (which is all the firmware used to do) cannot suppress an edge
//! that has not happened yet. [`Clicks::consumed_by_ceremony`] marks it instead.
//!
//! Pure logic over `(now_ms, pressed)` so it is host-testable; the firmware keeps
//! the button, the clock and the typing.

/// A multi-click must land within this window to count toward the same gesture,
/// and the gesture fires this long after the last release.
pub const CLICK_WINDOW_MS: u64 = 1000;

/// The click counter: last sampled level, clicks so far, and the ms of the last
/// release.
#[derive(Default)]
pub struct Clicks {
    pressed: bool,
    count: u8,
    last_release_ms: u64,
    /// The button was still down when a dispatch ended, so the release that is
    /// coming belongs to the press that dispatch consumed.
    release_spent: bool,
}

impl Clicks {
    pub const fn new() -> Self {
        Self {
            pressed: false,
            count: 0,
            last_release_ms: 0,
            release_spent: false,
        }
    }

    /// One idle sample. Returns the slot to type when a gesture completes.
    pub fn tick(&mut self, now_ms: u64, pressed: bool) -> Option<u8> {
        if pressed != self.pressed {
            // A release the ceremony already paid for ends the press without
            // counting it; the flag is one-shot, so the next press is a click.
            if !pressed && !core::mem::take(&mut self.release_spent) {
                if self.last_release_ms == 0 || self.last_release_ms + CLICK_WINDOW_MS > now_ms {
                    self.count = self.count.saturating_add(1);
                }
                self.last_release_ms = now_ms;
            }
            self.pressed = pressed;
        }
        // Window closed with the button released → act on the click count.
        if self.last_release_ms > 0
            && self.count > 0
            && self.last_release_ms + CLICK_WINDOW_MS < now_ms
            && !self.pressed
        {
            let slot = self.count;
            self.count = 0;
            self.last_release_ms = 0;
            return Some(slot);
        }
        None
    }

    /// A dispatch has ended: drop any gesture it interrupted, and — if the button
    /// is *still* down — mark the release that press will produce as spent.
    ///
    /// Every dispatch arm must call this, and [`tick`](Self::tick) must not: its
    /// whole job is to accumulate a gesture across the click window.
    pub fn consumed_by_ceremony(&mut self, pressed: bool) {
        self.pressed = pressed;
        self.release_spent = pressed;
        self.count = 0;
        self.last_release_ms = 0;
    }
}

#[cfg(test)]
#[path = "click_tests.rs"]
mod tests;
