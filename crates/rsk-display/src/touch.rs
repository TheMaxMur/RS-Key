// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The touch controller, as this flow needs it: one non-blocking sample, plus the
//! release waits built on top of it.

use super::*;

/// Shortest window [`TouchPad::wait_release_ceremony`] absorbs a leftover finger
/// for, whatever deadline the host handed the ceremony.
const RELEASE_FLOOR_MS: Duration = Duration::from_millis(3_000);

/// A touch panel. The only thing an implementation must supply is one sample; the
/// debounce waits below are pure logic over it and a clock, so the firmware's
/// CST328 and the emulator's mouse share them rather than each growing a copy.
pub trait TouchPad {
    /// The first finger's coordinate, if any, in panel pixels. Reading is expected
    /// to *consume* the report so the next one can be served, and any transport
    /// error reads as "no touch".
    fn read(&mut self) -> Option<rsk_ui::Point>;

    /// Block until the finger lifts (bounded by `start + timeout`), so one tap maps
    /// to one key press — a panel reports contact continuously while touched. Used
    /// by the PIN pad, where a held finger must not machine-gun a digit.
    fn wait_release(&mut self, start: Instant, timeout: Duration) {
        self.wait_release_until(start + timeout);
    }

    /// [`Self::wait_release`] for a host consent ceremony, which never waits less
    /// than [`RELEASE_FLOOR_MS`]: a host can shorten the presence timeout, and an
    /// expiry that returns here with the finger still down degrades the debounce
    /// into a no-op for a level-triggered caller. Only the ceremonies take the
    /// floor — a menu's deadline is the UI's own idle limit, and stalling it on a
    /// resting finger is a UI bug, not a consent question.
    fn wait_release_ceremony(&mut self, start: Instant, timeout: Duration) {
        self.wait_release_until((start + timeout).max(Instant::now() + RELEASE_FLOOR_MS));
    }

    fn wait_release_until(&mut self, deadline: Instant) {
        while self.read().is_some() {
            if Instant::now() >= deadline {
                break;
            }
            block_for(Duration::from_millis(TOUCH_POLL_MS));
        }
    }
}
