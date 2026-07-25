// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The CST328 touch controller on I2C1: tap reads and release waits.

use super::*;

/// CST328 7-bit I2C address.
const CST328_ADDR: u16 = 0x1A;

/// Shortest window [`Touch::wait_release_ceremony`] absorbs a leftover finger for,
/// whatever deadline the host handed the ceremony.
const RELEASE_FLOOR_MS: Duration = Duration::from_millis(3_000);

/// The CST328 touch controller on I2C1. Owns only the bus; the reset pin is pulsed
/// once during [`Ui::build`].
pub(super) struct Touch {
    pub(super) i2c: I2c<'static, I2C1, I2cBlocking>,
}

impl Touch {
    /// Leave normal reporting mode set after the reset pulse — write register
    /// 0xD109 (REG_MODE_NORMAL) as a 2-byte big-endian address with no payload.
    pub(super) fn normal_mode(&mut self) {
        let _ = self.i2c.blocking_write(CST328_ADDR, &[0xD1, 0x09]);
    }

    /// Read the first finger's coordinate, if any, then clear the report so the
    /// controller serves the next one. Any I2C error reads as "no touch". The
    /// coordinate is already in panel pixels (the controller is configured at the
    /// panel resolution; HW bringup confirmed the axes need no swap).
    pub(super) fn read(&mut self) -> Option<rsk_ui::Point> {
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

    /// Block until the finger lifts (bounded by `start + timeout`), so one tap maps
    /// to one key press — the CST328 reports continuously while touched. Used by the
    /// PIN pad, where a held finger must not machine-gun a digit.
    pub(super) fn wait_release(&mut self, start: Instant, timeout: Duration) {
        self.wait_release_until(start + timeout);
    }

    /// [`Self::wait_release`] for a host consent ceremony, which never waits less
    /// than [`RELEASE_FLOOR_MS`]: a host can shorten the presence timeout, and an
    /// expiry that returns here with the finger still down degrades the debounce
    /// into a no-op for a level-triggered caller. Only the ceremonies take the
    /// floor — a menu's deadline is the UI's own idle limit, and stalling it on a
    /// resting finger is a UI bug, not a consent question.
    pub(super) fn wait_release_ceremony(&mut self, start: Instant, timeout: Duration) {
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
