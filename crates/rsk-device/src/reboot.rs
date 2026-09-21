// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The device's one reboot slot, which the trusted display parks on. It reads pending from
//! the request until the reset: the worker waits and scrubs after taking it, on the executor
//! the display shares, so a slot that read clear once taken let the panel run in that wait.

use core::sync::atomic::{AtomicU8, Ordering};

const NONE: u8 = 0;
const WARM: u8 = 1;
const BOOTSEL: u8 = 2;
/// Taken, or begun with no request behind it: the reset is under way.
const RESETTING: u8 = 3;

/// A queued reboot and the mode it resets into. Atomic because it is a static every writer
/// reaches — the applets inside the worker, a phy write, the panel — all on one executor.
#[derive(Default)]
pub struct RebootSlot {
    state: AtomicU8,
}

impl RebootSlot {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(NONE),
        }
    }

    /// Queue a warm reboot, or one into the BOOTSEL bootloader.
    pub fn queue(&self, bootsel: bool) {
        let mode = if bootsel { BOOTSEL } else { WARM };
        self.state.store(mode, Ordering::Relaxed);
    }

    /// The queued reboot, for the worker to carry out: `Some(1)` warm, `Some(2)` BOOTSEL.
    /// Taking it begins the reset, so the slot stays pending.
    pub fn take(&self) -> Option<u8> {
        self.state
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |state| {
                matches!(state, WARM | BOOTSEL).then_some(RESETTING)
            })
            .ok()
    }

    /// The worker has begun a reset, taken or not: Management RESET's wipe queues none.
    pub fn begin_reset(&self) {
        self.state.store(RESETTING, Ordering::Relaxed);
    }

    /// Whether a reboot is queued or under way — true from the request until the reset.
    pub fn pending(&self) -> bool {
        self.state.load(Ordering::Relaxed) != NONE
    }
}

#[cfg(test)]
#[path = "reboot_tests.rs"]
mod tests;
