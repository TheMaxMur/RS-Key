// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! [`Platform`] for the emulator: a session RTC, and honest "no" answers about
//! everything the RP2350 fuses back.
//!
//! Secure boot reports **disabled**, and both fuse burns refuse. That is not a
//! stub to fill in later — the emulator has no OTP, so a "locked" answer would
//! be a lie a host tool could act on, and a fuse burn it accepted would report
//! an irreversible step that never happened.

use std::time::Instant;

use rsk_rescue::{Platform, SecureBootStatus, rollback::RollbackRaw};

pub struct EmuPlatform {
    boot: Instant,
    /// Epoch base + the uptime it was set at, so `now` advances like the
    /// firmware's session RTC and is likewise lost when the process exits.
    epoch: Option<(u32, u32)>,
    /// Set by a host reboot request; the device loop reports it and carries on.
    pub reboot_requested: Option<bool>,
}

impl EmuPlatform {
    pub fn new() -> Self {
        Self {
            boot: Instant::now(),
            epoch: None,
            reboot_requested: None,
        }
    }

    fn uptime_secs(&self) -> u32 {
        self.boot.elapsed().as_secs() as u32
    }
}

impl Platform for EmuPlatform {
    fn secure_boot_status(&self) -> SecureBootStatus {
        SecureBootStatus {
            enabled: false,
            locked: false,
            bootkey: 0xFF,
        }
    }

    fn now(&self) -> Option<u32> {
        let (base, at) = self.epoch?;
        Some(base.wrapping_add(self.uptime_secs().wrapping_sub(at)))
    }

    fn set_time(&mut self, epoch: u32) {
        self.epoch = Some((epoch, self.uptime_secs()));
    }

    fn request_reboot(&mut self, bootsel: bool) {
        self.reboot_requested = Some(bootsel);
    }

    fn read_page58_lock_raw(&self) -> Option<u32> {
        None
    }

    fn lock_page58(&mut self) -> bool {
        false
    }

    fn read_rollback_raw(&self) -> Option<RollbackRaw> {
        None
    }

    fn set_rollback_required(&mut self) -> bool {
        false
    }
}
