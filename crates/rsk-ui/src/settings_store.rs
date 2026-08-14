// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `EF_DISPLAY` wire-format codec — the persisted on-device display settings the
//! trusted-display firmware reads at boot and writes when the user edits them in
//! Settings → Display.
//!
//! The block is `[brightness, sleep_secs_be(2), flags]` (4 bytes): the backlight
//! level (`1..=BRIGHTNESS_LEVELS`), the display-sleep timeout in seconds (`0` =
//! Off), and a flags byte (currently only [`FLAG_PIN_DECLINED`] — the user chose
//! "continue without a device PIN" at first-run, so the panel must not re-prompt).
//! The **touch timeout** is *not* here — it persists in the phy record's
//! `PresenceTimeout` tag (shared with `rsk hw --touch-timeout`), so it keeps one
//! source of truth.
//!
//! [`DisplayConfig::apply_block`] overlays a stored block onto a default `self`,
//! field by field, so a record written by an *older* firmware (the original
//! `CORE_LEN`-byte block, no flags) or read by an *older* firmware (a future,
//! longer block — only its known prefix is read) survives a firmware upgrade
//! without losing or misreading a field; anything a shorter block omits keeps its
//! current value. [`DisplayConfig::default`] mirrors the firmware's live defaults,
//! so a device with no record behaves exactly as before.
//!
//! Like `rsk-led`'s codec this crate is pure (no `embassy` / HAL), so the format is
//! unit-testable on the host; `firmware/src/display.rs` owns the live brightness
//! field and the `SLEEP_TIMEOUT_MS` atomic and marshals them through here.

/// `EF_DISPLAY` length: `[brightness, sleep_secs_be(2), flags]`.
pub const CONF_LEN: usize = 4;

/// The original layout (`[brightness, sleep_secs_be(2)]`, no flags byte). A record
/// written before the flags byte existed is exactly this long; [`DisplayConfig::apply_block`]
/// still reads its two fields and leaves the flags at their default, so an already-provisioned
/// device keeps its brightness / sleep across the upgrade that added the byte.
const CORE_LEN: usize = 3;

/// Flags-byte bit 0: the user chose "continue without a device PIN" at the
/// first-run prompt. Set, the panel never re-shows that onboarding screen (until a
/// factory reset wipes `EF_DISPLAY`); clear (the default), a PIN-less device is
/// offered the prompt once.
pub const FLAG_PIN_DECLINED: u8 = 0x01;

/// Default display-sleep timeout in seconds — the single source of truth: the
/// firmware derives its `DEFAULT_SLEEP_MS` from it, so a device with no record
/// blanks on the same schedule it did before this record existed.
pub const DEFAULT_SLEEP_SECS: u16 = 60;

/// The persisted display settings: backlight level, the display-sleep timeout, and
/// the first-run PIN-prompt flag.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DisplayConfig {
    /// Backlight level `1..=BRIGHTNESS_LEVELS`. Stored raw; the firmware clamps it
    /// to the valid range when it applies it to the PWM, so a corrupt or
    /// out-of-range byte can never blank or over-drive the panel.
    pub brightness: u8,
    /// Display-sleep timeout in seconds; `0` = Off (never blanks).
    pub sleep_secs: u16,
    /// The user has dismissed the first-run "set a device PIN?" prompt by choosing
    /// to continue without one — so the panel must not re-offer it. Cleared on a
    /// factory reset (which wipes the record), so a wiped device re-onboards.
    pub pin_declined: bool,
}

impl Default for DisplayConfig {
    fn default() -> Self {
        Self {
            brightness: crate::BRIGHTNESS_LEVELS,
            sleep_secs: DEFAULT_SLEEP_SECS,
            pin_declined: false,
        }
    }
}

impl DisplayConfig {
    /// Pack into the 4-byte wire block: `[brightness, sleep_secs_be, flags]`
    /// (big-endian sleep, matching the phy record's byte order).
    pub fn encode(&self) -> [u8; CONF_LEN] {
        let s = self.sleep_secs.to_be_bytes();
        let flags = if self.pin_declined {
            FLAG_PIN_DECLINED
        } else {
            0
        };
        [self.brightness, s[0], s[1], flags]
    }

    /// Overlay a stored block onto `self`, field by field. The brightness + sleep
    /// pair is read from any block at least `CORE_LEN` long (so the original
    /// flags-less record still loads, keeping `pin_declined` at its default); the
    /// flags byte is read only from a full [`CONF_LEN`] block. A future, longer
    /// block is read up to its known prefix. Anything shorter than `CORE_LEN` can
    /// only be flash corruption, so those fields stay at their defaults rather than
    /// half-applied.
    pub fn apply_block(&mut self, b: &[u8]) {
        if b.len() >= CORE_LEN {
            self.brightness = b[0];
            self.sleep_secs = u16::from_be_bytes([b[1], b[2]]);
        }
        if b.len() >= CONF_LEN {
            self.pin_declined = b[3] & FLAG_PIN_DECLINED != 0;
        }
    }
}

#[cfg(kani)]
#[path = "settings_store_kani.rs"]
mod proofs;

#[cfg(test)]
#[path = "settings_store_tests.rs"]
mod tests;
