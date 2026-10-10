// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The touchless menu's persisted config: the entry delay the SETTINGS page last
//! confirmed, and whether the panel is drawn 180° rotated for a reversible USB-C
//! plug.
//!
//! It is a record of its own ([`EF_MENU_CONF`]) rather than two more bits in the
//! touch build's `EF_DISPLAY` (`0xE030`). That record belongs to `rsk-display`,
//! which this build does not pull in, and its one writer carries only the flags
//! it knows: a flip bit it has never heard of would be cleared by the first
//! touch-build boot after a reflash, and keeping it would mean editing the touch
//! build's write path for a setting it does not have. `0xE0xx` is the
//! display-config area, so a factory reset clears this one exactly as it clears
//! `EF_DISPLAY`.

/// The menu's config record: two bytes, `[delay option index, flip flag]`. A
/// record from an older build may be shorter — see [`MenuConf::decode`].
pub const EF_MENU_CONF: u16 = 0xE031;

/// The selectable entry delays, in seconds, in menu order.
pub const DELAY_OPTIONS_S: [u16; 4] = [3, 5, 10, 30];

/// The delay a device with no usable record waits — the pre-settings behaviour.
/// `usize`, because it indexes [`DELAY_OPTIONS_S`] as well as seeding the record.
pub const DEFAULT_DELAY_IDX: usize = 3;

/// The menu's persisted settings, decoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MenuConf {
    /// Index into [`DELAY_OPTIONS_S`].
    pub delay_idx: u8,
    /// Whether the panel is rotated 180°.
    pub flip: bool,
}

impl Default for MenuConf {
    fn default() -> Self {
        Self {
            delay_idx: DEFAULT_DELAY_IDX as u8,
            flip: false,
        }
    }
}

impl MenuConf {
    /// Decode a record `n` bytes long. A missing record, a one-byte one from an
    /// older build, or a delay index this build does not list keeps that field's
    /// default rather than refusing the boot — the record is read once, at boot,
    /// and a newer or older layout must not be able to brick it.
    pub fn decode(rec: &[u8], n: usize) -> Self {
        let mut out = Self::default();
        if n >= 1 && (rec[0] as usize) < DELAY_OPTIONS_S.len() {
            out.delay_idx = rec[0];
        }
        out.flip = n >= 2 && rec[1] != 0;
        out
    }

    /// The record bytes, in the order [`decode`](Self::decode) reads them.
    pub fn encode(&self) -> [u8; 2] {
        [self.delay_idx, self.flip as u8]
    }

    /// The delay this config selects, in milliseconds. Total on purpose: a
    /// hand-built index outside the table reads as the longest delay rather than
    /// indexing past it.
    pub fn delay_ms(&self) -> u32 {
        let idx = (self.delay_idx as usize).min(DELAY_OPTIONS_S.len() - 1);
        u32::from(DELAY_OPTIONS_S[idx]) * 1000
    }
}

#[cfg(test)]
#[path = "menu_conf_tests.rs"]
mod tests;
