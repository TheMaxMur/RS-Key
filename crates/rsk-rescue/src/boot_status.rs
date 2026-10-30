// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Decode the physical OTP copies used by the read-only Rescue status.

use crate::SecureBootStatus;

pub const CRIT1_ROW: usize = 0x40;
pub const CRIT1_COPIES: usize = 8;
pub const BOOT_FLAGS1_ROW: usize = 0x4b;
const PAGE_LOCK_ROWS: [usize; 2] = [0xf83, 0xf85];
const PAGE_LOCK_BL_NS_RO: u32 = 0x141414;
const HARDEN_MASK: u32 = (1 << 1) | (1 << 2) | (1 << 4) | (3 << 5);

/// Read all copies; an unreadable row cannot establish a boot-policy claim.
pub fn read_status(mut read: impl FnMut(usize) -> Option<u32>) -> SecureBootStatus {
    let unknown = SecureBootStatus {
        enabled: false,
        locked: false,
        bootkey: 0xff,
    };
    let mut copies = [0; CRIT1_COPIES];
    for (i, value) in copies.iter_mut().enumerate() {
        let Some(raw) = read(CRIT1_ROW + i) else {
            return unknown;
        };
        *value = raw;
    }
    let mut flags = [0; 3];
    for (i, value) in flags.iter_mut().enumerate() {
        let Some(raw) = read(BOOT_FLAGS1_ROW + i) else {
            return unknown;
        };
        *value = raw;
    }
    let flags = crate::rollback::majority(flags);
    let invalid = (flags >> 8) & 0xf;
    let trusted = flags & !invalid & 0xf;
    let bootkey = (0..4u8).find(|i| trusted & (1 << i) != 0);
    let pages_locked = PAGE_LOCK_ROWS
        .into_iter()
        .all(|row| read(row).is_some_and(|raw| raw & PAGE_LOCK_BL_NS_RO == PAGE_LOCK_BL_NS_RO));
    // RP2350 datasheet §13.4: CRIT1 asserts each flag at three of eight copies.
    let enabled = copies.iter().filter(|raw| **raw & 1 != 0).count() >= 3 && bootkey.is_some();
    let locked = enabled
        && trusted.count_ones() == 1
        && invalid | trusted == 0xf
        && pages_locked
        && copies.iter().all(|raw| raw & HARDEN_MASK == HARDEN_MASK);
    SecureBootStatus {
        enabled,
        locked,
        bootkey: bootkey.unwrap_or(0xff),
    }
}

#[cfg(test)]
#[path = "boot_status_tests.rs"]
mod tests;
