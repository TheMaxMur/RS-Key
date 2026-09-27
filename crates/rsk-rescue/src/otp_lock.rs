// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Page-58 hard-lock decision. The MKEK/DEVK live in OTP page 58; their lock row
//! PAGE58_LOCK1 (0xFF5) is in page 63, which RP2350 ships bootloader-read-only, so
//! only secure firmware can write it — one idempotent, guarded fuse write, never at boot.

/// OTP row of PAGE58_LOCK1 (= PAGE0_LOCK0 0xF80 + 58*2 + 1).
pub const PAGE58_LOCK1_ROW: usize = 0xFF5;

/// The only value the firmware will ever write to that row: byte 0x3C in each
/// of the row's three majority-vote copies. 0x3C = LOCK_S 0 (secure read-write —
/// the firmware keeps reading the keys), LOCK_NS 3 and LOCK_BL 3 (inaccessible).
/// Once it lands, `picotool otp get` can no longer read the page-58 keys.
pub const PAGE58_LOCK_VALUE: u32 = 0x3C_3C_3C;

/// What to do given the current raw value of PAGE58_LOCK1.
#[derive(Debug, PartialEq, Eq)]
pub enum LockDecision {
    /// Row is blank — write the lock.
    Write,
    /// Row already holds exactly our value — idempotent no-op.
    AlreadyLocked,
    /// Row holds some other (partial / foreign) value — refuse. OTP bits only
    /// ever go 0→1, so ORing our value into a non-zero row could land a
    /// different, unintended access config; never clobber.
    Unexpected,
}

/// What a boot's seal passes left under the pre-burn key: the record a flash writer
/// could plant under the public chip-serial key, which the next boot would launder
/// onto the fused root (audit run-27 #8). One bit per pass; the lock burns only over 0.
pub const PRE_OTP_FIDO: u16 = 1 << 0;
pub const PRE_OTP_DEVICE_KEY: u16 = 1 << 1;
pub const PRE_OTP_PIV: u16 = 1 << 2;
pub const PRE_OTP_OATH: u16 = 1 << 3;
pub const PRE_OTP_OTP: u16 = 1 << 4;

/// READ `1E/07`'s answer for a boot that ran its seal passes without the fused key,
/// so checked nothing: every bit set.
pub const PRE_OTP_UNCHECKED: u16 = u16::MAX;

/// Decide the lock action purely from the row's current raw value.
pub fn lock_decision(current_raw: u32) -> LockDecision {
    match current_raw {
        0 => LockDecision::Write,
        PAGE58_LOCK_VALUE => LockDecision::AlreadyLocked,
        _ => LockDecision::Unexpected,
    }
}

#[cfg(test)]
#[path = "otp_lock_tests.rs"]
mod tests;
