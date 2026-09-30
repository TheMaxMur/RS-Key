// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Page-58 hard-lock decision. The MKEK/DEVK live in OTP page 58; their lock row
//! PAGE58_LOCK1 (0xFF5) is in page 63, which RP2350 ships bootloader-read-only, so
//! only secure firmware can write it — one idempotent, guarded fuse write, never at boot.

/// OTP row of PAGE58_LOCK1 (= PAGE0_LOCK0 0xF80 + 58*2 + 1).
pub const PAGE58_LOCK1_ROW: usize = 0xFF5;

/// The lock an older build burnt, and the host ritual still tries: byte 0x3C in
/// each of the row's three majority-vote copies. 0x3C = LOCK_S 0 (secure
/// read-write — the firmware keeps reading the keys), LOCK_NS 3 and LOCK_BL 3
/// (inaccessible). Once it lands, `picotool otp get` can no longer read the keys.
pub const PAGE58_LOCK_VALUE: u32 = 0x3C_3C_3C;

/// The lock this build burns, and the fuse latch: 0x3D is 0x3C with LOCK_S 1
/// (secure read-only, still reads the keys). Burnt only over a finished migration,
/// it closes the arms below the OTP root ([`arms_closed`]); 0x3C to 0x3D sets bits.
pub const PAGE58_LATCH_VALUE: u32 = 0x3D_3D_3D;

/// What to do given the current raw value of PAGE58_LOCK1.
#[derive(Debug, PartialEq, Eq)]
pub enum LockDecision {
    /// Row is blank — write the latch.
    Write,
    /// Row holds a subset of the latch — an older build's lock, or a burn a power
    /// cut tore — and a burn completes it, under the same guards as a first lock.
    Latch,
    /// Row already holds the latch — idempotent no-op.
    AlreadyLocked,
    /// Row holds a bit outside the latch — a foreign value — refuse. OTP bits only
    /// ever go 0→1, so ORing our value into it could land a different,
    /// unintended access config; never clobber.
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

/// READ `1E/07`'s answer for a boot that could not read the fused key and so ran no
/// seal pass: under the chip-serial arm each would re-seal, provision or migrate
/// what only the fused root should hold.
pub const PRE_OTP_KEY_UNREADABLE: u16 = 0xFFFE;

/// What a fused key's rows read as.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum KeyRows {
    /// Every row reads zero: the factory state, a board never provisioned.
    Blank,
    /// A row holds data: the key is fused.
    Fused,
    /// A row did not read: the page is closed even to secure code, which is a
    /// misconfiguration and never the factory state.
    Unreadable,
}

/// Classify a key from its raw 24-bit rows, `None` for a row the OTP block refused.
pub fn key_rows(raw: impl IntoIterator<Item = Option<u32>>) -> KeyRows {
    let mut any = false;
    for word in raw {
        let Some(word) = word else {
            return KeyRows::Unreadable;
        };
        any |= word & 0x00FF_FFFF != 0;
    }
    if any { KeyRows::Fused } else { KeyRows::Blank }
}

/// Decide the lock action purely from the row's current raw value.
pub fn lock_decision(current_raw: u32) -> LockDecision {
    match current_raw {
        0 => LockDecision::Write,
        PAGE58_LATCH_VALUE => LockDecision::AlreadyLocked,
        // A burn only sets bits, so over a subset it lands exactly on the latch.
        raw if raw & !PAGE58_LATCH_VALUE == 0 => LockDecision::Latch,
        _ => LockDecision::Unexpected,
    }
}

/// Whether PAGE58_LOCK1 carries the latch, the row's three copies voting as the
/// hardware reads them: the boot then closes every arm below the OTP root.
pub fn arms_closed(raw: u32) -> bool {
    let byte = |i: u32| (raw >> (8 * i)) & 0xFF;
    crate::rollback::majority([byte(0), byte(1), byte(2)]) == PAGE58_LATCH_VALUE & 0xFF
}

#[cfg(test)]
#[path = "otp_lock_tests.rs"]
mod tests;
