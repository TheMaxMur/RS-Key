// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! ISO-7816 status words.

/// A two-byte status word (SW1 SW2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sw(pub u16);

/// Largest remaining-attempt count `63Cx` can carry — SW2's low nibble. A retry
/// total above this needs admin auth to set, so the clamp is display honesty
/// rather than a gate; a YubiKey reports the same ceiling.
const RETRIES_REPORTED_MAX: u8 = 0x0F;

impl Sw {
    #[inline]
    pub const fn new(sw1: u8, sw2: u8) -> Self {
        Sw(((sw1 as u16) << 8) | sw2 as u16)
    }
    #[inline]
    pub const fn sw1(self) -> u8 {
        (self.0 >> 8) as u8
    }
    #[inline]
    pub const fn sw2(self) -> u8 {
        self.0 as u8
    }
    #[inline]
    pub const fn is_ok(self) -> bool {
        self.0 == Self::OK.0
    }
    /// Big-endian bytes, as appended to a response APDU.
    #[inline]
    pub const fn to_bytes(self) -> [u8; 2] {
        [self.sw1(), self.sw2()]
    }

    /// ISO 7816-4 `63Cx` — verification failed, `x` retries remaining, saturating
    /// at `RETRIES_REPORTED_MAX`. Unclamped, `left` past the nibble sets stray
    /// SW2 bits and `0x40` collides with `63C0`, which every host reads as blocked.
    #[inline]
    pub const fn retries(left: u8) -> Self {
        let left = if left > RETRIES_REPORTED_MAX {
            RETRIES_REPORTED_MAX
        } else {
            left
        };
        Sw::new(0x63, 0xC0 | left)
    }

    pub const BYTES_REMAINING_00: Sw = Sw::new(0x61, 0x00);
    pub const WARNING_STATE_UNCHANGED: Sw = Sw::new(0x62, 0x00);
    pub const WARNING_EOF: Sw = Sw::new(0x62, 0x82);
    pub const WARNING_NOINFO: Sw = Sw::new(0x63, 0x00);
    pub const EXEC_ERROR: Sw = Sw::new(0x64, 0x00);
    pub const MEMORY_FAILURE: Sw = Sw::new(0x65, 0x81);
    pub const SECURE_MESSAGE_EXEC_ERROR: Sw = Sw::new(0x66, 0x00);
    pub const WRONG_LENGTH: Sw = Sw::new(0x67, 0x00);
    pub const LOGICAL_CHANNEL_NOT_SUPPORTED: Sw = Sw::new(0x68, 0x81);
    pub const SECURE_MESSAGING_NOT_SUPPORTED: Sw = Sw::new(0x68, 0x82);
    pub const COMMAND_INCOMPATIBLE: Sw = Sw::new(0x69, 0x81);
    pub const SECURITY_STATUS_NOT_SATISFIED: Sw = Sw::new(0x69, 0x82);
    pub const PIN_BLOCKED: Sw = Sw::new(0x69, 0x83);
    pub const DATA_INVALID: Sw = Sw::new(0x69, 0x84);
    pub const CONDITIONS_NOT_SATISFIED: Sw = Sw::new(0x69, 0x85);
    pub const COMMAND_NOT_ALLOWED: Sw = Sw::new(0x69, 0x86);
    pub const APPLET_SELECT_FAILED: Sw = Sw::new(0x69, 0x99);
    pub const INCORRECT_PARAMS: Sw = Sw::new(0x6A, 0x80);
    pub const FUNC_NOT_SUPPORTED: Sw = Sw::new(0x6A, 0x81);
    pub const FILE_NOT_FOUND: Sw = Sw::new(0x6A, 0x82);
    pub const RECORD_NOT_FOUND: Sw = Sw::new(0x6A, 0x83);
    pub const FILE_FULL: Sw = Sw::new(0x6A, 0x84);
    pub const INCORRECT_P1P2: Sw = Sw::new(0x6A, 0x86);
    pub const WRONG_NC: Sw = Sw::new(0x6A, 0x87);
    pub const REFERENCE_NOT_FOUND: Sw = Sw::new(0x6A, 0x88);
    pub const FILE_EXISTS: Sw = Sw::new(0x6A, 0x89);
    pub const WRONG_P1P2: Sw = Sw::new(0x6B, 0x00);
    pub const CORRECT_LENGTH_00: Sw = Sw::new(0x6C, 0x00);
    pub const INS_NOT_SUPPORTED: Sw = Sw::new(0x6D, 0x00);
    pub const CLA_NOT_SUPPORTED: Sw = Sw::new(0x6E, 0x00);
    /// ISO 7816-4 §5.1.1.1 — "last command of the chain expected": an APDU arrived
    /// that neither continues nor legitimately closes the open command chain.
    pub const LAST_CHAIN_EXPECTED: Sw = Sw::new(0x68, 0x83);
    pub const UNKNOWN: Sw = Sw::new(0x6F, 0x00);
    pub const OK: Sw = Sw::new(0x90, 0x00);
}

#[cfg(test)]
#[path = "sw_tests.rs"]
mod tests;
