// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Internal request/reply ABI between Non-secure transports and the Secure worker.

pub const CBOR: u32 = 0;
pub const MSG: u32 = 1;
pub const APDU: u32 = 2;
pub const SECURE_PIN: u32 = 3;
pub const VENDOR: u32 = 4;
pub const RESET_CARD: u32 = 5;
pub const OTP: u32 = 6;
pub const REPLY_HEADER: usize = 3;
pub const ABANDONED: u32 = u32::MAX - 2;
pub const PENDING: u32 = u32::MAX - 1;
pub const INVALID: u32 = u32::MAX;
pub const UP_PENDING: u32 = 0;
pub const CANCEL: u32 = 1;
pub const OTP_PENDING: u32 = 2;
pub const CANCEL_OTP: u32 = 3;
pub const KEYBOARD_CHAR: u32 = 4;
pub const DESELECT_MSG: u32 = 5;
pub const ABANDON: u32 = 6;
pub const CAN_WINK: u32 = 8;
pub const WINK: u32 = 9;
pub const KEY_PRESENT: u32 = 1 << 8;
pub const KEY_ENCODE: u32 = 1 << 9;
pub const OTP_REQUEST_LEN: usize = 65;
pub const LONG_OPERATION_MS: u64 = 3_000;
