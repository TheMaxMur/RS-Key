// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Bounded controller operations; all controller memory remains Secure.

pub const EPOCH: u32 = 0;
pub const ALLOC_IN: u32 = 1;
pub const ALLOC_OUT: u32 = 2;
pub const START: u32 = 3;
pub const BUS_POLL: u32 = 4;
pub const BUS_ENABLE: u32 = 5;
pub const BUS_DISABLE: u32 = 6;
pub const EP_ENABLE: u32 = 7;
pub const EP_STALL: u32 = 8;
pub const EP_STALLED: u32 = 9;
pub const EP_READY: u32 = 10;
pub const EP_READ: u32 = 11;
pub const EP_WRITE: u32 = 12;
pub const CTRL_SETUP: u32 = 13;
pub const CTRL_IN: u32 = 14;
pub const CTRL_OUT: u32 = 15;
pub const CTRL_ACCEPT: u32 = 16;
pub const CTRL_REJECT: u32 = 17;
pub const CTRL_ADDRESS: u32 = 18;
pub const CTRL_POLL: u32 = 19;
pub const CTRL_ABANDON: u32 = 20;
pub const ADDRESS_SHIFT: u32 = 8;
pub const FIRST: u32 = 1 << 16;
pub const LAST: u32 = 1 << 17;
pub const FLAG: u32 = FIRST;
pub const PACKET_SIZE_U16: u16 = 64;
pub const PACKET_SIZE: usize = PACKET_SIZE_U16 as usize;
pub const ALLOCATION_SIZE: usize = 5;
pub const DISABLED: u32 = u32::MAX - 3;
pub const OVERFLOW: u32 = u32::MAX - 4;
pub const POWER_DETECTED: u32 = 1;
pub const POWER_REMOVED: u32 = 2;
pub const RESET: u32 = 3;
pub const SUSPEND: u32 = 4;
pub const RESUME: u32 = 5;

#[cfg(test)]
#[path = "usb_abi_tests.rs"]
mod tests;
