// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! A short synchronous retry window for an already borrowed Bulk IN packet.

#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use embassy_usb::driver::{EndpointAddress, EndpointType};

use crate::{usb_abi as abi, worker_abi::PENDING};

const BUDGET_US: u32 = 64;
const MAX_RETRIES: u8 = 8;

pub fn eligible(
    operation: u32,
    length: usize,
    endpoint_type: Option<EndpointType>,
    blocked: bool,
) -> bool {
    let Ok(address) = u8::try_from((operation >> abi::ADDRESS_SHIFT) & 0xff) else {
        return false;
    };
    let address = EndpointAddress::from(address);
    operation & !(0xffff | abi::FLAG) == 0
        && operation & 0xff == abi::EP_WRITE
        && address.is_in()
        && address.index() != 0
        && (1..=abi::PACKET_SIZE).contains(&length)
        && endpoint_type == Some(EndpointType::Bulk)
        && !blocked
}

pub struct Retry {
    started: u32,
    remaining: u8,
}

impl Retry {
    pub fn new(started: u32) -> Self {
        Self {
            started,
            remaining: MAX_RETRIES,
        }
    }

    // The deadline admits a retry; that complete observer/HAL cycle can finish later.
    pub fn next(&mut self, result: u32, now: u32, progress: bool) -> bool {
        if result != PENDING
            || progress
            || self.remaining == 0
            || now.wrapping_sub(self.started) >= BUDGET_US
        {
            self.remaining = 0;
            return false;
        }
        self.remaining -= 1;
        true
    }
}

#[cfg(test)]
#[path = "bulk_retry_tests.rs"]
mod tests;
