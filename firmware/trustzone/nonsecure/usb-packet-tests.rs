// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Host checks for the NS USB callers; SG and wake timing are controlled mocks.
#![allow(dead_code)]

#[path = "../../../crates/rsk-usb/src/usb_abi.rs"]
mod abi;
#[path = "src/usb_packet_tests.rs"]
mod tests;
#[path = "../../src/sweep/buffer.rs"]
mod wipe_impl;
#[path = "../../../crates/rsk-usb/src/worker_abi.rs"]
mod worker_abi;

use tests::{EndpointAddress, EndpointError, EndpointInfo};
use worker_abi::{INVALID, PENDING};

mod usb {
    include!(env!("RSK_NS_USB_SOURCE"));
}
mod reply {
    include!(env!("RSK_NS_REPLY_SOURCE"));
}
mod notify {
    pub use crate::tests::{generation, wait};
}
mod sweep_buffer {
    pub fn wipe_bytes(bytes: &mut [u8]) {
        let before = bytes.to_vec();
        crate::wipe_impl::wipe_bytes(bytes);
        crate::tests::wiped(before, bytes.to_vec());
    }
}
