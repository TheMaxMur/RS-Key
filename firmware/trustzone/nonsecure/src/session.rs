// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::abi;
use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use embassy_usb::Handler;
use embassy_usb::control::{OutResponse, Recipient, Request, RequestType};

static EPOCH: AtomicU32 = AtomicU32::new(0);
static FIDO: AtomicU32 = AtomicU32::new(0);
static CCID: AtomicU32 = AtomicU32::new(0);
static ABORT: AtomicU16 = AtomicU16::new(0);
const ABORT_ARMED: u16 = 1 << 8;

pub fn epoch() -> u32 {
    EPOCH.load(Ordering::Acquire)
}

pub fn control(action: u32, ticket: u32) -> u32 {
    // SAFETY: the SG control entry accepts only numeric actions and request tickets.
    unsafe { super::rsk_tz_control(action, ticket) }
}

pub struct Pending {
    ticket: u32,
    kind: u32,
}
impl Pending {
    pub fn new(ticket: u32, kind: u32) -> Self {
        let kind = kind & 0xff;
        match kind {
            abi::CBOR | abi::MSG | abi::VENDOR => FIDO.store(ticket, Ordering::Release),
            abi::APDU | abi::SECURE_PIN | abi::RESET_CARD => CCID.store(ticket, Ordering::Release),
            _ => {}
        }
        Self { ticket, kind }
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        control(abi::ABANDON, self.ticket);
        match self.kind {
            abi::CBOR | abi::MSG | abi::VENDOR => FIDO.store(0, Ordering::Release),
            abi::APDU | abi::SECURE_PIN | abi::RESET_CARD => CCID.store(0, Ordering::Release),
            _ => {}
        }
    }
}

pub fn cancel_fido() {
    control(abi::ABANDON, FIDO.load(Ordering::Acquire));
    if control(abi::UP_PENDING, 0) != 0 {
        control(abi::CANCEL, 0);
    }
}

pub fn abort(_sequence: u8) -> bool {
    if abort_pending() {
        control(abi::ABANDON, CCID.load(Ordering::Acquire));
        true
    } else {
        false
    }
}
pub fn abort_pending() -> bool {
    ABORT.load(Ordering::Acquire) != 0
}
pub fn acknowledge_abort(sequence: u8) -> Option<bool> {
    Some(
        ABORT
            .compare_exchange(
                ABORT_ARMED | u16::from(sequence),
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok(),
    )
}

pub struct UsbHandler {
    pub ccid_interface: u8,
}
impl UsbHandler {
    fn reset_session(&mut self) {
        EPOCH.fetch_add(1, Ordering::AcqRel);
        ABORT.store(0, Ordering::Release);
        control(abi::RESET_SESSION, 0);
    }
}
impl Handler for UsbHandler {
    fn reset(&mut self) {
        self.reset_session();
    }
    fn configured(&mut self, configured: bool) {
        if !configured {
            self.reset_session();
        }
    }
    fn suspended(&mut self, suspended: bool) {
        if suspended {
            self.reset_session();
        }
    }
    fn control_out(&mut self, request: Request, data: &[u8]) -> Option<OutResponse> {
        if request.request_type != RequestType::Class
            || request.recipient != Recipient::Interface
            || request.index != u16::from(self.ccid_interface)
            || request.request != rsk_usb::ccid::ABORT_REQUEST
        {
            return None;
        }
        let [slot, sequence] = request.value.to_le_bytes();
        if slot != 0 || request.length != 0 || !data.is_empty() {
            return Some(OutResponse::Rejected);
        }
        ABORT.store(ABORT_ARMED | u16::from(sequence), Ordering::Release);
        Some(OutResponse::Accepted)
    }
}
