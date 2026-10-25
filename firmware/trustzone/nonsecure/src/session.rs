// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::abi;
use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use embassy_usb::Handler;
use embassy_usb::control::{OutResponse, Recipient, Request, RequestType};

static FIDO: AtomicU32 = AtomicU32::new(0);
static CCID: AtomicU32 = AtomicU32::new(0);
static ABORT: AtomicU16 = AtomicU16::new(0);
static ABORT_EPOCH: AtomicU32 = AtomicU32::new(0);
const ABORT_ARMED: u16 = 1 << 8;

pub fn epoch() -> u32 {
    super::usb::epoch()
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
    ABORT_EPOCH.load(Ordering::Acquire) == epoch() && ABORT.load(Ordering::Acquire) != 0
}
pub fn acknowledge_abort(sequence: u8) -> Option<bool> {
    if !abort_pending() {
        return Some(false);
    }
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
    pub ccid_interface: Option<u8>,
}
impl Handler for UsbHandler {
    fn control_out(&mut self, request: Request, data: &[u8]) -> Option<OutResponse> {
        if request.request_type != RequestType::Class
            || request.recipient != Recipient::Interface
            || Some(request.index) != self.ccid_interface.map(u16::from)
            || request.request != rsk_usb::ccid::ABORT_REQUEST
        {
            return None;
        }
        let [slot, sequence] = request.value.to_le_bytes();
        if slot != 0 || request.length != 0 || !data.is_empty() {
            return Some(OutResponse::Rejected);
        }
        arm_abort(sequence);
        Some(OutResponse::Accepted)
    }
}

#[cfg(feature = "test-gateway-probes")]
pub(crate) fn late_reset_callback() {
    let mut handler = UsbHandler {
        ccid_interface: None,
    };
    handler.reset();
    handler.configured(false);
    handler.suspended(true);
}

fn arm_abort(sequence: u8) {
    ABORT_EPOCH.store(epoch(), Ordering::Release);
    ABORT.store(ABORT_ARMED | u16::from(sequence), Ordering::Release);
}

#[cfg(feature = "test-gateway-probes")]
pub(crate) fn probe_abort(arm: bool) -> bool {
    if arm {
        arm_abort(0);
    }
    abort_pending()
}
