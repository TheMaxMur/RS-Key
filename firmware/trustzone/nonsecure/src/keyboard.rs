// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use core::cell::RefCell;
use embassy_sync::{
    blocking_mutex::{Mutex, raw::CriticalSectionRawMutex},
    signal::Signal,
};
use embassy_usb::{
    class::hid::{HidWriter, ReportId, RequestHandler},
    control::OutResponse,
};
use rsk_otp::hid::{OtpHid, REPORT_SIZE};

use crate::{Drv, abi, exchange, rsk_tz_control};

static HID: Mutex<CriticalSectionRawMutex, RefCell<OtpHid>> =
    Mutex::new(RefCell::new(OtpHid::new()));
static REQUEST: Signal<CriticalSectionRawMutex, ()> = Signal::new();
pub struct Handler;

impl RequestHandler for Handler {
    fn set_report(&mut self, id: ReportId, data: &[u8]) -> OutResponse {
        if !matches!(id, ReportId::Feature(_)) {
            return OutResponse::Accepted;
        }
        let result = HID.lock(|cell| cell.borrow_mut().set_report(data));
        if result.ends_touch_wait() {
            // SAFETY: Secure owns the scope and only cancels its OTP presence wait.
            unsafe {
                rsk_tz_control(abi::CANCEL_OTP, 0);
            }
        }
        if result == rsk_otp::hid::SetOutcome::Frame {
            REQUEST.signal(());
        }
        OutResponse::Accepted
    }
    fn get_report(&mut self, id: ReportId, out: &mut [u8]) -> Option<usize> {
        if !matches!(id, ReportId::Feature(_)) {
            return None;
        }
        let out = out.get_mut(..REPORT_SIZE)?;
        // SAFETY: this gateway returns only the pending-touch status bit.
        let pending = unsafe { rsk_tz_control(abi::OTP_PENDING, 0) != 0 };
        let mut report = [0u8; REPORT_SIZE];
        HID.lock(|cell| cell.borrow_mut().get_report(&mut report, pending));
        out.copy_from_slice(&report);
        Some(REPORT_SIZE)
    }
}

#[embassy_executor::task]
pub async fn commands() {
    loop {
        REQUEST.wait().await;
        let Some((slot, payload)) = HID.lock(|cell| cell.borrow_mut().take_request()) else {
            continue;
        };
        let mut request = rsk_secret::Secret::<[u8; abi::OTP_REQUEST_LEN]>::zeroed();
        let [command, data @ ..] = request.expose_mut();
        *command = slot;
        data.copy_from_slice(payload.expose());
        let mut buffer = [0u8; 128];
        let mut response = rsk_secret::WipeGuard::new(&mut buffer);
        let reply = exchange(abi::OTP, 0, request.expose(), &mut response).await;
        if let Some((status, body)) = response
            .get(..reply.len)
            .and_then(|b| b.split_first_chunk::<REPORT_SIZE>())
        {
            HID.lock(|cell| cell.borrow_mut().finish_response(*status, body));
        }
    }
}

#[embassy_executor::task]
pub async fn run(mut writer: HidWriter<'static, Drv, 8>) {
    loop {
        // SAFETY: Secure returns only an already-authorized character and consumes its queue slot.
        let character = unsafe { rsk_tz_control(abi::KEYBOARD_CHAR, 0) };
        if character & abi::KEY_PRESENT != 0 {
            let Ok(byte) = u8::try_from(character & 0xff) else {
                continue;
            };
            if let Some(press) = rsk_usb::kbd::keystroke(byte, character & abi::KEY_ENCODE != 0) {
                let _ = writer.write(&press).await;
                embassy_time::Timer::after_millis(10).await;
                let _ = writer.write(&[0; 8]).await;
            }
        }
        embassy_time::Timer::after_millis(10).await;
    }
}
