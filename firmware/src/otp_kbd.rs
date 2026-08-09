// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Emulated keyboard interface: types tickets on a button press (input reports)
//! and speaks the legacy 8-byte OTP frame protocol (feature reports — the
//! `ykman otp` transport). The control pipe runs on the interrupt executor while
//! flash + the OTP applet live in the worker, so the request handler only marshals
//! bytes through the [`OTP_HID`] critical-section static and signals [`OTP_REQ`];
//! the worker runs the command and stores the response back.
//!
//! The protocol's own state machine is [`rsk_otp::hid::OtpHid`] — shared with the
//! emulator, which declares the same interface. What is board-specific is here:
//! the critical-section mutex the control pipe needs, the touch-wait scope, and
//! the keyboard queue.

use core::cell::RefCell;

use embassy_sync::blocking_mutex::Mutex as BlockingMutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use embassy_usb::class::hid::{HidWriter, ReportId, RequestHandler};
use embassy_usb::control::OutResponse;
use zeroize::Zeroize;

use rsk_usb::kbd::keystroke;

use rsk_otp::hid::{OtpHid, PAYLOAD_SIZE, REPORT_SIZE, status_frame};

use crate::Drv;
use crate::presence::otp_up_pending;

type Cs = CriticalSectionRawMutex;

static OTP_HID: BlockingMutex<Cs, RefCell<OtpHid>> =
    BlockingMutex::new(RefCell::new(OtpHid::new()));
/// Set by SET_REPORT when a full frame arrives; awaited by the worker.
pub static OTP_REQ: Signal<Cs, ()> = Signal::new();

/// The control-request handler for the keyboard interface: marshals the OTP frame
/// protocol's GET/SET_REPORT feature transfers in and out of [`OTP_HID`]. A ZST —
/// all state is in the static.
pub struct OtpHidHandler;

impl RequestHandler for OtpHidHandler {
    fn set_report(&mut self, id: ReportId, data: &[u8]) -> OutResponse {
        // Only feature reports carry the frame protocol; accept (ignore) the LED
        // output report a host may send.
        if !matches!(id, ReportId::Feature(_)) {
            return OutResponse::Accepted;
        }
        let outcome = OTP_HID.lock(|c| c.borrow_mut().set_report(data));
        // The host moved on — a new command, or the dummy write. A YubiKey lets
        // either supersede a challenge still waiting for its touch.
        if outcome.ends_touch_wait() {
            crate::presence::cancel_otp_wait();
        }
        if outcome == rsk_otp::hid::SetOutcome::Frame {
            OTP_REQ.signal(());
        }
        OutResponse::Accepted
    }

    fn get_report(&mut self, id: ReportId, buf: &mut [u8]) -> Option<usize> {
        if !matches!(id, ReportId::Feature(_)) || buf.len() < REPORT_SIZE {
            return None;
        }
        let mut out = [0u8; REPORT_SIZE];
        OTP_HID.lock(|c| c.borrow_mut().get_report(&mut out, otp_up_pending()));
        buf[..REPORT_SIZE].copy_from_slice(&out);
        Some(REPORT_SIZE)
    }
}

/// Take a pending frame request, if any (called by the worker after [`OTP_REQ`]).
pub fn take_request() -> Option<(u8, [u8; PAYLOAD_SIZE])> {
    OTP_HID.lock(|c| c.borrow_mut().take_request())
}

/// Wipe every OTP-transport buffer that can hold slot secrets: the reassembly frame,
/// the taken request, the response body, and any ticket still queued for typing.
/// Called before dropping to the BOOTSEL bootloader, alongside the CTAP/CCID/DRBG
/// scrubs — a reflash must not be able to recover them from RAM.
pub fn scrub() {
    OTP_HID.lock(|c| c.borrow_mut().scrub());
    TYPE_Q.lock(|c| {
        let mut q = c.borrow_mut();
        q.buf.zeroize();
        q.len = 0;
        q.pos = 0;
    });
}

/// Store a command's result: refresh the cached status frame and, if `body` is
/// non-empty, start streaming it (a read command); otherwise go idle so the host
/// reads the updated status (a configure/swap that only bumped the sequence).
pub fn finish_response(status: [u8; REPORT_SIZE], body: &[u8]) {
    OTP_HID.lock(|c| c.borrow_mut().finish_response(status, body));
}

/// Seed the cached status frame at boot (before any host poll).
pub fn set_status(status: [u8; REPORT_SIZE]) {
    OTP_HID.lock(|c| c.borrow_mut().set_status(status));
}

/// Build the idle status frame from the applet's 7-byte status record.
pub fn make_status_frame(record: [u8; 7]) -> [u8; REPORT_SIZE] {
    status_frame(record)
}

// ---------------- typed-ticket keyboard queue ----------------

const TYPE_CAP: usize = 256;

struct TypeQueue {
    buf: [u8; TYPE_CAP],
    len: usize,
    pos: usize,
    encode: bool,
}

impl TypeQueue {
    const fn new() -> Self {
        Self {
            buf: [0; TYPE_CAP],
            len: 0,
            pos: 0,
            encode: false,
        }
    }
}

static TYPE_Q: BlockingMutex<Cs, RefCell<TypeQueue>> =
    BlockingMutex::new(RefCell::new(TypeQueue::new()));
static TYPE_SIG: Signal<Cs, ()> = Signal::new();

/// Queue a ticket for the keyboard task to type. `encode` true → `bytes` are
/// ASCII to be mapped through the keycode table; false → raw HID scancodes (a
/// static password). Replaces any ticket still queued (a fresh press wins).
pub fn enqueue(bytes: &[u8], encode: bool) {
    TYPE_Q.lock(|c| {
        let mut q = c.borrow_mut();
        let n = bytes.len().min(TYPE_CAP);
        q.buf[..n].copy_from_slice(&bytes[..n]);
        q.len = n;
        q.pos = 0;
        q.encode = encode;
    });
    TYPE_SIG.signal(());
}

fn pop_char() -> Option<(u8, bool)> {
    TYPE_Q.lock(|c| {
        let mut q = c.borrow_mut();
        if q.pos < q.len {
            let pos = q.pos;
            let b = q.buf[pos];
            // Consume destructively: a static-password ticket *is* the secret, so a
            // drained queue must not keep it readable in the static.
            q.buf[pos] = 0;
            q.pos = pos + 1;
            Some((b, q.encode))
        } else {
            None
        }
    })
}

/// Drains the typed-ticket queue, emitting one press + release input report per
/// character.
#[embassy_executor::task]
pub async fn kbd_task(mut writer: HidWriter<'static, Drv, 8>) {
    use embassy_time::Timer;
    loop {
        TYPE_SIG.wait().await;
        while let Some((b, encode)) = pop_char() {
            let Some(press) = keystroke(b, encode) else {
                continue; // unmapped — type nothing
            };
            let _ = writer.write(&press).await;
            Timer::after_millis(10).await;
            let _ = writer.write(&[0u8; 8]).await; // release
            Timer::after_millis(10).await;
        }
    }
}
