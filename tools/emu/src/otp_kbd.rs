// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The keyboard interface's OTP frame protocol, over USB/IP.
//!
//! The 8-byte feature-report transport `ykman otp` speaks, and the reason the
//! keyboard interface exists at all beyond holding index 0. The protocol's state
//! machine is [`rsk_otp::hid::OtpHid`] — the device's own — so what is here is the
//! board's half rewritten for this build: a plain mutex instead of a
//! critical-section one, and a task that hands each frame to the device thread
//! instead of a worker awaiting a `Signal`.
//!
//! Typed tickets are **not** here. A ticket is emitted by a button gesture and
//! this build has no button, so the keyboard's IN endpoint stays silent — which
//! is also what a real key does until someone presses it.

use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use embassy_usb::class::hid::{ReportId, RequestHandler};
use embassy_usb::control::OutResponse;

use rsk_otp::hid::{OtpHid, PAYLOAD_SIZE, REPORT_SIZE, SetOutcome, status_frame};

use crate::device::{Job, Jobs};
use crate::signals::Signals;

/// The state machine plus whatever is waiting on it. One mutex, because the USB
/// thread's control pipe and the task that runs commands are the only two
/// touchers and neither holds it across an await.
#[derive(Default)]
struct Shared {
    hid: OtpHid,
    /// Parked in `OtpKbd::next_request`; woken when a whole frame lands.
    waker: Option<Waker>,
}

/// A handle on the transport, cloneable into the request handler and the task.
#[derive(Clone, Default)]
pub struct OtpKbd(Arc<Mutex<Shared>>);

impl OtpKbd {
    pub fn new() -> Self {
        Self::default()
    }

    /// The `RequestHandler` the keyboard interface is built with.
    pub fn handler(&self, signals: Arc<Signals>) -> OtpHandler {
        OtpHandler {
            shared: self.0.clone(),
            signals,
        }
    }

    /// Wait for the next complete frame the host wrote.
    async fn next_request(&self) -> (u8, [u8; PAYLOAD_SIZE]) {
        std::future::poll_fn(|cx: &mut Context<'_>| {
            let mut s = self.0.lock().expect("otp mutex poisoned");
            match s.hid.take_request() {
                Some(req) => Poll::Ready(req),
                None => {
                    s.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        })
        .await
    }
}

/// Marshals the frame protocol's feature transfers in and out of the state
/// machine. Synchronous, because `embassy-usb` calls it from the control pipe.
pub struct OtpHandler {
    shared: Arc<Mutex<Shared>>,
    signals: Arc<Signals>,
}

impl RequestHandler for OtpHandler {
    fn set_report(&mut self, id: ReportId, data: &[u8]) -> OutResponse {
        // Only feature reports carry the frame protocol; accept (ignore) the LED
        // output report a host may send.
        if !matches!(id, ReportId::Feature(_)) {
            return OutResponse::Accepted;
        }
        let mut s = self.shared.lock().expect("otp mutex poisoned");
        let outcome = s.hid.set_report(data);
        // The host moved on — a new command, or the dummy write. A YubiKey lets
        // either supersede a challenge still waiting for its touch, and not
        // honouring that is what made KeePassXC treat the key as broken.
        if outcome.ends_touch_wait() {
            self.signals.cancel_otp();
        }
        if outcome == SetOutcome::Frame
            && let Some(w) = s.waker.take()
        {
            w.wake();
        }
        OutResponse::Accepted
    }

    fn get_report(&mut self, id: ReportId, buf: &mut [u8]) -> Option<usize> {
        if !matches!(id, ReportId::Feature(_)) || buf.len() < REPORT_SIZE {
            return None;
        }
        let mut out = [0u8; REPORT_SIZE];
        let up = self.signals.up_pending_for(crate::signals::SCOPE_OTP);
        self.shared
            .lock()
            .expect("otp mutex poisoned")
            .hid
            .get_report(&mut out, up);
        buf[..REPORT_SIZE].copy_from_slice(&out);
        Some(REPORT_SIZE)
    }
}

/// Run frames as they arrive, forever — the emulator's half of what the board's
/// worker does when it wakes on `OTP_REQ`.
pub async fn run(otp: OtpKbd, jobs: Jobs, signals: Arc<Signals>) {
    // Seed the status frame before the host's first poll. An idle GET_REPORT is
    // the very first thing `ykman` issues, and the machine's default is a
    // plausible record rather than this device's.
    if let Some(record) = crate::usbip_stack::run_job(&jobs, Job::OtpStatus).await
        && record.len() == 7
    {
        let mut r = [0u8; 7];
        r.copy_from_slice(&record);
        otp.0
            .lock()
            .expect("otp mutex poisoned")
            .hid
            .set_status(status_frame(r));
    }
    loop {
        let (slot, payload) = otp.next_request().await;
        // Scope the touch wait this command may start to the OTP transport, so a
        // host that abandons it cannot also end a FIDO ceremony on the same
        // presence backend.
        signals.begin_otp();
        let out = crate::usbip_stack::run_job(
            &jobs,
            Job::OtpHid {
                slot,
                payload: payload.to_vec(),
            },
        )
        .await;
        signals.end_otp();
        // `status ‖ body` — the device thread answers on one channel, and the
        // status frame is fixed-width, so the split is the report size.
        let Some(out) = out.filter(|v| v.len() >= REPORT_SIZE) else {
            continue;
        };
        let mut status = [0u8; REPORT_SIZE];
        status.copy_from_slice(&out[..REPORT_SIZE]);
        otp.0
            .lock()
            .expect("otp mutex poisoned")
            .hid
            .finish_response(status, &out[REPORT_SIZE..]);
    }
}
