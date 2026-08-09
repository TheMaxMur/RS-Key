// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Emulated keyboard interface: types tickets on a button press (input reports)
//! and speaks the legacy 8-byte OTP frame protocol (feature reports — the
//! `ykman otp` transport). The control pipe runs on the interrupt executor while
//! flash + the OTP applet live in the worker, so the request handler only marshals
//! bytes through the [`OTP_HID`] critical-section static and signals [`OTP_REQ`];
//! the worker runs the command and stores the response back.

use core::cell::RefCell;

use embassy_sync::blocking_mutex::Mutex as BlockingMutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use embassy_usb::class::hid::{HidWriter, ReportId, RequestHandler};
use embassy_usb::control::OutResponse;
use zeroize::Zeroize;

use rsk_usb::kbd::KEYBOARD_MODIFIER_LEFTSHIFT;

use rsk_otp::hid::{
    FrameRx, FrameTx, PAYLOAD_SIZE, ProcessingStatus, REPORT_SIZE, RxOutcome, status_frame,
};

use crate::Drv;
use crate::presence::otp_up_pending;

type Cs = CriticalSectionRawMutex;

/// Whether the frame protocol is idle, computing, or streaming a response.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    Processing,
    Responding,
}

/// Frame-protocol state shared between the USB control pipe (request handler) and
/// the worker, behind a critical-section mutex (the worker on the thread executor
/// can be preempted mid-update by the high-priority USB task).
struct OtpHid {
    rx: FrameRx,
    tx: FrameTx,
    state: State,
    /// Status byte served while `state` is [`State::Processing`].
    processing: ProcessingStatus,
    /// Cached idle status frame (refreshed by the worker after each command).
    status: [u8; REPORT_SIZE],
    req_slot: u8,
    req_payload: [u8; PAYLOAD_SIZE],
    req_ready: bool,
}

impl OtpHid {
    const fn new() -> Self {
        Self {
            rx: FrameRx::new(),
            tx: FrameTx::new(),
            state: State::Idle,
            processing: ProcessingStatus::new(),
            // Plausible pre-boot status (version, no slots); the worker overwrites
            // it with the real record before the host ever reads it.
            status: [0, 5, 7, 4, 0, 0, 0, 0],
            req_slot: 0,
            req_payload: [0; PAYLOAD_SIZE],
            req_ready: false,
        }
    }
}

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
        let mut report = [0u8; REPORT_SIZE];
        let n = data.len().min(REPORT_SIZE);
        report[..n].copy_from_slice(&data[..n]);
        OTP_HID.lock(|c| {
            let mut h = c.borrow_mut();
            match h.rx.feed(&report) {
                RxOutcome::Frame { slot, payload } => {
                    // The host moved on to another command: a YubiKey lets that
                    // supersede a challenge still waiting for its touch.
                    crate::presence::cancel_otp_wait();
                    h.req_slot = slot;
                    h.req_payload = payload;
                    h.req_ready = true;
                    h.processing.reset();
                    h.state = State::Processing;
                    OTP_REQ.signal(());
                }
                RxOutcome::Reset => {
                    crate::presence::cancel_otp_wait();
                    h.tx = FrameTx::new();
                    h.state = State::Idle;
                }
                RxOutcome::None | RxOutcome::BadCrc => {}
            }
        });
        OutResponse::Accepted
    }

    fn get_report(&mut self, id: ReportId, buf: &mut [u8]) -> Option<usize> {
        if !matches!(id, ReportId::Feature(_)) || buf.len() < REPORT_SIZE {
            return None;
        }
        let mut out = [0u8; REPORT_SIZE];
        OTP_HID.lock(|c| {
            let mut h = c.borrow_mut();
            match h.state {
                State::Responding => {
                    if !h.tx.next(&mut out) {
                        h.state = State::Idle;
                        out = h.status;
                    }
                }
                State::Processing => {
                    // Latched: the press must not flip the byte back before the
                    // response, or the host reads that as a touch timeout.
                    out[REPORT_SIZE - 1] = h.processing.poll(otp_up_pending());
                }
                State::Idle => out = h.status,
            }
        });
        buf[..REPORT_SIZE].copy_from_slice(&out);
        Some(REPORT_SIZE)
    }
}

/// Take a pending frame request, if any (called by the worker after [`OTP_REQ`]).
pub fn take_request() -> Option<(u8, [u8; PAYLOAD_SIZE])> {
    OTP_HID.lock(|c| {
        let mut h = c.borrow_mut();
        if h.req_ready {
            h.req_ready = false;
            let req = (h.req_slot, h.req_payload);
            // A slot-configure frame carries the AES key, the private UID and the
            // presented access code; don't leave them in the static once the worker
            // holds its own copy. Same rule the CTAP/CCID exchange buffers follow.
            h.req_payload.zeroize();
            Some(req)
        } else {
            None
        }
    })
}

/// Wipe every OTP-transport buffer that can hold slot secrets: the reassembly frame,
/// the taken request, and any ticket still queued for typing. Called before dropping to
/// the BOOTSEL bootloader, alongside the CTAP/CCID/DRBG scrubs — a reflash must not be
/// able to recover them from RAM.
pub fn scrub() {
    OTP_HID.lock(|c| {
        let mut h = c.borrow_mut();
        h.rx.scrub();
        // The TX buffer still holds the last response body — for slots 0x30/0x38
        // that is a 20-byte HMAC-SHA1 challenge-response, which with a fixed
        // challenge (yubikey-luks) IS the credential. `FrameTx::next` streams
        // without clearing, so nothing else wipes it.
        h.tx = rsk_otp::hid::FrameTx::new();
        h.req_payload.zeroize();
        h.req_slot = 0;
    });
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
    OTP_HID.lock(|c| {
        let mut h = c.borrow_mut();
        h.status = status;
        if body.is_empty() {
            h.tx = FrameTx::new();
            // A frame that arrived while this command ran is already queued — stay
            // in `Processing` for it rather than flashing idle at the host.
            if !h.req_ready {
                h.state = State::Idle;
            }
        } else {
            h.tx.load(body);
            h.state = State::Responding;
        }
    });
}

/// Seed the cached status frame at boot (before any host poll).
pub fn set_status(status: [u8; REPORT_SIZE]) {
    OTP_HID.lock(|c| c.borrow_mut().status = status);
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

/// ASCII → (left-shift?, HID keycode) for the characters a typed ticket can
/// contain (modhex letters, digits, CR) plus the rest of the printable set for
/// completeness; unmapped bytes type nothing.
fn ascii_to_keycode(c: u8) -> (bool, u8) {
    match c {
        b'a'..=b'z' => (false, 0x04 + (c - b'a')),
        b'A'..=b'Z' => (true, 0x04 + (c - b'A')),
        b'1'..=b'9' => (false, 0x1E + (c - b'1')),
        b'0' => (false, 0x27),
        b'\n' | b'\r' => (false, 0x28), // Enter
        0x1B => (false, 0x29),          // Esc
        0x08 => (false, 0x2A),          // Backspace
        b'\t' => (false, 0x2B),
        b' ' => (false, 0x2C),
        b'-' => (false, 0x2D),
        b'=' => (false, 0x2E),
        b'[' => (false, 0x2F),
        b']' => (false, 0x30),
        b'\\' => (false, 0x31),
        b';' => (false, 0x33),
        b'\'' => (false, 0x34),
        b'`' => (false, 0x35),
        b',' => (false, 0x36),
        b'.' => (false, 0x37),
        b'/' => (false, 0x38),
        b'!' => (true, 0x1E),
        b'@' => (true, 0x1F),
        b'#' => (true, 0x20),
        b'$' => (true, 0x21),
        b'%' => (true, 0x22),
        b'^' => (true, 0x23),
        b'&' => (true, 0x24),
        b'*' => (true, 0x25),
        b'(' => (true, 0x26),
        b')' => (true, 0x27),
        b'_' => (true, 0x2D),
        b'+' => (true, 0x2E),
        b'{' => (true, 0x2F),
        b'}' => (true, 0x30),
        b'|' => (true, 0x31),
        b':' => (true, 0x33),
        b'"' => (true, 0x34),
        b'~' => (true, 0x35),
        b'<' => (true, 0x36),
        b'>' => (true, 0x37),
        b'?' => (true, 0x38),
        _ => (false, 0),
    }
}

/// Drains the typed-ticket queue, emitting one press + release input report per
/// character. The 8-byte report is `[modifier, 0, keycode, 0, 0, 0, 0, 0]`.
#[embassy_executor::task]
pub async fn kbd_task(mut writer: HidWriter<'static, Drv, 8>) {
    use embassy_time::Timer;
    loop {
        TYPE_SIG.wait().await;
        while let Some((b, encode)) = pop_char() {
            let (modifier, keycode) = if encode {
                let (shift, k) = ascii_to_keycode(b);
                (
                    if shift {
                        KEYBOARD_MODIFIER_LEFTSHIFT
                    } else {
                        0
                    },
                    k,
                )
            } else {
                // Raw scancode: high bit means "with shift".
                (
                    if b & 0x80 != 0 {
                        KEYBOARD_MODIFIER_LEFTSHIFT
                    } else {
                        0
                    },
                    b & 0x7F,
                )
            };
            if keycode == 0 {
                continue; // unmapped — type nothing
            }
            let mut press = [0u8; 8];
            press[0] = modifier;
            press[2] = keycode;
            let _ = writer.write(&press).await;
            Timer::after_millis(10).await;
            let _ = writer.write(&[0u8; 8]).await; // release
            Timer::after_millis(10).await;
        }
    }
}
