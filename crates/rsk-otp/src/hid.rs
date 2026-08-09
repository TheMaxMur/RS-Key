// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The legacy YubiKey OTP HID frame protocol: a 70-byte frame (64-byte payload
//! ‖ slot ‖ CRC ‖ pad) carried 7 payload bytes per 8-byte FEATURE report, written
//! via SET_REPORT and polled via GET_REPORT — the transport `ykman otp` speaks.

use zeroize::Zeroize;

use crate::crc16;

/// HID feature-report size.
pub const REPORT_SIZE: usize = 8;
/// Payload bytes per report — the 8th byte is the flag/sequence field.
pub const REPORT_DATA: usize = REPORT_SIZE - 1;
/// Reassembled frame: 64-byte payload ‖ slot ‖ CRC(2) ‖ pad(3) = 70.
pub const FRAME_SIZE: usize = 70;
/// Command payload size.
pub const PAYLOAD_SIZE: usize = 64;
/// Offset of the frame CRC: payload ‖ slot ‖ CRC(2).
const FRAME_CRC_OFF: usize = PAYLOAD_SIZE + 1;

/// Host→device flag: a data frame (the low 5 bits are the sequence number).
const FLAG_WRITE: u8 = 0x80;
/// Device→host flag: a response frame is pending / present.
const FLAG_RESP_PENDING: u8 = 0x40;
/// Device→host flag: the running command is waiting for its button press.
const FLAG_TIMEOUT_WAIT: u8 = 0x20;
/// Device→host status while a command runs with no touch outstanding: non-zero
/// and non-pending, so the host keeps polling.
const STATUS_PROCESSING: u8 = 0x10;
/// Host→device sentinel byte that resets the transfer state.
const FLAG_RESET: u8 = 0xFF;
const SEQ_MASK: u8 = 0x1F;

/// What a host feature report did to the [`FrameRx`] state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxOutcome {
    /// Mid-frame, or a report that carried no actionable change.
    None,
    /// The host asked to reset the transfer (clear any pending response).
    Reset,
    /// A complete, CRC-valid frame: run `slot_id` with `payload` as the APDU.
    Frame {
        slot: u8,
        payload: [u8; PAYLOAD_SIZE],
    },
    /// A complete frame whose CRC did not match — dropped.
    BadCrc,
}

/// Reassembles the 10 sequenced feature reports of one host frame.
///
/// Report byte 7 is `0xFF` (reset) or `0x80 | seq` for a data slice. Slice
/// `seq` lands at offset `seq*7`; the final slice (`seq == 9`) completes the
/// 70-byte frame, whose stored CRC (a plain CRC-16 over the 64-byte payload) is
/// checked before the frame is released.
pub struct FrameRx {
    buf: [u8; FRAME_SIZE],
}

impl Default for FrameRx {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameRx {
    pub const fn new() -> Self {
        Self {
            buf: [0; FRAME_SIZE],
        }
    }

    /// Consume one 8-byte feature report.
    pub fn feed(&mut self, report: &[u8; REPORT_SIZE]) -> RxOutcome {
        let flag = report[REPORT_DATA];
        if flag == FLAG_RESET {
            self.scrub();
            return RxOutcome::Reset;
        }
        if flag & FLAG_WRITE == 0 {
            return RxOutcome::None;
        }
        let seq = (flag & SEQ_MASK) as usize;
        if seq > 9 {
            // A write with an out-of-range sequence is the host's dummy write
            // (`0x8f`, ykpers `yk_force_key_update`): abort what is in flight and
            // reset the read mode. Dropping it strands the host mid-transfer.
            self.scrub();
            return RxOutcome::Reset;
        }
        if seq == 0 {
            self.scrub();
        }
        self.buf[seq * REPORT_DATA..seq * REPORT_DATA + REPORT_DATA]
            .copy_from_slice(&report[..REPORT_DATA]);
        if seq != 9 {
            return RxOutcome::None;
        }
        // Final slice: validate the frame CRC (plain CRC-16 over the payload).
        let want = u16::from_le_bytes([self.buf[FRAME_CRC_OFF], self.buf[FRAME_CRC_OFF + 1]]);
        if crc16(&self.buf[..PAYLOAD_SIZE]) != want {
            self.scrub();
            return RxOutcome::BadCrc;
        }
        let mut payload = [0u8; PAYLOAD_SIZE];
        payload.copy_from_slice(&self.buf[..PAYLOAD_SIZE]);
        let slot = self.buf[PAYLOAD_SIZE];
        // The caller owns the bytes now. A slot-configure frame holds the AES key,
        // the private UID and the presented access code, and nothing else clears
        // this buffer until some later frame happens to reuse it — so wipe it here.
        self.scrub();
        RxOutcome::Frame { slot, payload }
    }

    /// Wipe the reassembly buffer. Called after a frame is handed off, on an abort,
    /// and before the device drops to the bootloader.
    pub fn scrub(&mut self) {
        self.buf.zeroize();
    }
}

/// Slices a response body back to the host across feature reports.
///
/// The body is suffixed with the complement of its CRC-16 (so the host's
/// payload-plus-CRC check lands on the X.25 residual), then served 7 bytes per
/// report tagged `0x40 | seq` (response-pending), finished by a lone `0x40`
/// end marker.
pub struct FrameTx {
    buf: [u8; FRAME_SIZE + 2],
    remaining: usize,
    seq: u8,
    expected: u8,
}

impl Default for FrameTx {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameTx {
    pub const fn new() -> Self {
        Self {
            buf: [0; FRAME_SIZE + 2],
            remaining: 0,
            seq: 0,
            expected: 0,
        }
    }

    /// Whether a response is still being streamed.
    pub fn active(&self) -> bool {
        self.remaining > 0 || self.expected > 0
    }

    /// Load a response body (≤ 64 bytes); the CRC suffix is appended here.
    pub fn load(&mut self, body: &[u8]) {
        let n = body.len().min(PAYLOAD_SIZE);
        self.buf = [0; FRAME_SIZE + 2];
        self.buf[..n].copy_from_slice(&body[..n]);
        let crc = !crc16(&body[..n]);
        self.buf[n..n + 2].copy_from_slice(&crc.to_le_bytes());
        let total = n + 2;
        self.remaining = total;
        self.expected = total.div_ceil(REPORT_DATA) as u8;
        self.seq = 0;
    }

    /// Fill the next 8-byte response report. Returns `false` once the stream is
    /// drained (the caller then serves the status frame).
    pub fn next(&mut self, out: &mut [u8; REPORT_SIZE]) -> bool {
        if self.remaining > 0 {
            let off = self.seq as usize * REPORT_DATA;
            let n = self.remaining.min(REPORT_DATA);
            *out = [0; REPORT_SIZE];
            out[..n].copy_from_slice(&self.buf[off..off + n]);
            out[REPORT_DATA] = FLAG_RESP_PENDING | self.seq;
            self.remaining -= n;
            self.seq += 1;
            true
        } else if self.expected > 0 && self.seq == self.expected {
            // End-of-response marker: pending bit set, sequence bits zero.
            *out = [0; REPORT_SIZE];
            out[REPORT_DATA] = FLAG_RESP_PENDING;
            self.seq = 0;
            self.expected = 0;
            true
        } else {
            false
        }
    }
}

/// The status byte a host sees while the command it wrote is still running.
///
/// Once the device has announced a touch wait, ykpers' blocking read
/// (`yk_wait_for_key_status`) takes any later byte that is neither
/// response-pending nor still-waiting as a timeout and abandons the challenge. So
/// the wait latches for the rest of the command: the press itself must not flip
/// the byte back, only the response — or the idle status frame — replaces it.
pub struct ProcessingStatus {
    waiting: bool,
}

impl Default for ProcessingStatus {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessingStatus {
    pub const fn new() -> Self {
        Self { waiting: false }
    }

    /// Start a fresh command: nothing announced to the host yet.
    pub fn reset(&mut self) {
        self.waiting = false;
    }

    /// One host poll while the command runs; `touch_pending` is the live presence
    /// flag.
    pub fn poll(&mut self, touch_pending: bool) -> u8 {
        self.waiting |= touch_pending;
        if self.waiting {
            FLAG_TIMEOUT_WAIT
        } else {
            STATUS_PROCESSING
        }
    }
}

/// The 8-byte status frame served by an idle GET_REPORT:
/// `status` (= [`crate::OtpApplet::status_bytes`]) prefixed by a reserved byte.
pub fn status_frame(status: [u8; 7]) -> [u8; REPORT_SIZE] {
    [
        0, status[0], status[1], status[2], status[3], status[4], status[5], status[6],
    ]
}

/// Whether the frame protocol is idle, running a command, or streaming its
/// response back.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Idle,
    Processing,
    Responding,
}

/// What a host feature report asks of the transport's owner, beyond the state
/// machine's own bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetOutcome {
    /// Mid-frame, or a report that changed nothing actionable.
    None,
    /// A complete frame is queued — take it with [`OtpHid::take_request`] and run
    /// it.
    Frame,
    /// The host abandoned the transfer.
    Reset,
}

impl SetOutcome {
    /// Whether this report ends a touch wait the *previous* command started.
    ///
    /// A YubiKey lets both the dummy write and the next command supersede a
    /// challenge still waiting for its press. Honouring neither is what made
    /// KeePassXC treat the key as broken until `bcdDevice` 0x085B, so it is a
    /// property of the protocol rather than of either build's presence layer.
    pub fn ends_touch_wait(self) -> bool {
        matches!(self, Self::Frame | Self::Reset)
    }
}

/// The frame protocol's state machine: what a host's GET/SET_REPORT feature
/// transfers mean, and what the device answers between them.
///
/// Free of the transport it rides and of the presence layer it gates on, so both
/// builds run this one rather than two readings of it — the firmware behind a
/// critical-section mutex (its control pipe preempts the worker), the emulator
/// behind a plain one. What stays outside is the marshalling: report-size checks,
/// waking whatever runs the command, and cancelling the touch wait
/// [`SetOutcome::ends_touch_wait`] names.
pub struct OtpHid {
    rx: FrameRx,
    tx: FrameTx,
    state: State,
    /// Status byte served while a command runs.
    processing: ProcessingStatus,
    /// Cached idle status frame, refreshed after each command.
    status: [u8; REPORT_SIZE],
    req_slot: u8,
    req_payload: [u8; PAYLOAD_SIZE],
    req_ready: bool,
}

impl Default for OtpHid {
    fn default() -> Self {
        Self::new()
    }
}

impl OtpHid {
    pub const fn new() -> Self {
        Self {
            rx: FrameRx::new(),
            tx: FrameTx::new(),
            state: State::Idle,
            processing: ProcessingStatus::new(),
            // Plausible pre-boot status (version, no slots); whoever runs commands
            // overwrites it with the real record before the host ever reads it.
            status: [0, 5, 7, 4, 0, 0, 0, 0],
            req_slot: 0,
            req_payload: [0; PAYLOAD_SIZE],
            req_ready: false,
        }
    }

    /// One host SET_REPORT. `data` shorter than a report is zero-padded; longer is
    /// truncated, because the report size is the protocol's and not the host's.
    pub fn set_report(&mut self, data: &[u8]) -> SetOutcome {
        let mut report = [0u8; REPORT_SIZE];
        let n = data.len().min(REPORT_SIZE);
        report[..n].copy_from_slice(&data[..n]);
        match self.rx.feed(&report) {
            RxOutcome::Frame { slot, payload } => {
                self.req_slot = slot;
                self.req_payload = payload;
                self.req_ready = true;
                self.processing.reset();
                self.state = State::Processing;
                SetOutcome::Frame
            }
            RxOutcome::Reset => {
                self.tx = FrameTx::new();
                self.state = State::Idle;
                SetOutcome::Reset
            }
            RxOutcome::None | RxOutcome::BadCrc => SetOutcome::None,
        }
    }

    /// One host GET_REPORT: the next response slice, the running command's status
    /// byte, or the idle status frame.
    pub fn get_report(&mut self, out: &mut [u8; REPORT_SIZE], touch_pending: bool) {
        *out = [0; REPORT_SIZE];
        match self.state {
            State::Responding => {
                if !self.tx.next(out) {
                    self.state = State::Idle;
                    *out = self.status;
                }
            }
            State::Processing => {
                // Latched: the press must not flip the byte back before the
                // response, or the host reads that as a touch timeout.
                out[REPORT_SIZE - 1] = self.processing.poll(touch_pending);
            }
            State::Idle => *out = self.status,
        }
    }

    /// Take the frame waiting to be run, if any.
    pub fn take_request(&mut self) -> Option<(u8, [u8; PAYLOAD_SIZE])> {
        if !self.req_ready {
            return None;
        }
        self.req_ready = false;
        let req = (self.req_slot, self.req_payload);
        // A slot-configure frame carries the AES key, the private UID and the
        // presented access code; don't leave them here once the caller holds its
        // own copy. Same rule the CTAP/CCID exchange buffers follow.
        self.req_payload.zeroize();
        Some(req)
    }

    /// Store a command's result: refresh the cached status frame and, if `body` is
    /// non-empty, start streaming it (a read command); otherwise go idle so the
    /// host reads the updated status (a configure/swap that only bumped the
    /// program sequence).
    pub fn finish_response(&mut self, status: [u8; REPORT_SIZE], body: &[u8]) {
        self.status = status;
        if body.is_empty() {
            self.tx = FrameTx::new();
            // A frame that arrived while this command ran is already queued — stay
            // in `Processing` for it rather than flashing idle at the host.
            if !self.req_ready {
                self.state = State::Idle;
            }
        } else {
            self.tx.load(body);
            self.state = State::Responding;
        }
    }

    /// Seed the cached status frame at boot, before any host poll.
    pub fn set_status(&mut self, status: [u8; REPORT_SIZE]) {
        self.status = status;
    }

    /// Wipe every buffer here that can hold slot secrets.
    ///
    /// The TX buffer is the one that is easy to miss: for slots `0x30`/`0x38` it
    /// holds a 20-byte HMAC-SHA1 response, which with a fixed challenge
    /// (yubikey-luks) *is* the credential, and `FrameTx::next` streams without
    /// clearing.
    pub fn scrub(&mut self) {
        self.rx.scrub();
        self.tx = FrameTx::new();
        self.req_payload.zeroize();
        self.req_slot = 0;
    }
}

/// Frame one host command for [`FrameRx`] testing/fuzzing: split a 64-byte
/// `payload` + `slot` into the 10 sequenced 8-byte reports (with the plain frame
/// CRC), matching `yubikit.core.otp._format_frame`.
pub fn split_frame(payload: &[u8; PAYLOAD_SIZE], slot: u8) -> [[u8; REPORT_SIZE]; 10] {
    let mut frame = [0u8; FRAME_SIZE];
    frame[..PAYLOAD_SIZE].copy_from_slice(payload);
    frame[PAYLOAD_SIZE] = slot;
    let crc = crc16(payload);
    frame[FRAME_CRC_OFF..FRAME_CRC_OFF + 2].copy_from_slice(&crc.to_le_bytes());
    let mut reports = [[0u8; REPORT_SIZE]; 10];
    for (seq, rep) in reports.iter_mut().enumerate() {
        rep[..REPORT_DATA]
            .copy_from_slice(&frame[seq * REPORT_DATA..seq * REPORT_DATA + REPORT_DATA]);
        rep[REPORT_DATA] = FLAG_WRITE | seq as u8;
    }
    reports
}

#[cfg(test)]
#[path = "hid_tests.rs"]
mod tests;
