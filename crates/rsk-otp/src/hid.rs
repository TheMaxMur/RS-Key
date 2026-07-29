// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The legacy YubiKey OTP HID frame protocol: a 70-byte frame (64-byte payload
//! ‖ slot ‖ CRC ‖ pad) carried 7 payload bytes per 8-byte FEATURE report, written
//! via SET_REPORT and polled via GET_REPORT — the transport `ykman otp` speaks.

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
            self.buf = [0; FRAME_SIZE];
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
            self.buf = [0; FRAME_SIZE];
            return RxOutcome::Reset;
        }
        if seq == 0 {
            self.buf = [0; FRAME_SIZE];
        }
        self.buf[seq * REPORT_DATA..seq * REPORT_DATA + REPORT_DATA]
            .copy_from_slice(&report[..REPORT_DATA]);
        if seq != 9 {
            return RxOutcome::None;
        }
        // Final slice: validate the frame CRC (plain CRC-16 over the payload).
        let want = u16::from_le_bytes([self.buf[FRAME_CRC_OFF], self.buf[FRAME_CRC_OFF + 1]]);
        if crc16(&self.buf[..PAYLOAD_SIZE]) != want {
            return RxOutcome::BadCrc;
        }
        let mut payload = [0u8; PAYLOAD_SIZE];
        payload.copy_from_slice(&self.buf[..PAYLOAD_SIZE]);
        RxOutcome::Frame {
            slot: self.buf[PAYLOAD_SIZE],
            payload,
        }
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
