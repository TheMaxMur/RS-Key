// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use rsk_usb::ccid::{
    ERR_BAD_DWLENGTH, HEADER, STATUS_FAILED, STATUS_INACTIVE, process_message, refuse_short_xfr,
    secure_apdu, xfr_apdu,
};

const ATR: &[u8] = &[0x3b, 0xda, 0x18, 0xff, 0x81, 0xb1, 0xfe, 0x75, 0x1f, 0x03];
const SENTINEL: u8 = 0xA5;
const B_SEQ: usize = 6;
const B_STATUS: usize = 7;
const B_ERROR: usize = 8;
const SLOT_STATUS_RESPONSE: u8 = 0x81;

pub fn replay(data: &[u8]) {
    let mut status = STATUS_INACTIVE;
    let mut rest = data;
    while let Some((&n, tail)) = rest.split_first() {
        let end = usize::from(n).min(tail.len());
        let message = &tail[..end];
        rest = &tail[end..];
        // RFU byte 8 supplies output capacity without changing the corpus framing.
        // Zero keeps old seeds' full buffer; nonzero reaches short-buffer paths.
        let capacity = usize::from(message.get(B_ERROR).copied().unwrap_or(0));
        let mut out = [SENTINEL; 2048];
        let room = if capacity == 0 { out.len() } else { capacity };
        let previous = status;
        let xfr = xfr_apdu(message);
        for (a, b) in xfr.into_iter().chain(secure_apdu(message)) {
            assert_eq!(a, HEADER);
            assert!(
                a <= b && b <= message.len(),
                "APDU range escaped the request"
            );
        }

        let refusal = refuse_short_xfr(message, status, &mut out[..room]);
        let expected = xfr.is_some_and(|(a, b)| b - a < 4) && room >= HEADER;
        assert_eq!(refusal, expected.then_some(HEADER));
        if let Some(n) = refusal {
            assert_eq!(out[0], SLOT_STATUS_RESPONSE);
            assert_eq!(&out[1..6], &[0; 5]);
            assert_eq!(out[B_SEQ], message[B_SEQ]);
            assert_eq!(out[B_STATUS], STATUS_FAILED | status);
            assert_eq!(out[B_ERROR], ERR_BAD_DWLENGTH);
            assert!(out[n..].iter().all(|byte| *byte == SENTINEL));
        } else {
            assert!(out.iter().all(|byte| *byte == SENTINEL));
        }

        out.fill(SENTINEL);
        let written = process_message(message, ATR, &mut status, &mut out[..room]);
        assert!(written <= room, "response escaped the output buffer");
        assert!(out[written..].iter().all(|byte| *byte == SENTINEL));
        if written == 0 {
            assert_eq!(status, previous, "a silent command changed the slot status");
        } else {
            assert!(written >= HEADER, "response has no CCID header");
            assert_eq!(
                u32::from_le_bytes(out[1..5].try_into().unwrap()) as usize,
                written - HEADER
            );
            assert_eq!(out[5], 0, "response changed the slot number");
            assert_eq!(out[B_SEQ], message[B_SEQ], "response lost its sequence");
            assert_eq!(
                out[B_STATUS], status,
                "reply reports a different slot status"
            );
            assert_eq!(out[B_ERROR], 0, "successful command reports an error");
        }
    }
}

#[cfg(test)]
#[path = "ccid_frame_tests.rs"]
mod tests;
