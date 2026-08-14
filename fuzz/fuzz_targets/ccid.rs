// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the CCID transport framing (`rsk_usb::ccid::process_message`): the
//! whole 10-byte CCID header + payload comes off the USB bulk-OUT endpoint
//! attacker-controlled, so parsing `dwLength` / the message type and writing the
//! response header must never panic — only ever produce a (possibly empty)
//! response. `process_message` handles only the framing (power on/off, slot
//! status, params); the XfrBlock applet dispatch is driven and fuzzed separately
//! (`openpgp_apdu` / `mgmt_apdu`).
//!
//! The input is a sequence of length-prefixed messages over ONE slot `bStatus`,
//! not a single message: `bStatus` is the whole state this layer carries, and a
//! host reads it back to decide whether a card is present. A power-on that fails
//! to publish what it just set — or a later message that reports a status the
//! slot is no longer in — is a card that has gone missing while still answering.

use libfuzzer_sys::fuzz_target;
use rsk_usb::ccid::{HEADER, process_message};

/// `bStatus` lives in response byte 7 (`put_header`).
const B_STATUS: usize = 7;

fuzz_target!(|data: &[u8]| {
    const ATR: &[u8] = &[0x3b, 0xda, 0x18, 0xff, 0x81, 0xb1, 0xfe, 0x75, 0x1f, 0x03];
    let mut status = 0u8;
    let mut out = [0u8; 2048];

    let mut rest = data;
    while let Some((&n, tail)) = rest.split_first() {
        let end = (n as usize).min(tail.len());
        let w = process_message(&tail[..end], ATR, &mut status, &mut out);
        rest = &tail[end..];
        if w > 0 {
            assert!(w >= HEADER, "a {w}-byte response is not a CCID message");
            assert_eq!(
                out[B_STATUS], status,
                "the reply reports a slot status the slot is not in"
            );
        }
    }
});
