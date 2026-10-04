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
mod ccid_frame;

fuzz_target!(|data: &[u8]| {
    ccid_frame::replay(data);
});
