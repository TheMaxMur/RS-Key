// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the management applet dispatch (`ManagementApplet::process`): SELECT
//! returns the version string, READ CONFIG builds the capability/serial/version
//! TLV, and WRITE CONFIG parses an attacker-controlled length-prefixed blob it
//! persists to `EF_DEV_CONF` (then READ CONFIG echoes it back). A stream of raw
//! APDUs is replayed against the live applet + flash; none may panic.

use core::cell::RefCell;
use libfuzzer_sys::fuzz_target;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_mgmt::{AlwaysConfirm, ManagementApplet};
use rsk_sdk::{Apdu, Applet, ResBuf};

mod apdu_frame;
use apdu_frame::next_frame;

fuzz_target!(|data: &[u8]| {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = ManagementApplet::new([0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4], &presence);

    // Split the input into length-prefixed APDUs and replay each (see
    // `apdu_frame` for the 0xFF extended-Lc escape).
    let mut rest = data;
    while let Some((frame, tail)) = next_frame(rest) {
        rest = tail;
        if let Ok(apdu) = Apdu::parse(frame.as_slice()) {
            let mut buf = [0u8; 256];
            let mut res = ResBuf::new(&mut buf);
            let _ = app.process(&apdu, &mut fs, &mut res);
        }
    }
});
