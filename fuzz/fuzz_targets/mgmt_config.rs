// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Structured WRITE→READ stress of the management config store. The generic
//! `mgmt_apdu` target replays arbitrary APDU bytes, so it only reaches the
//! interesting state by chance: WRITE CONFIG's `data[0] == nc - 1` framing
//! constraint plus a >64-byte blob plus a following READ is a low-probability
//! combination from random input. This target *constructs* a valid WRITE CONFIG
//! for every blob the fuzzer supplies (any length, including past the 64-byte
//! read buffer) and always reads it back, so the blob-length dimension — the one
//! that hid the EF_DEV_CONF over-length panic — is explored directly against the
//! persisted flash. Nothing may panic.
//!
//! The read-back is judged, not discarded. Three properties, none of which needs
//! to know the DeviceInfo field set: an accepted write leaves a READ CONFIG that
//! still answers; the answer is a body a host can parse whole; and the answer the
//! live path serves is the one a cold boot would serve. The last two are the
//! generic detector for the silent-corruption class this target was born from — a
//! command that stores or serves less than it claims and still reports success.

use core::cell::RefCell;
use libfuzzer_sys::fuzz_target;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_mgmt::{AlwaysConfirm, ManagementApplet};
use rsk_sdk::tlv::{Tlv, len_tag};
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};

const INS_WRITE_CONFIG: u8 = 0x1C;
const INS_READ_CONFIG: u8 = 0x1D;

/// The CCID short-APDU response budget — what the dispatch path gets.
const CCID_RES_CAP: usize = 256;

/// Smallest response buffer any transport hands READ CONFIG: the OTP-HID frame
/// (mirrors rsk-mgmt's crate-private `MIN_CONFIG_RES_CAP`). It is the budget the
/// echo clamp actually bites at — a 43-byte config once wedged this transport into
/// a permanently empty `9000` (audit run-33).
const MIN_CONFIG_RES_CAP: usize = 64;

fn run(app: &mut ManagementApplet<'_>, fs: &mut Fs<RamStorage>, raw: &[u8]) -> Option<Sw> {
    let apdu = Apdu::parse(raw).ok()?;
    let mut buf = [0u8; CCID_RES_CAP];
    let mut res = ResBuf::new(&mut buf);
    Some(app.process(&apdu, fs, &mut res))
}

/// One READ CONFIG through the direct (non-CCID) entry point into a `cap`-byte
/// response buffer — the transports differ only in how much room they give it.
fn read_back(app: &ManagementApplet<'_>, fs: &mut Fs<RamStorage>, cap: usize) -> (Sw, Vec<u8>) {
    let mut buf = [0u8; CCID_RES_CAP];
    let mut res = ResBuf::new(&mut buf[..cap]);
    let sw = app.read_config(fs, &mut res);
    (sw, res.as_slice().to_vec())
}

/// The two checks a host makes on a DeviceInfo body before it can read one field:
/// the leading overall-length byte describes the rest, and the rest walks as whole
/// TLV objects. `Tlv::next` ends iteration silently on an overrunning declared
/// length, so a leftover tail is precisely a record cut mid-entry.
fn assert_parseable(sw: Sw, body: &[u8]) {
    if sw != Sw::OK {
        return;
    }
    let Some((&declared, entries)) = body.split_first() else {
        panic!("READ CONFIG answered OK with an empty body");
    };
    assert_eq!(
        declared as usize,
        entries.len(),
        "DeviceInfo length byte disagrees with the body: {body:02x?}"
    );
    let walked: usize = Tlv::new(entries)
        .map(|(tag, value)| len_tag(tag, value.len() as u16))
        .sum();
    assert_eq!(
        walked,
        entries.len(),
        "DeviceInfo TLV walk left a tail: {body:02x?}"
    );
}

fuzz_target!(|data: &[u8]| {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = ManagementApplet::new([0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4], &presence);

    // Consume the input as a sequence of `(len, blob)` writes; after each one,
    // read the config back. State persists in `fs` across the whole sequence.
    let mut i = 0;
    while i < data.len() {
        let inner = data[i] as usize; // 0..=255 — short Lc fits, may exceed 64
        i += 1;
        let end = (i + inner).min(data.len());
        let blob = &data[i..end];
        i = end;

        // A valid WRITE CONFIG: leading length byte = inner length, then blob.
        let mut cmd = std::vec![
            0x00,
            INS_WRITE_CONFIG,
            0,
            0,
            (blob.len() + 1) as u8,
            blob.len() as u8,
        ];
        cmd.extend_from_slice(blob);
        let wrote = run(&mut app, &mut fs, &cmd);

        // Read it back over every interface that serves the DeviceInfo TLV.
        let _ = run(&mut app, &mut fs, &[0x00, INS_READ_CONFIG, 0, 0, 0x00]);
        for cap in [MIN_CONFIG_RES_CAP, CCID_RES_CAP] {
            let (sw, body) = read_back(&app, &mut fs, cap);
            // A write the device accepted must leave it able to describe itself.
            // A refused one changed nothing, so it carries no such obligation.
            if wrote == Some(Sw::OK) {
                assert_eq!(sw, Sw::OK, "READ CONFIG failed after an accepted write");
            }
            assert_parseable(sw, &body);
        }
    }

    // The rescan invariant, over the state the whole sequence left behind. `scan`
    // rebuilds the present-cache from the backend exactly as the device does at
    // power-up, so a difference is a record only one of the two paths can see.
    let (sw_live, live) = read_back(&app, &mut fs, CCID_RES_CAP);
    fs.scan();
    let (sw_cold, cold) = read_back(&app, &mut fs, CCID_RES_CAP);
    assert_eq!(
        sw_live, sw_cold,
        "READ CONFIG status changed across a rescan"
    );
    assert_eq!(live, cold, "READ CONFIG body changed across a rescan");
});
