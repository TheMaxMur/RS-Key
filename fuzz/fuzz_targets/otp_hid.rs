// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the keyboard-interface OTP frame codec (`rsk_otp::hid`). Arbitrary bytes
//! are fed to [`FrameRx`] as a stream of 8-byte feature reports — the host
//! SET_REPORT attacker surface — and every completed frame is round-tripped
//! through [`FrameTx`]. None of the reassembly / framing may panic.

use libfuzzer_sys::fuzz_target;
use rsk_otp::hid::{FrameRx, FrameTx, PAYLOAD_SIZE, REPORT_SIZE, RxOutcome};
use rsk_secret::Secret;

fuzz_target!(|data: &[u8]| {
    let mut rx = FrameRx::new();
    let mut payload = Secret::<[u8; PAYLOAD_SIZE]>::zeroed();
    let mut tx = FrameTx::new();
    for chunk in data.chunks(REPORT_SIZE) {
        let mut report = [0u8; REPORT_SIZE];
        report[..chunk.len()].copy_from_slice(chunk);
        match rx.feed(&report, &mut payload) {
            RxOutcome::Frame { slot: _ } => {
                // A completed frame's payload is a plausible response body; stream
                // it back out and drain every report.
                tx.load(payload.expose());
                let mut out = [0u8; REPORT_SIZE];
                let mut guard = 0;
                while tx.next(&mut out) {
                    guard += 1;
                    assert!(guard < 64, "FrameTx must terminate");
                }
            }
            RxOutcome::None | RxOutcome::Reset | RxOutcome::BadCrc => {}
        }
    }
});
