// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the typed-ticket generator (`rsk_otp::ticket`, via
//! `OtpApplet::button_ticket`) over two boots, each first press advancing a use
//! counter, and an ADVERSARIAL slot config sealed into flash — the kind a flash-snapshot
//! rollback can plant. The HOTP / static-password / Yubico-OTP builders must
//! never panic and never type more than `MAX_TICKET` bytes.

use core::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use rsk_crypto::Device;
use rsk_fs::storage::ram::RamStorage;
use rsk_fs::{Fs, KeyFid};
use rsk_otp::seal::seal_put;
use rsk_otp::ticket::MAX_TICKET;
use rsk_otp::{AlwaysConfirm, OtpApplet, Rng, SlotRecord};

/// First OTP slot FID (crate-private `EF_OTP_SLOT1`; the four slots are 0xBB00..=0xBB03).
const SLOT1_FID: u16 = 0xBB00;

struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            *x = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let rnd = [data[0], data[1]];
    let ts = data.len() as u32;

    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
        latched: false,
    };
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let mut seed_rng = CountRng(1);

    // Seal a fuzz-derived config into each of the four slots (padded into the
    // full 60-byte record the builder unseals). A rotated view per slot varies
    // their tkt/cfg flag bytes across HOTP / static / Yubico-OTP arms.
    let body = &data[2..];
    for slot in 0..4u16 {
        let mut rec = [0u8; 60];
        let off = (slot as usize * 7).min(body.len());
        let src = &body[off..];
        let n = src.len().min(60);
        rec[..n].copy_from_slice(&src[..n]);
        let _ = seal_put(
            &dev,
            &mut fs,
            &mut seed_rng,
            KeyFid::new(SLOT1_FID + slot),
            &SlotRecord::from_bytes(&rec).expect("a full record"),
        );
    }

    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut out = [0u8; MAX_TICKET];
    // A boot is a fresh applet: the second one's first presses advance counters
    // the first one's already moved.
    for _boot in 0..2 {
        let mut app = OtpApplet::new([1, 2, 3, 4, 5, 6, 7, 8], [0x22; 32], None, &rng, &presence);
        for slot_no in 1..=4u8 {
            if let Some((len, _ascii)) = app.button_ticket(slot_no, ts, rnd, &mut fs, &mut out) {
                assert!(len <= MAX_TICKET);
            }
        }
    }
});
