// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the U2F command path: any APDU that parses must run through
//! register/authenticate/version without panicking and stay in bounds.

use libfuzzer_sys::fuzz_target;
use rsk_crypto::Device;
use rsk_fido::{Ctx, Rng, seed::ensure_seed};
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_sdk::apdu::Apdu;

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(apdu) = Apdu::parse(data) else {
        return;
    };
    let dev = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
        latched: false,
    };
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    let _ = ensure_seed(&dev, &mut fs, &mut rng);
    let mut out = [0u8; 2048];
    let mut state = rsk_fido::FidoState::new();
    let mut presence = rsk_fido::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev,
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    let (_sw, n) = rsk_fido::u2f::process_u2f(&mut ctx, &apdu, &mut out);
    assert!(n <= out.len());
});
