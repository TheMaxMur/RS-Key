// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the CTAPHID_CBOR dispatch (getInfo + makeCredential + getAssertion +
//! clientPIN) on arbitrary input: it must never panic, must always write at least
//! the status byte, and must stay in bounds. The seed is provisioned so the crypto
//! paths are reached for inputs that pass validation.

use libfuzzer_sys::fuzz_target;
use rsk_crypto::Device;
use rsk_fido::{Ctx, Rng, seed::ensure_seed};
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;

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
    let n = rsk_fido::process_cbor(&mut ctx, data, &mut out);
    assert!(n >= 1 && n <= out.len());
    if data.first() == Some(&rsk_fido::consts::CTAP_GET_INFO) {
        assert_eq!(out[0], rsk_fido::CTAP2_OK);
    }
});
