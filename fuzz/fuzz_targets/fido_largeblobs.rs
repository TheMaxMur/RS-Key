// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz `authenticatorLargeBlobs` (get/set) on arbitrary params, with a
//! largeBlobWrite-armed token and the default large-blob array provisioned. It
//! must never panic and must always stay within the output buffer (the
//! multi-fragment accumulator and the offset arithmetic are the interesting bits).

use libfuzzer_sys::fuzz_target;
use rsk_crypto::Device;
use rsk_fido::largeblobs::large_blobs;
use rsk_fido::seed::ensure_seed;
use rsk_fido::state::PERM_LBW;
use rsk_fido::{Ctx, FidoState, Rng};
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

    // Arm a largeBlobWrite token (the fuzzer won't forge a valid MAC, but the
    // parse / offset / accumulate paths must stay panic-free regardless).
    let mut state = FidoState::new();
    state.paut.token = [0x99; 32];
    state.paut.permissions = PERM_LBW;
    state.begin_using_token(false, 0);

    let mut out = [0u8; 2048];
    let mut presence = rsk_fido::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev,
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 2,
    };
    if let Ok(n) = large_blobs(&mut ctx, data, &mut out) {
        assert!(n <= out.len());
    }
});
