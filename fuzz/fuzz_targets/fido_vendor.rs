// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the authenticatorVendor (0x41) seed-backup + soft-lock dispatch on
//! arbitrary input, with an MSE channel pre-established, a seed provisioned and
//! (on half the inputs) the soft lock engaged, so the gated export/load/unlock
//! blob-decode paths are all reached. It must never panic, must always write at
//! most the bounded body, and must stay in bounds.

use libfuzzer_sys::fuzz_target;
use rsk_crypto::Device;
use rsk_fido::consts::EF_KEY_DEV;
use rsk_fido::{
    Ctx, Rng,
    seed::{ensure_seed, seal_seed_locked},
    vendor::vendor,
};
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;

/// The OTP DEVK as `FidoState` takes it — a reader, not the key.
fn devk() -> Option<[u8; 32]> {
    Some([0x42; 32])
}

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
    };
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    let _ = ensure_seed(&dev, &mut fs, &mut rng);

    // First input byte picks the device shape: odd = soft-locked (only the
    // wrapped blob on flash), so UNLOCK/AUT_DISABLE-adjacent paths and the
    // locked guards in EXPORT/LOAD are reachable too.
    if data.first().is_some_and(|b| b & 1 == 1) {
        let blob = seal_seed_locked(&mut rng, &[0x4D; 32], &[0x5A; 32]);
        let _ = fs.put(rsk_fido::consts::EF_KEY_DEV_ENC.get(), &blob);
        let _ = fs.delete(EF_KEY_DEV.get());
    }

    let mut state = rsk_fido::FidoState::new();
    // Pre-establish the MSE channel so EXPORT/LOAD/UNLOCK reach the AEAD paths.
    state.mse_active = true;
    state.mse_key = [0x5A; 32];
    state.mse_pub = [0x04; 65];
    // A DEVK so AUDIT_CHECKPOINT's derive-and-sign path is reachable too. The state
    // holds a READER, not the key: the OTP row is read on demand so an unrotatable
    // signing key never sits in RAM for the whole power cycle.
    state.devk_source = Some(devk);

    let mut out = [0u8; 2048];
    let mut presence = rsk_fido::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev,
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    let n = vendor(&mut ctx, data, &mut out);
    if let Ok(len) = n {
        assert!(len <= out.len());
    }
});
