// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the rescue device-key seal (`rsk_rescue::keydev`): `load_or_generate`
//! (which drives `unseal_scalar`) and the boot `migrate_kbase`, over arbitrary
//! `EF_DEVCERT_KEY` bytes and both device generations. The seal moved from raw
//! AES-CBC to AES-256-GCM with a pre-OTP→OTP recovery arm; the invariants:
//! no panic on any stored shape; a load never crashes; and `migrate_kbase` is
//! idempotent (the recovered key is stable across a second pass), so a torn or
//! repeated boot migration cannot corrupt the attestation key.

use libfuzzer_sys::fuzz_target;
use rsk_crypto::Device;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_rescue::Rng;
use rsk_rescue::keydev::{EF_DEVCERT_KEY, load_or_generate, migrate_kbase};

const OTP: [u8; 32] = [0x5A; 32];

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
    if data.len() > 128 {
        return;
    }
    let dev_old = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
        latched: false,
    };
    let dev_new = Device {
        otp_key: Some(&OTP),
        ..dev_old
    };
    let mut rng = CountRng(1);

    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    // Seed EF_DEVCERT_KEY with the fuzzer's bytes — any on-flash shape (a legacy
    // CBC record, a pre-OTP or OTP GCM record, or garbage). The raw-FID `put` is
    // the deliberate escape hatch past the KeyFid chokepoint.
    if fs.put(EF_DEVCERT_KEY.get(), data).is_err() {
        return;
    }

    // A load under either generation must never panic (garbage → None).
    let _ = load_or_generate(&dev_old, None, &mut fs, &mut rng);
    let _ = load_or_generate(&dev_new, None, &mut fs, &mut rng);

    // The boot migration under the OTP arm must tolerate any stored shape and be
    // idempotent: whatever key it recovers (if any) is stable across a re-run.
    migrate_kbase(&dev_new, &mut fs, &mut rng);
    let after = load_or_generate(&dev_new, None, &mut fs, &mut rng).map(|k| k.to_bytes());
    migrate_kbase(&dev_new, &mut fs, &mut rng);
    let again = load_or_generate(&dev_new, None, &mut fs, &mut rng).map(|k| k.to_bytes());
    assert_eq!(after, again, "migrate_kbase must be idempotent");
});
