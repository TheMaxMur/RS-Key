// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the Yubico OTP-slot at-rest seal (`rsk_otp::seal`): the `seal_put` /
//! `seal_read` round-trip and the boot `migrate_seal`, across the pre-OTP and OTP
//! device generations. Invariants: no panic on any stored bytes; a freshly sealed
//! record unseals to its exact plaintext; a slot sealed under the pre-OTP (NO-OTP)
//! arm SURVIVES `migrate_seal` to the OTP arm, recovered byte-identical (the #12
//! recovery arm), and never orphaned or double-sealed; the migration is idempotent.

use libfuzzer_sys::fuzz_target;
use rsk_crypto::Device;
use rsk_fs::storage::ram::RamStorage;
use rsk_fs::{Fs, KeyFid};
use rsk_otp::Rng;
use rsk_otp::seal::{seal_put, seal_read};
use rsk_secret::Secret;

/// First OTP slot FID (crate-private `EF_OTP_SLOT1`; the four slots are
/// `0xBB00..=0xBB03`), the one `migrate_seal` scans.
const SLOT_FID: u16 = 0xBB00;

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
    if data.is_empty() || data.len() > 200 {
        return;
    }
    let dev_old = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    };
    let dev_new = Device {
        otp_key: Some(&[0x5A; 32]),
        ..dev_old
    };
    let mut rng = CountRng(1);
    let fid = KeyFid::new(SLOT_FID);
    let mut out = Secret::<[u8; 256]>::zeroed();

    // Round-trip + pre-OTP→OTP survival: seal the fuzz bytes under the pre-OTP arm
    // (skipped when over-length), then the OTP boot migration must recover and
    // re-seal them — never orphan (drop) or double-seal (corrupt).
    {
        let mut fs = Fs::new(RamStorage::new());
        fs.scan();
        if seal_put(&dev_old, &mut fs, &mut rng, fid, data) {
            let n = seal_read(&dev_old, &mut fs, fid, &mut out).expect("a fresh seal must unseal");
            assert_eq!(&out.expose()[..n], data);
            // The OTP arm can't read a pre-OTP-sealed record yet…
            assert!(seal_read(&dev_new, &mut fs, fid, &mut out).is_none());
            // …migrate_seal recovers it under the OTP arm, byte-identical…
            rsk_otp::migrate_seal(&dev_new, &mut fs, &mut rng);
            let m =
                seal_read(&dev_new, &mut fs, fid, &mut out).expect("slot must survive the burn");
            assert_eq!(&out.expose()[..m], data);
            // …and a second pass is a no-op (idempotent).
            rsk_otp::migrate_seal(&dev_new, &mut fs, &mut rng);
            let mut out2 = Secret::<[u8; 256]>::zeroed();
            let m2 = seal_read(&dev_new, &mut fs, fid, &mut out2).expect("idempotent");
            assert_eq!(&out.expose()[..m], &out2.expose()[..m2]);
        }
    }

    // Robustness: migrate_seal over arbitrary raw stored bytes (not a valid seal)
    // must never panic, under either generation, and leave a readable-or-absent slot.
    {
        let mut fs = Fs::new(RamStorage::new());
        fs.scan();
        let _ = fs.put(SLOT_FID, data);
        rsk_otp::migrate_seal(&dev_new, &mut fs, &mut rng);
        rsk_otp::migrate_seal(&dev_old, &mut fs, &mut rng);
        let _ = seal_read(&dev_new, &mut fs, fid, &mut out);
    }
});
