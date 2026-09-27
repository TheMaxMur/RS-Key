// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Fuzz `load_keydev` over arbitrary EF_KEY_DEV bytes — the four
//! format tags (0x01/0x03 pre-OTP, 0x11/0x13 OTP) and every malformed shape,
//! against both device generations, plus the boot and PIN-verify migration
//! passes. Invariants: no panic; a fuzz-written blob never round-trips as a
//! valid seed under the WRONG generation (0x11/0x13 with `otp_key: None` must
//! yield `None`, never CBC garbage); legacy PIN-wrapped tags are never loadable
//! directly; migration is idempotent.

#![no_main]
use libfuzzer_sys::fuzz_target;

use rsk_crypto::Device;
use rsk_fido::seed::{load_keydev, migrate_keydev_boot, migrate_keydev_pin};
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;

const EF_KEY_DEV: u16 = 0xCC00;
const OTP: [u8; 32] = [0x5A; 32];

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 64 {
        return;
    }
    let dev_old = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    };
    let dev_new = Device {
        otp_key: Some(&OTP),
        ..dev_old
    };

    let mut fs = Fs::new(RamStorage::new());
    if fs.put(EF_KEY_DEV, data).is_err() {
        return;
    }

    // An OTP-generation tag must be unreadable without the OTP key; legacy
    // PIN-wrapped tags must never load directly under either generation.
    if matches!(data[0], 0x03 | 0x11 | 0x13) {
        assert!(load_keydev(&dev_old, &mut fs).is_none());
    }
    if data[0] == 0x13 {
        assert!(load_keydev(&dev_new, &mut fs).is_none());
    }
    let _ = load_keydev(&dev_old, &mut fs);
    let _ = load_keydev(&dev_new, &mut fs);

    // The PIN-verify migration must tolerate any stored shape (a random AEAD
    // body fails authentication → error, blob untouched, no panic).
    let _ = migrate_keydev_pin(&dev_old, &mut fs, &[0x42; 16]);
    let _ = migrate_keydev_pin(&dev_new, &mut fs, &[0x42; 16]);

    // The boot pass must tolerate any stored shape and be idempotent.
    let _ = migrate_keydev_boot(&dev_new, &mut fs);
    let after_one = load_keydev(&dev_new, &mut fs).map(|s| *s.expose());
    let _ = migrate_keydev_boot(&dev_new, &mut fs);
    assert_eq!(
        after_one,
        load_keydev(&dev_new, &mut fs).map(|s| *s.expose())
    );
});
