// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_crypto::{Device, Mode, PinKdf, aes_encrypt};
use rsk_rescue::otp_lock::{PAGE58_LOCK1_ROW, PRE_OTP_FIDO};
use rsk_rescue::seal::{self, CHAFF_OFFSET, DEVK_ROW, KEY_ROWS, MKEK_ROW, Status};

#[derive(Default)]
struct Page {
    lock: u32,
    writes: usize,
}

impl seal::Otp for Page {
    fn test_keys(&self) -> bool {
        false
    }
    fn read_raw(&mut self, row: usize) -> Option<u32> {
        if row == PAGE58_LOCK1_ROW {
            Some(self.lock)
        } else if (DEVK_ROW..MKEK_ROW + KEY_ROWS).contains(&row) {
            Some(0x351111) // ECC encoding of the fixture's 0x1111 words.
        } else if (DEVK_ROW + CHAFF_OFFSET..MKEK_ROW + CHAFF_OFFSET + KEY_ROWS).contains(&row) {
            Some(0x351111 ^ 0xFFFFFF)
        } else {
            None
        }
    }
    fn read_ecc(&mut self, _row: usize) -> Option<u16> {
        Some(0x1111)
    }
    fn burn_lock(&mut self, value: u32) -> bool {
        self.lock |= value;
        self.writes += 1;
        true
    }
}

#[test]
fn legacy_pin_wrapped_seed_blocks_auto_seal_until_the_real_migration_succeeds() {
    let old = Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL_ID,
        otp_key: None,
        latched: false,
    };
    let fused = Device {
        otp_key: Some(&[0x11; 32]),
        ..old
    };
    let pin_hash = [0x35; 16];
    let seed = [0x42; 32];
    let mut ciphertext = seed;
    let root = old.derive_kbase();
    let iv: &[u8; 16] = old.serial_hash[..16].try_into().unwrap();
    aes_encrypt(root.expose(), iv, Mode::Cbc, &mut ciphertext).unwrap();
    let session = old.pin_derive_session(&pin_hash);
    let mut record = [0; 61];
    record[0] = 3;
    old.encrypt_with_aad(
        session.expose(),
        &ciphertext,
        PinKdf::V2,
        &[0x24; 12],
        &mut record[1..],
    )
    .unwrap();
    let mut fs = Fs::new(RamStorage::new());
    let fid = rsk_fido::consts::EF_KEY_DEV;
    fs.put(fid.get(), &record).unwrap();
    let mut page = Page::default();
    for _ in 0..2 {
        assert!(rsk_fido::seed::migrate_keydev_boot(&fused, &mut fs).unwrap());
        assert!(seal::scrub_before_seal(&mut fs));
        let result = seal::seal_at_boot(&mut page, Some(PRE_OTP_FIDO), true, false);
        assert_eq!(result.status, Status::MigrationPending);
        assert_eq!(page.writes, 0);
        fs = Fs::new(fs.into_storage());
        fs.scan();
    }
    assert!(rsk_fido::seed::migrate_keydev_pin(&fused, &mut fs, &[0; 16]).is_err());
    assert!(rsk_fido::seed::migrate_keydev_boot(&fused, &mut fs).unwrap());
    rsk_fido::seed::migrate_keydev_pin(&fused, &mut fs, &pin_hash).unwrap();
    assert!(!rsk_fido::seed::migrate_keydev_boot(&fused, &mut fs).unwrap());
    assert!(seal::scrub_before_seal(&mut fs));
    let result = seal::seal_at_boot(&mut page, Some(0), true, false);
    assert_eq!(result.status, Status::Sealed);
    assert!(result.restart);
    assert_eq!(page.writes, 2);
    let closed = Device {
        latched: true,
        ..fused
    };
    assert_eq!(
        rsk_fido::seed::load_keydev(&closed, &mut fs)
            .unwrap()
            .expose(),
        &seed
    );
    fs.put(fid.get(), &record).unwrap();
    assert!(
        rsk_fido::seed::load_keydev(&closed, &mut fs).is_none(),
        "old wrapped seed replay reopened the arm"
    );
}
