// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::ram::RamStorage;

fn fs() -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    fs
}

#[test]
fn empty_card_has_no_slots_and_default_retries() {
    let mut fs = fs();
    let info = read_info(&mut fs);
    assert_eq!(info.populated(), 0);
    for s in &info.slots {
        assert!(!s.present && !s.cert);
        assert_eq!(s.algo, 0);
    }
    assert_eq!((info.pin_retries, info.puk_retries), (3, 3));
}

#[test]
fn auth_slot_reads_algo_and_policy_from_meta() {
    let mut fs = fs();
    fs.put(key_fid(SLOT_AUTHENTICATION).get(), &[0xAB; 64])
        .unwrap();
    fs.meta_add(
        key_fid(SLOT_AUTHENTICATION).get(),
        &[
            ALGO_ECCP256,
            PINPOLICY_ALWAYS,
            TOUCHPOLICY_CACHED,
            ORIGIN_GENERATED,
        ],
    )
    .unwrap();
    let s = read_info(&mut fs).slots[0];
    assert_eq!(s.slot, SLOT_AUTHENTICATION);
    assert!(s.present);
    assert_eq!(algo_name(s.algo), "NIST P-256");
    assert_eq!(pin_policy_name(s.pin_policy), "Always");
    assert_eq!(touch_policy_name(s.touch_policy), "Cached");
    assert_eq!(origin_name(s.origin), "Generated");
}

#[test]
fn cert_without_key_counts_as_populated() {
    let mut fs = fs();
    let cert_fid = cert_fid_for_slot(SLOT_SIGNATURE).unwrap();
    fs.put(cert_fid, &[0x30, 0x03, 0x01, 0x02, 0x03]).unwrap();
    let info = read_info(&mut fs);
    assert!(!info.slots[1].present);
    assert!(info.slots[1].cert);
    assert_eq!(info.populated(), 1);
}

#[test]
fn retries_come_from_ef_retries() {
    let mut fs = fs();
    fs.put(EF_RETRIES, &[3, 2, 3, 0]).unwrap();
    let info = read_info(&mut fs);
    assert_eq!((info.pin_retries, info.puk_retries), (2, 0));
}

#[test]
fn extra_lists_populated_retired_and_f9_only() {
    let mut fs = fs();
    // F9 present, retired 0x82 has a key, 0x84 has only a cert, the rest are empty.
    fs.put(key_fid(SLOT_ATTESTATION).get(), &[0xAA; 64])
        .unwrap();
    fs.put(key_fid(0x82).get(), &[0xBB; 64]).unwrap();
    fs.put(
        cert_fid_for_slot(0x84).unwrap(),
        &[0x30, 0x03, 0x01, 0x02, 0x03],
    )
    .unwrap();
    let mut out = [PivSlot::default(); MAX_EXTRA_SLOTS];
    let n = read_extra(&mut fs, &mut out);
    assert_eq!(n, 3);
    assert_eq!((out[0].slot, out[0].present), (SLOT_ATTESTATION, true));
    assert_eq!((out[1].slot, out[1].present), (0x82, true));
    assert_eq!(
        (out[2].slot, out[2].present, out[2].cert),
        (0x84, false, true)
    );
    assert_eq!(extra_count(&mut fs), 3);
}

#[test]
fn next_free_retired_skips_taken_slots() {
    let mut fs = fs();
    assert_eq!(next_free_retired(&mut fs), Some(0x82));
    fs.put(key_fid(0x82).get(), &[0xBB; 64]).unwrap();
    assert_eq!(next_free_retired(&mut fs), Some(0x83));
}

/// A slot holding only a certificate is populated to [`read_extra`], so the picker must
/// skip it too — offering it would have the generate overwrite that certificate under a
/// screen promising it adds to an empty slot.
#[test]
fn next_free_retired_skips_a_cert_without_a_key() {
    let mut fs = fs();
    fs.put(
        cert_fid_for_slot(0x82).unwrap(),
        &[0x30, 0x03, 0x01, 0x02, 0x03],
    )
    .unwrap();
    assert!(!read_slot(&mut fs, 0x82).present);
    assert_eq!(next_free_retired(&mut fs), Some(0x83));
}

/// Deterministic LCG randomness — enough for an EC keygen in a host test.
struct TestRng(u64);
impl Rng for TestRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *x = (self.0 >> 33) as u8;
        }
    }
}

#[test]
fn on_device_generate_fills_an_empty_retired_slot() {
    let mut fs = fs();
    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    };
    let mut rng = TestRng(0xC0FFEE);
    assert!(generate_slot_key(&dev, &mut fs, &mut rng, 0x82, ALGO_ECCP256).is_ok());
    let s = read_slot(&mut fs, 0x82);
    assert!(s.present);
    assert_eq!(algo_name(s.algo), "NIST P-256");
    assert_eq!(origin_name(s.origin), "Generated");
    assert!(s.cert, "a self-signed cert is stored alongside the key");

    // Refuses to overwrite a populated slot, a non-retired slot, and RSA on-device.
    assert!(generate_slot_key(&dev, &mut fs, &mut rng, 0x82, ALGO_ECCP256).is_err());
    assert!(generate_slot_key(&dev, &mut fs, &mut rng, SLOT_AUTHENTICATION, ALGO_ECCP256).is_err());
    assert!(generate_slot_key(&dev, &mut fs, &mut rng, 0x83, ALGO_RSA2048).is_err());
}
