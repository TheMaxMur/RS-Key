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
fn slot_labels_match_the_ui_screens() {
    // The consent prompt's label; the touch build's detail screens show the same
    // strings (rsk-ui render/applets.rs), so this pins the shared vocabulary.
    let mut buf = [0u8; SLOT_LABEL_MAX];
    assert_eq!(slot_label(SLOT_AUTHENTICATION, &mut buf), "9A Auth");
    assert_eq!(slot_label(SLOT_SIGNATURE, &mut buf), "9C Sign");
    assert_eq!(slot_label(SLOT_KEYMGM, &mut buf), "9D Key Mgmt");
    assert_eq!(slot_label(SLOT_CARDAUTH, &mut buf), "9E Card Auth");
    assert_eq!(slot_label(SLOT_CARDMGM, &mut buf), "9B Mgmt");
    assert_eq!(slot_label(SLOT_ATTESTATION, &mut buf), "F9 Attestation");
    // Retired slots are numbered from 0x82; a bare name could not tell two of
    // them apart, which is the whole point of the number.
    assert_eq!(slot_label(SLOT_RETIRED_FIRST, &mut buf), "Retired #1");
    assert_eq!(slot_label(SLOT_RETIRED_LAST, &mut buf), "Retired #20");
    assert_eq!(slot_label(0x81, &mut buf), "PIV slot");
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

/// The panel's generate is fenced by presence alone — no management key — so
/// `retired_slot_is_free` is the whole authorisation for overwriting nothing. Both its
/// probes collapsed a failed read into "absent", so one faulted probe reported an
/// OCCUPIED retired slot free and the generate wrote over the sealed key and the
/// certificate the screen promises it never erases. One row per probe, each aimed at
/// its OWN fid: a fault on the key shadows the cert probe behind it.
#[test]
fn a_faulted_retired_probe_does_not_overwrite_a_populated_slot() {
    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    };
    // (slot, the fid to fault, the fid whose bytes must survive, what it holds)
    for (slot, faulted, guarded, what) in [
        (
            0x82u8,
            key_fid(0x82).get(),
            key_fid(0x82).get(),
            "the sealed key of a slot holding a key and no certificate",
        ),
        (
            0x83,
            cert_fid_for_slot(0x83).unwrap(),
            cert_fid_for_slot(0x83).unwrap(),
            "the certificate of a slot holding a certificate and no key",
        ),
    ] {
        let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
        let mut fs = Fs::new(backend);
        fs.scan();
        fs.put(key_fid(0x82).get(), &[0xBB; 64]).unwrap();
        fs.put(
            cert_fid_for_slot(0x83).unwrap(),
            &[0x30, 0x03, 0x01, 0x02, 0x03],
        )
        .unwrap();
        let before = medium.value(guarded);
        assert!(before.is_some(), "{what} is present before the fault");

        medium.stick(Some(faulted));
        // The picker must not offer a slot it could not confirm empty.
        let offered = next_free_retired(&mut fs);
        let sw = generate_slot_key(&dev, &mut fs, &mut TestRng(0xC0FFEE), slot, ALGO_ECCP256);
        medium.stick(None);

        assert_eq!(
            medium.value(guarded),
            before,
            "a faulted probe let the panel generate destroy {what}"
        );
        assert_ne!(
            offered,
            Some(slot),
            "the picker offered slot {slot:#04x}, which it could not confirm empty"
        );
        assert_eq!(
            sw,
            Err(Sw::MEMORY_FAILURE),
            "a generate that could not confirm slot {slot:#04x} empty has to refuse"
        );
    }
}
