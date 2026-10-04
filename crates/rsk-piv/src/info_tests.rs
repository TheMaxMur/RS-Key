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
fn legacy_and_incomplete_metadata_never_invent_an_origin_or_policy() {
    let mut fs = fs();
    let fid = key_fid(SLOT_SIGNATURE).get();
    fs.put(fid, &[0xAB; 64]).unwrap();
    for meta in [
        &[ALGO_ECCP384, PINPOLICY_ONCE, TOUCHPOLICY_ALWAYS][..],
        &[ALGO_ECCP384, PINPOLICY_ONCE][..],
    ] {
        fs.meta_add(fid, meta).unwrap();
        let slot = read_slot(&mut fs, SLOT_SIGNATURE);
        assert!(slot.present);
        assert_eq!(slot.origin, 0);
        if meta.len() == 3 {
            assert_eq!(
                (slot.algo, slot.pin_policy, slot.touch_policy),
                (ALGO_ECCP384, PINPOLICY_ONCE, TOUCHPOLICY_ALWAYS)
            );
        } else {
            assert_eq!((slot.algo, slot.pin_policy, slot.touch_policy), (0, 0, 0));
        }
    }
    fs.put(EF_RETRIES, &[3, 0, 3]).unwrap();
    let info = read_info(&mut fs);
    assert_eq!(
        (info.pin_retries, info.puk_retries),
        (DEFAULT_RETRIES, DEFAULT_RETRIES)
    );
}

#[test]
fn extra_slot_enumeration_respects_every_output_capacity() {
    let mut fs = fs();
    for slot in [SLOT_ATTESTATION, SLOT_RETIRED_FIRST, SLOT_RETIRED_LAST] {
        fs.put(key_fid(slot).get(), &[0xAA; 64]).unwrap();
    }
    for size in 0..=MAX_EXTRA_SLOTS {
        let mut out = vec![PivSlot::default(); size];
        let n = read_extra(&mut fs, &mut out);
        assert_eq!(n, size.min(3));
        assert_eq!(
            out[..n].iter().map(|s| s.slot).collect::<Vec<_>>(),
            [SLOT_ATTESTATION, SLOT_RETIRED_FIRST, SLOT_RETIRED_LAST][..n]
        );
        assert!(out[n..].iter().all(|s| *s == PivSlot::default()));
    }
}

#[test]
fn display_labels_distinguish_supported_keys_and_public_policies() {
    for (slot, label) in [
        (SLOT_AUTHENTICATION, "Authentication"),
        (SLOT_SIGNATURE, "Signature"),
        (SLOT_KEYMGM, "Key Management"),
        (SLOT_CARDAUTH, "Card Auth"),
        (SLOT_CARDMGM, "Management"),
        (SLOT_ATTESTATION, "Attestation"),
        (SLOT_RETIRED_FIRST, "Retired"),
    ] {
        assert_eq!(slot_name(slot), label);
    }
    for (algo, label) in [
        (ALGO_RSA1024, "RSA 1024"),
        (ALGO_RSA2048, "RSA 2048"),
        (ALGO_RSA3072, "RSA 3072"),
        (ALGO_RSA4096, "RSA 4096"),
        (ALGO_ECCP256, "NIST P-256"),
        (ALGO_ECCP384, "NIST P-384"),
        (ALGO_ED25519, "Ed25519"),
        (ALGO_X25519, "X25519"),
        (ALGO_3DES, "3DES"),
        (ALGO_AES128, "AES-128"),
        (ALGO_AES192, "AES-192"),
        (ALGO_AES256, "AES-256"),
        (0xFF, "—"),
    ] {
        assert_eq!(algo_name(algo), label);
    }
    for (value, label) in [
        (PINPOLICY_NEVER, "Never"),
        (PINPOLICY_ONCE, "Once"),
        (PINPOLICY_ALWAYS, "Always"),
        (0xFF, "Default"),
    ] {
        assert_eq!(pin_policy_name(value), label);
    }
    for (value, label) in [
        (TOUCHPOLICY_NEVER, "Never"),
        (TOUCHPOLICY_ALWAYS, "Always"),
        (TOUCHPOLICY_CACHED, "Cached"),
        (0xFF, "Default"),
    ] {
        assert_eq!(touch_policy_name(value), label);
    }
    for (value, label) in [
        (ORIGIN_GENERATED, "Generated"),
        (ORIGIN_IMPORTED, "Imported"),
        (0xFF, "—"),
    ] {
        assert_eq!(origin_name(value), label);
    }
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
/// skip it too — offering it would put a new key beside someone's certificate under a
/// screen promising an empty slot.
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
        latched: false,
    };
    let mut rng = TestRng(0xC0FFEE);
    assert!(generate_slot_key(&dev, &mut fs, &mut rng, 0x82, ALGO_ECCP256).is_ok());
    let s = read_slot(&mut fs, 0x82);
    assert!(s.present);
    assert_eq!(algo_name(s.algo), "NIST P-256");
    assert_eq!(origin_name(s.origin), "Generated");
    assert!(!s.cert, "no certificate, as from a host GENERATE");

    // Refuses to overwrite a populated slot, a non-retired slot, and RSA on-device.
    assert!(generate_slot_key(&dev, &mut fs, &mut rng, 0x82, ALGO_ECCP256).is_err());
    assert!(generate_slot_key(&dev, &mut fs, &mut rng, SLOT_AUTHENTICATION, ALGO_ECCP256).is_err());
    assert!(generate_slot_key(&dev, &mut fs, &mut rng, 0x83, ALGO_RSA2048).is_err());
}

/// The panel's generate drops the slot's metadata head before it writes the key, as the
/// host GENERATE does: a head it cannot read refuses with no key written, where a stale
/// head a failed MOVE left would otherwise govern the new key.
#[test]
fn a_faulted_head_refuses_the_panel_generate_before_it_writes() {
    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
        latched: false,
    };
    let rsa = rsk_rsa::generate_rsa(&mut crate::RsaRng(&mut TestRng(99)), 1024).unwrap();
    for via_rsa in [false, true] {
        let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
        let mut fs = Fs::new(backend);
        fs.scan();
        let stale = [
            ALGO_ECCP256,
            PINPOLICY_NEVER,
            TOUCHPOLICY_NEVER,
            ORIGIN_GENERATED,
        ];
        fs.meta_add(key_fid(0x82).get(), &stale).unwrap();
        medium.stick(Some(rsk_fs::EF_META));
        let got = if via_rsa {
            store_retired_rsa(&dev, &mut fs, &mut TestRng(5), 0x82, &rsa)
        } else {
            generate_slot_key(&dev, &mut fs, &mut TestRng(5), 0x82, ALGO_ECCP256)
        };
        medium.stick(None);
        assert_eq!(got, Err(Sw::MEMORY_FAILURE), "RSA {via_rsa}");
        assert_eq!(
            medium.value(key_fid(0x82).get()),
            None,
            "RSA {via_rsa}: a key was written"
        );
    }
}

/// The panel's generate is fenced by presence alone — no management key — so
/// `retired_slot_is_free` is the whole authorisation for overwriting nothing. Both its
/// probes collapsed a failed read into "absent", so one faulted probe reported an
/// OCCUPIED retired slot free and the generate wrote over the sealed key, or put a key
/// beside a certificate that is someone else's. One row per probe, each aimed at its OWN
/// fid: a fault on the key shadows the cert probe behind it.
#[test]
fn a_faulted_retired_probe_does_not_overwrite_a_populated_slot() {
    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
        latched: false,
    };
    // (slot, the fid to fault, the fid whose contents must not change, what it holds)
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
            key_fid(0x83).get(),
            "the absent key of a slot holding only a certificate",
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
        let populated = (
            medium.value(key_fid(0x82).get()).is_some(),
            medium.value(cert_fid_for_slot(0x83).unwrap()).is_some(),
        );
        assert_eq!(populated, (true, true), "control: both slots populated");
        let before = medium.value(guarded);

        medium.stick(Some(faulted));
        // The picker must not offer a slot it could not confirm empty.
        let offered = next_free_retired(&mut fs);
        let sw = generate_slot_key(&dev, &mut fs, &mut TestRng(0xC0FFEE), slot, ALGO_ECCP256);
        medium.stick(None);

        assert_eq!(
            medium.value(guarded),
            before,
            "a faulted probe let the panel generate change {what}"
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
