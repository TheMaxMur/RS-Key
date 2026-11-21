// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Fixed codec fixtures exercise every field and malformed boundary."
)]

use super::*;

#[test]
fn persisted_counter_locations_and_slot_bytes_match_format_vectors() {
    assert_eq!(public_pin(PIV_RETRIES), Some(0xCD21));
    assert_eq!(public_pin(OPENPGP_RETRIES), Some(0xCD22));
    assert_eq!(public_pin(FIDO_PIN), None);
    let generation = 0x0102_0304_0506_0708;
    for (fid, offset) in [
        (PIV_RETRIES, 0),
        (OPENPGP_RETRIES, 16),
        (FIDO_PIN, 32),
        (DEVICE_PIN, 48),
        (OATH_PIN, 64),
    ] {
        let slot = Slot::pin(fid).unwrap();
        assert_eq!(slot.bucket, 0xCD00);
        let mut encoded = [0; 80];
        let mut absent = [0xA5; 3];
        assert_eq!(slot.read(&encoded, 0, &mut absent), Ok(None));
        assert_eq!(absent, [0xA5; 3]);
        slot.replace(&mut encoded, 0, &[5]).unwrap();
        assert_eq!(slot.read(&encoded, 0, &mut absent), Ok(Some(1)));
        assert_eq!(absent, [5, 0xA5, 0xA5]);
        encoded.fill(0);
        slot.replace(&mut encoded, generation, &[5]).unwrap();
        let mut expected = [0; 80];
        expected[offset..offset + 10].copy_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1, 1, 5]);
        assert_eq!(encoded, expected);
        let mut decoded = [0];
        assert_eq!(slot.read(&expected, generation, &mut decoded), Ok(Some(1)));
        assert_eq!(decoded, [5]);
    }
    let slot = Slot::oath(0xBA09).unwrap();
    assert_eq!(slot.bucket, 0xCD02);
    let mut encoded = [0; 384];
    slot.replace(&mut encoded, generation, &[0xA5; 36]).unwrap();
    let mut expected = [0; 384];
    expected[48..57].copy_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1, 36]);
    expected[57..93].fill(0xA5);
    assert_eq!(encoded, expected);
    let mut decoded = [0; 36];
    assert_eq!(slot.read(&expected, generation, &mut decoded), Ok(Some(36)));
    assert_eq!(decoded, [0xA5; 36]);
}

#[test]
fn slot_codecs_reject_overflowing_and_empty_values_before_copying_or_writing() {
    for (slot, widths) in [
        (Slot::pin(PIV_RETRIES).unwrap(), [0, 5, 15]),
        (Slot::oath(OATH_FIRST).unwrap(), [0, 37, 47]),
    ] {
        for width in widths {
            let mut encoded = vec![0; slot.bytes()];
            encoded[0] = 1;
            encoded[8] = width;
            let mut out = [0xA5; 48];
            assert_eq!(slot.read(&encoded, 1, &mut out), Err(Error::MemoryFatal));
            assert_eq!(out, [0xA5; 48]);
            let mut blank = vec![0; slot.bytes()];
            assert_eq!(
                slot.replace(&mut blank, 1, &vec![0; usize::from(width)]),
                Err(Error::MemoryFatal)
            );
            assert!(blank.iter().all(|&byte| byte == 0));
        }
    }
}

#[test]
fn every_oath_owner_has_a_distinct_slot_and_all_255_fit() {
    let mut slots = std::collections::HashSet::new();
    for fid in 0xBA00..=0xBAFE {
        let slot = Slot::oath(fid).unwrap();
        assert!(slots.insert((slot.bucket, slot.index)));
        assert!(bucket_index(slot.bucket).is_some());
        let mut bytes = [0; BUFFER_BYTES];
        slot.replace(&mut bytes[..slot.bytes()], 3, &[0x42; VALUE_BYTES])
            .unwrap();
        let mut value = [0; VALUE_BYTES];
        assert_eq!(
            slot.read(&bytes[..slot.bytes()], 3, &mut value),
            Ok(Some(VALUE_BYTES))
        );
        assert_eq!(value, [0x42; VALUE_BYTES]);
        assert_eq!(slot.read(&bytes[..slot.bytes()], 4, &mut value), Ok(None));
    }
    assert!(Slot::oath(0xB9FF).is_none());
    assert!(Slot::oath(0xBAFF).is_none());
}

#[test]
fn malformed_slots_and_neighbors_are_errors_not_legacy_fallbacks() {
    let slot = Slot::oath(0xBA00).unwrap();
    let mut bytes = [0; BUFFER_BYTES];
    slot.replace(&mut bytes, 0, &[8; VALUE_BYTES]).unwrap();
    for at in [8, SLOT_BYTES + 8, SLOT_BYTES + 47, 47] {
        let mut damaged = bytes;
        damaged[at] = 0xFF;
        assert_eq!(slot.read(&damaged, 0, &mut []), Err(Error::MemoryFatal));
    }
    assert_eq!(
        slot.read(&bytes[..BUFFER_BYTES - 1], 0, &mut []),
        Err(Error::MemoryFatal)
    );
}

#[test]
fn only_retry_bytes_may_use_the_pin_overlay() {
    for (fid, length, retries) in [
        (0xD1FE, 4, vec![1, 3]),
        (0x10C4, 7, vec![4, 5, 6]),
        (0x1080, 35, vec![0]),
        (0xCE20, 35, vec![0]),
        (0x10A0, 34, vec![0]),
        (0x10C4, 8, vec![4, 5, 6]),
        (0x1080, 1, vec![0]),
        (0x1080, 36, vec![0]),
        (0xCE20, 1, vec![0]),
        (0xCE20, 36, vec![0]),
        (0x10A0, 1, vec![0]),
        (0x10A0, 36, vec![0]),
    ] {
        let before = vec![3; length];
        for at in 0..length {
            let mut after = before.clone();
            after[at] = 2;
            assert_eq!(
                only_retries_changed(fid, &before, &after),
                retries.contains(&at)
            );
        }
        assert!(!only_retries_changed(fid, &before, &before[..length - 1]));
        for count in [0, retries.len() + 1] {
            let mut after = before.clone();
            assert_eq!(
                apply_retries(fid, &mut after, &vec![1; count]),
                Err(Error::MemoryFatal)
            );
            assert_eq!(after, before);
        }
    }
}

#[test]
fn malformed_pin_lengths_cannot_publish_or_apply_retry_overlays() {
    for (fid, valid, retries) in [
        (PIV_RETRIES, 4..=4, 2),
        (OPENPGP_RETRIES, 7..=8, 3),
        (FIDO_PIN, 1..=36, 1),
        (DEVICE_PIN, 1..=36, 1),
        (OATH_PIN, 1..=36, 1),
    ] {
        for length in (0..=37).filter(|length| !valid.contains(length)) {
            let before = vec![3; length];
            assert!(!only_retries_changed(fid, &before, &before));
            let mut packed = [0xA5; 3];
            assert_eq!(
                pack_retries(fid, &before, &mut packed),
                Err(Error::MemoryFatal)
            );
            assert_eq!(packed, [0xA5; 3]);
            let mut after = before.clone();
            assert_eq!(
                apply_retries(fid, &mut after, &vec![1; retries]),
                Err(Error::MemoryFatal)
            );
            assert_eq!(after, before);
        }
    }
}
