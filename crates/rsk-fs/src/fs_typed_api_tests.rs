// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn a_yielded_key_is_decided_live_even_when_its_inventory_walk_is_truncated() {
    let mut backend = CountingStorage::new();
    backend.scan_complete = false;
    backend.inner.write(KEY_DEV, b"owner").unwrap();
    let mut fs = Fs::new(backend);
    fs.scan();
    assert_eq!(fs.cache_view(KEY_DEV), store_assurance::CacheView::LIVE);
    assert_eq!(
        fs.cache_view(KEY_DEV + 2),
        store_assurance::CacheView::CLEAR
    );
}

#[test]
fn fallible_key_reads_preserve_absence_length_prefix_and_empty_values() {
    let mut fs = fs();
    let slot = KeyFid::new(0xCEFF);
    let mut out = [0; 2];
    assert_eq!(fs.try_read_key(slot, &mut out), Ok(None));
    assert_eq!(fs.try_has_key(slot), Ok(false));
    fs.put_key(slot, Sealed::wrap(b"sealed blob")).unwrap();
    assert_eq!(fs.try_read_key(slot, &mut out), Ok(Some(11)));
    assert_eq!(&out, b"se");
    assert_eq!(fs.try_has_key(slot), Ok(true));
    fs.put_key(slot, Sealed::wrap(&[])).unwrap();
    assert_eq!(fs.try_read_key(slot, &mut out), Ok(Some(0)));
    assert_eq!(fs.try_has_key(slot), Ok(false));
}

#[test]
fn counter_reads_preserve_absence_length_prefix_and_empty_values() {
    let mut fs = fs();
    let fid = crate::counter::EF_COUNTER;
    let mut out = [0; 2];
    assert_eq!(fs.read_counter(fid, &mut out), None);
    assert_eq!(fs.try_read_counter(fid, &mut out), Ok(None));
    assert!(!fs.has_counter(fid));
    fs.put_counter(fid, &[0x12, 0x34, 0x56, 0x78]).unwrap();
    assert_eq!(fs.read_counter(fid, &mut out), Some(4));
    assert_eq!(out, [0x12, 0x34]);
    assert_eq!(fs.try_read_counter(fid, &mut out), Ok(Some(4)));
    assert!(fs.has_counter(fid));
    fs.put_counter(fid, &[]).unwrap();
    assert_eq!(fs.read_counter(fid, &mut out), Some(0));
    assert_eq!(fs.try_read_counter(fid, &mut out), Ok(Some(0)));
    assert!(!fs.has_counter(fid));
}

#[test]
fn writes_over_a_record_apply_with_and_without_a_landed_rearm() {
    for rearm in [false, true] {
        let mut fs = fs();
        let slot = KeyFid::new(0xCEFF);
        fs.put(KEY_DEV, b"old").unwrap();
        fs.put_key(slot, Sealed::wrap(b"old sealed")).unwrap();
        fs.put(KEY_DEV + 2, b"neighbor").unwrap();
        let landed = if rearm {
            fs.put(crate::EF_HARDENED, &[1]).unwrap();
            Some(crate::request_rescrub(&mut fs).unwrap())
        } else {
            None
        };
        fs.put_over(KEY_DEV, b"replacement", landed.as_ref())
            .unwrap();
        fs.put_key_over(slot, Sealed::wrap(b"new sealed"), landed.as_ref())
            .unwrap();
        let mut out = [0; 11];
        assert_eq!(fs.read(KEY_DEV, &mut out), Some(11));
        assert_eq!(&out, b"replacement");
        assert_eq!(fs.read_key(slot, &mut out), Some(10));
        assert_eq!(&out[..10], b"new sealed");
        fs.delete_over(KEY_DEV, landed.as_ref()).unwrap();
        fs.delete_key_over(slot, landed.as_ref()).unwrap();
        assert_eq!(fs.read(KEY_DEV, &mut out), None);
        assert_eq!(fs.read_key(slot, &mut out), None);
        assert_eq!(fs.read(KEY_DEV + 2, &mut out), Some(8));
        assert_eq!(&out[..8], b"neighbor");
    }
}

#[test]
fn unconditional_removal_releases_only_the_removed_dynamic_slot() {
    let mut fs = fs();
    fs.put(KEY_DEV, b"owner").unwrap();
    fs.put(KEY_DEV + 2, b"neighbor").unwrap();
    assert_eq!(fs.free_dynamic(), MAX_DYNAMIC_FILES - 2);
    let removed = fs.force_delete_halves(KEY_DEV);
    assert_eq!(removed.value, Ok(()));
    assert_eq!(removed.record, Ok(()));
    assert_eq!(fs.dynamic.as_slice(), &[KEY_DEV + 2]);
    assert_eq!(fs.free_dynamic(), MAX_DYNAMIC_FILES - 1);
    assert_eq!(fs.read(KEY_DEV + 2, &mut [0; 8]), Some(8));
}

#[test]
fn metadata_rebuild_accepts_an_exactly_filled_output() {
    let record = [0xCC, 0x00, 0, 1, 0xA5];
    let mut out = [0; 5];
    assert_eq!(rebuild_meta(&record, KEY_DEV + 2, None, &mut out), Ok(5));
    assert_eq!(out, record);
    out.fill(0);
    assert_eq!(rebuild_meta(&[], KEY_DEV, Some(&[0xA5]), &mut out), Ok(5));
    assert_eq!(out, record);
}
