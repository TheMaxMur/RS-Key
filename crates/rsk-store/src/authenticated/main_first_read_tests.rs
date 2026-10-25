// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::authenticated::{Layout, RawBank, storage::AUTHORITY_BYTES};
use sequential_storage::cache::key_pointers::ArrayKeyPointers;
use sequential_storage::cache::page_pointers::ArrayPagePointers;
use sequential_storage::cache::page_states::ArrayPageStates;

type CachedMap = Cache<ArrayPageStates<8>, ArrayPagePointers<8>, ArrayKeyPointers<u16, 32>, u16>;

fn prepared_cached() -> (
    Main<crate::tests::FaultFlash, CachedMap>,
    Secret<[u8; 32]>,
    crate::tests::FaultFlash,
) {
    ROOT.with(|root| root.set([0x56; 32]));
    MODE.with(|mode| mode.set(RootRead::Fused));
    CHANGE_AFTER_READ.with(|change| change.set(false));
    RESTORE_AFTER_READ.with(|change| change.set(false));
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let layout = Layout::new(32768..32768 + AUTHORITY_BYTES).unwrap();
    let mut main = Main::<_, CachedMap>::new(
        MapStorage::new(
            VerifiedFlash::new(flash.clone()),
            MapConfig::try_new(0..32768).unwrap(),
            Cache::new(
                ArrayPageStates::new(),
                ArrayPagePointers::new(),
                ArrayKeyPointers::new(),
            ),
        ),
        layout.main.map(|range| {
            Journal::new(RawBank::new(flash.clone(), range).unwrap(), Partition::Main)
        }),
        EPOCH,
        RootArm::Otp,
    );
    let key = source().key(RootArm::Otp).unwrap();
    main.initialize(key.expose(), 0, &Directory::new()).unwrap();
    main.write(key.expose(), 0xB001, Some(&[0x63; 512]))
        .unwrap();
    main.write(key.expose(), 0xB000, Some(b"owner")).unwrap();
    assert_eq!(main.read(key.expose(), 0xB001, &mut []), Ok(Some(512)));
    main.map.invalidate_cache();
    (main, key, flash)
}

#[test]
fn a_cold_small_record_is_proven_once_beside_larger_records() {
    let (mut main, _key, flash) = prepared_cached();
    let bound = main.authority.read_bound(main.identity, main.arm).unwrap();
    let entry = main.directory.find(0xB000).unwrap();
    let original = flash.image();
    flash.arm(&[]);
    for attempt in 0..2 {
        READS.with(|count| count.set(0));
        READ_MAC_PROOFS.with(|count| count.set(0));
        DERIVATIONS.with(|count| count.set(0));
        if attempt == 0 {
            main.buffer.expose_mut().fill(0xA5);
        }
        let mut out = [0xA5; 3];
        assert_eq!(
            main.read_with_source(source(), RootArm::Otp, 0xB000, &mut out),
            Ok(Some(5))
        );
        assert_eq!(&out, b"own");
        assert!(main.buffer.expose().iter().all(|&byte| byte == 0));
        assert_eq!(READS.with(core::cell::Cell::get), 1);
        assert_eq!(
            DERIVATIONS.with(core::cell::Cell::get),
            usize::from(attempt == 0)
        );
        assert_eq!(
            READ_MAC_PROOFS.with(core::cell::Cell::get),
            usize::from(attempt == 0)
        );
        if attempt == 1 {
            assert!(main.read_tags.find(bound, entry).is_some());
        }
    }
    assert_eq!(flash.image(), original);
    assert!(
        flash
            .events()
            .iter()
            .all(|event| event.0 == crate::tests::Io::Read)
    );
}

#[test]
fn a_failed_cold_scan_wipes_larger_unrelated_values_before_returning() {
    let (mut main, _key, flash) = prepared_cached();
    flash.arm(&[]);
    assert_eq!(
        main.read_with_source(source(), RootArm::Otp, 0xB000, &mut []),
        Ok(Some(5))
    );
    let large_read = flash
        .events()
        .iter()
        .position(|event| event.2 > 128)
        .unwrap();
    main.map.invalidate_cache();
    main.read_tags.clear();
    main.buffer.expose_mut().fill(0xA5);
    flash.arm(&[crate::tests::Rule {
        io: crate::tests::Io::Read,
        skip: large_read + 1,
        effect: crate::tests::Effect::Refuse,
        latched: true,
    }]);
    let mut out = [0xA5; 3];
    assert_eq!(
        main.read_with_source(source(), RootArm::Otp, 0xB000, &mut out),
        Err(Error::MemoryFatal)
    );
    assert_eq!(flash.hits(), [1]);
    assert!(
        flash
            .events()
            .iter()
            .take(large_read + 1)
            .any(|event| event.2 > 128)
    );
    assert_eq!(out, [0xA5; 3]);
    assert!(main.buffer.expose().iter().all(|&byte| byte == 0));
    assert!(main.read_cache.is_none());
    assert!(main.authority.established());
}

#[test]
fn the_maximum_value_fits_both_a_first_proof_and_its_hit() {
    let value = vec![0x5A; rsk_fs::MAX_VALUE_BYTES];
    let (mut main, _key) = prepared_value(&value);
    let bound = main.authority.read_bound(main.identity, main.arm).unwrap();
    let entry = main.directory.find(0xB000).unwrap();
    for capacity in [0, 3] {
        let mut out = vec![0xA5; capacity];
        assert_eq!(
            main.read_with_source(source(), RootArm::Otp, 0xB000, &mut out),
            Ok(Some(rsk_fs::MAX_VALUE_BYTES))
        );
        assert_eq!(out, vec![0x5A; capacity]);
        assert!(main.read_tags.find(bound, entry).is_some());
        assert!(main.buffer.expose().iter().all(|&byte| byte == 0));
    }
}
