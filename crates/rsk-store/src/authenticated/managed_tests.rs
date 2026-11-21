// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use sequential_storage::cache::{Cache, Uncached};

#[test]
#[expect(
    clippy::unwrap_used,
    reason = "Initialized managed fixtures must preserve counters across mount and owner replacement."
)]
fn bound_counters_require_a_ready_managed_store_and_follow_the_current_owner() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let source = KeySource::new([0x43; 32], |_| super::super::RootRead::Blank, false);
    let mut store = Managed::new_unmounted(
        flash.clone(),
        0..32768,
        32768..32768 + super::super::storage::AUTHORITY_BYTES,
        source,
        Cache::<Uncached, Uncached, Uncached, u16>::new_uncached,
    );
    let mut out = [0xA5; 36];
    let before = flash.image();
    assert_eq!(
        store.read_bound_counter(0xBA00, &mut out),
        Err(Error::MemoryFatal)
    );
    assert_eq!(
        store.write_bound_counter(0xBA00, &[0x42; 36]),
        Err(Error::MemoryFatal)
    );
    assert_eq!(out, [0xA5; 36]);
    assert_eq!(flash.image(), before);
    store
        .administer(StorageAction::Initialize, [0x4B; 16])
        .unwrap();
    store.write(0xBA00, b"owner").unwrap();
    assert_eq!(store.read_bound_counter(0xBA00, &mut out), Ok(None));
    assert_eq!(store.write_bound_counter(0xBA00, &[0x42; 36]), Ok(true));
    store.mount().unwrap();
    assert_eq!(store.read_bound_counter(0xBA00, &mut out), Ok(Some(36)));
    assert_eq!(out, [0x42; 36]);
    store.remove(0xBA00).unwrap();
    assert_eq!(
        store.read_bound_counter(0xBA00, &mut out),
        Err(Error::MemoryFatal)
    );
    store.write(0xBA00, b"replacement").unwrap();
    assert_eq!(store.read_bound_counter(0xBA00, &mut out), Ok(None));
    assert_eq!(store.write_bound_counter(0xBA00, &[0x43; 36]), Ok(true));
    assert_eq!(store.read_bound_counter(0xBA00, &mut out), Ok(Some(36)));
    assert_eq!(out, [0x43; 36]);
}

#[expect(
    clippy::unwrap_used,
    reason = "Verified zero-sequence headers precede deliberately malformed unpublished snapshot entries."
)]
#[test]
fn a_dirty_unpublished_snapshot_has_no_positive_progress_to_adopt() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let source = KeySource::new([0x43; 32], |_| super::super::RootRead::Blank, false);
    let main = 0..32768;
    let counter = main.end..main.end + super::super::storage::AUTHORITY_BYTES;
    let layout = Layout::new(counter.clone()).unwrap();
    let mut key = source.key(RootArm::PreOtp).unwrap();
    let identity = super::super::Identity {
        partition: Partition::Main,
        epoch: [0x4B; 16],
    };
    let entry = super::super::Entry::live(identity, key.expose(), 0xB000, 0, b"owner").unwrap();
    let mut directory = super::super::Directory::<{ super::super::MAX_MAIN_ENTRIES }>::new();
    directory.apply(entry).unwrap();
    let header = Checkpoint {
        identity,
        arm: RootArm::PreOtp,
        sequence: 0,
        entries: 1,
        digest: directory.digest(identity, key.expose(), 0).unwrap(),
    };
    for range in layout.main {
        let mut raw = RawBank::new(flash.clone(), range).unwrap();
        raw.program(0, &header.encode(key.expose()).unwrap())
            .unwrap();
        raw.program(
            u32::try_from(super::super::CHECKPOINT_BYTES).unwrap(),
            &[0; super::super::ENTRY_BYTES],
        )
        .unwrap();
    }
    key.wipe();
    let mut store = Managed::new_unmounted(
        flash.clone(),
        main,
        counter,
        source,
        Cache::<Uncached, Uncached, Uncached, u16>::new_uncached,
    );
    let before = flash.image();
    assert_eq!(store.check_import_progress(), Ok(()));
    assert_eq!(store.state(), StorageState::Recovery);
    assert_eq!(flash.image(), before);
}

#[test]
#[expect(
    clippy::unwrap_used,
    reason = "A mounted fixture must retain its rejecting hardware backend across remount."
)]
fn constructor_bank_digest_survives_mount_and_configuration() {
    use crate::tests::FaultFlash;
    use rsk_fs::Storage;
    fn refused(
        flash: &mut FaultFlash,
        range: Range<u32>,
        end: u32,
        prefix: &[u8],
    ) -> Result<Option<[u8; 32]>> {
        let layout =
            super::super::Layout::new(32768..32768 + super::super::storage::AUTHORITY_BYTES)?;
        if layout.counter.contains(&range) {
            return super::super::RawBank::new(flash.clone(), range)?
                .digest_if_erased_tail(end, prefix);
        }
        Err(Error::MemoryFatal)
    }
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let main = 0..32768;
    let counter = main.end..main.end + super::super::storage::AUTHORITY_BYTES;
    let source = KeySource::new([0x43; 32], |_| super::super::RootRead::Blank, false);
    let mut store = Managed::new_unmounted_with_digest(
        flash.clone(),
        main,
        counter,
        source,
        Cache::<Uncached, Uncached, Uncached, u16>::new_uncached,
        Some(refused),
    );
    store
        .administer(StorageAction::Initialize, [0x4B; 16])
        .unwrap();
    for _ in 0..2 {
        store.mount().unwrap();
        assert_eq!(store.read(0xB000, &mut []), None);
        assert!(!store.last_error());
        assert_eq!(store.read(0xB000, &mut []), None);
        assert!(!store.last_error());
        let before = flash.image();
        flash.arm(&[]);
        assert!(store.write(0xB000, b"new").is_err());
        assert_eq!(flash.image(), before);
        assert!(
            flash
                .events()
                .iter()
                .all(|event| event.0 == crate::tests::Io::Read)
        );
    }
}

#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Fixtures index known NOR images and assert authenticated progress and injected failures."
)]
#[path = "managed_checkpoint_tests.rs"]
mod checkpoint;

#[path = "managed_erased_tests.rs"]
mod erased;

#[test]
#[expect(
    clippy::unwrap_used,
    reason = "An explicitly staged legacy image is replayed after a live authenticated update."
)]
fn a_live_mount_and_administration_refuse_replayed_import_before_writing() {
    use rsk_fs::Storage;
    use sequential_storage::map::{MapConfig, MapStorage};
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let main = 0..32768;
    let counter = main.end..main.end + super::super::storage::AUTHORITY_BYTES;
    let source = KeySource::new([0x43; 32], |_| super::super::RootRead::Blank, false);
    let mut legacy = MapStorage::<u16, _, _>::new(
        crate::verified_flash::VerifiedFlash::new(flash.clone()),
        MapConfig::try_new(main.clone()).unwrap(),
        Cache::new_uncached(),
    );
    embassy_futures::block_on(legacy.store_item(
        &mut [0; crate::KV_BUF],
        &0xB000,
        &b"old".as_slice(),
    ))
    .unwrap();
    let mut import =
        super::super::import::Import::new(flash.clone(), main.clone(), counter.clone(), source)
            .unwrap();
    import.stage([0x4B; 16]).unwrap();
    let old = flash.image();
    let mut store = Managed::new(
        flash.clone(),
        main,
        counter,
        source,
        Cache::<Uncached, Uncached, Uncached, u16>::new_uncached,
    );
    store.write(0xB000, b"current").unwrap();
    assert_eq!(store.read(0xB000, &mut []), Some(7));
    assert!(!store.last_error());
    flash.replace_image_before_read(0, old.clone());
    flash.arm(&[]);
    assert_eq!(store.mount(), Err(Error::MemoryFatal));
    assert!(
        store
            .administer(StorageAction::ImportLegacy, [0x4B; 16])
            .is_err()
    );
    assert!(
        store
            .administer(StorageAction::Initialize, [0x4C; 16])
            .is_err()
    );
    assert_eq!(flash.image(), old);
    assert!(
        flash
            .events()
            .iter()
            .all(|event| event.0 == crate::tests::Io::Read)
    );
}

#[test]
#[expect(
    clippy::unwrap_used,
    reason = "A live backend is given erased media before exercising its administration entry points."
)]
fn a_live_authority_refuses_fresh_staging_on_erased_replacement_media() {
    use rsk_fs::Storage;
    for action in [StorageAction::ImportLegacy, StorageAction::Initialize] {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let erased = flash.image();
        let main = 0..32768;
        let counter = main.end..main.end + super::super::storage::AUTHORITY_BYTES;
        let source = KeySource::new([0x43; 32], |_| super::super::RootRead::Blank, false);
        let mut store = Managed::new_unmounted(
            flash.clone(),
            main,
            counter,
            source,
            Cache::<Uncached, Uncached, Uncached, u16>::new_uncached,
        );
        store
            .administer(StorageAction::Initialize, [0x4B; 16])
            .unwrap();
        store.write(0xB000, b"current").unwrap();
        assert_eq!(store.read(0xB000, &mut []), Some(7));
        assert!(!store.last_error());
        flash.replace_image_before_read(0, erased.clone());
        flash.arm(&[]);
        assert_eq!(store.mount(), Err(Error::MemoryFatal));
        let result = store.administer(action, [0x4C; 16]);
        assert!(
            flash
                .events()
                .iter()
                .all(|event| event.0 == crate::tests::Io::Read)
        );
        assert_eq!(flash.image(), erased);
        assert_eq!(result, Err(Error::Blocked));
    }
}
