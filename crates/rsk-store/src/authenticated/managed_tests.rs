// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use sequential_storage::cache::{Cache, Uncached};

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
