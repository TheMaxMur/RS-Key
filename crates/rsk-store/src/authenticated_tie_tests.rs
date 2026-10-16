// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::authenticated::{
    Checkpoint, Directory, Journal, JournalStatus, Layout, Partition, RawBank, RootArm,
};

#[test]
fn equal_main_authorities_refuse_a_changed_first_peer_rescan() {
    let flash = FaultFlash::new();
    let mut store = mount_authenticated(&flash);
    store.initialize_blank().unwrap();
    store.write(CRED, b"owner").unwrap();
    let original = flash.image();
    let layout = Layout::new(MAIN.end..MAIN.end + 128 * 1024).unwrap();
    let mut key = crate::authenticated::KeySource::new([0x43; 32], auth_blank, false)
        .key(RootArm::PreOtp)
        .unwrap();
    let mut directory = Directory::<{ crate::authenticated::MAX_MAIN_ENTRIES }>::new();
    let mut zero = Journal::new(
        RawBank::new(flash.clone(), layout.main[0].clone()).unwrap(),
        Partition::Main,
    );
    let mut one = Journal::new(
        RawBank::new(flash.clone(), layout.main[1].clone()).unwrap(),
        Partition::Main,
    );

    // Calibrate through journal scans, which the source-selection mutation cannot change.
    flash.arm(&[]);
    let zero_scan = zero.scan(key.expose(), &mut directory).unwrap();
    let zero_digest = directory
        .digest(zero_scan.checkpoint.unwrap().identity, key.expose(), 0)
        .unwrap();
    let one_scan = one.scan(key.expose(), &mut directory).unwrap();
    assert_eq!(zero_scan.status, JournalStatus::Complete);
    assert_eq!(one_scan.status, JournalStatus::Complete);
    assert_eq!(
        zero_scan.state.unwrap().sequence(),
        one_scan.state.unwrap().sequence()
    );
    assert_eq!(
        zero_digest,
        directory
            .digest(one_scan.checkpoint.unwrap().identity, key.expose(), 0)
            .unwrap()
    );
    let skip = flash
        .events()
        .iter()
        .filter(|event| event.0 == Io::Read)
        .count();
    let header = zero_scan.checkpoint.unwrap();
    let sequence = zero_scan.state.unwrap().sequence();
    let changed_scan = zero
        .write_snapshot(
            Checkpoint {
                sequence,
                entries: u32::try_from(directory.entries().len()).unwrap(),
                digest: directory
                    .digest(header.identity, key.expose(), sequence)
                    .unwrap(),
                ..header
            },
            key.expose(),
            &directory,
        )
        .unwrap();
    assert_ne!(zero_scan, changed_scan);
    let changed = flash.image();

    *flash.inner.bytes.borrow_mut() = original;
    flash.arm(&[]);
    assert_eq!(
        authenticated_value(&mut mount_authenticated(&flash), CRED)
            .unwrap()
            .as_deref(),
        Some(&b"owner"[..])
    );
    flash.arm(&[]);
    flash.replace_image_before_read(skip, changed.clone());
    assert_eq!(
        authenticated_value(&mut mount_authenticated(&flash), CRED),
        Err(Error::MemoryFatal)
    );
    assert_eq!(flash.image(), changed);
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    key.wipe();
}
