// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::Storage;
use rsk_fs::storage::StorageState;

#[test]
fn existing_legacy_image_migrates_on_open_and_keeps_its_geometry_and_values() {
    let path = std::env::temp_dir().join(format!("rsk-auto-legacy-{}.store", std::process::id()));
    assert!(!path.exists());
    let flash = FlashFile::open(Some(path.clone()), None).unwrap();
    let mut legacy = rsk_store::SeqStorage::new(
        flash,
        MAIN_RANGE,
        COUNTER_RANGE,
        Cache::new_uncached(),
        Cache::new_uncached(),
    );
    legacy.write(0xB000, b"existing owner").unwrap();
    let counter = rsk_fs::counter::COUNTER_FIDS[0].get();
    legacy.write(counter, &1234_u32.to_le_bytes()).unwrap();
    drop(legacy);
    let mut store = open(Some(path.clone()), None, b"RSKEMU01").unwrap();
    assert_eq!(store.state(), StorageState::Ready);
    let mut out = [0; 16];
    assert_eq!(store.read(0xB000, &mut out), Some(14));
    assert_eq!(&out[..14], b"existing owner");
    assert_eq!(store.read(counter, &mut out), Some(4));
    assert_eq!(&out[..4], &1234_u32.to_le_bytes());
    let medium = fs::read(&path).unwrap();
    assert_eq!(medium.len(), MAGIC.len() + PAGES * WORD * PAGE_WORDS);
    assert_eq!(&medium[..MAGIC.len()], MAGIC);
    drop(store);
    let mut reboot = open(Some(path.clone()), None, b"RSKEMU01").unwrap();
    assert_eq!(reboot.read(0xB000, &mut out), Some(14));
    assert_eq!(fs::read(&path).unwrap(), medium);
    let refused = open(Some(path.clone()), None, b"DIFFERNT").unwrap();
    assert_eq!(refused.state(), StorageState::Recovery);
    assert_eq!(fs::read(&path).unwrap(), medium);
    fs::remove_file(path).unwrap();
}

#[test]
fn existing_wholly_erased_image_initializes_without_a_setup_command() {
    let path = std::env::temp_dir().join(format!("rsk-auto-blank-{}.store", std::process::id()));
    assert!(!path.exists());
    let mut bytes = MAGIC.to_vec();
    bytes.resize(MAGIC.len() + PAGES * WORD * PAGE_WORDS, 0xFF);
    fs::write(&path, bytes).unwrap();
    let mut store = open(Some(path.clone()), None, b"RSKEMU01").unwrap();
    assert_eq!(store.state(), StorageState::Ready);
    assert_eq!(store.read(0xB000, &mut []), None);
    assert!(!store.last_error());
    fs::remove_file(path).unwrap();
}
