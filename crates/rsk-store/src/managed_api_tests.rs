// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn explicit_initialization_refuses_a_non_erased_counter_window_after_an_erased_main() {
    let flash = FaultFlash::new();
    flash
        .inner
        .bytes
        .borrow_mut()
        .resize(MAIN.end as usize + 128 * 1024, 0xFF);
    let mut store = Managed::new_unmounted(
        flash.clone(),
        MAIN,
        MAIN.end..MAIN.end + 128 * 1024,
        source(),
        cache,
    );
    flash.inner.bytes.borrow_mut()[MAIN.end as usize + 16] = 0;
    let before = flash.image();
    assert_eq!(
        store.administer(StorageAction::Initialize, [0x4B; 16]),
        Err(Error::Blocked)
    );
    assert_eq!(flash.image(), before);
}

#[test]
fn recovery_operations_refuse_and_ready_storage_blocks_internal_writes_and_administration() {
    let flash = provision_legacy();
    let mut store = Managed::new_unmounted(
        flash.clone(),
        MAIN,
        MAIN.end..MAIN.end + 128 * 1024,
        source(),
        cache,
    );
    let before = flash.image();
    assert_eq!(store.write(CRED, b"replacement"), Err(Error::MemoryFatal));
    assert_eq!(store.remove(CRED), Err(Error::MemoryFatal));
    assert_eq!(store.compact(), Err(Error::MemoryFatal));
    assert!(!store.for_each_key(&mut |_| panic!("recovery cannot disclose inventory")));
    assert_eq!(flash.image(), before);
    store.boot([0x4B; 16]).unwrap();
    assert_imported(&mut store);
    let before = flash.image();
    for fid in rsk_fs::STORE_INTERNAL_FIDS {
        assert_eq!(store.write(fid, b"forbidden"), Err(Error::Blocked));
        assert_eq!(store.remove(fid), Err(Error::Blocked));
    }
    for action in [StorageAction::Initialize, StorageAction::ImportLegacy] {
        assert_eq!(store.administer(action, [0xA6; 16]), Err(Error::Blocked));
    }
    assert_eq!(flash.image(), before);
    assert_imported(&mut store);
}

#[test]
fn a_verified_header_in_the_wrong_partition_or_another_epoch_cannot_mount() {
    for wrong_partition in [false, true] {
        let flash = provision_legacy();
        managed(&flash, source())
            .administer(StorageAction::ImportLegacy, [0x4B; 16])
            .unwrap();
        let layout = crate::authenticated::Layout::new(MAIN.end..MAIN.end + 128 * 1024).unwrap();
        let start = usize::try_from(layout.main[0].start).unwrap();
        let mut image = flash.image();
        let mut header = crate::authenticated::Checkpoint::decode(
            &image[start..start + crate::authenticated::CHECKPOINT_BYTES],
        )
        .unwrap();
        let mut key = source().key(header.arm).unwrap();
        let target = if wrong_partition {
            usize::try_from(layout.counter[0].start).unwrap()
        } else {
            header.identity.epoch[0] ^= 1;
            start
        };
        image[target..target + crate::authenticated::CHECKPOINT_BYTES]
            .copy_from_slice(&header.encode(key.expose()).unwrap());
        key.wipe();
        *flash.inner.bytes.borrow_mut() = image;
        let before = flash.image();
        let mut refused = managed(&flash, source());
        assert_eq!(refused.state(), StorageState::Recovery);
        assert_eq!(refused.read(CRED, &mut [0; 32]), None);
        assert_eq!(flash.image(), before);
    }
}

#[test]
fn surviving_authority_without_activation_blocks_import_and_repairs_on_boot() {
    let flash = provision_legacy();
    managed(&flash, source())
        .administer(StorageAction::ImportLegacy, [0x4B; 16])
        .unwrap();
    let mut map = sequential_storage::map::MapStorage::<u16, _, _>::new(
        crate::verified_flash::VerifiedFlash::new(flash.clone()),
        sequential_storage::map::MapConfig::try_new(MAIN).unwrap(),
        sequential_storage::cache::Cache::new_uncached(),
    );
    block_on(map.remove_item(&mut [0; KV_BUF], &0xCEFD)).unwrap();
    let mut store = Managed::new_unmounted(
        flash.clone(),
        MAIN,
        MAIN.end..MAIN.end + 128 * 1024,
        source(),
        cache,
    );
    let before = flash.image();
    assert_eq!(
        store.administer(StorageAction::ImportLegacy, [0xA6; 16]),
        Err(Error::Blocked)
    );
    assert_eq!(flash.image(), before);
    store.boot([0xA6; 16]).unwrap();
    assert_imported(&mut store);
}

#[test]
fn map_repair_retains_the_canonical_activation_and_all_imported_owners() {
    const HOT: u16 = 0xB123;
    let flash = provision_legacy();
    let mut store = managed(&flash, source());
    store
        .administer(StorageAction::ImportLegacy, [0x4B; 16])
        .unwrap();
    let mut cut = None;
    for byte in 0..24u8 {
        let before = flash.image();
        flash.arm(&[]);
        store.write(HOT, &[byte; 3500]).unwrap();
        if flash
            .events()
            .iter()
            .any(|(io, at, _)| *io == Io::Erase && *at < MAIN.end)
        {
            cut = Some((before, byte));
            break;
        }
    }
    let (before, byte) = cut.expect("the payload ring must reclaim a source page");
    *flash.inner.bytes.borrow_mut() = before;
    flash.arm(&[Rule {
        io: Io::Erase,
        skip: 0,
        effect: Effect::KeepTail,
        latched: true,
    }]);
    assert_eq!(
        managed(&flash, source()).write(HOT, &[byte; 3500]),
        Err(Error::MemoryFatal)
    );
    assert!(flash.hits()[0] > 0);
    flash.clear();
    let mut reboot = managed(&flash, source());
    assert_eq!(reboot.state(), StorageState::Ready);
    let mut value = [0; 3500];
    assert_eq!(reboot.read(HOT, &mut value), Some(value.len()));
    assert_eq!(value, [byte - 1; 3500]);
    reboot.write(HOT, &[0xA6; 3500]).unwrap();
    assert_eq!(reboot.read(HOT, &mut value), Some(value.len()));
    assert_eq!(value, [0xA6; 3500]);
    reboot.remove(HOT).unwrap();
    assert_imported(&mut reboot);
}
