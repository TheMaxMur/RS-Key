// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use embedded_storage_async::nor_flash::ReadNorFlash;
use rsk_fs::Storage;

type TestCache = Cache<Uncached, Uncached, Uncached, u16>;
#[expect(
    clippy::unwrap_used,
    reason = "The admitted physical layout constructs two views of one test medium."
)]
fn prepared_import() -> (
    crate::tests::FaultFlash,
    Import<crate::tests::FaultFlash>,
    Authenticated<crate::tests::FaultFlash, TestCache>,
) {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let source = KeySource::new([0x43; 32], |_| super::super::RootRead::Blank, false);
    let main = 0..32768;
    let counter = main.end..main.end + super::super::storage::AUTHORITY_BYTES;
    let import = Import::new(flash.clone(), main.clone(), counter.clone(), source).unwrap();
    let authenticated = Authenticated::new(
        flash.clone(),
        main,
        counter,
        Cache::new_uncached(),
        source,
        [0x4B; 16],
        RootArm::PreOtp,
    )
    .unwrap();
    (flash, import, authenticated)
}

#[expect(
    clippy::unwrap_used,
    reason = "Legacy setup writes through the original writable map, not the read-only import view."
)]
fn write_legacy_counter(flash: &crate::tests::FaultFlash, value: &[u8]) {
    let mut map = MapStorage::<u16, _, _>::new(
        VerifiedFlash::new(flash.clone()),
        MapConfig::try_new(32768..32768 + super::super::storage::AUTHORITY_BYTES).unwrap(),
        Cache::new_uncached(),
    );
    block_on(map.store_item(
        &mut [0; crate::KV_BUF],
        &rsk_fs::counter::EF_COUNTER.get(),
        &value,
    ))
    .unwrap();
}

#[expect(
    clippy::unwrap_used,
    reason = "The frozen live set has an independently observed owner and hidden scrub filler."
)]
#[test]
fn changed_frozen_main_values_refuse_import_and_scrub_fillers_are_not_owners() {
    let (flash, mut import, mut authenticated) = prepared_import();
    block_on(
        import
            .main
            .store_item(import.buffer.expose_mut(), &0xB000, &b"owner".as_slice()),
    )
    .unwrap();
    block_on(import.main.store_item(
        import.buffer.expose_mut(),
        &crate::SCRUB_FILLER_FID,
        &b"filler".as_slice(),
    ))
    .unwrap();
    import.stage([0x4B; 16]).unwrap();
    let mut key = import.source.key(RootArm::PreOtp).unwrap();
    let mut directory = Directory::<MAX_MAIN_ENTRIES>::new();
    import
        .directory([0x4B; 16], key.expose(), &mut directory)
        .unwrap();
    assert_eq!(directory.entries().len(), 1);
    assert!(directory.find(0xB000).is_some());
    assert!(directory.find(crate::SCRUB_FILLER_FID).is_none());
    key.wipe();
    block_on(
        import
            .main
            .store_item(import.buffer.expose_mut(), &0xB000, &b"other".as_slice()),
    )
    .unwrap();
    let before = flash.image();
    assert_eq!(import.resume(&mut authenticated), Err(Error::MemoryFatal));
    assert_eq!(flash.image(), before);
}

#[expect(
    clippy::unwrap_used,
    reason = "An already activated import may neither recreate a lost backup nor accept another activation."
)]
#[test]
fn activated_import_refuses_missing_backups_and_wrong_activation_bytes() {
    for missing_backup in [false, true] {
        let (flash, mut import, mut authenticated) = prepared_import();
        write_legacy_counter(&flash, b"counter");
        import.stage([0x4B; 16]).unwrap();
        let activation = if missing_backup {
            activation_bytes([0x4B; 16]).unwrap()
        } else {
            [0; 32]
        };
        block_on(import.main.store_item(
            import.buffer.expose_mut(),
            &ACTIVATION_FID,
            &activation.as_slice(),
        ))
        .unwrap();
        if !missing_backup {
            block_on(import.main.store_item(
                import.buffer.expose_mut(),
                &BACKUP_FIRST,
                &b"counter".as_slice(),
            ))
            .unwrap();
        }
        let before = flash.image();
        assert_eq!(import.resume(&mut authenticated), Err(Error::MemoryFatal));
        assert_eq!(flash.image(), before);
    }
}

#[expect(
    clippy::unwrap_used,
    reason = "Each scheduled image change must fire before authority reuse and preserve the frozen-set refusal."
)]
#[test]
fn a_main_change_during_backup_copy_refuses_or_retains_the_frozen_authenticated_owner() {
    let (baseline, mut import, mut authenticated) = prepared_import();
    block_on(
        import
            .main
            .store_item(import.buffer.expose_mut(), &0xB000, &b"owner".as_slice()),
    )
    .unwrap();
    write_legacy_counter(&baseline, b"counter");
    import.stage([0x4B; 16]).unwrap();
    let original = baseline.image();
    baseline.arm(&[]);
    import.resume(&mut authenticated).unwrap();
    let trace = baseline.events();
    let first_erase = trace
        .iter()
        .position(|(io, _, _)| *io == crate::tests::Io::Erase)
        .unwrap();
    let reads = trace
        .iter()
        .take(first_erase)
        .filter(|(io, _, _)| *io == crate::tests::Io::Read)
        .count();
    let (changed_flash, mut changed_import, _) = prepared_import();
    changed_flash.replace_image_before_read(0, original.clone());
    assert!(block_on(changed_flash.clone().read(0, &mut [])).is_ok());
    block_on(changed_import.main.store_item(
        changed_import.buffer.expose_mut(),
        &0xB000,
        &b"other".as_slice(),
    ))
    .unwrap();
    block_on(changed_import.main.store_item(
        changed_import.buffer.expose_mut(),
        &BACKUP_FIRST,
        &b"counter".as_slice(),
    ))
    .unwrap();
    let changed = changed_flash.image();
    assert!(reads > 0);
    for skip in 0..reads {
        let (flash, mut import, mut authenticated) = prepared_import();
        flash.replace_image_before_read(0, original.clone());
        assert!(block_on(flash.clone().read(0, &mut [])).is_ok());
        flash.arm(&[]);
        flash.replace_image_before_read(skip, changed.clone());
        match import.resume(&mut authenticated) {
            Err(Error::MemoryFatal | Error::NoMemory) => {
                assert!(
                    !flash
                        .events()
                        .iter()
                        .any(|(io, _, _)| *io == crate::tests::Io::Erase),
                    "read {skip}"
                );
            }
            Ok(()) => {
                let mut owner = [0; 5];
                assert_eq!(
                    authenticated.read(0xB000, &mut owner),
                    Some(5),
                    "read {skip}"
                );
                assert!(!authenticated.last_error());
                assert_eq!(&owner, b"owner", "read {skip}");
                let mut counter = [0; 7];
                assert_eq!(
                    authenticated.read(rsk_fs::counter::EF_COUNTER.get(), &mut counter),
                    Some(7)
                );
                assert_eq!(&counter, b"counter");
            }
            Err(error) => assert_eq!(
                error,
                Error::MemoryFatal,
                "unexpected import error, read {skip}"
            ),
        }
    }
}

#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "The recorded trace targets the backup loader after the counter bank's verified erase."
)]
#[test]
fn a_backup_width_change_after_verification_is_refused_by_the_import_loader() {
    let (baseline, mut import, mut authenticated) = prepared_import();
    write_legacy_counter(&baseline, b"counter");
    import.stage([0x4B; 16]).unwrap();
    let original = baseline.image();
    baseline.arm(&[]);
    import.resume(&mut authenticated).unwrap();
    let trace = baseline.events();
    let layout = super::super::Layout::new(import.counter_range.clone()).unwrap();
    let counter_erase = trace
        .iter()
        .position(|(io, at, _)| *io == crate::tests::Io::Erase && *at == layout.counter[0].start)
        .unwrap();
    let load = trace
        .iter()
        .enumerate()
        .skip(counter_erase + 1)
        .find(|(_, (io, at, _))| *io == crate::tests::Io::Read && *at < import.main_range.end)
        .unwrap()
        .0;
    let skip = trace[..load]
        .iter()
        .filter(|(io, _, _)| *io == crate::tests::Io::Read)
        .count();
    let (changed_flash, mut changed_import, _) = prepared_import();
    changed_flash.replace_image_before_read(0, baseline.image());
    assert!(block_on(changed_flash.clone().read(0, &mut [])).is_ok());
    block_on(changed_import.main.store_item(
        changed_import.buffer.expose_mut(),
        &BACKUP_FIRST,
        &b"changed backup".as_slice(),
    ))
    .unwrap();
    let (flash, mut import, mut authenticated) = prepared_import();
    flash.replace_image_before_read(0, original);
    assert!(block_on(flash.clone().read(0, &mut [])).is_ok());
    flash.arm(&[]);
    flash.replace_image_before_read(skip, changed_flash.image());
    assert_eq!(import.resume(&mut authenticated), Err(Error::MemoryFatal));
    assert!(
        flash
            .events()
            .iter()
            .any(|(io, at, _)| *io == crate::tests::Io::Erase && *at == layout.counter[0].start)
    );
}

#[expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "Signed fixtures deliberately contradict each manifest field."
)]
#[test]
fn manifest_layout_mac_routing_and_generation_refusals_are_independent() {
    let source = KeySource::new([0x43; 32], |_| super::super::RootRead::Blank, false);
    let mut key = source.key(RootArm::PreOtp).unwrap();
    let main = 0..32768;
    let counter = 32768..49152;
    let epoch = [0x4B; 16];
    let identity = Identity {
        partition: Partition::Counter,
        epoch,
    };
    let counters = rsk_fs::counter::COUNTER_FIDS
        .map(|fid| Entry::deleted(identity, key.expose(), fid.get(), 0).unwrap());
    let manifest = Manifest {
        epoch,
        arm: RootArm::PreOtp,
        main_digest: [0xA6; 32],
        counters,
    };
    let encoded = manifest.encode(key.expose(), &main, &counter).unwrap();
    assert!(Manifest::verify(&encoded, source, &main, &counter).is_ok());
    for width in 0..MANIFEST_BYTES {
        assert!(Manifest::verify(&encoded[..width], source, &main, &counter).is_err());
    }
    for offset in [0, 8, 9, 64, 68, 72, 76, 80, 84, 108] {
        let mut bytes = encoded;
        bytes[offset] ^= 0x80;
        let tag = hmac_sha256(key.expose(), &bytes[..BODY_BYTES]);
        bytes[BODY_BYTES..].copy_from_slice(&tag);
        assert!(
            Manifest::verify(&bytes, source, &main, &counter).is_err(),
            "offset {offset}"
        );
    }
    let mut bytes = encoded;
    bytes[BODY_BYTES] ^= 1;
    assert!(Manifest::verify(&bytes, source, &main, &counter).is_err());
    key.wipe();
}

#[expect(
    clippy::unwrap_used,
    reason = "The real map publishes the initial manifest before a second staging request."
)]
#[test]
fn staging_refuses_existing_activation_manifest_and_reserved_backup_owners() {
    let source = KeySource::new([0x43; 32], |_| super::super::RootRead::Blank, false);
    for fid in [ACTIVATION_FID, MANIFEST_FID, BACKUP_FIRST] {
        let flash = crate::tests::flash_for_authenticated_tests();
        let mut import = Import::new(flash.clone(), 0..32768, 32768..49152, source).unwrap();
        block_on(import.main.store_item(
            import.buffer.expose_mut(),
            &fid,
            &b"retained owner".as_slice(),
        ))
        .unwrap();
        let mut before = std::vec![0; flash.capacity()];
        assert!(block_on(flash.clone().read(0, &mut before)).is_ok());
        assert_eq!(import.stage([0x4B; 16]), Err(Error::Blocked));
        let mut after = std::vec![0; flash.capacity()];
        assert!(block_on(flash.clone().read(0, &mut after)).is_ok());
        assert_eq!(after, before, "fid {fid:04x}");
    }
    let flash = crate::tests::flash_for_authenticated_tests();
    let mut import = Import::new(flash, 0..32768, 32768..49152, source).unwrap();
    import.stage([0x4B; 16]).unwrap();
    assert!(import.has_manifest().unwrap());
    assert_eq!(import.stage([0xA6; 16]), Err(Error::Blocked));
}

#[test]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Fixed page markers and an observed 32-read prefix isolate pre-admission repair."
)]
fn frozen_import_directory_never_repairs_media_before_admission() {
    use crate::tests::Io;
    let (flash, mut import, _) = prepared_import();
    block_on(
        import
            .main
            .store_item(import.buffer.expose_mut(), &0xB000, &b"owner".as_slice()),
    )
    .unwrap();
    let mut key = import.source.key(RootArm::PreOtp).unwrap();
    let mut directory = Directory::<MAX_MAIN_ENTRIES>::new();
    flash.arm(&[]);
    import
        .directory([0x4B; 16], key.expose(), &mut directory)
        .unwrap();
    assert!(directory.find(0xB000).is_some());
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    let mut closed = flash.image();
    for page in 0..8 {
        closed[page * 4096] = 0;
        closed[(page + 1) * 4096 - 1] = 0;
    }
    let mut changed = closed.clone();
    changed[0] = 0xFF;
    flash.replace_image_before_read(0, closed.clone());
    block_on(flash.clone().read(0, &mut [])).unwrap();
    import.main.invalidate_cache();
    flash.arm(&[]);
    flash.replace_image_before_read(32, changed);
    let result = import.directory([0x4B; 16], key.expose(), &mut directory);
    assert!(
        flash.events().iter().all(|event| event.0 == Io::Read),
        "pre-admission directory validation must never program or erase"
    );
    assert_eq!(result, Err(Error::MemoryFatal));
    assert_eq!(flash.image(), closed);
    assert_eq!(flash.events().len(), 32);
    key.wipe();
}
