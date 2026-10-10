// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::authenticated::{KeySource, Managed, RootRead};
use rsk_fs::storage::{StorageAction, StorageState};

type ManagedStore = Managed<FaultFlash, MainCache>;

fn cache() -> MainCache {
    MainCache::new(
        ArrayPageStates::new(),
        ArrayPagePointers::new(),
        ArrayKeyPointers::new(),
    )
}

fn managed(flash: &FaultFlash, source: KeySource) -> ManagedStore {
    let counter = MAIN.end..MAIN.end + 128 * 1024;
    flash
        .inner
        .bytes
        .borrow_mut()
        .resize(counter.end as usize, 0xFF);
    Managed::new(flash.clone(), MAIN, counter, source, cache)
}

fn source() -> KeySource {
    KeySource::new([0x43; 32], auth_blank, false)
}

#[test]
fn construction_and_mount_can_use_separate_frames_without_exposing_unmounted_data() {
    let flash = provision_legacy();
    managed(&flash, source())
        .administer(StorageAction::ImportLegacy, [0x4B; 16])
        .unwrap();
    flash.arm(&[]);
    let mut store = Managed::new_unmounted(
        flash.clone(),
        MAIN,
        MAIN.end..MAIN.end + 128 * 1024,
        source(),
        cache,
    );
    assert!(flash.events().is_empty());
    assert_eq!(store.state(), StorageState::Recovery);
    assert_eq!(store.read(CRED, &mut [0; 32]), None);
    assert!(store.last_error());
    assert!(flash.events().is_empty());
    store.mount().unwrap();
    assert_imported(&mut store);
    let mut fs = rsk_fs::Fs::new(store);
    fs.scan();
    assert_eq!(fs.try_has_data(CRED), Ok(true));
    flash.arm(&[Rule {
        io: Io::Read,
        skip: 0,
        effect: Effect::Refuse,
        latched: true,
    }]);
    assert_eq!(fs.mount_storage(), Err(Error::MemoryFatal));
    assert_eq!(fs.storage_state(), StorageState::Recovery);
    assert_eq!(fs.free_dynamic(), 0);
    assert_eq!(fs.try_has_data(CRED), Err(Error::MemoryFatal));
    flash.clear();
    fs.mount_storage().unwrap();
    fs.scan();
    assert_eq!(fs.try_has_data(CRED), Ok(true));
}

fn provision_legacy() -> FaultFlash {
    let flash = FaultFlash::new();
    let counter = MAIN.end..MAIN.end + 128 * 1024;
    flash
        .inner
        .bytes
        .borrow_mut()
        .resize(counter.end as usize, 0xFF);
    let mut legacy = SeqStorage::new(
        flash.clone(),
        MAIN,
        counter,
        sequential_storage::cache::Cache::new_uncached(),
        sequential_storage::cache::Cache::new_uncached(),
    );
    legacy.write(CRED, b"legacy owner key").unwrap();
    legacy.write(0xB000, b"neighbor").unwrap();
    for (index, fid) in rsk_fs::counter::COUNTER_FIDS.iter().enumerate() {
        legacy
            .write(
                fid.get(),
                &[u8::try_from(index + 1).unwrap(); rsk_fs::MAX_VALUE_BYTES],
            )
            .unwrap();
    }
    flash
}

fn assert_imported(store: &mut ManagedStore) {
    assert_eq!(store.state(), StorageState::Ready);
    let mut out = [0; rsk_fs::MAX_VALUE_BYTES];
    assert_eq!(store.read(CRED, &mut out), Some(16));
    assert_eq!(&out[..16], b"legacy owner key");
    assert_eq!(store.read(0xB000, &mut out), Some(8));
    assert_eq!(&out[..8], b"neighbor");
    for (index, fid) in rsk_fs::counter::COUNTER_FIDS.iter().enumerate() {
        assert_eq!(store.read(fid.get(), &mut out), Some(out.len()));
        assert!(
            out.iter()
                .all(|&byte| byte == u8::try_from(index + 1).unwrap())
        );
    }
    let mut fids = Vec::new();
    assert!(store.for_each_key(&mut |fid| fids.push(fid)));
    assert_eq!(fids.len(), 6);
    assert!(
        fids.iter()
            .all(|fid| !rsk_fs::STORE_INTERNAL_FIDS.contains(fid))
    );
}

#[test]
fn legacy_import_is_explicit_preserves_full_counters_and_keeps_activation_closed() {
    let flash = provision_legacy();
    let saved = flash.inner.bytes.borrow().clone();
    let mut store = managed(&flash, source());
    assert_eq!(store.state(), StorageState::Recovery);
    assert_eq!(
        *flash.inner.bytes.borrow(),
        saved,
        "mounting unrecognized storage must not write"
    );
    assert_eq!(store.read(CRED, &mut [0; 32]), None);
    assert!(store.last_error());
    assert_eq!(
        store.administer(StorageAction::Initialize, [0x4B; 16]),
        Err(Error::Blocked)
    );
    store
        .administer(StorageAction::ImportLegacy, [0x4B; 16])
        .unwrap();
    assert_imported(&mut store);
    assert_imported(&mut managed(&flash, source()));
    let layout = crate::authenticated::Layout::new(MAIN.end..MAIN.end + 128 * 1024).unwrap();
    for range in layout.main.into_iter().chain(layout.counter) {
        flash.inner.bytes.borrow_mut()[range.start as usize..range.start as usize + 128].fill(0xFF);
    }
    let mut lost = managed(&flash, source());
    assert_eq!(lost.state(), StorageState::Recovery);
    assert_eq!(
        lost.administer(StorageAction::ImportLegacy, [0x5A; 16]),
        Err(Error::Blocked)
    );
    assert_eq!(
        lost.administer(StorageAction::Initialize, [0x5A; 16]),
        Err(Error::Blocked)
    );
}

#[test]
fn legacy_import_preserves_routed_absence_for_a_counter_found_only_in_main() {
    let flash = FaultFlash::new();
    let counter = MAIN.end..MAIN.end + 128 * 1024;
    flash
        .inner
        .bytes
        .borrow_mut()
        .resize(counter.end as usize, 0xFF);
    let mut legacy = mount_fault(&flash);
    block_on(
        legacy
            .main
            .store_item::<&[u8]>(&mut legacy.buf, &CTR, &b"misrouted".as_slice()),
    )
    .unwrap();
    legacy.write(CRED, b"owner").unwrap();
    assert_eq!(legacy.read(CTR, &mut [0; 32]), None);
    assert!(!legacy.last_error());
    let mut store = managed(&flash, source());
    store
        .administer(StorageAction::ImportLegacy, [0x4B; 16])
        .unwrap();
    assert_eq!(store.state(), StorageState::Ready);
    assert_eq!(store.read(CTR, &mut [0; 32]), None);
    assert!(!store.last_error());
    let mut out = [0; 32];
    assert_eq!(store.read(CRED, &mut out), Some(5));
    assert_eq!(&out[..5], b"owner");
    let mut keys = Vec::new();
    assert!(store.for_each_key(&mut |fid| keys.push(fid)));
    assert_eq!(keys, [CRED]);
}

#[test]
fn legacy_import_program_and_erase_failures_resume_without_changing_an_owner() {
    let baseline = provision_legacy();
    let saved = baseline.inner.bytes.borrow().clone();
    let mut trace = managed(&baseline, source());
    baseline.arm(&[]);
    trace
        .administer(StorageAction::ImportLegacy, [0x4B; 16])
        .unwrap();
    for io in [Io::Program, Io::Erase] {
        let count = baseline
            .events()
            .iter()
            .filter(|event| event.0 == io)
            .count();
        assert!(count > 0);
        for skip in 0..count {
            for effect in [Effect::Refuse, Effect::Drop, Effect::KeepTail] {
                let flash = FaultFlash::new();
                *flash.inner.bytes.borrow_mut() = saved.clone();
                let mut store = managed(&flash, source());
                flash.arm(&[Rule {
                    io,
                    skip,
                    effect,
                    latched: true,
                }]);
                let _result = store.administer(StorageAction::ImportLegacy, [0x4B; 16]);
                assert!(flash.hits()[0] > 0, "{io:?} {skip}");
                flash.clear();
                let mut reboot = managed(&flash, source());
                if reboot.state() == StorageState::Recovery {
                    reboot
                        .administer(StorageAction::ImportLegacy, [0x4B; 16])
                        .unwrap_or_else(|error| {
                            panic!("{io:?} {skip} {effect:?}: resume {error:?}")
                        });
                }
                assert_imported(&mut reboot);
            }
        }
    }
}

fn fused(out: &mut [u8; 32]) -> RootRead {
    *out = [0xA7; 32];
    RootRead::Fused
}
fn unreadable(_: &mut [u8; 32]) -> RootRead {
    RootRead::Unreadable
}

#[test]
fn the_closed_root_report_requires_a_ready_backend_and_both_otp_arms() {
    let flash = provision_legacy();
    let mut public = managed(&flash, source());
    assert!(!public.root_closed());
    public
        .administer(StorageAction::ImportLegacy, [0x4B; 16])
        .unwrap();
    assert!(!public.root_closed());
    assert!(!rsk_fs::Fs::new(public).storage_root_closed());
    let mut otp = managed(&flash, KeySource::new([0x43; 32], fused, false));
    assert_imported(&mut otp);
    assert!(otp.root_closed());
    assert!(rsk_fs::Fs::new(otp).storage_root_closed());
    assert!(!managed(&flash, KeySource::new([0x43; 32], unreadable, false)).root_closed());
    let unmounted = Managed::new_unmounted(
        flash,
        MAIN,
        MAIN.end..MAIN.end + 128 * 1024,
        KeySource::new([0x43; 32], fused, true),
        cache,
    );
    assert!(!unmounted.root_closed());
}

#[test]
fn a_replayed_import_manifest_cannot_erase_surviving_newer_counter_authority() {
    let baseline = provision_legacy();
    let saved = baseline.inner.bytes.borrow().clone();
    baseline.arm(&[]);
    managed(&baseline, source())
        .administer(StorageAction::ImportLegacy, [0x4B; 16])
        .unwrap();
    let before_erase = baseline
        .events()
        .iter()
        .take_while(|event| event.0 != Io::Erase)
        .filter(|event| event.0 == Io::Program)
        .count();
    let flash = FaultFlash::new();
    *flash.inner.bytes.borrow_mut() = saved;
    let mut store = managed(&flash, source());
    flash.arm(&[Rule {
        io: Io::Program,
        skip: before_erase,
        effect: Effect::Refuse,
        latched: true,
    }]);
    assert_eq!(
        store.administer(StorageAction::ImportLegacy, [0x4B; 16]),
        Err(Error::MemoryFatal)
    );
    assert!(flash.hits()[0] > 0);
    let old_main = flash.inner.snapshot(MAIN);
    flash.clear();
    let mut recovered = managed(&flash, source());
    assert_imported(&mut recovered);
    let initial_import = flash.inner.bytes.borrow().clone();
    recovered.write(CTR, b"new acknowledged counter").unwrap();
    let acknowledged = flash.inner.bytes.borrow().clone();
    let layout = crate::authenticated::Layout::new(MAIN.end..MAIN.end + 128 * 1024).unwrap();
    use crate::authenticated::{
        Checkpoint, Delta, DeltaKind, Directory, Entry, Identity, Journal, Partition, RawBank,
        RootArm,
    };
    let mut key = source().key(RootArm::PreOtp).unwrap();
    let mut directory = Directory::<{ crate::authenticated::MAX_MAIN_ENTRIES }>::new();
    let mut journal = Journal::new(
        RawBank::new(flash.clone(), layout.main[0].clone()).unwrap(),
        Partition::Main,
    );
    let original = journal
        .scan(key.expose(), &mut directory)
        .unwrap()
        .checkpoint
        .unwrap();
    for case in 0..4 {
        *flash.inner.bytes.borrow_mut() = acknowledged.clone();
        let sequence = if case < 2 { 1 } else { 0 };
        let checkpoint = Checkpoint {
            sequence,
            digest: directory
                .digest(original.identity, key.expose(), sequence)
                .unwrap(),
            ..original
        };
        let mut journal = Journal::new(
            RawBank::new(flash.clone(), layout.main[0].clone()).unwrap(),
            Partition::Main,
        );
        let scan = journal
            .write_snapshot(checkpoint, key.expose(), &directory)
            .unwrap();
        match case {
            1 => flash.inner.bytes.borrow_mut()[layout.main[0].start as usize + 128] ^= 0x80,
            2 => {
                let entry = Entry::live(
                    Identity {
                        partition: Partition::Main,
                        epoch: [0x4B; 16],
                    },
                    key.expose(),
                    CRED,
                    1,
                    b"candidate",
                )
                .unwrap();
                journal
                    .append(
                        scan.next,
                        Delta {
                            kind: DeltaKind::Prepare,
                            partition: Partition::Main,
                            sequence: 1,
                            address: 4096,
                            entry,
                            previous: scan.state.unwrap().chain(),
                        },
                        key.expose(),
                    )
                    .unwrap();
            }
            3 => {
                flash.inner.bytes.borrow_mut()[layout.main[0].start as usize + scan.next as usize] =
                    0
            }
            _ => {}
        }
        flash.inner.bytes.borrow_mut()[..MAIN.end as usize].copy_from_slice(&old_main);
        for range in [&layout.main[1], &layout.counter[0], &layout.counter[1]] {
            flash.inner.bytes.borrow_mut()[range.start as usize..range.start as usize + 128]
                .fill(0xFF);
        }
        let before = flash.inner.bytes.borrow().clone();
        flash.arm(&[]);
        let mut rejected = managed(&flash, source());
        assert_eq!(
            rejected.state(),
            StorageState::Recovery,
            "main progress case {case}"
        );
        assert!(
            rejected
                .administer(StorageAction::ImportLegacy, [0x4B; 16])
                .is_err()
        );
        assert_eq!(
            *flash.inner.bytes.borrow(),
            before,
            "main progress case {case}"
        );
        assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    }
    key.wipe();
    for damaged_snapshot in [false, true] {
        *flash.inner.bytes.borrow_mut() = initial_import.clone();
        flash.inner.bytes.borrow_mut()[..MAIN.end as usize].copy_from_slice(&old_main);
        for range in &layout.main {
            flash.inner.bytes.borrow_mut()[range.start as usize..range.start as usize + 128]
                .fill(0xFF);
        }
        if damaged_snapshot {
            for range in &layout.counter {
                flash.inner.bytes.borrow_mut()[range.start as usize + 128] ^= 0x80;
            }
        }
        let mut resumed = managed(&flash, source());
        assert_imported(&mut resumed);
    }
    for dirty_tail in [false, true] {
        for missing_peer in [None, Some(0), Some(1)] {
            *flash.inner.bytes.borrow_mut() = acknowledged.clone();
            if dirty_tail {
                use crate::authenticated::{
                    CounterBank, Directory, JournalStatus, RawBank, RootArm,
                };
                let mut key = source().key(RootArm::PreOtp).unwrap();
                for range in &layout.counter {
                    let at = {
                        let bytes = flash.inner.bytes.borrow();
                        let start = range.start as usize;
                        start
                            + bytes[start..range.end as usize]
                                .windows(b"new acknowledged counter".len())
                                .position(|value| value == b"new acknowledged counter")
                                .unwrap()
                    };
                    flash.inner.bytes.borrow_mut()[at] ^= 0x80;
                    let mut bank =
                        CounterBank::new(RawBank::new(flash.clone(), range.clone()).unwrap());
                    let scan = bank.scan(key.expose(), &mut Directory::new()).unwrap();
                    assert_eq!(scan.status, JournalStatus::Dirty);
                    assert_eq!(scan.sequence, Some(0));
                    assert_eq!(scan.lower_bound, Some(0));
                }
                key.wipe();
            }
            flash.inner.bytes.borrow_mut()[MAIN.start as usize..MAIN.end as usize]
                .copy_from_slice(&old_main);
            for range in &layout.main {
                flash.inner.bytes.borrow_mut()[range.start as usize..range.start as usize + 128]
                    .fill(0xFF);
            }
            if let Some(index) = missing_peer {
                let range = &layout.counter[index];
                flash.inner.bytes.borrow_mut()[range.start as usize..range.start as usize + 128]
                    .fill(0xFF);
            }
            let before = flash.inner.bytes.borrow().clone();
            let mut rejected = managed(&flash, source());
            assert_eq!(rejected.state(), StorageState::Recovery);
            assert_eq!(
                *flash.inner.bytes.borrow(),
                before,
                "newer or ambiguous counter progress forbids re-import"
            );
            assert!(
                rejected
                    .administer(StorageAction::ImportLegacy, [0x4B; 16])
                    .is_err()
            );
            assert_eq!(*flash.inner.bytes.borrow(), before);
            assert_eq!(rejected.read(CTR, &mut [0; 32]), None);
            assert!(rejected.last_error());
        }
    }
}

#[test]
fn a_corrupt_partition_byte_in_one_header_is_repaired_from_the_authenticated_peer() {
    let flash = provision_legacy();
    managed(&flash, source())
        .administer(StorageAction::ImportLegacy, [0x4B; 16])
        .unwrap();
    let layout = crate::authenticated::Layout::new(MAIN.end..MAIN.end + 128 * 1024).unwrap();
    let address = layout.main[0].start as usize + 8;
    flash.inner.bytes.borrow_mut()[address] = crate::authenticated::Partition::Counter.code();
    assert_imported(&mut managed(&flash, source()));
}

#[test]
fn a_damaged_private_activation_is_reconstructed_only_from_its_signed_directory_entry() {
    let flash = provision_legacy();
    managed(&flash, source())
        .administer(StorageAction::ImportLegacy, [0x4B; 16])
        .unwrap();
    let before = flash.inner.bytes.borrow().clone();
    let magic = b"RSKACT02";
    let positions: Vec<_> = before
        .windows(magic.len())
        .enumerate()
        .filter_map(|(index, bytes)| (bytes == magic).then_some(index))
        .collect();
    assert!(!positions.is_empty());
    for position in positions {
        flash.inner.bytes.borrow_mut()[position] ^= 0x80;
    }
    let mut repaired = managed(&flash, source());
    assert_imported(&mut repaired);
    repaired.write(0xB000, b"healthy update").unwrap();
    let mut out = [0; 32];
    assert_eq!(repaired.read(0xCEFD, &mut out), None);
    assert!(!repaired.last_error());
    assert_eq!(repaired.remove(0xCEFD), Err(Error::Blocked));
    assert_eq!(
        repaired.write(0xCEFD, b"forged witness"),
        Err(Error::Blocked)
    );
    assert_eq!(repaired.read(0xB000, &mut out), Some(14));
    assert_eq!(&out[..14], b"healthy update");
}

#[test]
fn a_crc_valid_wrong_latest_activation_cannot_replace_the_signed_value_during_gc() {
    let flash = provision_legacy();
    managed(&flash, source())
        .administer(StorageAction::ImportLegacy, [0x4B; 16])
        .unwrap();
    let mut legacy = SeqStorage::new(
        flash.clone(),
        MAIN,
        MAIN.end..MAIN.end + 128 * 1024,
        sequential_storage::cache::Cache::new_uncached(),
        sequential_storage::cache::Cache::new_uncached(),
    );
    let mut bad = [0xFF; 32];
    bad[..8].copy_from_slice(b"RSKACT02");
    bad[8] = 2;
    bad[16..].fill(0x4B);
    bad[31] ^= 0x80;
    legacy.write(0xCEFD, &bad).unwrap();
    let mut restored = managed(&flash, source());
    assert_imported(&mut restored);
    restored.compact().unwrap();
    assert_imported(&mut managed(&flash, source()));
}

#[test]
fn a_damaged_activation_and_one_dirty_authority_recover_without_minting_owner_values() {
    let flash = provision_legacy();
    managed(&flash, source())
        .administer(StorageAction::ImportLegacy, [0x4B; 16])
        .unwrap();
    let positions: Vec<_> = flash
        .inner
        .bytes
        .borrow()
        .windows(8)
        .enumerate()
        .filter_map(|(index, bytes)| (bytes == b"RSKACT02").then_some(index))
        .collect();
    for position in positions {
        flash.inner.bytes.borrow_mut()[position] ^= 0x80;
    }
    let layout = crate::authenticated::Layout::new(MAIN.end..MAIN.end + 128 * 1024).unwrap();
    flash.inner.bytes.borrow_mut()[layout.main[0].start as usize] ^= 0x80;
    assert_imported(&mut managed(&flash, source()));
}

#[test]
fn authenticated_storage_preserves_the_full_dynamic_budget_and_excludes_its_witness() {
    let flash = FaultFlash::new();
    let mut store = managed(&flash, source());
    store
        .administer(StorageAction::Initialize, [0x4B; 16])
        .unwrap();
    let mut fs = rsk_fs::Fs::new(store);
    fs.scan();
    for index in 0..rsk_fs::MAX_DYNAMIC_FILES {
        flash.arm(&[]);
        let fid = 0x9000 + u16::try_from(index).unwrap();
        fs.put(fid, &u32::try_from(index).unwrap().to_le_bytes())
            .unwrap();
    }
    assert_eq!(fs.free_dynamic(), 0);
    assert_eq!(fs.put(0xAFFF, b"one too many"), Err(Error::NoMemory));
    let mut reboot = rsk_fs::Fs::new(managed(&flash, source()));
    reboot.scan();
    assert_eq!(reboot.free_dynamic(), 0);
    for index in 0..rsk_fs::MAX_DYNAMIC_FILES {
        let mut out = [0; 4];
        assert_eq!(
            reboot.try_read(0x9000 + u16::try_from(index).unwrap(), &mut out),
            Ok(Some(4))
        );
        assert_eq!(out, u32::try_from(index).unwrap().to_le_bytes());
    }
}

#[test]
fn import_without_backup_space_refuses_before_touching_any_counter_sector() {
    let flash = FaultFlash::new();
    let counter = MAIN.end..MAIN.end + 128 * 1024;
    flash
        .inner
        .bytes
        .borrow_mut()
        .resize(counter.end as usize, 0xFF);
    let mut legacy = SeqStorage::new(
        flash.clone(),
        MAIN,
        counter.clone(),
        sequential_storage::cache::Cache::new_uncached(),
        sequential_storage::cache::Cache::new_uncached(),
    );
    let mut accepted = Vec::new();
    for fid in 0x9000..0x9020 {
        let value = [0x35; rsk_fs::MAX_VALUE_BYTES];
        if legacy.write(fid, &value).is_err() {
            break;
        }
        accepted.push(fid);
    }
    assert!(!accepted.is_empty());
    for fid in rsk_fs::counter::COUNTER_FIDS {
        legacy
            .write(fid.get(), &[0xA7; rsk_fs::MAX_VALUE_BYTES])
            .unwrap();
    }
    let frozen = flash.inner.snapshot(counter.clone());
    let mut unknown = managed(&flash, source());
    flash.arm(&[]);
    assert!(
        unknown
            .administer(StorageAction::ImportLegacy, [0x4B; 16])
            .is_err()
    );
    assert_eq!(flash.inner.snapshot(counter), frozen);
    assert!(
        flash
            .events()
            .iter()
            .filter(|event| event.0 != Io::Read)
            .all(|event| event.1 < MAIN.end)
    );
    let mut out = [0; rsk_fs::MAX_VALUE_BYTES];
    for fid in accepted {
        assert_eq!(legacy.read(fid, &mut out), Some(out.len()));
        assert_eq!(out, [0x35; rsk_fs::MAX_VALUE_BYTES]);
    }
}

#[test]
fn root_rekey_and_repeated_recovery_keep_values_and_close_the_old_arm() {
    let baseline = provision_legacy();
    managed(&baseline, source())
        .administer(StorageAction::ImportLegacy, [0x4B; 16])
        .unwrap();
    let saved = baseline.inner.bytes.borrow().clone();
    let otp = KeySource::new([0x43; 32], fused, false);
    baseline.arm(&[]);
    let mut ready = managed(&baseline, otp);
    assert_imported(&mut ready);
    assert!(ready.root_closed());
    let trace = baseline.events();
    for io in [Io::Program, Io::Erase] {
        let count = trace.iter().filter(|event| event.0 == io).count();
        assert!(count > 0);
        for skip in 0..count {
            for effect in [Effect::Refuse, Effect::Drop, Effect::KeepTail] {
                let flash = FaultFlash::new();
                *flash.inner.bytes.borrow_mut() = saved.clone();
                flash.arm(&[Rule {
                    io,
                    skip,
                    effect,
                    latched: true,
                }]);
                let _interrupted = managed(&flash, otp);
                assert!(flash.hits()[0] > 0, "rekey {io:?} {skip} {effect:?}");
                flash.clear();
                let interrupted = flash.inner.bytes.borrow().clone();
                flash.arm(&[]);
                let mut healthy = managed(&flash, otp);
                assert_imported(&mut healthy);
                let recovery = flash.events();
                for second_io in [Io::Program, Io::Erase] {
                    let second_count = recovery.iter().filter(|event| event.0 == second_io).count();
                    for second in 0..second_count {
                        *flash.inner.bytes.borrow_mut() = interrupted.clone();
                        flash.arm(&[Rule {
                            io: second_io,
                            skip: second,
                            effect: Effect::KeepTail,
                            latched: true,
                        }]);
                        let _second_cut = managed(&flash, otp);
                        assert!(
                            flash.hits()[0] > 0,
                            "rekey {io:?} {skip} {effect:?}, recovery {second_io:?} {second}"
                        );
                        flash.clear();
                        let mut reboot = managed(&flash, otp);
                        assert_imported(&mut reboot);
                        assert!(reboot.root_closed());
                        assert_imported(&mut managed(
                            &flash,
                            KeySource::new([0x43; 32], fused, true),
                        ));
                    }
                }
            }
        }
    }
    assert_eq!(
        managed(&baseline, KeySource::new([0x43; 32], unreadable, false)).state(),
        StorageState::Recovery
    );
    assert_eq!(managed(&baseline, source()).state(), StorageState::Recovery);
}
