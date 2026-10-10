// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn authenticated_value(store: &mut AuthStore, fid: u16) -> Result<Option<Vec<u8>>> {
    let mut out = [0; 128];
    let value = store.read(fid, &mut out);
    if store.last_error() {
        return Err(Error::MemoryFatal);
    }
    Ok(value.map(|length| out[..length].to_vec()))
}

#[test]
fn authenticated_overwrite_program_failures_preserve_whole_old_or_new_values_and_neighbors() {
    const OLD: &[u8] = b"old authenticated owner";
    const NEW: &[u8] = b"new authenticated owner";
    for fid in [CRED, CTR] {
        let baseline = FaultFlash::new();
        let mut initial = mount_authenticated(&baseline);
        initial.initialize_blank().unwrap();
        initial.write(CRED, OLD).unwrap();
        initial.write(CTR, OLD).unwrap();
        initial.write(0xB000, b"neighbor").unwrap();
        let saved = baseline.inner.bytes.borrow().clone();
        let trace = FaultFlash::new();
        *trace.inner.bytes.borrow_mut() = saved.clone();
        let mut traced = mount_authenticated(&trace);
        trace.arm(&[]);
        traced.write(fid, NEW).unwrap();
        let programs = trace
            .events()
            .iter()
            .filter(|event| event.0 == Io::Program)
            .count();
        assert!(programs > 0);
        for skip in 0..programs {
            for effect in [Effect::Refuse, Effect::Drop, Effect::KeepTail] {
                let flash = FaultFlash::new();
                *flash.inner.bytes.borrow_mut() = saved.clone();
                let mut store = mount_authenticated(&flash);
                flash.arm(&[Rule {
                    io: Io::Program,
                    skip,
                    effect,
                    latched: true,
                }]);
                let result = store.write(fid, NEW);
                if effect == Effect::Refuse {
                    assert_eq!(
                        result,
                        Err(Error::MemoryFatal),
                        "fid {fid:04X} program {skip}"
                    );
                }
                assert!(flash.hits()[0] > 0, "program {skip} must fire");
                flash.clear();
                let mut reboot = mount_authenticated(&flash);
                let current = authenticated_value(&mut reboot, fid).unwrap_or_else(|error| {
                    panic!("fid {fid:04X} program {skip} {effect:?}: recovery {error:?}")
                });
                if result.is_ok() {
                    assert_eq!(
                        current.as_deref(),
                        Some(NEW),
                        "fid {fid:04X} program {skip} {effect:?}: success must retain the requested value"
                    );
                }
                assert!(
                    current.as_deref() == Some(OLD) || current.as_deref() == Some(NEW),
                    "fid {fid:04X} program {skip} {effect:?}: {current:?}"
                );
                let other = if fid == CRED { CTR } else { CRED };
                assert_eq!(
                    authenticated_value(&mut reboot, other).unwrap().as_deref(),
                    Some(OLD)
                );
                assert_eq!(
                    authenticated_value(&mut reboot, 0xB000).unwrap().as_deref(),
                    Some(&b"neighbor"[..])
                );
                reboot.write(fid, b"healthy retry").unwrap();
                assert_eq!(
                    authenticated_value(&mut mount_authenticated(&flash), fid)
                        .unwrap()
                        .as_deref(),
                    Some(&b"healthy retry"[..])
                );
            }
        }
    }
}

#[test]
fn unauthenticated_blank_authority_cannot_supply_confirmed_absence_or_boot_writes() {
    let flash = FaultFlash::new();
    let mut store = mount_authenticated(&flash);
    assert_eq!(store.read(CRED, &mut [0; 32]), None);
    assert!(store.last_error());
    assert_eq!(store.write(CRED, b"new seed"), Err(Error::MemoryFatal));
    assert_eq!(store.remove(CRED), Err(Error::MemoryFatal));
    let mut fs = rsk_fs::Fs::new(store);
    assert_eq!(fs.try_exists(CRED), Err(Error::MemoryFatal));
    fs.scan();
    assert_eq!(fs.free_dynamic(), 0);
}

#[test]
fn gc_refuses_a_wrong_mapped_value_even_when_an_authenticated_older_copy_exists() {
    let flash = FaultFlash::new();
    let mut store = mount_authenticated(&flash);
    store.initialize_blank().unwrap();
    store.write(CRED, b"signed owner").unwrap();
    store.write(0xB000, b"neighbor").unwrap();
    let mut raw = mount_fault(&flash);
    raw.write(CRED, b"unsigned latest").unwrap();
    let mut reboot = mount_authenticated(&flash);
    assert_eq!(
        authenticated_value(&mut reboot, CRED).unwrap().as_deref(),
        Some(&b"signed owner"[..])
    );
    let before = flash.inner.bytes.borrow().clone();
    flash.arm(&[]);
    assert_eq!(reboot.compact(), Err(Error::MemoryFatal));
    assert_eq!(*flash.inner.bytes.borrow(), before);
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
}

#[test]
fn equivalent_authorities_with_distinct_valid_chains_publish_to_both_peers() {
    use crate::authenticated::{
        Checkpoint, Directory, Journal, Layout, Partition, RawBank, RootArm,
    };
    let flash = FaultFlash::new();
    let mut store = mount_authenticated(&flash);
    store.initialize_blank().unwrap();
    store.write(CRED, b"old owner").unwrap();
    store.write(0xB000, b"neighbor").unwrap();
    let layout = Layout::new(MAIN.end..MAIN.end + 128 * 1024).unwrap();
    let mut key = crate::authenticated::KeySource::new([0x43; 32], auth_blank, false)
        .key(RootArm::PreOtp)
        .unwrap();
    let mut directory = Directory::<{ crate::authenticated::MAX_MAIN_ENTRIES }>::new();
    let mut peer = Journal::new(
        RawBank::new(flash.clone(), layout.main[1].clone()).unwrap(),
        Partition::Main,
    );
    let before = peer.scan(key.expose(), &mut directory).unwrap();
    let sequence = before.state.unwrap().sequence();
    let checkpoint = Checkpoint {
        sequence,
        entries: u32::try_from(directory.entries().len()).unwrap(),
        digest: directory
            .digest(before.checkpoint.unwrap().identity, key.expose(), sequence)
            .unwrap(),
        ..before.checkpoint.unwrap()
    };
    let after = peer
        .write_snapshot(checkpoint, key.expose(), &directory)
        .unwrap();
    assert_ne!(before.state.unwrap().chain(), after.state.unwrap().chain());
    let mut reopened = mount_authenticated(&flash);
    assert_eq!(
        authenticated_value(&mut reopened, CRED).unwrap().as_deref(),
        Some(&b"old owner"[..])
    );
    flash.arm(&[]);
    reopened.write(CRED, b"new owner").unwrap();
    assert!(
        flash.events().iter().all(|event| event.0 != Io::Erase),
        "a valid append with free authority space must not need checkpoint repair"
    );
    flash.inner.bytes.borrow_mut()
        [layout.main[0].start as usize..layout.main[0].start as usize + 128]
        .fill(0xFF);
    assert_eq!(
        authenticated_value(&mut mount_authenticated(&flash), CRED)
            .unwrap()
            .as_deref(),
        Some(&b"new owner"[..])
    );
    key.wipe();
}

#[test]
fn main_authority_refuses_a_valid_mac_from_another_epoch_or_root_arm() {
    use crate::authenticated::{Journal, Layout, Main, Partition, RawBank, RootArm};
    let flash = FaultFlash::new();
    mount_authenticated(&flash).initialize_blank().unwrap();
    let layout = Layout::new(MAIN.end..MAIN.end + 128 * 1024).unwrap();
    let mut key = crate::authenticated::KeySource::new([0x43; 32], auth_blank, false)
        .key(RootArm::PreOtp)
        .unwrap();
    for (epoch, arm) in [([0xA7; 16], RootArm::PreOtp), ([0x4B; 16], RootArm::Otp)] {
        let journals = layout.main.clone().map(|range| {
            Journal::new(RawBank::new(flash.clone(), range).unwrap(), Partition::Main)
        });
        let mut main = Main::new(mount_fault(&flash).main, journals, epoch, arm);
        let before = flash.inner.bytes.borrow().clone();
        flash.arm(&[]);
        assert_eq!(
            main.read(key.expose(), CRED, &mut []),
            Err(Error::MemoryFatal)
        );
        assert_eq!(
            main.for_each_key(key.expose(), |_| {}),
            Err(Error::MemoryFatal)
        );
        assert_eq!(*flash.inner.bytes.borrow(), before);
        assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    }
    key.wipe();
}

#[test]
fn an_incomplete_candidate_with_a_dirty_publication_tail_is_unknown_not_an_abort() {
    use crate::authenticated::{Directory, Journal, Layout, Partition, RawBank, RootArm};
    let baseline = FaultFlash::new();
    let mut store = mount_authenticated(&baseline);
    store.initialize_blank().unwrap();
    store.write(CRED, b"old owner").unwrap();
    let saved = baseline.inner.bytes.borrow().clone();
    baseline.arm(&[]);
    store.write(CRED, b"new owner").unwrap();
    let events = baseline.events();
    let candidate = events
        .iter()
        .position(|event| event.0 == Io::Program && event.1 < MAIN.end)
        .unwrap();
    let skip = events[..candidate]
        .iter()
        .filter(|event| event.0 == Io::Program)
        .count();
    let flash = FaultFlash::new();
    *flash.inner.bytes.borrow_mut() = saved;
    flash.arm(&[Rule {
        io: Io::Program,
        skip,
        effect: Effect::Refuse,
        latched: true,
    }]);
    assert_eq!(
        mount_authenticated(&flash).write(CRED, b"new owner"),
        Err(Error::MemoryFatal)
    );
    assert!(flash.hits()[0] > 0);
    flash.clear();
    let layout = Layout::new(MAIN.end..MAIN.end + 128 * 1024).unwrap();
    let mut key = crate::authenticated::KeySource::new([0x43; 32], auth_blank, false)
        .key(RootArm::PreOtp)
        .unwrap();
    let range = &layout.main[1];
    let scan = Journal::new(
        RawBank::new(flash.clone(), range.clone()).unwrap(),
        Partition::Main,
    )
    .scan(
        key.expose(),
        &mut Directory::<{ crate::authenticated::MAX_MAIN_ENTRIES }>::new(),
    )
    .unwrap();
    assert!(scan.state.unwrap().pending().is_some());
    flash.inner.bytes.borrow_mut()[range.start as usize + scan.next as usize] = 0;
    let before = flash.inner.bytes.borrow().clone();
    flash.arm(&[]);
    assert_eq!(
        authenticated_value(&mut mount_authenticated(&flash), CRED),
        Err(Error::MemoryFatal)
    );
    assert_eq!(*flash.inner.bytes.borrow(), before);
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    key.wipe();
}

#[test]
fn main_authority_selects_the_newer_peer_and_refuses_equal_sequence_disagreement() {
    use crate::authenticated::{
        Checkpoint, Directory, Entry, Journal, Layout, Partition, RawBank, RootArm,
    };
    let baseline = FaultFlash::new();
    let mut store = mount_authenticated(&baseline);
    store.initialize_blank().unwrap();
    store.write(CRED, b"owner").unwrap();
    let saved = baseline.inner.bytes.borrow().clone();
    let layout = Layout::new(MAIN.end..MAIN.end + 128 * 1024).unwrap();
    let mut key = crate::authenticated::KeySource::new([0x43; 32], auth_blank, false)
        .key(RootArm::PreOtp)
        .unwrap();
    for disagree in [false, true] {
        *baseline.inner.bytes.borrow_mut() = saved.clone();
        let mut directory = Directory::<{ crate::authenticated::MAX_MAIN_ENTRIES }>::new();
        let mut peer = Journal::new(
            RawBank::new(baseline.clone(), layout.main[1].clone()).unwrap(),
            Partition::Main,
        );
        let scan = peer.scan(key.expose(), &mut directory).unwrap();
        let sequence = scan.state.unwrap().sequence() + u64::from(!disagree);
        let header = scan.checkpoint.unwrap();
        if disagree {
            directory
                .apply(
                    Entry::live(
                        header.identity,
                        key.expose(),
                        0xB000,
                        sequence,
                        b"conflicting owner",
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        peer.write_snapshot(
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
        let before = baseline.inner.bytes.borrow().clone();
        baseline.arm(&[]);
        let result = authenticated_value(&mut mount_authenticated(&baseline), CRED);
        if disagree {
            assert_eq!(result, Err(Error::MemoryFatal));
            assert_eq!(*baseline.inner.bytes.borrow(), before);
            assert!(baseline.events().iter().all(|event| event.0 == Io::Read));
        } else {
            assert_eq!(result.unwrap().as_deref(), Some(&b"owner"[..]));
        }
    }
    key.wipe();
}

#[test]
fn main_authority_refuses_a_changed_rescan_even_when_the_directory_is_identical() {
    use crate::authenticated::{
        Checkpoint, Directory, Journal, Layout, Partition, RawBank, RootArm,
    };
    let flash = FaultFlash::new();
    let mut store = mount_authenticated(&flash);
    store.initialize_blank().unwrap();
    store.write(CRED, b"owner").unwrap();
    let layout = Layout::new(MAIN.end..MAIN.end + 128 * 1024).unwrap();
    let absent_peer = &layout.main[1];
    flash.inner.bytes.borrow_mut()[absent_peer.start as usize..absent_peer.end as usize].fill(0xFF);
    let original = flash.inner.bytes.borrow().clone();
    flash.arm(&[]);
    assert_eq!(
        authenticated_value(&mut mount_authenticated(&flash), CRED)
            .unwrap()
            .as_deref(),
        Some(&b"owner"[..])
    );
    let reads: Vec<_> = flash
        .events()
        .into_iter()
        .filter(|event| event.0 == Io::Read)
        .collect();
    let skip = reads
        .iter()
        .enumerate()
        .filter(|(_, event)| event.1 == layout.main[0].start && event.2 == 128)
        .nth(1)
        .unwrap()
        .0;
    *flash.inner.bytes.borrow_mut() = original.clone();
    let mut key = crate::authenticated::KeySource::new([0x43; 32], auth_blank, false)
        .key(RootArm::PreOtp)
        .unwrap();
    let mut directory = Directory::<{ crate::authenticated::MAX_MAIN_ENTRIES }>::new();
    let mut journal = Journal::new(
        RawBank::new(flash.clone(), layout.main[0].clone()).unwrap(),
        Partition::Main,
    );
    let scan = journal.scan(key.expose(), &mut directory).unwrap();
    let sequence = scan.state.unwrap().sequence();
    let header = scan.checkpoint.unwrap();
    let after = journal
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
    assert_ne!(scan, after);
    let changed = flash.inner.bytes.borrow().clone();
    *flash.inner.bytes.borrow_mut() = original;
    flash.arm(&[]);
    flash.replace_image_before_read(skip, changed.clone());
    assert_eq!(
        authenticated_value(&mut mount_authenticated(&flash), CRED),
        Err(Error::MemoryFatal)
    );
    assert_eq!(*flash.inner.bytes.borrow(), changed);
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    key.wipe();
}

#[test]
fn a_newer_complete_authority_does_not_replay_an_older_peers_abandoned_candidate() {
    use crate::authenticated::{
        Checkpoint, Delta, DeltaKind, Directory, Entry, Journal, Layout, Partition, RawBank,
        RootArm,
    };
    const ABANDONED: u16 = 0xB001;
    let flash = FaultFlash::new();
    let mut store = mount_authenticated(&flash);
    store.initialize_blank().unwrap();
    store.write(CRED, b"owner").unwrap();
    let layout = Layout::new(MAIN.end..MAIN.end + 128 * 1024).unwrap();
    let mut key = crate::authenticated::KeySource::new([0x43; 32], auth_blank, false)
        .key(RootArm::PreOtp)
        .unwrap();
    let mut directory = Directory::<{ crate::authenticated::MAX_MAIN_ENTRIES }>::new();
    let mut older = Journal::new(
        RawBank::new(flash.clone(), layout.main[0].clone()).unwrap(),
        Partition::Main,
    );
    let scan = older.scan(key.expose(), &mut directory).unwrap();
    let header = scan.checkpoint.unwrap();
    let sequence = scan.state.unwrap().sequence() + 1;
    let mut newer = Journal::new(
        RawBank::new(flash.clone(), layout.main[1].clone()).unwrap(),
        Partition::Main,
    );
    newer
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
    let mut raw = mount_fault(&flash);
    let data = b"abandoned owner".as_slice();
    let reserved = block_on(
        raw.main
            .reserve_item::<&[u8]>(&mut raw.buf, &ABANDONED, &data),
    )
    .unwrap();
    block_on(
        raw.main
            .append_reserved(&mut raw.buf, &ABANDONED, &data, reserved),
    )
    .unwrap();
    older
        .append(
            scan.next,
            Delta {
                kind: DeltaKind::Prepare,
                partition: Partition::Main,
                sequence,
                address: reserved.address(),
                entry: Entry::live(header.identity, key.expose(), ABANDONED, sequence, data)
                    .unwrap(),
                previous: scan.state.unwrap().chain(),
            },
            key.expose(),
        )
        .unwrap();
    let mut reboot = mount_authenticated(&flash);
    assert_eq!(authenticated_value(&mut reboot, ABANDONED), Ok(None));
    assert_eq!(
        authenticated_value(&mut reboot, CRED).unwrap().as_deref(),
        Some(&b"owner"[..])
    );
    key.wipe();
}

#[test]
fn interrupted_post_commit_delete_is_physically_retired_by_the_next_scrub() {
    const SECRET: &[u8] = b"plaintext legacy secret must leave the flash";
    let baseline = FaultFlash::new();
    let mut store = mount_authenticated(&baseline);
    store.initialize_blank().unwrap();
    store.write(CRED, SECRET).unwrap();
    store.write(0xB000, b"neighbor").unwrap();
    let saved = baseline.inner.bytes.borrow().clone();
    baseline.arm(&[]);
    store.remove(CRED).unwrap();
    let last_program = baseline
        .events()
        .iter()
        .filter(|event| event.0 == Io::Program)
        .count()
        - 1;
    let flash = FaultFlash::new();
    *flash.inner.bytes.borrow_mut() = saved;
    flash.arm(&[Rule {
        io: Io::Program,
        skip: last_program,
        effect: Effect::Refuse,
        latched: true,
    }]);
    assert_eq!(
        mount_authenticated(&flash).remove(CRED),
        Err(Error::MemoryFatal)
    );
    assert!(flash.hits()[0] > 0);
    assert!(flash.inner.contains(MAIN, SECRET));
    flash.clear();
    let mut reboot = mount_authenticated(&flash);
    assert_eq!(authenticated_value(&mut reboot, CRED), Ok(None));
    reboot.compact().unwrap();
    assert!(!flash.inner.contains(MAIN, SECRET));
    assert_eq!(
        authenticated_value(&mut reboot, 0xB000).unwrap().as_deref(),
        Some(&b"neighbor"[..])
    );
}

#[test]
fn authenticated_deletion_can_retire_a_corrupt_payload_without_reading_it_as_absent() {
    const DAMAGED: &[u8] = b"damaged live payload";
    let flash = FaultFlash::new();
    let mut store = mount_authenticated(&flash);
    store.initialize_blank().unwrap();
    store.write(CRED, DAMAGED).unwrap();
    store.write(0xB000, b"neighbor").unwrap();
    let offset = flash
        .inner
        .bytes
        .borrow()
        .windows(DAMAGED.len())
        .position(|bytes| bytes == DAMAGED)
        .unwrap();
    flash.inner.bytes.borrow_mut()[offset] ^= 0x80;
    let mut reboot = mount_authenticated(&flash);
    assert_eq!(
        authenticated_value(&mut reboot, CRED),
        Err(Error::MemoryFatal)
    );
    reboot.remove(CRED).unwrap();
    assert_eq!(
        authenticated_value(&mut mount_authenticated(&flash), CRED),
        Ok(None)
    );
    assert_eq!(
        authenticated_value(&mut reboot, 0xB000).unwrap().as_deref(),
        Some(&b"neighbor"[..])
    );
}

#[test]
fn interrupted_write_then_interrupted_recovery_keeps_whole_values_and_neighbors() {
    const OLD: &[u8] = b"old authenticated owner";
    const NEW: &[u8] = b"new authenticated owner";
    for fid in [CRED, CTR] {
        let baseline = FaultFlash::new();
        let mut store = mount_authenticated(&baseline);
        store.initialize_blank().unwrap();
        store.write(fid, OLD).unwrap();
        store.write(0xB000, b"neighbor").unwrap();
        let saved = baseline.inner.bytes.borrow().clone();
        baseline.arm(&[]);
        store.write(fid, NEW).unwrap();
        let programs = baseline
            .events()
            .iter()
            .filter(|event| event.0 == Io::Program)
            .count();
        for first in 0..programs {
            let flash = FaultFlash::new();
            *flash.inner.bytes.borrow_mut() = saved.clone();
            flash.arm(&[Rule {
                io: Io::Program,
                skip: first,
                effect: Effect::KeepTail,
                latched: true,
            }]);
            let _write = mount_authenticated(&flash).write(fid, NEW);
            assert!(flash.hits()[0] > 0);
            flash.clear();
            let interrupted = flash.inner.bytes.borrow().clone();
            flash.arm(&[]);
            let expected = authenticated_value(&mut mount_authenticated(&flash), fid).unwrap();
            let recovery = flash.events();
            for io in [Io::Program, Io::Erase] {
                let count = recovery.iter().filter(|event| event.0 == io).count();
                for second in 0..count {
                    *flash.inner.bytes.borrow_mut() = interrupted.clone();
                    flash.arm(&[Rule {
                        io,
                        skip: second,
                        effect: Effect::KeepTail,
                        latched: true,
                    }]);
                    let _recovery = authenticated_value(&mut mount_authenticated(&flash), fid);
                    assert!(
                        flash.hits()[0] > 0,
                        "fid {fid:04X} cut {first}, recovery {io:?} {second}"
                    );
                    flash.clear();
                    let mut reboot = mount_authenticated(&flash);
                    let current = authenticated_value(&mut reboot, fid).unwrap_or_else(|error| {
                        panic!("fid {fid:04X} cut {first}, recovery {io:?} {second}: {error:?}")
                    });
                    assert_eq!(current, expected);
                    assert!(current.as_deref() == Some(OLD) || current.as_deref() == Some(NEW));
                    assert_eq!(
                        authenticated_value(&mut reboot, 0xB000).unwrap().as_deref(),
                        Some(&b"neighbor"[..])
                    );
                }
            }
        }
    }
}

#[test]
fn counter_checkpoint_wear_is_measured_without_touching_main_payload_or_authority() {
    const WRITES: u32 = 20_000;
    let flash = FaultFlash::new();
    let mut store = mount_authenticated(&flash);
    store.initialize_blank().unwrap();
    store.write(CRED, b"unchanged owner").unwrap();
    let layout = crate::authenticated::Layout::new(MAIN.end..MAIN.end + 128 * 1024).unwrap();
    let frozen = flash.inner.snapshot(MAIN.start..layout.main[1].end);
    let mut sectors = [0u32; 32];
    let mut programmed = 0usize;
    for value in 0..WRITES {
        flash.arm(&[]);
        store.write(CTR, &value.to_le_bytes()).unwrap();
        for (io, address, length) in flash.events() {
            if io == Io::Program {
                programmed += length;
            }
            if io == Io::Erase {
                for sector in address / SECTOR as u32
                    ..(address + u32::try_from(length).unwrap()) / SECTOR as u32
                {
                    sectors[usize::try_from(sector - MAIN.end / SECTOR as u32).unwrap()] += 1;
                }
            }
        }
    }
    assert_eq!(flash.inner.snapshot(MAIN.start..layout.main[1].end), frozen);
    assert!(sectors[..22].iter().all(|&count| count == 0));
    assert!(sectors[22..].iter().all(|&count| count > 0));
    println!("v2 counter writes={WRITES} program_bytes={programmed} sector_erases={sectors:?}");

    let legacy_flash = FaultFlash::new();
    legacy_flash
        .inner
        .bytes
        .borrow_mut()
        .resize((MAIN.end + 128 * 1024) as usize, 0xFF);
    let mut legacy = SeqStorage::new(
        legacy_flash.clone(),
        MAIN,
        MAIN.end..MAIN.end + 128 * 1024,
        sequential_storage::cache::Cache::new_uncached(),
        sequential_storage::cache::Cache::new_uncached(),
    );
    let mut legacy_sectors = [0u32; 32];
    let mut legacy_programmed = 0usize;
    for value in 0..WRITES {
        legacy_flash.arm(&[]);
        legacy.write(CTR, &value.to_le_bytes()).unwrap();
        for (io, address, length) in legacy_flash.events() {
            if io == Io::Program {
                legacy_programmed += length;
            }
            if io == Io::Erase {
                for sector in address / SECTOR as u32
                    ..(address + u32::try_from(length).unwrap()) / SECTOR as u32
                {
                    legacy_sectors[usize::try_from(sector - MAIN.end / SECTOR as u32).unwrap()] +=
                        1;
                }
            }
        }
    }
    println!(
        "legacy counter writes={WRITES} program_bytes={legacy_programmed} sector_erases={legacy_sectors:?}"
    );
}

#[test]
fn an_interrupted_gc_source_erase_preserves_migrated_owners_and_permits_a_healthy_write() {
    let flash = FaultFlash::new();
    let mut store = mount_authenticated(&flash);
    store.initialize_blank().unwrap();
    store.write(0xB000, b"migrated neighbor").unwrap();
    let mut checkpoint = None;
    for index in 0..24u8 {
        let before = flash.inner.bytes.borrow().clone();
        flash.arm(&[]);
        store.write(CRED, &[index; 3500]).unwrap();
        if flash
            .events()
            .iter()
            .any(|event| event.0 == Io::Erase && event.1 < MAIN.end)
        {
            checkpoint = Some((before, index));
            break;
        }
    }
    let (before, index) = checkpoint.expect("the small payload ring must reclaim a source page");
    *flash.inner.bytes.borrow_mut() = before;
    flash.arm(&[Rule {
        io: Io::Erase,
        skip: 0,
        effect: Effect::KeepTail,
        latched: true,
    }]);
    assert_eq!(
        mount_authenticated(&flash).write(CRED, &[index; 3500]),
        Err(Error::MemoryFatal)
    );
    assert!(flash.hits()[0] > 0);
    flash.clear();
    let mut reboot = mount_authenticated(&flash);
    let mut out = [0; 3500];
    assert_eq!(reboot.read(CRED, &mut out), Some(out.len()));
    assert!(!reboot.last_error());
    assert_eq!(out, [index - 1; 3500]);
    assert_eq!(
        authenticated_value(&mut reboot, 0xB000).unwrap().as_deref(),
        Some(&b"migrated neighbor"[..])
    );
    reboot.write(CRED, &[0xB7; 3500]).unwrap();
    assert_eq!(reboot.read(CRED, &mut out), Some(out.len()));
    assert_eq!(out, [0xB7; 3500]);
}

#[test]
fn repair_refuses_before_erasing_an_older_authenticated_copy_when_newest_is_wrong() {
    use crate::authenticated::{Entry, Identity, Partition};
    let flash = FaultFlash::new();
    let mut legacy = mount_fault(&flash);
    let owner = [0x35; 3500];
    legacy.write(CRED, &owner).unwrap();
    legacy.write(CRED, &[0xB7; 3500]).unwrap();
    legacy.write(CRED, &owner).unwrap();
    let locations: Vec<_> = flash
        .inner
        .bytes
        .borrow()
        .windows(owner.len())
        .enumerate()
        .filter_map(|(position, bytes)| (bytes == owner).then_some(position))
        .collect();
    assert_eq!(locations.len(), 2);
    flash.inner.bytes.borrow_mut()[locations[1]] ^= 0x80;
    for page in 3..7usize {
        let start = page * SECTOR;
        flash.inner.bytes.borrow_mut()[start..start + WORD].fill(0);
        flash.inner.bytes.borrow_mut()[start + SECTOR - WORD..start + SECTOR].fill(0);
    }
    flash.inner.bytes.borrow_mut()[7 * SECTOR..7 * SECTOR + WORD].fill(0);
    let before = flash.inner.bytes.borrow().clone();
    let mut map = mount_fault(&flash);
    let mut key = crate::authenticated::KeySource::new([0x43; 32], auth_blank, false)
        .key(crate::authenticated::RootArm::PreOtp)
        .unwrap();
    let identity = Identity {
        partition: Partition::Main,
        epoch: [0x4B; 16],
    };
    let entry = Entry::live(identity, key.expose(), CRED, 3, &owner).unwrap();
    flash.arm(&[]);
    assert!(
        block_on(
            map.main
                .repair_preserving(&mut map.buf, &[CRED], |_, value| {
                    entry.verify(identity, key.expose(), value).is_ok()
                })
        )
        .is_err()
    );
    assert_eq!(*flash.inner.bytes.borrow(), before);
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    let recovered = block_on(map.main.fetch_matching_item(&mut map.buf, &CRED, |value| {
        entry.verify(identity, key.expose(), value).is_ok()
    }))
    .unwrap()
    .unwrap();
    assert_eq!(recovered, owner);
    key.wipe();
}

#[test]
fn repair_propagates_a_general_page_probe_read_error_before_any_mutation() {
    let flash = FaultFlash::new();
    let owner = [0x35; 3500];
    let mut legacy = mount_fault(&flash);
    legacy.write(CRED, &owner).unwrap();
    let initial = flash.inner.bytes.borrow().clone();
    flash.arm(&[]);
    let mut healthy = mount_fault(&flash);
    block_on(
        healthy
            .main
            .repair_preserving(&mut healthy.buf, &[CRED], |_, value| value == owner),
    )
    .unwrap();
    let events = flash.events();
    assert!(events.iter().all(|event| event.0 == Io::Read));
    let probe = events
        .iter()
        .rposition(|event| event.0 == Io::Read && event.1 == u32::try_from(7 * SECTOR).unwrap())
        .unwrap();
    let skip = events[..probe]
        .iter()
        .filter(|event| event.0 == Io::Read)
        .count();
    *flash.inner.bytes.borrow_mut() = initial.clone();
    let mut interrupted = mount_fault(&flash);
    flash.arm(&[Rule {
        io: Io::Read,
        skip,
        effect: Effect::Refuse,
        latched: false,
    }]);
    assert!(
        block_on(
            interrupted
                .main
                .repair_preserving(&mut interrupted.buf, &[CRED], |_, value| { value == owner })
        )
        .is_err()
    );
    assert_eq!(flash.hits(), [1]);
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    assert_eq!(*flash.inner.bytes.borrow(), initial);
}

#[test]
fn authority_rollover_and_its_interrupted_recovery_preserve_whole_values() {
    for (fid, length) in [(CRED, 64), (CTR, 3500)] {
        let baseline = FaultFlash::new();
        let mut store = mount_authenticated(&baseline);
        store.initialize_blank().unwrap();
        store.write(0xB000, b"neighbor").unwrap();
        let mut rollover = None;
        for generation in 0..512u16 {
            let before = baseline.inner.bytes.borrow().clone();
            baseline.arm(&[]);
            let byte = u8::try_from(generation % 251).unwrap();
            store.write(fid, &vec![byte; length]).unwrap();
            if baseline
                .events()
                .iter()
                .any(|event| event.0 == Io::Erase && event.1 >= MAIN.end)
            {
                rollover = Some((before, byte, baseline.events()));
                break;
            }
        }
        let (saved, byte, trace) = rollover.expect("the authority must roll over");
        for io in [Io::Program, Io::Erase] {
            let count = trace.iter().filter(|event| event.0 == io).count();
            assert!(count > 0);
            for first in 0..count {
                for effect in [Effect::Refuse, Effect::Drop, Effect::KeepTail] {
                    let flash = FaultFlash::new();
                    *flash.inner.bytes.borrow_mut() = saved.clone();
                    flash.arm(&[Rule {
                        io,
                        skip: first,
                        effect,
                        latched: true,
                    }]);
                    let result = mount_authenticated(&flash).write(fid, &vec![byte; length]);
                    assert!(flash.hits()[0] > 0);
                    flash.clear();
                    let interrupted = flash.inner.bytes.borrow().clone();
                    flash.arm(&[]);
                    let mut out = vec![0; length];
                    let mut healthy = mount_authenticated(&flash);
                    assert_eq!(healthy.read(fid, &mut out), Some(length));
                    assert!(!healthy.last_error());
                    assert!(out == vec![byte; length] || out == vec![byte - 1; length]);
                    if result.is_ok() {
                        assert_eq!(out, vec![byte; length]);
                    }
                    let expected = out;
                    let recovery = flash.events();
                    healthy.write(fid, &vec![0xD2; length]).unwrap();
                    let layout =
                        crate::authenticated::Layout::new(MAIN.end..MAIN.end + 128 * 1024).unwrap();
                    let lost = if fid == CRED {
                        &layout.main[0]
                    } else {
                        &layout.counter[0]
                    };
                    flash.inner.bytes.borrow_mut()[lost.start as usize..lost.start as usize + 128]
                        .fill(0xFF);
                    let mut peer = mount_authenticated(&flash);
                    let mut retained = vec![0; length];
                    assert_eq!(peer.read(fid, &mut retained), Some(length));
                    assert!(!peer.last_error());
                    assert_eq!(retained, vec![0xD2; length]);
                    for second_io in [Io::Program, Io::Erase] {
                        let second_count =
                            recovery.iter().filter(|event| event.0 == second_io).count();
                        for second in 0..second_count {
                            *flash.inner.bytes.borrow_mut() = interrupted.clone();
                            flash.arm(&[Rule {
                                io: second_io,
                                skip: second,
                                effect: Effect::KeepTail,
                                latched: true,
                            }]);
                            let _second_cut =
                                mount_authenticated(&flash).read(fid, &mut vec![0; length]);
                            assert!(
                                flash.hits()[0] > 0,
                                "fid {fid:04X}, {io:?} {first}, {second_io:?} {second}"
                            );
                            flash.clear();
                            let mut reboot = mount_authenticated(&flash);
                            let mut actual = vec![0; length];
                            assert_eq!(
                                reboot.read(fid, &mut actual),
                                Some(length),
                                "fid {fid:04X}, {io:?} {first}, {second_io:?} {second}"
                            );
                            assert!(!reboot.last_error());
                            assert_eq!(actual, expected);
                            assert_eq!(
                                authenticated_value(&mut reboot, 0xB000).unwrap().as_deref(),
                                Some(&b"neighbor"[..])
                            );
                        }
                    }
                }
            }
        }
    }
}
