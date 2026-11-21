// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::authenticated::{
    Authenticated, KeySource, Layout, Partition, RawBank, RootArm, RootRead,
};

#[path = "authenticated_compact_tests.rs"]
mod compact;

#[test]
fn authenticated_size_reports_full_values_and_keeps_faults_distinct_from_absence() {
    let flash = FaultFlash::new();
    let mut store = mount_authenticated(&flash);
    store.initialize_blank().unwrap();
    for (fid, value) in [(CRED, &b"owner"[..]), (CTR, &b"counter"[..])] {
        store.write(fid, value).unwrap();
        assert_eq!(store.size(fid), Some(value.len()));
        assert!(!store.last_error());
        assert!(store.exists(fid));
        store.write(fid, &[]).unwrap();
        assert_eq!(store.size(fid), Some(0));
        store.remove(fid).unwrap();
        assert_eq!(store.size(fid), None);
        assert!(!store.last_error());
    }
    store.write(CRED, b"owner").unwrap();
    let before = flash.image();
    flash.arm(&[Rule {
        io: Io::Read,
        skip: 0,
        effect: Effect::Refuse,
        latched: true,
    }]);
    assert_eq!(store.size(CRED), None);
    assert!(store.last_error());
    assert!(flash.hits()[0] > 0);
    flash.clear();
    assert_eq!(store.size(CRED), Some(5));
    assert!(!store.last_error());
    assert_eq!(flash.image(), before);
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
}

#[test]
fn an_enumeration_fault_in_either_partition_keeps_the_walk_incomplete() {
    let flash = FaultFlash::new();
    let mut store = mount_authenticated(&flash);
    store.initialize_blank().unwrap();
    store.write(CRED, b"owner").unwrap();
    store.write(CTR, b"counter").unwrap();
    let layout = Layout::new(MAIN.end..MAIN.end + 128 * 1024).unwrap();
    let before = flash.image();
    for partition in [Partition::Main, Partition::Counter] {
        flash.arm(&[]);
        let mut seen = Vec::new();
        assert!(store.for_each_key(&mut |fid| seen.push(fid)));
        assert!(!store.last_error());
        assert!(seen.contains(&CRED) && seen.contains(&CTR));
        let reads: Vec<_> = flash
            .events()
            .into_iter()
            .filter(|event| event.0 == Io::Read)
            .collect();
        let skip = match partition {
            Partition::Main => 0,
            Partition::Counter => reads
                .iter()
                .position(|event| layout.counter.iter().any(|range| range.contains(&event.1)))
                .unwrap(),
        };
        flash.arm(&[Rule {
            io: Io::Read,
            skip,
            effect: Effect::Refuse,
            latched: false,
        }]);
        seen.clear();
        assert!(
            !store.for_each_key(&mut |fid| seen.push(fid)),
            "{partition:?} fault must keep the walk incomplete"
        );
        assert!(store.last_error());
        assert_eq!(flash.hits(), [1]);
        assert_eq!(seen.contains(&CRED), partition == Partition::Counter);
        assert_eq!(seen.contains(&CTR), partition == Partition::Main);
        assert_eq!(flash.image(), before);
        assert!(flash.events().iter().all(|event| event.0 == Io::Read));
        flash.clear();
    }
}

#[test]
#[expect(
    clippy::reversed_empty_ranges,
    reason = "Invalid intervals are inputs to the layout validator, not iteration ranges."
)]
fn authenticated_layout_and_overlapping_payload_windows_refuse_before_io() {
    let flash = FaultFlash::new();
    let end = MAIN.end + 128 * 1024;
    flash.inner.bytes.borrow_mut().resize(end as usize, 0xFF);
    for range in [0..0, 1..0, 0..128 * 1024 - 1] {
        assert_eq!(Layout::new(range), Err(Error::MemoryFatal));
    }
    let upper = u32::MAX - 128 * 1024..u32::MAX;
    assert_eq!(
        Layout::new(upper.clone()).unwrap().counter[1].end,
        upper.end
    );
    for main in [0..0, MAIN.end..0, 0..MAIN.end + 4096] {
        assert!(
            Authenticated::new(
                flash.clone(),
                main,
                MAIN.end..end,
                MainCache::new(
                    ArrayPageStates::new(),
                    ArrayPagePointers::new(),
                    ArrayKeyPointers::new()
                ),
                KeySource::new([0x43; 32], auth_blank, false),
                [0x4B; 16],
                RootArm::PreOtp
            )
            .is_err()
        );
    }
    assert!(flash.events().is_empty());
}

#[test]
fn blank_initialization_refuses_non_erased_payload_or_authority_without_mutation() {
    for range in [MAIN, MAIN.end..MAIN.end + 128 * 1024] {
        let flash = FaultFlash::new();
        let mut store = mount_authenticated(&flash);
        RawBank::new(flash.clone(), range)
            .unwrap()
            .program(16, b"retained owner")
            .unwrap();
        let before = flash.inner.bytes.borrow().clone();
        assert_eq!(store.initialize_blank(), Err(Error::MemoryFatal));
        assert_eq!(*flash.inner.bytes.borrow(), before);
    }
}

#[test]
fn private_storage_fids_remain_hidden_and_counter_delete_keeps_neighbors() {
    let flash = FaultFlash::new();
    let mut store = mount_authenticated(&flash);
    store.initialize_blank().unwrap();
    store.write(CRED, b"owner").unwrap();
    store.write(CTR, b"counter").unwrap();
    let before = flash.inner.bytes.borrow().clone();
    for fid in rsk_fs::STORE_INTERNAL_FIDS {
        assert_eq!(store.write(fid, b"forbidden"), Err(Error::Blocked));
        assert_eq!(store.remove(fid), Err(Error::Blocked));
        assert_eq!(store.read(fid, &mut [0; 32]), None);
        assert!(!store.last_error());
    }
    assert_eq!(*flash.inner.bytes.borrow(), before);
    store.remove(CTR).unwrap();
    assert_eq!(store.read(CTR, &mut [0; 32]), None);
    let mut value = [0; 5];
    assert_eq!(store.read(CRED, &mut value), Some(5));
    assert_eq!(&value, b"owner");
}

std::thread_local! {
    static ROOT_READS: Cell<usize> = const { Cell::new(usize::MAX) };
}

fn bounded_root(_: &mut [u8; 32]) -> RootRead {
    ROOT_READS.with(|remaining| {
        if remaining.get() == 0 {
            RootRead::Unreadable
        } else {
            remaining.set(remaining.get() - 1);
            RootRead::Blank
        }
    })
}

#[test]
fn each_partition_key_read_failure_marks_a_walk_incomplete() {
    for budget in [0, 1] {
        ROOT_READS.with(|remaining| remaining.set(usize::MAX));
        let flash = FaultFlash::new();
        let end = MAIN.end + 128 * 1024;
        flash.inner.bytes.borrow_mut().resize(end as usize, 0xFF);
        let mut store = Authenticated::new(
            flash.clone(),
            MAIN,
            MAIN.end..end,
            MainCache::new(
                ArrayPageStates::new(),
                ArrayPagePointers::new(),
                ArrayKeyPointers::new(),
            ),
            KeySource::new([0x43; 32], bounded_root, false),
            [0x4B; 16],
            RootArm::PreOtp,
        )
        .unwrap();
        store.initialize_blank().unwrap();
        store.write(CRED, b"owner").unwrap();
        store.write(CTR, b"counter").unwrap();
        let before = flash.inner.bytes.borrow().clone();
        ROOT_READS.with(|remaining| remaining.set(budget));
        let mut seen = Vec::new();
        assert!(!store.for_each_key(&mut |fid| seen.push(fid)));
        assert!(store.last_error());
        assert!(!seen.contains(&CTR));
        assert_eq!(seen.contains(&CRED), budget == 1);
        assert_eq!(*flash.inner.bytes.borrow(), before);
        ROOT_READS.with(|remaining| remaining.set(usize::MAX));
        seen.clear();
        assert!(store.for_each_key(&mut |fid| seen.push(fid)));
        assert!(!store.last_error());
        assert!(seen.contains(&CRED) && seen.contains(&CTR));
    }
}
