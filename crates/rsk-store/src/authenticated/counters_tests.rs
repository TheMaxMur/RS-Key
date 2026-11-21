// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::super::{Layout, RawBank};
use super::*;
use crate::tests::FaultFlash;
use embassy_futures::block_on;
use embedded_storage_async::nor_flash::ReadNorFlash;

#[path = "counter_independence_tests.rs"]
mod independence;

const KEY: [u8; 32] = [0x35; 32];
const EPOCH: [u8; 16] = [0x4B; 16];
const IDENTITY: Identity = Identity {
    partition: Partition::Counter,
    epoch: EPOCH,
};

fn counters(flash: &FaultFlash) -> Counters<FaultFlash> {
    let layout = Layout::new(32768..32768 + super::super::storage::AUTHORITY_BYTES).unwrap();
    Counters::new(
        layout
            .counter
            .map(|range| CounterBank::new(RawBank::new(flash.clone(), range).unwrap())),
        IDENTITY,
        RootArm::PreOtp,
    )
    .unwrap()
}

#[test]
fn wrong_partition_bank_selector_and_non_counter_fids_are_refused() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut counters = counters(&flash);
    let wrong = Identity {
        partition: Partition::Main,
        ..IDENTITY
    };
    let layout = Layout::new(32768..32768 + super::super::storage::AUTHORITY_BYTES).unwrap();
    let banks = layout
        .counter
        .map(|range| CounterBank::new(RawBank::new(flash.clone(), range).unwrap()));
    assert_eq!(
        Counters::new(banks, wrong, RootArm::PreOtp).err(),
        Some(Error::MemoryFatal)
    );
    assert!(flash.events().is_empty());
    assert_eq!(counters.source_target(2).err(), Some(Error::MemoryFatal));
    counters
        .initialize(&KEY, &Directory::new(), 0, |_, _| unreachable!())
        .unwrap();
    assert_eq!(
        counters.write(&KEY, 0xB000, Some(b"owner")),
        Err(Error::MemoryFatal)
    );
    assert_eq!(counters.write(&KEY, 0xB000, None), Err(Error::MemoryFatal));
}

#[test]
fn authenticated_counter_headers_with_foreign_epoch_or_root_arm_are_refused() {
    for wrong_arm in [false, true] {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let mut counters = counters(&flash);
        counters
            .initialize(&KEY, &Directory::new(), 0, |_, _| unreachable!())
            .unwrap();
        let mut header = counters.checkpoint(&Directory::new(), &KEY, 0).unwrap();
        if wrong_arm {
            header.arm = RootArm::Otp;
        } else {
            header.identity.epoch[0] ^= 1;
        }
        header.digest = Directory::<MAX_COUNTER_ENTRIES>::new()
            .digest(header.identity, &KEY, 0)
            .unwrap();
        counters.banks[0]
            .write_snapshot(header, &KEY, &Directory::new(), |_, _| unreachable!())
            .unwrap();
        assert_eq!(
            counters.read(&KEY, rsk_fs::counter::EF_COUNTER.get(), &mut []),
            Err(Error::MemoryFatal)
        );
    }
}

#[test]
fn a_counter_rollover_retains_other_counter_owners() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut counters = counters(&flash);
    let hot = rsk_fs::counter::EF_COUNTER.get();
    let neighbor = rsk_fs::counter::EF_CRED_CTR.get();
    counters
        .initialize(&KEY, &Directory::new(), 0, |_, _| unreachable!())
        .unwrap();
    counters.write(&KEY, neighbor, Some(b"neighbor")).unwrap();
    for byte in 0..8 {
        counters
            .write(&KEY, hot, Some(&[byte; rsk_fs::MAX_VALUE_BYTES]))
            .unwrap();
        let mut value = [0; 8];
        assert_eq!(counters.read(&KEY, neighbor, &mut value), Ok(Some(8)));
        assert_eq!(&value, b"neighbor");
        assert_eq!(
            counters.read(&KEY, hot, &mut value),
            Ok(Some(rsk_fs::MAX_VALUE_BYTES))
        );
        assert_eq!(value, [byte; 8]);
    }
    assert!(
        flash
            .events()
            .iter()
            .filter(|(io, _, _)| *io == crate::tests::Io::Erase)
            .count()
            > 2
    );
}

fn replace_peer(
    image: &mut [u8],
    range: core::ops::Range<u32>,
    key: &[u8; 32],
    sequence: u64,
    arm: RootArm,
    owner: bool,
) {
    let start = usize::try_from(range.start).unwrap();
    let end = usize::try_from(range.end).unwrap();
    image[start..end].fill(0xFF);
    let mut directory = Directory::<MAX_COUNTER_ENTRIES>::new();
    if owner {
        directory
            .apply(
                Entry::live(
                    IDENTITY,
                    key,
                    rsk_fs::counter::EF_COUNTER.get(),
                    sequence,
                    b"owner",
                )
                .unwrap(),
            )
            .unwrap();
    }
    let header = Checkpoint {
        identity: IDENTITY,
        arm,
        sequence,
        entries: u32::try_from(directory.entries().len()).unwrap(),
        digest: directory.digest(IDENTITY, key, sequence).unwrap(),
    };
    image[start..start + super::super::CHECKPOINT_BYTES]
        .copy_from_slice(&header.encode(key).unwrap());
    if let Some(entry) = directory.entries().first() {
        let at = start + super::super::CHECKPOINT_BYTES;
        image[at..at + ENTRY_BYTES].copy_from_slice(&entry.encode().unwrap());
        image[at + ENTRY_BYTES..at + ENTRY_BYTES + 5].copy_from_slice(b"owner");
    }
}

#[test]
fn repair_rejects_a_changed_peer_scan_after_verified_publication() {
    let layout = Layout::new(32768..32768 + super::super::storage::AUTHORITY_BYTES).unwrap();
    let peer = layout.counter[1].clone();
    let baseline = crate::tests::fault_flash_for_authenticated_tests();
    let mut healthy = counters(&baseline);
    healthy
        .initialize(&KEY, &Directory::new(), 0, |_, _| unreachable!())
        .unwrap();
    RawBank::new(baseline.clone(), peer.clone())
        .unwrap()
        .erase()
        .unwrap();
    let original = baseline.image();
    healthy.mount = None;
    baseline.arm(&[]);
    assert_eq!(
        healthy.read(&KEY, rsk_fs::counter::EF_COUNTER.get(), &mut []),
        Ok(None)
    );
    let trace = baseline.events();
    let last = trace
        .iter()
        .rposition(|(io, _, _)| *io == crate::tests::Io::Program)
        .unwrap();
    let header = trace
        .iter()
        .enumerate()
        .skip(last + 1)
        .find(|(_, (io, at, len))| {
            *io == crate::tests::Io::Read
                && *at == peer.start
                && *len == super::super::CHECKPOINT_BYTES
        })
        .unwrap()
        .0;
    let skip = trace[..header]
        .iter()
        .filter(|(io, _, _)| *io == crate::tests::Io::Read)
        .count();
    for case in 0..3 {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        flash.replace_image_before_read(0, original.clone());
        assert!(embassy_futures::block_on(flash.clone().read(0, &mut [])).is_ok());
        let mut store = counters(&flash);
        let mut changed = baseline.image();
        if case == 0 {
            changed[usize::try_from(peer.start).unwrap() + 80] ^= 1;
        } else {
            replace_peer(
                &mut changed,
                peer.clone(),
                &KEY,
                u64::from(case == 1),
                RootArm::PreOtp,
                case == 2,
            );
        }
        flash.arm(&[]);
        flash.replace_image_before_read(skip, changed);
        assert_eq!(
            store.read(&KEY, rsk_fs::counter::EF_COUNTER.get(), &mut []),
            Err(Error::MemoryFatal),
            "case {case}"
        );
        assert!(
            flash
                .events()
                .iter()
                .any(|(io, at, _)| *io == crate::tests::Io::Program && *at == peer.start + 80)
        );
    }
}

#[test]
fn rekey_rejects_changed_status_or_sequence_at_its_peer_scan() {
    let next_key = [0x4B; 32];
    let layout = Layout::new(32768..32768 + super::super::storage::AUTHORITY_BYTES).unwrap();
    let peer = layout.counter[1].clone();
    let baseline = crate::tests::fault_flash_for_authenticated_tests();
    let mut healthy = counters(&baseline);
    healthy
        .initialize(&KEY, &Directory::new(), 0, |_, _| unreachable!())
        .unwrap();
    healthy
        .write(&KEY, rsk_fs::counter::EF_COUNTER.get(), Some(b"owner"))
        .unwrap();
    let original = baseline.image();
    let mut healthy = counters(&baseline);
    baseline.arm(&[]);
    healthy.rekey(&KEY, &next_key, RootArm::Otp).unwrap();
    let trace = baseline.events();
    let published = trace
        .iter()
        .position(|(io, at, _)| *io == crate::tests::Io::Program && *at == peer.start + 80)
        .unwrap();
    let header = trace
        .iter()
        .enumerate()
        .skip(published + 1)
        .find(|(_, (io, at, len))| {
            *io == crate::tests::Io::Read
                && *at == peer.start
                && *len == super::super::CHECKPOINT_BYTES
        })
        .unwrap()
        .0;
    let skip = trace[..header]
        .iter()
        .filter(|(io, _, _)| *io == crate::tests::Io::Read)
        .count();
    for sequence in [0, 2, 3, 4] {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        flash.replace_image_before_read(0, original.clone());
        assert!(block_on(flash.clone().read(0, &mut [])).is_ok());
        let mut store = counters(&flash);
        let mut changed = baseline.image();
        replace_peer(
            &mut changed,
            peer.clone(),
            &next_key,
            sequence,
            RootArm::Otp,
            false,
        );
        if sequence == 0 {
            changed[usize::try_from(peer.start).unwrap() + 80] ^= 1;
        }
        flash.arm(&[]);
        flash.replace_image_before_read(skip, changed);
        assert_eq!(
            store.rekey(&KEY, &next_key, RootArm::Otp),
            Err(Error::MemoryFatal)
        );
    }
}

#[test]
fn rollover_rejects_changed_status_or_sequence_before_copying_the_second_bank() {
    let layout = Layout::new(32768..32768 + super::super::storage::AUTHORITY_BYTES).unwrap();
    let peer = layout.counter[1].clone();
    let baseline = crate::tests::fault_flash_for_authenticated_tests();
    let mut healthy = counters(&baseline);
    let hot = rsk_fs::counter::EF_COUNTER.get();
    healthy
        .initialize(&KEY, &Directory::new(), 0, |_, _| unreachable!())
        .unwrap();
    loop {
        let scan = healthy.banks[0].scan(&KEY, &mut Directory::new()).unwrap();
        if healthy.banks[0].capacity() - scan.next
            < u32::try_from(ENTRY_BYTES + rsk_fs::MAX_VALUE_BYTES.div_ceil(16) * 16).unwrap()
        {
            break;
        }
        healthy
            .write(&KEY, hot, Some(&[0xA5; rsk_fs::MAX_VALUE_BYTES]))
            .unwrap();
    }
    let sequence = healthy.banks[0]
        .scan(&KEY, &mut Directory::new())
        .unwrap()
        .sequence
        .unwrap()
        + 1;
    let original = baseline.image();
    let mut healthy = counters(&baseline);
    baseline.arm(&[]);
    healthy
        .write(&KEY, hot, Some(&[0x4B; rsk_fs::MAX_VALUE_BYTES]))
        .unwrap();
    let trace = baseline.events();
    let published = trace
        .iter()
        .position(|(io, at, _)| *io == crate::tests::Io::Program && *at == peer.start + 80)
        .unwrap();
    let header = trace
        .iter()
        .enumerate()
        .skip(published + 1)
        .find(|(_, (io, at, len))| {
            *io == crate::tests::Io::Read
                && *at == peer.start
                && *len == super::super::CHECKPOINT_BYTES
        })
        .unwrap()
        .0;
    let skip = trace[..header]
        .iter()
        .filter(|(io, _, _)| *io == crate::tests::Io::Read)
        .count();
    for case in 0..3 {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        flash.replace_image_before_read(0, original.clone());
        assert!(block_on(flash.clone().read(0, &mut [])).is_ok());
        let mut store = counters(&flash);
        let mut changed = baseline.image();
        replace_peer(
            &mut changed,
            peer.clone(),
            &KEY,
            if case == 2 { sequence } else { 0 },
            RootArm::PreOtp,
            false,
        );
        if case == 1 {
            changed[usize::try_from(peer.start).unwrap() + 80] ^= 1;
        }
        flash.arm(&[]);
        flash.replace_image_before_read(skip, changed);
        assert_eq!(
            store.write(&KEY, hot, Some(&[0x4B; rsk_fs::MAX_VALUE_BYTES])),
            Err(Error::MemoryFatal)
        );
    }
}

#[path = "counter_mount_tests.rs"]
mod mount;

#[test]
fn live_counter_authority_rejects_another_authenticated_directory_at_the_same_sequence() {
    let layout = Layout::new(32768..32768 + super::super::storage::AUTHORITY_BYTES).unwrap();
    for keep_owner in [false, true] {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let mut pair = counters(&flash);
        pair.initialize(&KEY, &Directory::new(), 0, |_, _| unreachable!())
            .unwrap();
        pair.write(&KEY, rsk_fs::counter::EF_COUNTER.get(), Some(b"current"))
            .unwrap();
        let mut substituted = flash.image();
        for range in &layout.counter {
            substituted[usize::try_from(range.start).unwrap()..usize::try_from(range.end).unwrap()]
                .fill(0xff);
            replace_peer(
                &mut substituted,
                range.clone(),
                &KEY,
                1,
                RootArm::PreOtp,
                keep_owner,
            );
        }
        flash.replace_image_before_read(0, substituted);
        pair.mount = None;
        for _ in 0..2 {
            let mut out = [0xA5; 7];
            assert_eq!(
                pair.read(&KEY, rsk_fs::counter::EF_COUNTER.get(), &mut out),
                Err(Error::MemoryFatal)
            );
            assert_eq!(out, [0xA5; 7]);
        }
    }
}

#[path = "counter_proven_tests.rs"]
mod proven;
