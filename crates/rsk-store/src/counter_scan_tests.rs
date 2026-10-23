// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::api::Geometry;
use super::*;
use crate::authenticated::{CHECKPOINT_BYTES, ENTRY_BYTES};

const SNAPSHOT_SEQUENCE: u64 = 7;
const SNAPSHOT_VALUE: usize = CHECKPOINT_BYTES + ENTRY_BYTES;
const LIVE_HEADER: usize = SNAPSHOT_VALUE + 16;
const LIVE_VALUE: usize = LIVE_HEADER + ENTRY_BYTES;
const DELETED_HEADER: usize = LIVE_VALUE + 16;
const TERMINATOR: usize = DELETED_HEADER + ENTRY_BYTES;

fn populated<const R: usize>() -> (FaultFlash, CounterBank<Geometry<R, 4, SECTOR>>) {
    let flash = FaultFlash::new();
    let mut bank = CounterBank::new(
        RawBank::new(Geometry::<R, 4, SECTOR>(flash.clone()), 0..SECTOR as u32).unwrap(),
    );
    let mut directory = Directory::new();
    directory
        .apply(Entry::live(COUNTER_ID, &JOURNAL_KEY, CTR, SNAPSHOT_SEQUENCE, b"old").unwrap())
        .unwrap();
    bank.write_snapshot(
        counter_checkpoint(&directory, SNAPSHOT_SEQUENCE),
        &JOURNAL_KEY,
        &directory,
        |_, out| {
            out.copy_from_slice(b"old");
            Ok(())
        },
    )
    .unwrap();
    let scan = bank.scan(&JOURNAL_KEY, &mut directory).unwrap();
    bank.append(
        scan,
        &JOURNAL_KEY,
        Entry::live(COUNTER_ID, &JOURNAL_KEY, CTR, SNAPSHOT_SEQUENCE + 1, b"new").unwrap(),
        b"new",
    )
    .unwrap();
    let scan = bank.scan(&JOURNAL_KEY, &mut directory).unwrap();
    bank.append(
        scan,
        &JOURNAL_KEY,
        Entry::deleted(COUNTER_ID, &JOURNAL_KEY, CTR, SNAPSHOT_SEQUENCE + 2).unwrap(),
        &[],
    )
    .unwrap();
    flash.arm(&[]);
    (flash, bank)
}

fn expected_reads() -> Vec<(Io, u32, usize)> {
    let mut reads = vec![
        (Io::Read, 0, CHECKPOINT_BYTES),
        (Io::Read, CHECKPOINT_BYTES as u32, ENTRY_BYTES),
        (Io::Read, SNAPSHOT_VALUE as u32, 16),
        (Io::Read, LIVE_HEADER as u32, ENTRY_BYTES),
        (Io::Read, LIVE_VALUE as u32, 16),
        (Io::Read, DELETED_HEADER as u32, ENTRY_BYTES),
        (Io::Read, TERMINATOR as u32, ENTRY_BYTES),
    ];
    for at in (TERMINATOR..SECTOR).step_by(256) {
        reads.push((Io::Read, at as u32, (SECTOR - at).min(256)));
    }
    reads
}

fn check_trace<const R: usize>() {
    let (flash, mut bank) = populated::<R>();
    let before = flash.image();
    let mut directory = Directory::new();
    let scan = bank.scan(&JOURNAL_KEY, &mut directory).unwrap();
    assert_eq!(scan.status, JournalStatus::Complete);
    assert_eq!(scan.sequence, Some(SNAPSHOT_SEQUENCE + 2));
    assert_eq!(scan.lower_bound, scan.sequence);
    assert_eq!(scan.next, TERMINATOR as u32);
    assert!(scan.locations.iter().all(Option::is_none));
    assert!(directory.entries().is_empty());
    let expected = expected_reads();
    assert_eq!(flash.events(), expected);
    for skip in 0..expected.len() {
        flash.arm(&[Rule {
            io: Io::Read,
            skip,
            effect: Effect::Refuse,
            latched: false,
        }]);
        assert_eq!(
            bank.scan(&JOURNAL_KEY, &mut directory),
            Err(Error::MemoryFatal)
        );
        assert_eq!(flash.events(), expected[..=skip]);
        assert_eq!(flash.hits(), [1]);
    }
    assert_eq!(flash.image(), before);
}

#[test]
fn counter_scan_preserves_physical_read_trace_and_each_read_error() {
    check_trace::<1>();
    check_trace::<4>();
    check_trace::<16>();
}

fn check_large_value<const R: usize>() {
    let flash = FaultFlash::new();
    let mut bank = CounterBank::new(
        RawBank::new(Geometry::<R, 4, SECTOR>(flash.clone()), 0..SECTOR as u32).unwrap(),
    );
    let value = [0x69; 519];
    let entry = Entry::live(COUNTER_ID, &JOURNAL_KEY, CTR, SNAPSHOT_SEQUENCE, &value).unwrap();
    let mut directory = Directory::new();
    directory.apply(entry).unwrap();
    bank.write_snapshot(
        counter_checkpoint(&directory, SNAPSHOT_SEQUENCE),
        &JOURNAL_KEY,
        &directory,
        |_, out| {
            out.copy_from_slice(&value);
            Ok(())
        },
    )
    .unwrap();
    flash.arm(&[]);
    let scan = bank.scan(&JOURNAL_KEY, &mut directory).unwrap();
    assert_eq!(scan.status, JournalStatus::Complete);
    assert_eq!(directory.entries(), &[entry]);
    let end = SNAPSHOT_VALUE + 528;
    let mut expected = vec![
        (Io::Read, 0, CHECKPOINT_BYTES),
        (Io::Read, CHECKPOINT_BYTES as u32, ENTRY_BYTES),
        (Io::Read, SNAPSHOT_VALUE as u32, 528),
        (Io::Read, end as u32, ENTRY_BYTES),
    ];
    for at in (end..SECTOR).step_by(256) {
        expected.push((Io::Read, at as u32, (SECTOR - at).min(256)));
    }
    assert_eq!(flash.events(), expected);
}

#[test]
fn counter_scan_large_value_preserves_physical_read_boundaries() {
    check_large_value::<1>();
    check_large_value::<4>();
    check_large_value::<16>();
}

#[test]
fn counter_scan_authentication_failure_precedes_a_later_read_error() {
    for case in 0..3 {
        let (flash, mut bank) = populated::<4>();
        let mut image = flash.image();
        let reads = if case == 1 { 5 } else { 3 };
        if case == 2 {
            let mut header = Checkpoint::verify(&image[..CHECKPOINT_BYTES], &JOURNAL_KEY).unwrap();
            header.digest[0] ^= 1;
            image[..CHECKPOINT_BYTES].copy_from_slice(&header.encode(&JOURNAL_KEY).unwrap());
        } else {
            image[if case == 0 {
                SNAPSHOT_VALUE
            } else {
                LIVE_VALUE
            }] ^= 1;
        }
        *flash.inner.bytes.borrow_mut() = image.clone();
        flash.arm(&[Rule {
            io: Io::Read,
            skip: reads,
            effect: Effect::Refuse,
            latched: false,
        }]);
        let scan = bank.scan(&JOURNAL_KEY, &mut Directory::new()).unwrap();
        assert_eq!(scan.status, JournalStatus::Dirty);
        assert_eq!(scan.lower_bound, Some(SNAPSHOT_SEQUENCE));
        assert_eq!(scan.sequence, (case == 1).then_some(SNAPSHOT_SEQUENCE));
        assert_eq!(flash.events(), expected_reads()[..reads]);
        assert_eq!(flash.hits(), [0]);
        assert_eq!(flash.image(), image);
    }
}

#[test]
fn counter_scan_preserves_distinct_overlapping_erased_observations() {
    let (flash, mut bank) = populated::<16>();
    let mut changed = flash.image();
    changed[TERMINATOR] = 0;
    flash.replace_image_before_read(7, changed.clone());
    let scan = bank.scan(&JOURNAL_KEY, &mut Directory::new()).unwrap();
    assert_eq!(scan.status, JournalStatus::Dirty);
    assert_eq!(scan.lower_bound, Some(SNAPSHOT_SEQUENCE + 2));
    assert_eq!(flash.events(), expected_reads()[..8]);
    assert_eq!(flash.image(), changed);

    let flash = FaultFlash::new();
    let mut bank = CounterBank::new(
        RawBank::new(Geometry::<16, 4, SECTOR>(flash.clone()), 0..SECTOR as u32).unwrap(),
    );
    let mut changed = flash.image();
    changed[0] = 0;
    flash.replace_image_before_read(1, changed.clone());
    let scan = bank.scan(&JOURNAL_KEY, &mut Directory::new()).unwrap();
    assert_eq!(scan.status, JournalStatus::Dirty);
    assert_eq!(scan.checkpoint, None);
    assert_eq!(scan.lower_bound, None);
    assert_eq!(
        flash.events(),
        [(Io::Read, 0, CHECKPOINT_BYTES), (Io::Read, 0, 256)]
    );
    assert_eq!(flash.image(), changed);
}
