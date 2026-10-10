// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::api::Geometry;
use super::*;
use crate::authenticated::{CHECKPOINT_BYTES, ENTRY_BYTES};

#[test]
fn journal_snapshot_and_directory_contradictions_remain_dirty_authenticated_progress() {
    for case in 0..5 {
        let flash = FaultFlash::new();
        let entry = Entry::live(JOURNAL_ID, &JOURNAL_KEY, CRED, 0, b"owner").unwrap();
        let mut directory = Directory::<2>::new();
        directory.apply(entry).unwrap();
        let mut header = checkpoint(&directory, 0);
        let mut raw = RawBank::new(flash.clone(), MAIN).unwrap();
        if case == 0 {
            header.identity.partition = Partition::Counter;
        }
        raw.program(0, &header.encode(&JOURNAL_KEY).unwrap())
            .unwrap();
        let encoded = match case {
            1 => {
                let mut bytes = entry.encode().unwrap();
                bytes[28] = 0;
                bytes
            }
            2 => Entry::live(JOURNAL_ID, &JOURNAL_KEY, CTR, 0, b"owner")
                .unwrap()
                .encode()
                .unwrap(),
            3 => Entry::live(JOURNAL_ID, &JOURNAL_KEY, CRED, 1, b"owner")
                .unwrap()
                .encode()
                .unwrap(),
            _ => entry.encode().unwrap(),
        };
        raw.program(u32::try_from(CHECKPOINT_BYTES).unwrap(), &encoded)
            .unwrap();
        let mut journal = Journal::new(raw, Partition::Main);
        let before = flash.inner.bytes.borrow().clone();
        let scan = if case == 4 {
            journal
                .scan(&JOURNAL_KEY, &mut Directory::<0>::new())
                .unwrap()
        } else {
            journal
                .scan(&JOURNAL_KEY, &mut Directory::<2>::new())
                .unwrap()
        };
        assert_eq!(scan.status, JournalStatus::Dirty, "case {case}");
        assert_eq!(*flash.inner.bytes.borrow(), before);
    }
}

#[test]
fn a_signed_snapshot_exceeding_its_window_and_an_erased_header_before_a_dirty_tail_refuse() {
    let flash = FaultFlash::new();
    let mut directory = Directory::<2>::new();
    directory
        .apply(Entry::live(JOURNAL_ID, &JOURNAL_KEY, CRED, 0, b"owner").unwrap())
        .unwrap();
    directory
        .apply(Entry::live(JOURNAL_ID, &JOURNAL_KEY, CRED + 1, 0, b"neighbor").unwrap())
        .unwrap();
    let mut tiny = RawBank::new(
        Geometry::<1, 4, 4>(flash.clone()),
        0..u32::try_from(CHECKPOINT_BYTES + ENTRY_BYTES).unwrap(),
    )
    .unwrap();
    tiny.program(0, &checkpoint(&directory, 0).encode(&JOURNAL_KEY).unwrap())
        .unwrap();
    let scan = Journal::new(tiny, Partition::Main)
        .scan(&JOURNAL_KEY, &mut Directory::<2>::new())
        .unwrap();
    assert_eq!(scan.status, JournalStatus::Dirty);
    assert_eq!(scan.lower_bound, Some(0));
    flash.inner.bytes.borrow_mut().fill(0xFF);
    let empty = Directory::<2>::new();
    let mut journal = Journal::new(RawBank::new(flash.clone(), MAIN).unwrap(), Partition::Main);
    let saved = journal
        .write_snapshot(checkpoint(&empty, 0), &JOURNAL_KEY, &empty)
        .unwrap();
    let mut raw = RawBank::new(flash.clone(), MAIN).unwrap();
    raw.program(
        saved.next + u32::try_from(crate::authenticated::DELTA_BYTES).unwrap(),
        b"hidden body",
    )
    .unwrap();
    let scan = journal.scan(&JOURNAL_KEY, &mut directory).unwrap();
    assert_eq!(scan.status, JournalStatus::Dirty);
    assert_eq!(scan.next, saved.next);
    assert_eq!(scan.state, saved.state);
}

#[test]
fn journal_refuses_commit_that_exhausts_the_supplied_directory() {
    let flash = FaultFlash::new();
    let mut journal = Journal::new(RawBank::new(flash.clone(), MAIN).unwrap(), Partition::Main);
    let empty = Directory::<2>::new();
    let initial = journal
        .write_snapshot(checkpoint(&empty, 0), &JOURNAL_KEY, &empty)
        .unwrap();
    let prepare = Delta {
        kind: DeltaKind::Prepare,
        partition: Partition::Main,
        sequence: 1,
        address: 4096,
        entry: Entry::live(JOURNAL_ID, &JOURNAL_KEY, CRED, 1, b"owner").unwrap(),
        previous: initial.state.unwrap().chain(),
    };
    journal.append(initial.next, prepare, &JOURNAL_KEY).unwrap();
    let pending = journal
        .scan(&JOURNAL_KEY, &mut Directory::<2>::new())
        .unwrap();
    journal
        .append(
            pending.next,
            Delta {
                kind: DeltaKind::Commit,
                previous: pending.state.unwrap().chain(),
                ..prepare
            },
            &JOURNAL_KEY,
        )
        .unwrap();
    let scan = journal
        .scan(&JOURNAL_KEY, &mut Directory::<0>::new())
        .unwrap();
    assert_eq!(scan.status, JournalStatus::Dirty);
    assert!(scan.state.unwrap().pending().is_some());
}

#[test]
fn journal_snapshot_arguments_are_checked_before_erasing_existing_authority() {
    let flash = FaultFlash::new();
    let mut journal = Journal::new(RawBank::new(flash.clone(), MAIN).unwrap(), Partition::Main);
    let mut directory = Directory::<2>::new();
    directory
        .apply(Entry::live(JOURNAL_ID, &JOURNAL_KEY, CRED, 0, b"owner").unwrap())
        .unwrap();
    let valid = checkpoint(&directory, 0);
    journal
        .write_snapshot(valid, &JOURNAL_KEY, &directory)
        .unwrap();
    let before = flash.inner.bytes.borrow().clone();
    let foreign = Checkpoint {
        identity: COUNTER_ID,
        ..valid
    };
    let wrong_count = Checkpoint {
        entries: 0,
        ..valid
    };
    let wrong_digest = Checkpoint {
        digest: [0; 32],
        ..valid
    };
    for wrong in [foreign, wrong_count, wrong_digest] {
        flash.arm(&[]);
        assert_eq!(
            journal.write_snapshot(wrong, &JOURNAL_KEY, &directory),
            Err(Error::MemoryFatal)
        );
        assert!(flash.events().is_empty());
        assert_eq!(*flash.inner.bytes.borrow(), before);
    }
    let mut wrong_route = Directory::<2>::new();
    wrong_route
        .apply(Entry::live(COUNTER_ID, &JOURNAL_KEY, CTR, 0, b"counter").unwrap())
        .unwrap();
    assert_eq!(
        journal.write_snapshot(checkpoint(&wrong_route, 0), &JOURNAL_KEY, &wrong_route),
        Err(Error::MemoryFatal)
    );
    assert_eq!(*flash.inner.bytes.borrow(), before);
}

#[test]
fn journal_append_rejects_foreign_partition_and_exhausted_window() {
    let flash = FaultFlash::new();
    let mut journal = Journal::new(RawBank::new(flash.clone(), MAIN).unwrap(), Partition::Main);
    let delta = Delta {
        kind: DeltaKind::Prepare,
        partition: Partition::Main,
        sequence: 1,
        address: 4096,
        entry: Entry::live(JOURNAL_ID, &JOURNAL_KEY, CRED, 1, b"owner").unwrap(),
        previous: [0; 32],
    };
    let foreign = Delta {
        partition: Partition::Counter,
        ..delta
    };
    assert_eq!(
        journal.append(0, foreign, &JOURNAL_KEY),
        Err(Error::MemoryFatal)
    );
    assert_eq!(
        journal.append(journal.capacity(), delta, &JOURNAL_KEY),
        Err(Error::NoMemory)
    );
    assert_eq!(
        journal.append(u32::MAX, delta, &JOURNAL_KEY),
        Err(Error::MemoryFatal)
    );
    assert!(flash.events().is_empty());
}
