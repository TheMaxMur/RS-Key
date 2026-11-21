// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::api::Geometry;
use super::*;
use crate::authenticated::{CHECKPOINT_BYTES, ENTRY_BYTES};

#[test]
fn a_snapshot_requires_exact_room_for_its_prepare_and_commit_before_erasing() {
    let count = (SECTOR - CHECKPOINT_BYTES - 2 * crate::authenticated::DELTA_BYTES) / ENTRY_BYTES;
    assert_eq!(
        CHECKPOINT_BYTES + count * ENTRY_BYTES + 2 * crate::authenticated::DELTA_BYTES,
        SECTOR
    );
    for missing in [0, 4] {
        let flash = FaultFlash::new();
        let mut directory = Directory::<128>::new();
        for index in 0..count {
            directory
                .apply(
                    Entry::live(
                        JOURNAL_ID,
                        &JOURNAL_KEY,
                        CRED + u16::try_from(index).unwrap(),
                        0,
                        b"owner",
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        let header = Checkpoint {
            identity: JOURNAL_ID,
            arm: RootArm::PreOtp,
            sequence: 0,
            entries: u32::try_from(count).unwrap(),
            digest: directory.digest(JOURNAL_ID, &JOURNAL_KEY, 0).unwrap(),
        };
        let mut raw = RawBank::new(
            Geometry::<1, 4, 4>(flash.clone()),
            0..u32::try_from(SECTOR - missing).unwrap(),
        )
        .unwrap();
        raw.program(0, &[0x7F]).unwrap();
        let before = flash.inner.bytes.borrow().clone();
        flash.arm(&[]);
        let result =
            Journal::new(raw, Partition::Main).write_snapshot(header, &JOURNAL_KEY, &directory);
        if missing == 0 {
            assert_eq!(result.unwrap().status, JournalStatus::Complete);
        } else {
            assert_eq!(result, Err(Error::NoMemory));
            assert!(flash.events().is_empty());
            assert_eq!(*flash.inner.bytes.borrow(), before);
        }
    }
}

#[test]
fn an_erased_journal_is_empty_only_when_its_whole_bank_is_erased() {
    for dirty_tail in [false, true] {
        let flash = FaultFlash::new();
        let mut raw = RawBank::new(flash.clone(), MAIN).unwrap();
        if dirty_tail {
            raw.program(raw.capacity() - 1, &[0x7F]).unwrap();
        }
        let before = flash.inner.bytes.borrow().clone();
        let mut directory = Directory::<2>::new();
        directory
            .apply(Entry::live(JOURNAL_ID, &JOURNAL_KEY, CRED, 0, b"stale").unwrap())
            .unwrap();
        flash.arm(&[]);
        let scan = Journal::new(raw, Partition::Main)
            .scan(&JOURNAL_KEY, &mut directory)
            .unwrap();
        assert_eq!(
            scan.status,
            if dirty_tail {
                JournalStatus::Dirty
            } else {
                JournalStatus::Empty
            }
        );
        assert_eq!(scan.checkpoint, None);
        assert_eq!(scan.state, None);
        assert_eq!(scan.lower_bound, None);
        assert_eq!(scan.next, 0);
        assert!(directory.entries().is_empty());
        assert_eq!(*flash.inner.bytes.borrow(), before);
        assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    }
}

#[test]
fn an_authenticated_snapshot_may_end_at_the_bank_boundary() {
    let flash = FaultFlash::new();
    let mut directory = Directory::<2>::new();
    for (fid, value) in [
        (CRED, b"owner".as_slice()),
        (CRED + 1, b"neighbor".as_slice()),
    ] {
        directory
            .apply(Entry::live(JOURNAL_ID, &JOURNAL_KEY, fid, 7, value).unwrap())
            .unwrap();
    }
    let header = checkpoint(&directory, 7);
    let end = u32::try_from(CHECKPOINT_BYTES + 2 * ENTRY_BYTES).unwrap();
    let mut raw = RawBank::new(Geometry::<1, 4, 4>(flash.clone()), 0..end).unwrap();
    raw.program(0, &header.encode(&JOURNAL_KEY).unwrap())
        .unwrap();
    for (index, entry) in directory.entries().iter().enumerate() {
        raw.program(
            u32::try_from(CHECKPOINT_BYTES + index * ENTRY_BYTES).unwrap(),
            &entry.encode().unwrap(),
        )
        .unwrap();
    }
    let before = flash.inner.bytes.borrow().clone();
    flash.arm(&[]);
    let mut restored = Directory::<2>::new();
    let scan = Journal::new(raw, Partition::Main)
        .scan(&JOURNAL_KEY, &mut restored)
        .unwrap();
    assert_eq!(scan.status, JournalStatus::Complete);
    assert_eq!(scan.checkpoint, Some(header));
    assert_eq!(scan.lower_bound, Some(7));
    assert_eq!(scan.state.unwrap().sequence(), 7);
    assert_eq!(scan.next, end);
    assert_eq!(restored.entries(), directory.entries());
    assert_eq!(*flash.inner.bytes.borrow(), before);
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
}

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
    // A valid first entry keeps a decoder refusal from masking the window guard.
    tiny.program(
        u32::try_from(CHECKPOINT_BYTES).unwrap(),
        &directory.entries()[0].encode().unwrap(),
    )
    .unwrap();
    let mut restored = Directory::<2>::new();
    let scan = Journal::new(tiny, Partition::Main)
        .scan(&JOURNAL_KEY, &mut restored)
        .unwrap();
    assert_eq!(scan.status, JournalStatus::Dirty);
    assert_eq!(scan.lower_bound, Some(0));
    assert!(restored.entries().is_empty());
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
