// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::authenticated::{
    Checkpoint, CounterBank, Delta, DeltaKind, Directory, Entry, Identity, Journal, JournalStatus,
    MAX_COUNTER_ENTRIES, Partition, RawBank, RootArm,
};

#[path = "counter_replica_tests.rs"]
mod counter_replica;

#[path = "raw_bank_geometry_tests.rs"]
mod api;

#[path = "journal_api_tests.rs"]
mod journal_api;

#[path = "counter_bank_api_tests.rs"]
mod counter_api;

#[test]
fn raw_bank_preserves_adjacent_bytes_during_unaligned_programs() {
    let flash = FaultFlash::new();
    let mut bank = RawBank::new(flash.clone(), MAIN).unwrap();
    let neighbor = flash.inner.snapshot(COUNTER);
    assert!(bank.read_erased(0).unwrap());
    bank.program(3, &[0xA5, 0x43, 0x12]).unwrap();
    bank.program(1, &[0x7F, 0x3F]).unwrap();
    let mut bytes = [0; 8];
    bank.read(0, &mut bytes).unwrap();
    assert_eq!(bytes, [0xFF, 0x7F, 0x3F, 0xA5, 0x43, 0x12, 0xFF, 0xFF]);
    let mut short = [0; 3];
    bank.read(3, &mut short).unwrap();
    assert_eq!(short, [0xA5, 0x43, 0x12]);
    assert_eq!(flash.inner.snapshot(COUNTER), neighbor);
    let before = flash.inner.snapshot(MAIN);
    assert_eq!(bank.program(3, &[0xFF]), Err(Error::MemoryFatal));
    assert_eq!(
        flash.inner.snapshot(MAIN),
        before,
        "NOR cannot restore cleared bits"
    );
}

#[test]
fn an_erased_header_does_not_hide_a_programmed_body_or_late_suffix() {
    let flash = FaultFlash::new();
    let mut bank = RawBank::new(flash.clone(), MAIN).unwrap();
    bank.program(128 + 32, b"unpublished body").unwrap();
    let mut header = [0; 128];
    bank.read(0, &mut header).unwrap();
    assert!(header.iter().all(|&byte| byte == 0xFF));
    assert!(!bank.read_erased(128).unwrap());
    bank.erase().unwrap();
    let tail = bank.capacity() - 1;
    bank.program(tail, &[0x7F]).unwrap();
    assert!(!bank.read_erased(0).unwrap());
    assert!(!bank.read_erased(tail).unwrap());
    assert!(bank.read_erased(bank.capacity()).unwrap());
}

#[test]
fn raw_bank_dropped_program_and_erase_are_errors_not_success() {
    for io in [Io::Program, Io::Erase] {
        let flash = FaultFlash::new();
        let mut bank = RawBank::new(flash.clone(), MAIN).unwrap();
        if io == Io::Erase {
            bank.program(16, b"published metadata").unwrap();
        }
        let before = flash.inner.snapshot(MAIN);
        flash.arm(&[Rule {
            io,
            skip: 0,
            effect: Effect::Drop,
            latched: false,
        }]);
        let result = if io == Io::Erase {
            bank.erase()
        } else {
            bank.program(16, b"metadata")
        };
        assert_eq!(result, Err(Error::MemoryFatal));
        assert!(flash.hits()[0] > 0);
        assert_eq!(flash.inner.snapshot(MAIN), before);
    }
}

#[test]
fn raw_bank_bounds_and_refused_read_do_not_touch_other_authority_windows() {
    let flash = FaultFlash::new();
    let mut bank = RawBank::new(flash.clone(), COUNTER).unwrap();
    let before = flash.inner.bytes.borrow().clone();
    for offset in [bank.capacity(), u32::MAX] {
        assert_eq!(bank.program(offset, &[0]), Err(Error::MemoryFatal));
        assert_eq!(bank.read(offset, &mut [0]), Err(Error::MemoryFatal));
    }
    flash.arm(&[Rule {
        io: Io::Read,
        skip: 0,
        effect: Effect::Refuse,
        latched: true,
    }]);
    assert_eq!(bank.read(0, &mut [0; 32]), Err(Error::MemoryFatal));
    assert_eq!(bank.program(0, &[0; 32]), Err(Error::MemoryFatal));
    assert!(flash.hits()[0] > 0);
    assert_eq!(*flash.inner.bytes.borrow(), before);
}

const JOURNAL_KEY: [u8; 32] = [0x7A; 32];
const JOURNAL_ID: Identity = Identity {
    partition: Partition::Main,
    epoch: [0x4B; 16],
};

fn checkpoint(directory: &Directory<2>, sequence: u64) -> Checkpoint {
    Checkpoint {
        identity: JOURNAL_ID,
        arm: RootArm::PreOtp,
        sequence,
        entries: u32::try_from(directory.entries().len()).unwrap(),
        digest: directory
            .digest(JOURNAL_ID, &JOURNAL_KEY, sequence)
            .unwrap(),
    }
}

#[test]
fn raw_journal_replays_only_authenticated_publication_after_its_intent() {
    let flash = FaultFlash::new();
    let mut journal = Journal::new(RawBank::new(flash.clone(), MAIN).unwrap(), Partition::Main);
    let mut directory = Directory::<2>::new();
    let old = Entry::live(JOURNAL_ID, &JOURNAL_KEY, CRED, 0, b"old owner").unwrap();
    directory.apply(old).unwrap();
    let initial = journal
        .write_snapshot(checkpoint(&directory, 0), &JOURNAL_KEY, &directory)
        .unwrap();
    let current = Entry::live(JOURNAL_ID, &JOURNAL_KEY, CRED, 1, b"new owner").unwrap();
    let prepare = Delta {
        kind: DeltaKind::Prepare,
        partition: Partition::Main,
        sequence: 1,
        address: 4096 + 4,
        entry: current,
        previous: initial.state.unwrap().chain(),
    };
    journal.append(initial.next, prepare, &JOURNAL_KEY).unwrap();
    let mut restored = Directory::<2>::new();
    let pending = journal.scan(&JOURNAL_KEY, &mut restored).unwrap();
    assert_eq!(pending.status, JournalStatus::Complete);
    assert_eq!(pending.lower_bound, Some(0));
    assert_eq!(restored.find(CRED), Some(old));
    assert!(pending.state.unwrap().pending().is_some());
    let commit = Delta {
        kind: DeltaKind::Commit,
        previous: pending.state.unwrap().chain(),
        ..prepare
    };
    journal.append(pending.next, commit, &JOURNAL_KEY).unwrap();
    let complete = journal.scan(&JOURNAL_KEY, &mut restored).unwrap();
    assert_eq!(complete.status, JournalStatus::Complete);
    assert_eq!(complete.lower_bound, Some(1));
    assert_eq!(restored.find(CRED), Some(current));
    assert_eq!(complete.state.unwrap().pending(), None);
}

#[test]
fn raw_journal_does_not_label_a_damaged_new_tail_as_complete_old_authority() {
    let flash = FaultFlash::new();
    let mut journal = Journal::new(RawBank::new(flash.clone(), MAIN).unwrap(), Partition::Main);
    let directory = Directory::<2>::new();
    let initial = journal
        .write_snapshot(checkpoint(&directory, 0), &JOURNAL_KEY, &directory)
        .unwrap();
    let entry = Entry::live(JOURNAL_ID, &JOURNAL_KEY, CRED, 1, b"new owner").unwrap();
    let delta = Delta {
        kind: DeltaKind::Prepare,
        partition: Partition::Main,
        sequence: 1,
        address: 4096 + 4,
        entry,
        previous: initial.state.unwrap().chain(),
    };
    journal.append(initial.next, delta, &JOURNAL_KEY).unwrap();
    flash.inner.bytes.borrow_mut()[initial.next as usize + 96] ^= 1;
    let scan = journal
        .scan(&JOURNAL_KEY, &mut Directory::<2>::new())
        .unwrap();
    assert_eq!(scan.status, JournalStatus::Dirty);
    assert_eq!(scan.lower_bound, Some(0));
    assert_eq!(scan.next, initial.next);
}

#[test]
fn authenticated_snapshot_progress_survives_a_damaged_snapshot_as_a_lower_bound() {
    let flash = FaultFlash::new();
    let mut journal = Journal::new(RawBank::new(flash.clone(), MAIN).unwrap(), Partition::Main);
    let mut directory = Directory::<2>::new();
    directory
        .apply(Entry::live(JOURNAL_ID, &JOURNAL_KEY, CRED, 7, b"owner").unwrap())
        .unwrap();
    journal
        .write_snapshot(checkpoint(&directory, 7), &JOURNAL_KEY, &directory)
        .unwrap();
    flash.inner.bytes.borrow_mut()[128 + 12] ^= 1;
    let scan = journal
        .scan(&JOURNAL_KEY, &mut Directory::<2>::new())
        .unwrap();
    assert_eq!(scan.status, JournalStatus::Dirty);
    assert_eq!(scan.lower_bound, Some(7));
}

#[test]
fn invalid_snapshot_inputs_are_refused_before_any_erase() {
    let flash = FaultFlash::new();
    let mut journal = Journal::new(RawBank::new(flash.clone(), MAIN).unwrap(), Partition::Main);
    let mut directory = Directory::<2>::new();
    directory
        .apply(Entry::live(JOURNAL_ID, &JOURNAL_KEY, CRED, 7, b"owner").unwrap())
        .unwrap();
    journal
        .write_snapshot(checkpoint(&directory, 7), &JOURNAL_KEY, &directory)
        .unwrap();
    let before = flash.inner.snapshot(MAIN);
    let future = checkpoint(&directory, 6);
    assert!(
        journal
            .write_snapshot(future, &JOURNAL_KEY, &directory)
            .is_err()
    );
    assert_eq!(flash.inner.snapshot(MAIN), before);
}

const COUNTER_ID: Identity = Identity {
    partition: Partition::Counter,
    epoch: [0x4B; 16],
};

fn counter_bank(flash: &FaultFlash) -> CounterBank<FaultFlash> {
    let range = COUNTER.start..COUNTER.start + 5 * SECTOR as u32;
    flash
        .inner
        .bytes
        .borrow_mut()
        .resize(range.end as usize, 0xFF);
    CounterBank::new(RawBank::new(flash.clone(), range).unwrap())
}

fn counter_checkpoint(directory: &Directory<MAX_COUNTER_ENTRIES>, sequence: u64) -> Checkpoint {
    Checkpoint {
        identity: COUNTER_ID,
        arm: RootArm::PreOtp,
        sequence,
        entries: u32::try_from(directory.entries().len()).unwrap(),
        digest: directory
            .digest(COUNTER_ID, &JOURNAL_KEY, sequence)
            .unwrap(),
    }
}

#[test]
fn counter_bank_preserves_all_four_maximum_values_without_reducing_the_ceiling() {
    let flash = FaultFlash::new();
    let mut bank = counter_bank(&flash);
    let mut directory = Directory::<MAX_COUNTER_ENTRIES>::new();
    let mut owners = Vec::new();
    for (index, fid) in rsk_fs::counter::COUNTER_FIDS.iter().enumerate() {
        let value = vec![u8::try_from(index + 1).unwrap(); rsk_fs::MAX_VALUE_BYTES];
        directory
            .apply(Entry::live(COUNTER_ID, &JOURNAL_KEY, fid.get(), 0, &value).unwrap())
            .unwrap();
        owners.push((fid.get(), value));
    }
    bank.write_snapshot(
        counter_checkpoint(&directory, 0),
        &JOURNAL_KEY,
        &directory,
        |entry, out| {
            out.copy_from_slice(
                &owners
                    .iter()
                    .find(|(fid, _)| *fid == entry.fid())
                    .unwrap()
                    .1,
            );
            Ok(())
        },
    )
    .unwrap();
    let initial = bank.scan(&JOURNAL_KEY, &mut Directory::new()).unwrap();
    assert_eq!(initial.status, JournalStatus::Complete);
    assert_eq!(initial.next, 16_576);
    let mut out = vec![0; rsk_fs::MAX_VALUE_BYTES];
    for (fid, expected) in &owners {
        assert_eq!(
            bank.read_value(initial, &JOURNAL_KEY, *fid, &mut out),
            Ok(Some(expected.len()))
        );
        assert_eq!(&out, expected);
    }
    let fid = owners[0].0;
    let replacement = vec![0xB5; rsk_fs::MAX_VALUE_BYTES];
    let entry = Entry::live(COUNTER_ID, &JOURNAL_KEY, fid, 1, &replacement).unwrap();
    assert_eq!(
        bank.append(initial, &JOURNAL_KEY, entry, &replacement),
        Err(Error::NoMemory)
    );
    owners[0].1 = replacement;
    directory.apply(entry).unwrap();
    bank.write_snapshot(
        counter_checkpoint(&directory, 1),
        &JOURNAL_KEY,
        &directory,
        |entry, out| {
            out.copy_from_slice(
                &owners
                    .iter()
                    .find(|(fid, _)| *fid == entry.fid())
                    .unwrap()
                    .1,
            );
            Ok(())
        },
    )
    .unwrap();
    let final_state = bank.scan(&JOURNAL_KEY, &mut Directory::new()).unwrap();
    assert_eq!(final_state.status, JournalStatus::Complete);
    assert_eq!(final_state.sequence, Some(1));
    for (fid, expected) in &owners {
        assert_eq!(
            bank.read_value(final_state, &JOURNAL_KEY, *fid, &mut out),
            Ok(Some(expected.len()))
        );
        assert_eq!(&out, expected);
    }
}

#[test]
fn counter_bank_authenticates_the_full_value_before_releasing_a_short_prefix() {
    let flash = FaultFlash::new();
    let mut bank = counter_bank(&flash);
    let mut directory = Directory::<MAX_COUNTER_ENTRIES>::new();
    let payload = vec![0x5A; rsk_fs::MAX_VALUE_BYTES];
    directory
        .apply(Entry::live(COUNTER_ID, &JOURNAL_KEY, CTR, 0, &payload).unwrap())
        .unwrap();
    bank.write_snapshot(
        counter_checkpoint(&directory, 0),
        &JOURNAL_KEY,
        &directory,
        |_, out| {
            out.copy_from_slice(&payload);
            Ok(())
        },
    )
    .unwrap();
    let scan = bank.scan(&JOURNAL_KEY, &mut Directory::new()).unwrap();
    let location = scan.locations.iter().flatten().next().unwrap();
    let physical = COUNTER.start as usize + location.value_offset as usize + payload.len() - 1;
    flash.inner.bytes.borrow_mut()[physical] ^= 0x80;
    let mut out = [0xCC; 1];
    assert_eq!(
        bank.read_value(scan, &JOURNAL_KEY, CTR, &mut out),
        Err(Error::MemoryFatal)
    );
    assert_eq!(
        out,
        [0xCC],
        "a validated prefix is not permission to release unverified data"
    );
    assert_eq!(
        bank.scan(&JOURNAL_KEY, &mut Directory::new())
            .unwrap()
            .status,
        JournalStatus::Dirty
    );
}

#[test]
fn counter_bank_does_not_skip_a_corrupted_delta_or_a_hidden_data_first_append() {
    let flash = FaultFlash::new();
    let mut bank = counter_bank(&flash);
    let directory = Directory::<MAX_COUNTER_ENTRIES>::new();
    bank.write_snapshot(
        counter_checkpoint(&directory, 0),
        &JOURNAL_KEY,
        &directory,
        |_, _| unreachable!(),
    )
    .unwrap();
    let initial = bank.scan(&JOURNAL_KEY, &mut Directory::new()).unwrap();
    let owner = Entry::live(COUNTER_ID, &JOURNAL_KEY, CTR, 1, b"new counter").unwrap();
    bank.append(initial, &JOURNAL_KEY, owner, b"new counter")
        .unwrap();
    let complete = bank.scan(&JOURNAL_KEY, &mut Directory::new()).unwrap();
    assert_eq!(complete.status, JournalStatus::Complete);
    assert_eq!(complete.sequence, Some(1));
    flash.inner.bytes.borrow_mut()[COUNTER.start as usize + initial.next as usize + 12] ^= 1;
    let damaged = bank.scan(&JOURNAL_KEY, &mut Directory::new()).unwrap();
    assert_eq!(damaged.status, JournalStatus::Dirty);
    assert_eq!(damaged.lower_bound, Some(0));
    bank.write_snapshot(
        counter_checkpoint(&directory, 0),
        &JOURNAL_KEY,
        &directory,
        |_, _| unreachable!(),
    )
    .unwrap();
    let mut raw = RawBank::new(
        flash.clone(),
        COUNTER.start..COUNTER.start + 5 * SECTOR as u32,
    )
    .unwrap();
    raw.program(initial.next + 32, b"unpublished body").unwrap();
    let dirty = bank.scan(&JOURNAL_KEY, &mut Directory::new()).unwrap();
    assert_eq!(dirty.status, JournalStatus::Dirty);
    assert_eq!(dirty.sequence, Some(0));
}
