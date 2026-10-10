// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::authenticated::{CHECKPOINT_BYTES, ENTRY_BYTES};

#[test]
fn an_unsupported_read_fault_rule_panics_before_arming_and_valid_rules_still_work() {
    let flash = FaultFlash::new();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            flash.arm(&[crate::tests::Rule {
                io: crate::tests::Io::Read,
                skip: 0,
                effect: crate::tests::Effect::Drop,
                latched: false,
            }]);
        }))
        .is_err()
    );
    assert!(flash.hits().is_empty());
    flash.arm(&[Rule {
        io: Io::Read,
        skip: 0,
        effect: Effect::Refuse,
        latched: false,
    }]);
    let mut bank = counter_bank(&flash);
    assert_eq!(bank.read_header(), Err(Error::MemoryFatal));
    assert_eq!(flash.hits(), [1]);
}

#[test]
fn counter_snapshot_arguments_are_checked_before_erasing_existing_authority() {
    let flash = FaultFlash::new();
    let mut bank = counter_bank(&flash);
    let mut directory = Directory::<MAX_COUNTER_ENTRIES>::new();
    directory
        .apply(Entry::live(COUNTER_ID, &JOURNAL_KEY, CTR, 0, b"value").unwrap())
        .unwrap();
    let valid = counter_checkpoint(&directory, 0);
    bank.write_snapshot(valid, &JOURNAL_KEY, &directory, |_, out| {
        out.copy_from_slice(b"value");
        Ok(())
    })
    .unwrap();
    let before = flash.inner.bytes.borrow().clone();
    let foreign = Checkpoint {
        identity: JOURNAL_ID,
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
            bank.write_snapshot(wrong, &JOURNAL_KEY, &directory, |_, _| unreachable!()),
            Err(Error::MemoryFatal)
        );
        assert!(flash.events().is_empty());
        assert_eq!(*flash.inner.bytes.borrow(), before);
    }
    let future = counter_checkpoint(&directory, 0);
    directory.clear();
    directory
        .apply(Entry::live(COUNTER_ID, &JOURNAL_KEY, CTR, 1, b"value").unwrap())
        .unwrap();
    let future = Checkpoint {
        digest: directory.digest(COUNTER_ID, &JOURNAL_KEY, 0).unwrap(),
        ..future
    };
    assert_eq!(
        bank.write_snapshot(future, &JOURNAL_KEY, &directory, |_, _| unreachable!()),
        Err(Error::MemoryFatal)
    );
    directory.clear();
    directory
        .apply(Entry::live(COUNTER_ID, &JOURNAL_KEY, CRED, 0, b"value").unwrap())
        .unwrap();
    let wrong = counter_checkpoint(&directory, 0);
    assert_eq!(
        bank.write_snapshot(wrong, &JOURNAL_KEY, &directory, |_, _| unreachable!()),
        Err(Error::MemoryFatal)
    );
    assert_eq!(*flash.inner.bytes.borrow(), before);
}

#[test]
fn counter_scan_rejects_signed_snapshot_contradictions_and_non_erased_padding() {
    let live = Entry::live(COUNTER_ID, &JOURNAL_KEY, CTR, 0, b"value").unwrap();
    let deleted = Entry::deleted(COUNTER_ID, &JOURNAL_KEY, CTR, 0).unwrap();
    let future = Entry::live(COUNTER_ID, &JOURNAL_KEY, CTR, 1, b"value").unwrap();
    let foreign = Entry::live(COUNTER_ID, &JOURNAL_KEY, CRED, 0, b"value").unwrap();
    for case in 0..7 {
        let flash = FaultFlash::new();
        let mut bank = counter_bank(&flash);
        let mut directory = Directory::<MAX_COUNTER_ENTRIES>::new();
        directory.apply(live).unwrap();
        bank.write_snapshot(
            counter_checkpoint(&directory, 0),
            &JOURNAL_KEY,
            &directory,
            |_, out| {
                out.copy_from_slice(b"value");
                Ok(())
            },
        )
        .unwrap();
        let start = usize::try_from(COUNTER.start).unwrap();
        let mut bytes = flash.inner.bytes.borrow_mut();
        match case {
            0 => bytes[start + CHECKPOINT_BYTES + 28] = 0,
            1 => bytes[start + CHECKPOINT_BYTES..start + CHECKPOINT_BYTES + ENTRY_BYTES]
                .copy_from_slice(&deleted.encode().unwrap()),
            2 => bytes[start + CHECKPOINT_BYTES..start + CHECKPOINT_BYTES + ENTRY_BYTES]
                .copy_from_slice(&future.encode().unwrap()),
            3 => bytes[start + CHECKPOINT_BYTES..start + CHECKPOINT_BYTES + ENTRY_BYTES]
                .copy_from_slice(&foreign.encode().unwrap()),
            4 => bytes[start + CHECKPOINT_BYTES + ENTRY_BYTES + 5] = 0,
            5 | 6 => {
                let mut header = counter_checkpoint(&directory, 0);
                if case == 5 {
                    header.identity.partition = Partition::Main;
                } else {
                    header.digest = [0; 32];
                }
                bytes[start..start + CHECKPOINT_BYTES]
                    .copy_from_slice(&header.encode(&JOURNAL_KEY).unwrap());
            }
            _ => unreachable!(),
        }
        drop(bytes);
        let before = flash.inner.bytes.borrow().clone();
        let scan = bank.scan(&JOURNAL_KEY, &mut directory).unwrap();
        assert_eq!(scan.status, JournalStatus::Dirty, "case {case}");
        assert_eq!(
            bank.read_value(scan, &JOURNAL_KEY, CTR, &mut [0; 5]),
            Err(Error::MemoryFatal)
        );
        assert_eq!(*flash.inner.bytes.borrow(), before);
    }
}

#[test]
fn counter_scan_rejects_malformed_foreign_and_skipped_generation_append_descriptors() {
    for case in 0..3 {
        let flash = FaultFlash::new();
        let mut bank = counter_bank(&flash);
        let mut directory = Directory::<MAX_COUNTER_ENTRIES>::new();
        bank.write_snapshot(
            counter_checkpoint(&directory, 0),
            &JOURNAL_KEY,
            &directory,
            |_, _| unreachable!(),
        )
        .unwrap();
        let scan = bank.scan(&JOURNAL_KEY, &mut directory).unwrap();
        let entry = Entry::live(COUNTER_ID, &JOURNAL_KEY, CTR, 1, b"value").unwrap();
        bank.append(scan, &JOURNAL_KEY, entry, b"value").unwrap();
        let at = usize::try_from(COUNTER.start + scan.next).unwrap();
        let changed = match case {
            1 => Entry::live(COUNTER_ID, &JOURNAL_KEY, CRED, 1, b"value")
                .unwrap()
                .encode()
                .unwrap(),
            2 => Entry::live(COUNTER_ID, &JOURNAL_KEY, CTR, 2, b"value")
                .unwrap()
                .encode()
                .unwrap(),
            _ => {
                let mut bytes = entry.encode().unwrap();
                bytes[28] = 0;
                bytes
            }
        };
        flash.inner.bytes.borrow_mut()[at..at + ENTRY_BYTES].copy_from_slice(&changed);
        let scanned = bank.scan(&JOURNAL_KEY, &mut directory).unwrap();
        assert_eq!(scanned.status, JournalStatus::Dirty);
        assert_eq!(scanned.lower_bound, Some(0));
        assert_eq!(scanned.next, scan.next);
    }
}

#[test]
fn counter_direct_scan_arguments_refuse_before_mutating_a_healthy_bank() {
    let flash = FaultFlash::new();
    let mut bank = counter_bank(&flash);
    let mut directory = Directory::<MAX_COUNTER_ENTRIES>::new();
    bank.write_snapshot(
        counter_checkpoint(&directory, 0),
        &JOURNAL_KEY,
        &directory,
        |_, _| unreachable!(),
    )
    .unwrap();
    let scan = bank.scan(&JOURNAL_KEY, &mut directory).unwrap();
    let entry = Entry::live(COUNTER_ID, &JOURNAL_KEY, CTR, 1, b"value").unwrap();
    let before = flash.inner.bytes.borrow().clone();
    for status in [JournalStatus::Empty, JournalStatus::Dirty] {
        let wrong = crate::authenticated::CounterScan { status, ..scan };
        assert_eq!(
            bank.append(wrong, &JOURNAL_KEY, entry, b"value"),
            Err(Error::MemoryFatal)
        );
        assert_eq!(
            bank.read_value(wrong, &JOURNAL_KEY, CTR, &mut [0; 5]),
            Err(Error::MemoryFatal)
        );
    }
    let old = Entry::live(COUNTER_ID, &JOURNAL_KEY, CTR, 0, b"value").unwrap();
    assert_eq!(
        bank.append(scan, &JOURNAL_KEY, old, b"value"),
        Err(Error::MemoryFatal)
    );
    let full = crate::authenticated::CounterScan {
        next: bank.capacity(),
        ..scan
    };
    assert_eq!(
        bank.append(full, &JOURNAL_KEY, entry, b"value"),
        Err(Error::NoMemory)
    );
    assert_eq!(
        bank.read_value(scan, &JOURNAL_KEY, CRED, &mut [0; 5]),
        Err(Error::MemoryFatal)
    );
    let mut wrong = scan;
    wrong.locations[0] = Some(crate::authenticated::CounterLocation {
        entry: Entry::live(COUNTER_ID, &JOURNAL_KEY, CRED, 1, b"value").unwrap(),
        value_offset: 0,
    });
    assert_eq!(
        bank.read_value(wrong, &JOURNAL_KEY, CTR, &mut [0; 5]),
        Err(Error::MemoryFatal)
    );
    assert_eq!(*flash.inner.bytes.borrow(), before);
}
