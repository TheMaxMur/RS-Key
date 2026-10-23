// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::authenticated::{CounterScan, ENTRY_BYTES};

fn history() -> (FaultFlash, CounterBank<FaultFlash>, Vec<CounterScan>) {
    let flash = FaultFlash::new();
    let mut bank = counter_bank(&flash);
    let mut directory = Directory::<MAX_COUNTER_ENTRIES>::new();
    directory
        .apply(Entry::live(COUNTER_ID, &JOURNAL_KEY, CTR, 0, b"snapshot").unwrap())
        .unwrap();
    bank.write_snapshot(
        counter_checkpoint(&directory, 0),
        &JOURNAL_KEY,
        &directory,
        |_, out| {
            out.copy_from_slice(b"snapshot");
            Ok(())
        },
    )
    .unwrap();
    let mut scans = vec![bank.scan(&JOURNAL_KEY, &mut directory).unwrap()];
    for (generation, value) in [
        (1, Some(b"obsolete".as_slice())),
        (2, None),
        (3, Some(b"current".as_slice())),
    ] {
        let entry = match value {
            Some(value) => Entry::live(COUNTER_ID, &JOURNAL_KEY, CTR, generation, value),
            None => Entry::deleted(COUNTER_ID, &JOURNAL_KEY, CTR, generation),
        }
        .unwrap();
        bank.append(
            *scans.last().unwrap(),
            &JOURNAL_KEY,
            entry,
            value.unwrap_or(&[]),
        )
        .unwrap();
        scans.push(bank.scan(&JOURNAL_KEY, &mut directory).unwrap());
    }
    (flash, bank, scans)
}

#[test]
fn counter_scan_mac_preserves_snapshot_history_delete_and_short_reads() {
    let (flash, mut bank, scans) = history();
    let before = flash.image();
    flash.arm(&[]);
    let mut directory = Directory::<MAX_COUNTER_ENTRIES>::new();
    let scan = bank.scan(&JOURNAL_KEY, &mut directory).unwrap();
    assert_eq!(scan, scans[3]);
    assert_eq!(scan.status, JournalStatus::Complete);
    assert_eq!(scan.sequence, Some(3));
    assert_eq!(scan.lower_bound, Some(3));
    assert_eq!(
        directory.entries(),
        &[Entry::live(COUNTER_ID, &JOURNAL_KEY, CTR, 3, b"current").unwrap()]
    );
    assert!(scans[2].locations.iter().all(Option::is_none));
    for length in [0, 1, 7, 16] {
        let mut out = [0xCC; 16];
        assert_eq!(
            bank.read_value(scan, &JOURNAL_KEY, CTR, &mut out[..length]),
            Ok(Some(7))
        );
        let copied = length.min(7);
        assert_eq!(&out[..copied], &b"current"[..copied]);
        assert!(out[copied..].iter().all(|&byte| byte == 0xCC));
    }
    assert_eq!(flash.image(), before);
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
}

#[test]
fn counter_scan_mac_never_skips_superseded_value_or_tombstone_authentication() {
    let (flash, mut bank, scans) = history();
    let original = flash.image();
    for (row, previous) in scans.iter().enumerate().take(2) {
        let header = usize::try_from(COUNTER.start + previous.next).unwrap();
        let mut offsets: Vec<usize> = (12..28).collect();
        if row == 0 {
            offsets.extend([ENTRY_BYTES + 7, ENTRY_BYTES + 8, ENTRY_BYTES + 15]);
        }
        for offset in offsets {
            let mut damaged = original.clone();
            damaged[header + offset] ^= 1;
            *flash.inner.bytes.borrow_mut() = damaged.clone();
            flash.arm(&[]);
            let scan = bank.scan(&JOURNAL_KEY, &mut Directory::new()).unwrap();
            assert_eq!(
                scan.status,
                JournalStatus::Dirty,
                "row {row}, offset {offset}"
            );
            assert_eq!(scan.sequence, previous.sequence);
            assert_eq!(scan.lower_bound, previous.lower_bound);
            assert_eq!(scan.next, previous.next);
            let mut out = [0xCC; 7];
            assert_eq!(
                bank.read_value(scan, &JOURNAL_KEY, CTR, &mut out),
                Err(Error::MemoryFatal)
            );
            assert_eq!(out, [0xCC; 7]);
            assert_eq!(flash.image(), damaged);
            assert!(flash.events().iter().all(|event| event.0 == Io::Read));
        }
    }
    *flash.inner.bytes.borrow_mut() = original;
    assert_eq!(
        bank.scan(&JOURNAL_KEY, &mut Directory::new()).unwrap(),
        scans[3]
    );
}

#[test]
fn counter_scan_mac_does_not_cross_root_or_epoch_between_scans() {
    let (flash, mut bank, _) = history();
    let key = [0x91; 32];
    let identity = Identity {
        epoch: [0x26; 16],
        ..COUNTER_ID
    };
    let mut directory = Directory::<MAX_COUNTER_ENTRIES>::new();
    directory
        .apply(Entry::live(identity, &key, CTR, 0, b"snapshot").unwrap())
        .unwrap();
    let checkpoint = Checkpoint {
        identity,
        digest: directory.digest(identity, &key, 0).unwrap(),
        ..counter_checkpoint(&directory, 0)
    };
    bank.write_snapshot(checkpoint, &key, &directory, |_, out| {
        out.copy_from_slice(b"snapshot");
        Ok(())
    })
    .unwrap();
    let initial = bank.scan(&key, &mut directory).unwrap();
    assert_eq!(initial.status, JournalStatus::Complete);
    let entry = Entry::live(identity, &key, CTR, 1, b"new root").unwrap();
    bank.append(initial, &key, entry, b"new root").unwrap();
    let current = bank.scan(&key, &mut directory).unwrap();
    assert_eq!(current.status, JournalStatus::Complete);
    assert_eq!(current.sequence, Some(1));
    let at = usize::try_from(COUNTER.start + initial.next).unwrap();
    for foreign in [
        Entry::live(identity, &JOURNAL_KEY, CTR, 1, b"new root").unwrap(),
        Entry::live(COUNTER_ID, &key, CTR, 1, b"new root").unwrap(),
    ] {
        flash.inner.bytes.borrow_mut()[at..at + ENTRY_BYTES]
            .copy_from_slice(&foreign.encode().unwrap());
        let rejected = bank.scan(&key, &mut directory).unwrap();
        assert_eq!(rejected.status, JournalStatus::Dirty);
        assert_eq!(rejected.sequence, Some(0));
        assert_eq!(rejected.lower_bound, Some(0));
        assert_eq!(rejected.next, initial.next);
    }
    flash.inner.bytes.borrow_mut()[at..at + ENTRY_BYTES].copy_from_slice(&entry.encode().unwrap());
    assert_eq!(bank.scan(&key, &mut directory).unwrap(), current);
    let mut out = [0xCC; 8];
    assert_eq!(bank.read_value(current, &key, CTR, &mut out), Ok(Some(8)));
    assert_eq!(&out, b"new root");
}

#[test]
fn counter_scan_mac_rejects_hidden_final_tail_after_valid_history() {
    let (flash, mut bank, scans) = history();
    let hidden = usize::try_from(COUNTER.start + bank.capacity() - 1).unwrap();
    flash.inner.bytes.borrow_mut()[hidden] = 0;
    let before = flash.image();
    flash.arm(&[]);
    let dirty = bank.scan(&JOURNAL_KEY, &mut Directory::new()).unwrap();
    assert_eq!(dirty.status, JournalStatus::Dirty);
    assert_eq!(dirty.sequence, scans[3].sequence);
    assert_eq!(dirty.lower_bound, scans[3].lower_bound);
    assert_eq!(dirty.next, scans[3].next);
    assert_eq!(flash.image(), before);
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    flash.inner.bytes.borrow_mut()[hidden] = 0xFF;
    assert_eq!(
        bank.scan(&JOURNAL_KEY, &mut Directory::new()).unwrap(),
        scans[3]
    );
}
