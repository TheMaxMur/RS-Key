// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::authenticated::{CHECKPOINT_BYTES, Counters, ENTRY_BYTES};

#[path = "counter_compaction_tests.rs"]
mod compaction;

fn counters(flash: &FaultFlash) -> Counters<FaultFlash> {
    let split = COUNTER.start + 5 * SECTOR as u32;
    let end = split + 5 * SECTOR as u32;
    flash.inner.bytes.borrow_mut().resize(end as usize, 0xFF);
    let zero = CounterBank::new(RawBank::new(flash.clone(), COUNTER.start..split).unwrap());
    let one = CounterBank::new(RawBank::new(flash.clone(), split..end).unwrap());
    Counters::new([zero, one], COUNTER_ID, RootArm::PreOtp).unwrap()
}

#[test]
fn counter_rekey_refuses_a_dirty_peer_before_retiring_the_old_root() {
    const VALUE_BYTES: usize = 16;
    let mut peer_corruption = None;
    for corrupt_peer in [false, true] {
        let flash = FaultFlash::new();
        let split = COUNTER.start + u32::try_from(SECTOR).unwrap();
        let end = split + u32::try_from(SECTOR).unwrap();
        flash.inner.bytes.borrow_mut().resize(end as usize, 0xFF);
        let banks = [
            CounterBank::new(RawBank::new(flash.clone(), COUNTER.start..split).unwrap()),
            CounterBank::new(RawBank::new(flash.clone(), split..end).unwrap()),
        ];
        let mut pair = Counters::new(banks, COUNTER_ID, RootArm::PreOtp).unwrap();
        let value = [0x48; SECTOR - CHECKPOINT_BYTES - 2 * ENTRY_BYTES - VALUE_BYTES];
        let mut directory = Directory::new();
        directory
            .apply(Entry::live(COUNTER_ID, &JOURNAL_KEY, CTR, 0, &value).unwrap())
            .unwrap();
        pair.initialize(&JOURNAL_KEY, &directory, 0, |entry, output| {
            assert_eq!(entry.fid(), CTR);
            output.copy_from_slice(&value);
            Ok(())
        })
        .unwrap();
        pair.write(&JOURNAL_KEY, CTR, Some(&[0x69; VALUE_BYTES]))
            .unwrap();
        for range in [COUNTER.start..split, split..end] {
            let mut bank = CounterBank::new(RawBank::new(flash.clone(), range).unwrap());
            let scan = bank.scan(&JOURNAL_KEY, &mut Directory::new()).unwrap();
            assert_eq!(scan.status, JournalStatus::Complete);
            assert_eq!(scan.sequence, Some(1));
            assert_eq!(scan.next, bank.capacity());
        }
        let old_authority = flash.inner.snapshot(COUNTER.start..split);
        flash.arm(&[]);
        if corrupt_peer {
            let (reads, image) = peer_corruption.take().unwrap();
            flash.replace_image_before_read(reads, image);
        }
        let new_key = [0x68; 32];
        let result = pair.rekey(&JOURNAL_KEY, &new_key, RootArm::Otp);
        if corrupt_peer {
            assert_eq!(result, Err(Error::MemoryFatal));
            assert!(
                flash.inner.snapshot(COUNTER.start..split) == old_authority,
                "a dirty peer must preserve the old root authority"
            );
            assert!(
                flash
                    .events()
                    .iter()
                    .all(|&(io, address, _)| { io == Io::Read || address >= split })
            );
        } else {
            result.unwrap();
            let events = flash.events();
            let commit = events
                .iter()
                .position(|&(io, address, _)| io == Io::Program && address == split)
                .unwrap();
            let scan = events
                .iter()
                .enumerate()
                .skip(commit + 1)
                .find(|&(_, &(io, address, len))| {
                    io == Io::Read && address == split && len == CHECKPOINT_BYTES
                })
                .unwrap()
                .0;
            let reads = events[..scan]
                .iter()
                .filter(|event| event.0 == Io::Read)
                .count();
            let mut image = flash.image();
            image[COUNTER.start as usize..split as usize].copy_from_slice(&old_authority);
            image[end as usize - WORD..end as usize].fill(0x69);
            // Readback already checks erases; this fault lands at the later scan
            // that must gate retirement of the old authority.
            peer_corruption = Some((reads, image));
        }
        let mut peer = CounterBank::new(RawBank::new(flash.clone(), split..end).unwrap());
        let scan = peer.scan(&new_key, &mut Directory::new()).unwrap();
        assert_eq!(scan.sequence, Some(2));
        assert_eq!(scan.lower_bound, Some(2));
        assert_eq!(
            scan.status,
            if corrupt_peer {
                JournalStatus::Dirty
            } else {
                JournalStatus::Complete
            }
        );
    }
}

#[test]
fn counter_replicas_keep_the_latest_value_when_one_acknowledged_copy_is_damaged() {
    let flash = FaultFlash::new();
    let mut pair = counters(&flash);
    pair.initialize(&JOURNAL_KEY, &Directory::new(), 0, |_, _| unreachable!())
        .unwrap();
    pair.write(&JOURNAL_KEY, CTR, Some(b"old counter")).unwrap();
    pair.write(&JOURNAL_KEY, CTR, Some(b"new counter")).unwrap();
    let before_main = flash.inner.snapshot(MAIN);
    let offset = flash
        .inner
        .bytes
        .borrow()
        .windows(b"new counter".len())
        .position(|bytes| bytes == b"new counter")
        .unwrap();
    flash.inner.bytes.borrow_mut()[offset] ^= 0x80;
    let mut reboot = counters(&flash);
    let mut out = [0; 32];
    assert_eq!(
        reboot.read(&JOURNAL_KEY, CTR, &mut out),
        Ok(Some(b"new counter".len()))
    );
    assert_eq!(&out[..b"new counter".len()], b"new counter");
    assert_eq!(flash.inner.snapshot(MAIN), before_main);
    reboot
        .write(&JOURNAL_KEY, CTR, Some(b"next counter"))
        .unwrap();
    assert_eq!(
        reboot.read(&JOURNAL_KEY, CTR, &mut out),
        Ok(Some(b"next counter".len()))
    );
    assert_eq!(&out[..b"next counter".len()], b"next counter");
}

#[test]
fn a_counter_write_uses_the_zero_peer_after_repairing_from_the_one_copy() {
    let flash = FaultFlash::new();
    let mut pair = counters(&flash);
    pair.initialize(&JOURNAL_KEY, &Directory::new(), 0, |_, _| unreachable!())
        .unwrap();
    pair.write(&JOURNAL_KEY, CTR, Some(b"old counter")).unwrap();
    pair.write(&JOURNAL_KEY, CTR, Some(b"new counter")).unwrap();
    let split = COUNTER.start + 5 * SECTOR as u32;
    let end = split + 5 * SECTOR as u32;
    let offset = flash
        .inner
        .bytes
        .borrow()
        .windows(b"new counter".len())
        .position(|bytes| bytes == b"new counter")
        .unwrap();
    assert!(offset < split as usize);
    flash.inner.bytes.borrow_mut()[offset] ^= 0x40;
    for (range, status) in [
        (COUNTER.start..split, JournalStatus::Dirty),
        (split..end, JournalStatus::Complete),
    ] {
        assert_eq!(
            CounterBank::new(RawBank::new(flash.clone(), range).unwrap())
                .scan(&JOURNAL_KEY, &mut Directory::new())
                .unwrap()
                .status,
            status
        );
    }
    let before_main = flash.inner.snapshot(MAIN);
    let mut reboot = counters(&flash);
    reboot
        .write(&JOURNAL_KEY, CTR, Some(b"next counter"))
        .unwrap();
    let mut out = [0; 32];
    assert_eq!(
        reboot.read(&JOURNAL_KEY, CTR, &mut out),
        Ok(Some(b"next counter".len()))
    );
    assert_eq!(&out[..b"next counter".len()], b"next counter");
    for range in [COUNTER.start..split, split..end] {
        let scan = CounterBank::new(RawBank::new(flash.clone(), range).unwrap())
            .scan(&JOURNAL_KEY, &mut Directory::new())
            .unwrap();
        assert_eq!(scan.status, JournalStatus::Complete);
        assert_eq!(scan.sequence, Some(3));
    }
    assert_eq!(flash.inner.snapshot(MAIN), before_main);
}

#[test]
fn counter_replica_equal_sequence_disagreement_is_an_error() {
    let flash = FaultFlash::new();
    let split = COUNTER.start + 5 * SECTOR as u32;
    let end = split + 5 * SECTOR as u32;
    flash.inner.bytes.borrow_mut().resize(end as usize, 0xFF);
    for (range, value) in [
        (COUNTER.start..split, b"first".as_slice()),
        (split..end, b"other".as_slice()),
    ] {
        let mut bank = CounterBank::new(RawBank::new(flash.clone(), range).unwrap());
        let mut directory = Directory::new();
        directory
            .apply(Entry::live(COUNTER_ID, &JOURNAL_KEY, CTR, 1, value).unwrap())
            .unwrap();
        bank.write_snapshot(
            counter_checkpoint(&directory, 1),
            &JOURNAL_KEY,
            &directory,
            |_, out| {
                out.copy_from_slice(value);
                Ok(())
            },
        )
        .unwrap();
    }
    let before = flash.inner.bytes.borrow().clone();
    let mut pair = counters(&flash);
    assert_eq!(
        pair.read(&JOURNAL_KEY, CTR, &mut [0; 32]),
        Err(Error::MemoryFatal)
    );
    assert_eq!(*flash.inner.bytes.borrow(), before);
}

#[test]
fn counter_replicas_do_not_repair_from_a_peer_below_authenticated_dirty_progress() {
    let flash = FaultFlash::new();
    let mut pair = counters(&flash);
    pair.initialize(&JOURNAL_KEY, &Directory::new(), 0, |_, _| unreachable!())
        .unwrap();
    let split = COUNTER.start + 5 * SECTOR as u32;
    let old_peer = flash.inner.snapshot(split..split + 5 * SECTOR as u32);
    pair.write(&JOURNAL_KEY, CTR, Some(b"acknowledged counter"))
        .unwrap();
    let mut raw = RawBank::new(flash.clone(), COUNTER.start..split).unwrap();
    // A complete counter delta occupies Entry32 + padded32 at offset128.
    raw.program(192 + 32, b"interrupted next body").unwrap();
    flash.inner.bytes.borrow_mut()[split as usize..split as usize + old_peer.len()]
        .copy_from_slice(&old_peer);
    let before = flash.inner.bytes.borrow().clone();
    let mut reboot = counters(&flash);
    assert_eq!(
        reboot.read(&JOURNAL_KEY, CTR, &mut [0; 64]),
        Err(Error::MemoryFatal)
    );
    assert_eq!(*flash.inner.bytes.borrow(), before);
}
