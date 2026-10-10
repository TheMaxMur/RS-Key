// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::authenticated::Counters;

fn counters(flash: &FaultFlash) -> Counters<FaultFlash> {
    let split = COUNTER.start + 5 * SECTOR as u32;
    let end = split + 5 * SECTOR as u32;
    flash.inner.bytes.borrow_mut().resize(end as usize, 0xFF);
    let zero = CounterBank::new(RawBank::new(flash.clone(), COUNTER.start..split).unwrap());
    let one = CounterBank::new(RawBank::new(flash.clone(), split..end).unwrap());
    Counters::new([zero, one], COUNTER_ID, RootArm::PreOtp).unwrap()
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
