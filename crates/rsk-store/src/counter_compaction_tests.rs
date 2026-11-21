// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn a_counter_compaction_refuses_a_dirty_peer_before_retiring_old_authority() {
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
        let value = [0x48; SECTOR - CHECKPOINT_BYTES - ENTRY_BYTES];
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
        for range in [COUNTER.start..split, split..end] {
            let mut bank = CounterBank::new(RawBank::new(flash.clone(), range).unwrap());
            let scan = bank.scan(&JOURNAL_KEY, &mut Directory::new()).unwrap();
            assert_eq!(scan.status, JournalStatus::Complete);
            assert_eq!(scan.sequence, Some(0));
            assert_eq!(scan.next, bank.capacity());
        }
        let old_authority = flash.inner.snapshot(COUNTER.start..split);
        flash.arm(&[]);
        if corrupt_peer {
            let (reads, image) = peer_corruption.take().unwrap();
            flash.replace_image_before_read(reads, image);
        }
        let result = pair.write(&JOURNAL_KEY, CTR, Some(&[0x69; VALUE_BYTES]));
        if corrupt_peer {
            assert_eq!(result, Err(Error::MemoryFatal));
            assert!(
                flash.inner.snapshot(COUNTER.start..split) == old_authority,
                "a dirty peer must preserve the old counter authority"
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
        let scan = peer.scan(&JOURNAL_KEY, &mut Directory::new()).unwrap();
        assert_eq!(scan.sequence, Some(1));
        assert_eq!(scan.lower_bound, Some(1));
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
