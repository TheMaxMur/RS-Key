// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::authenticated::CHECKPOINT_BYTES;
use crate::tests::{FaultFlash, Io};

fn provision(flash: &FaultFlash) -> Main<FaultFlash, UncachedMap> {
    let mut main = main_on(flash.clone());
    main.initialize(&KEY, 0, &Directory::new()).unwrap();
    for value in 0..8u8 {
        main.write(&KEY, 0xB000, Some(&[value])).unwrap();
    }
    main
}

#[test]
fn main_append_closes_with_complete_bank_reads_without_replaying_old_deltas() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut main = provision(&flash);
    flash.arm(&[]);
    main.write(&KEY, 0xB000, Some(b"next")).unwrap();
    let events = flash.events();
    let last = events
        .iter()
        .rposition(|event| event.0 == Io::Program)
        .unwrap();
    let closing = events.get(last + 1..).unwrap();
    let layout = super::super::super::Layout::new(
        32768..32768 + super::super::super::storage::AUTHORITY_BYTES,
    )
    .unwrap();
    for range in layout.main {
        let first_record = range.start + u32::try_from(CHECKPOINT_BYTES).unwrap();
        for address in range.clone() {
            assert!(closing.iter().any(|&(io, at, len)| io == Io::Read
                && at <= address
                && address < at + u32::try_from(len).unwrap()));
        }
        assert!(
            !closing
                .iter()
                .any(|event| event.1 == first_record && event.2 == DELTA_BYTES)
        );
    }
}

#[test]
fn main_append_refuses_changed_history_publications_and_tail_during_closure() {
    let trace = crate::tests::fault_flash_for_authenticated_tests();
    let mut healthy = provision(&trace);
    let before = trace.image();
    let old_end = healthy.read_cache.unwrap().ends[0];
    trace.arm(&[]);
    healthy.write(&KEY, 0xB000, Some(b"next")).unwrap();
    let after = trace.image();
    let events = trace.events();
    let layout = super::super::super::Layout::new(
        32768..32768 + super::super::super::storage::AUTHORITY_BYTES,
    )
    .unwrap();
    let last = events
        .iter()
        .rposition(|event| event.0 == Io::Program)
        .unwrap();
    let first = events
        .iter()
        .enumerate()
        .skip(last + 1)
        .find(|(_, event)| event.0 == Io::Read && event.1 == layout.main[0].start)
        .unwrap()
        .0;
    let reads = events
        .get(..first)
        .unwrap()
        .iter()
        .filter(|event| event.0 == Io::Read)
        .count();
    let mut images = vec![before];
    for range in layout.main {
        for offset in [
            0,
            95,
            96,
            old_end,
            old_end + u32::try_from(DELTA_BYTES).unwrap(),
            range.end - range.start - 1,
        ] {
            let mut damaged = after.clone();
            *damaged
                .get_mut(usize::try_from(range.start + offset).unwrap())
                .unwrap() ^= 1;
            images.push(damaged);
        }
    }
    for damaged in images {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let mut main = provision(&flash);
        flash.arm(&[]);
        flash.replace_image_before_read(reads, damaged.clone());
        assert_eq!(
            main.write(&KEY, 0xB000, Some(b"next")),
            Err(Error::MemoryFatal)
        );
        assert!(main.read_cache.is_none());
        assert_eq!(flash.image(), damaged);
    }
}

#[test]
fn main_append_reports_every_closing_read_failure() {
    use crate::tests::{Effect, Rule};
    let trace = crate::tests::fault_flash_for_authenticated_tests();
    let mut healthy = provision(&trace);
    trace.arm(&[]);
    healthy.write(&KEY, 0xB000, Some(b"next")).unwrap();
    let events = trace.events();
    let last = events
        .iter()
        .rposition(|event| event.0 == Io::Program)
        .unwrap();
    let before = events
        .get(..last)
        .unwrap()
        .iter()
        .filter(|event| event.0 == Io::Read)
        .count();
    let total = events.iter().filter(|event| event.0 == Io::Read).count();
    for skip in before..total {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let mut main = provision(&flash);
        flash.arm(&[Rule {
            io: Io::Read,
            skip,
            effect: Effect::Refuse,
            latched: false,
        }]);
        assert_eq!(
            main.write(&KEY, 0xB000, Some(b"next")),
            Err(Error::MemoryFatal),
            "read {skip}"
        );
        assert!(main.read_cache.is_none());
        assert_eq!(flash.hits(), [1]);
    }
}
