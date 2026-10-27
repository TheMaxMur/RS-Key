// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::authenticated::CHECKPOINT_BYTES;
use crate::tests::Io;

const FID: u16 = rsk_fs::counter::EF_SIG_COUNT.get();

fn provision(flash: &FaultFlash) -> Counters<FaultFlash> {
    let mut pair = counters(flash);
    pair.initialize(&KEY, &Directory::new(), 0, |_, _| unreachable!())
        .unwrap();
    for value in 0u8..12 {
        pair.write(&KEY, FID, Some(&[value])).unwrap();
    }
    pair
}

#[test]
fn a_counter_mount_reads_both_entire_banks_and_reduces_replay_reads() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut pair = provision(&flash);
    let layout = Layout::new(32768..32768 + super::super::super::storage::AUTHORITY_BYTES).unwrap();
    let mut out = [0; 1];
    flash.arm(&[]);
    assert_eq!(pair.read(&KEY, FID, &mut out), Ok(Some(1)));
    assert_eq!(out, [11]);
    let warm = flash.events();
    for range in layout.counter {
        for address in range {
            assert!(warm.iter().any(|&(io, at, len)| io == Io::Read
                && at <= address
                && address < at + u32::try_from(len).unwrap()));
        }
    }
    assert!(warm.iter().all(|event| event.0 == Io::Read));
    pair.mount = None;
    flash.arm(&[]);
    assert_eq!(pair.read(&KEY, FID, &mut out), Ok(Some(1)));
    assert!(warm.len() < flash.events().len());
}

#[test]
fn a_counter_mount_observes_valid_publication_beyond_its_previous_end() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut pair = provision(&flash);
    let mut writer = counters(&flash);
    writer.write(&KEY, FID, Some(b"new")).unwrap();
    let mut out = [0; 3];
    assert_eq!(pair.read(&KEY, FID, &mut out), Ok(Some(3)));
    assert_eq!(&out, b"new");
    writer.write(&KEY, FID, None).unwrap();
    assert_eq!(pair.read(&KEY, FID, &mut out), Ok(None));
    assert_eq!(&out, b"new");
}

#[test]
fn changed_counter_headers_entries_payloads_and_erased_tails_never_reuse_the_mount() {
    for offset in [0, 95, 96, 128, 20479] {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let mut pair = provision(&flash);
        let layout =
            Layout::new(32768..32768 + super::super::super::storage::AUTHORITY_BYTES).unwrap();
        let mut changed = flash.image();
        for range in layout.counter {
            changed[usize::try_from(range.start + offset).unwrap()] ^= 1;
        }
        flash.arm(&[]);
        flash.replace_image_before_read(0, changed.clone());
        let mut out = [0xa5; 1];
        assert_eq!(pair.read(&KEY, FID, &mut out), Err(Error::MemoryFatal));
        assert_eq!(out, [0xa5]);
        assert!(pair.mount.is_none());
        assert_eq!(flash.image(), changed);
        assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    }
}

#[test]
fn a_counter_mount_remains_bound_to_the_root_key_and_configuration() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut pair = provision(&flash);
    assert_eq!(
        pair.read(&[0x36; 32], FID, &mut []),
        Err(Error::MemoryFatal)
    );
    assert!(pair.mount.is_none());
    assert_eq!(pair.read(&KEY, FID, &mut []), Ok(Some(1)));
    pair.configure(EPOCH, RootArm::Otp);
    assert!(pair.mount.is_none());
    assert_eq!(pair.read(&KEY, FID, &mut []), Err(Error::MemoryFatal));
}

#[test]
fn counter_mount_writes_preserve_the_exact_publication_and_final_flash_image() {
    let measure = |reuse: bool| {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let mut pair = provision(&flash);
        if !reuse {
            pair.mount = None;
        }
        flash.arm(&[]);
        pair.write(&KEY, FID, Some(b"next")).unwrap();
        (flash.image(), flash.events())
    };
    let (warm_image, warm) = measure(true);
    let (cold_image, cold) = measure(false);
    assert_eq!(warm_image, cold_image);
    assert_eq!(
        warm.iter().filter(|e| e.0 != Io::Read).collect::<Vec<_>>(),
        cold.iter().filter(|e| e.0 != Io::Read).collect::<Vec<_>>()
    );
    assert!(warm.len() < cold.len());
}

#[test]
fn counter_append_closes_with_complete_bank_reads_without_replaying_old_records() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut pair = provision(&flash);
    flash.arm(&[]);
    pair.write(&KEY, FID, Some(b"next")).unwrap();
    let events = flash.events();
    let last_program = events
        .iter()
        .rposition(|event| event.0 == Io::Program)
        .unwrap();
    let closing = &events[last_program + 1..];
    let layout = Layout::new(32768..32768 + super::super::super::storage::AUTHORITY_BYTES).unwrap();
    for range in layout.counter {
        let first_record = range.start + u32::try_from(CHECKPOINT_BYTES).unwrap();
        for address in range.clone() {
            assert!(closing.iter().any(|&(io, at, len)| io == Io::Read
                && at <= address
                && address < at + u32::try_from(len).unwrap()));
        }
        assert!(
            !closing
                .iter()
                .any(|event| event.1 == first_record && event.2 == ENTRY_BYTES)
        );
    }
}

#[test]
fn counter_append_refuses_changed_history_new_records_and_tail_during_closure() {
    let trace = crate::tests::fault_flash_for_authenticated_tests();
    let mut healthy = provision(&trace);
    let before = trace.image();
    let old_end = healthy.mount.unwrap()[0].next;
    trace.arm(&[]);
    healthy.write(&KEY, FID, Some(b"next")).unwrap();
    let after = trace.image();
    let events = trace.events();
    let layout = Layout::new(32768..32768 + super::super::super::storage::AUTHORITY_BYTES).unwrap();
    let last = events
        .iter()
        .rposition(|event| event.0 == Io::Program)
        .unwrap();
    let first = events
        .iter()
        .enumerate()
        .skip(last + 1)
        .find(|(_, event)| event.0 == Io::Read && event.1 == layout.counter[0].start)
        .unwrap()
        .0;
    let reads = events[..first]
        .iter()
        .filter(|event| event.0 == Io::Read)
        .count();
    let mut images = vec![before];
    for range in layout.counter {
        for offset in [
            0,
            95,
            96,
            128,
            old_end,
            old_end + u32::try_from(ENTRY_BYTES).unwrap(),
            range.end - range.start - 1,
        ] {
            let mut damaged = after.clone();
            damaged[usize::try_from(range.start + offset).unwrap()] ^= 1;
            images.push(damaged);
        }
    }
    for damaged in images {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let mut pair = provision(&flash);
        flash.arm(&[]);
        flash.replace_image_before_read(reads, damaged.clone());
        assert_eq!(
            pair.write(&KEY, FID, Some(b"next")),
            Err(Error::MemoryFatal)
        );
        assert!(pair.mount.is_none());
        assert_eq!(flash.image(), damaged);
    }
}

#[test]
fn counter_append_reports_every_closing_read_failure() {
    use crate::tests::{Effect, Rule};
    let trace = crate::tests::fault_flash_for_authenticated_tests();
    let mut healthy = provision(&trace);
    trace.arm(&[]);
    healthy.write(&KEY, FID, Some(b"next")).unwrap();
    let events = trace.events();
    let last = events
        .iter()
        .rposition(|event| event.0 == Io::Program)
        .unwrap();
    let before = events[..last]
        .iter()
        .filter(|event| event.0 == Io::Read)
        .count();
    let total = events.iter().filter(|event| event.0 == Io::Read).count();
    for skip in before..total {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let mut pair = provision(&flash);
        flash.arm(&[Rule {
            io: Io::Read,
            skip,
            effect: Effect::Refuse,
            latched: false,
        }]);
        assert_eq!(
            pair.write(&KEY, FID, Some(b"next")),
            Err(Error::MemoryFatal),
            "read {skip}"
        );
        assert!(pair.mount.is_none());
        assert_eq!(flash.hits(), [1]);
    }
}

#[test]
fn accelerated_counter_mount_reads_refuse_every_io_error_without_falling_back() {
    use crate::tests::{Effect, Rule};
    fn digest(
        flash: &mut FaultFlash,
        range: core::ops::Range<u32>,
        end: u32,
        prefix: &[u8],
    ) -> Result<Option<[u8; 32]>> {
        RawBank::new(flash.clone(), range)?.digest_if_erased_tail(end, prefix)
    }
    let setup = || {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let mut pair = provision(&flash);
        for bank in &mut pair.banks {
            bank.set_digest(digest);
        }
        flash.arm(&[]);
        (flash, pair)
    };
    let (trace, mut healthy) = setup();
    assert_eq!(healthy.read(&KEY, FID, &mut [0; 1]), Ok(Some(1)));
    let reads = trace.events().iter().filter(|e| e.0 == Io::Read).count();
    for skip in 0..reads {
        let (flash, mut pair) = setup();
        flash.arm(&[Rule {
            io: Io::Read,
            skip,
            effect: Effect::Refuse,
            latched: false,
        }]);
        let mut out = [0xa5; 1];
        assert_eq!(
            pair.read(&KEY, FID, &mut out),
            Err(Error::MemoryFatal),
            "read {skip}"
        );
        assert_eq!(out, [0xa5]);
        assert!(pair.mount.is_none());
        assert_eq!(flash.hits(), [1]);
    }
}

#[test]
fn a_configured_counter_digest_refusal_cannot_silently_use_the_software_fallback() {
    fn refused(
        _: &mut FaultFlash,
        _: core::ops::Range<u32>,
        _: u32,
        _: &[u8],
    ) -> Result<Option<[u8; 32]>> {
        Err(Error::MemoryFatal)
    }
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut pair = provision(&flash);
    for bank in &mut pair.banks {
        bank.set_digest(refused);
    }
    let mut out = [0xa5];
    assert_eq!(pair.read(&KEY, FID, &mut out), Err(Error::MemoryFatal));
    assert_eq!(out, [0xa5]);
    assert!(pair.mount.is_none());
}
