// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::super::super::storage::AUTHORITY_BYTES;
use super::super::super::{
    Directory, Journal, JournalScan, JournalStatus, MAX_MAIN_ENTRIES, RootRead,
};
use super::*;
use crate::tests::{Effect, FaultFlash, Io, Rule};
use rsk_fs::Storage;
use sequential_storage::cache::Cache;
use std::sync::OnceLock;

type TestStore = Managed<FaultFlash, Cache<Uncached, Uncached, Uncached, u16>>;
const MAIN_END: u32 = 32768;
const SERIAL_HASH: [u8; 32] = [0x43; 32];
const OWNER: u16 = 0xB000;
const NEIGHBOR: u16 = OWNER + 1;
const DELETED: u16 = OWNER + 2;

fn source() -> KeySource {
    KeySource::new(SERIAL_HASH, |_| RootRead::Blank, false)
}

fn store(flash: &FaultFlash) -> TestStore {
    Managed::new_unmounted(
        flash.clone(),
        0..MAIN_END,
        MAIN_END..MAIN_END + AUTHORITY_BYTES,
        source(),
        Cache::<Uncached, Uncached, Uncached, u16>::new_uncached,
    )
}

fn scans(flash: &FaultFlash) -> [JournalScan; 2] {
    let layout = Layout::new(MAIN_END..MAIN_END + AUTHORITY_BYTES).unwrap();
    let key = source().key(RootArm::PreOtp).unwrap();
    layout.main.map(|range| {
        Journal::new(RawBank::new(flash.clone(), range).unwrap(), Partition::Main)
            .scan(key.expose(), &mut Directory::<{ MAX_MAIN_ENTRIES }>::new())
            .unwrap()
    })
}

fn directory(flash: &FaultFlash) -> Vec<super::super::super::Entry> {
    let layout = Layout::new(MAIN_END..MAIN_END + AUTHORITY_BYTES).unwrap();
    let key = source().key(RootArm::PreOtp).unwrap();
    let mut directory = Directory::<MAX_MAIN_ENTRIES>::new();
    Journal::new(
        RawBank::new(flash.clone(), layout.main[0].clone()).unwrap(),
        Partition::Main,
    )
    .scan(key.expose(), &mut directory)
    .unwrap();
    directory.entries().to_vec()
}

fn history() -> &'static Vec<u8> {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE.get_or_init(|| {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let mut mounted = store(&flash);
        mounted
            .administer(StorageAction::Initialize, [0x4B; 16])
            .unwrap();
        mounted.write(NEIGHBOR, b"neighbor").unwrap();
        mounted.write(DELETED, b"deleted").unwrap();
        mounted.remove(DELETED).unwrap();
        mounted
            .write(rsk_fs::counter::EF_COUNTER.get(), b"counter")
            .unwrap();
        for _ in 0..105 {
            mounted.write(OWNER, b"owner").unwrap();
        }
        let layout = Layout::new(MAIN_END..MAIN_END + AUTHORITY_BYTES).unwrap();
        let capacity = layout.main[0].end - layout.main[0].start;
        assert!(scans(&flash).iter().all(|scan| scan.next > capacity / 2));
        flash.image()
    })
}

fn from_history() -> FaultFlash {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    flash.replace_image_before_read(0, history().clone());
    flash
}

fn values(mounted: &mut TestStore) {
    for (fid, value) in [
        (OWNER, Some(b"owner".as_slice())),
        (NEIGHBOR, Some(b"neighbor".as_slice())),
        (DELETED, None),
        (
            rsk_fs::counter::EF_COUNTER.get(),
            Some(b"counter".as_slice()),
        ),
    ] {
        let mut out = [0xA5; 32];
        assert_eq!(mounted.read(fid, &mut out), value.map(<[u8]>::len));
        assert!(!mounted.last_error());
        if let Some(value) = value {
            assert_eq!(&out[..value.len()], value);
        } else {
            assert_eq!(out, [0xA5; 32]);
        }
    }
}

#[test]
fn mount_reclaims_history_without_changing_payloads_counters_or_generation() {
    let flash = from_history();
    let before = scans(&flash);
    let image = flash.image();
    let entries = directory(&flash);
    let mut mounted = store(&flash);
    flash.arm(&[]);
    mounted.mount().unwrap();
    let after = scans(&flash);
    assert_eq!(
        directory(&flash),
        entries,
        "entry generations and tags must be unchanged"
    );
    for (before, after) in before.iter().zip(&after) {
        assert!(
            after.next < before.next / 2,
            "mount must reclaim obsolete journal history"
        );
        assert_eq!(
            before.state.unwrap().sequence(),
            after.state.unwrap().sequence()
        );
        assert_eq!(after.status, JournalStatus::Complete);
    }
    assert_eq!(
        &flash.image()[..MAIN_END as usize],
        &image[..MAIN_END as usize]
    );
    let layout = Layout::new(MAIN_END..MAIN_END + AUTHORITY_BYTES).unwrap();
    for range in layout.counter {
        assert_eq!(
            &flash.image()[range.start as usize..range.end as usize],
            &image[range.start as usize..range.end as usize]
        );
    }
    values(&mut mounted);
    flash.arm(&[]);
    mounted.mount().unwrap();
    values(&mut mounted);
    assert!(
        flash.events().iter().all(|(io, _, _)| *io == Io::Read),
        "a short history must not be rewritten on each boot"
    );
}

#[test]
fn interrupted_mount_checkpoint_preserves_all_values_at_every_program_and_erase() {
    let baseline = from_history();
    let mut healthy = store(&baseline);
    baseline.arm(&[]);
    healthy.mount().unwrap();
    let events = baseline.events();
    for io in [Io::Program, Io::Erase] {
        let count = events.iter().filter(|(actual, _, _)| *actual == io).count();
        assert!(count > 0);
        for skip in 0..count {
            for effect in [Effect::Refuse, Effect::Drop, Effect::KeepTail] {
                let flash = from_history();
                let mut interrupted = store(&flash);
                flash.arm(&[Rule {
                    io,
                    skip,
                    effect,
                    latched: true,
                }]);
                let outcome = interrupted.mount();
                if effect == Effect::Refuse {
                    assert!(
                        outcome.is_err(),
                        "refused checkpoint must refuse readiness: {io:?}/{skip}"
                    );
                } else if outcome.is_ok() {
                    values(&mut interrupted);
                }
                assert!(flash.hits()[0] > 0);
                flash.clear();
                let mut rebooted = store(&flash);
                rebooted.mount().unwrap();
                values(&mut rebooted);
            }
        }
    }
}

#[test]
fn checkpoint_refuses_crc_valid_unauthenticated_payloads_before_erasing_either_journal() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let forged = crate::tests::fault_flash_for_authenticated_tests();
    let mut raw = crate::SeqStorage::new(
        forged.clone(),
        0..MAIN_END,
        MAIN_END..MAIN_END + AUTHORITY_BYTES,
        Cache::<Uncached, Uncached, Uncached, u16>::new_uncached(),
        Cache::<Uncached, Uncached, Uncached, u16>::new_uncached(),
    );
    raw.write(OWNER, b"nwner").unwrap();
    let forged_image = forged.image();
    let at = forged_image
        .windows(5)
        .position(|bytes| bytes == b"nwner")
        .unwrap();
    let crc = &forged_image[at - 10..at - 6];
    let mut image = history().clone();
    let positions: Vec<_> = image[..MAIN_END as usize]
        .windows(b"owner".len())
        .enumerate()
        .filter_map(|(at, bytes)| (bytes == b"owner").then_some(at))
        .collect();
    assert!(!positions.is_empty());
    for at in positions {
        assert_eq!(&image[at - 2..at], OWNER.to_le_bytes());
        image[at] ^= 1;
        image[at - 10..at - 6].copy_from_slice(crc);
    }
    flash.replace_image_before_read(0, image.clone());
    let mut raw = crate::SeqStorage::new(
        flash.clone(),
        0..MAIN_END,
        MAIN_END..MAIN_END + AUTHORITY_BYTES,
        Cache::<Uncached, Uncached, Uncached, u16>::new_uncached(),
        Cache::<Uncached, Uncached, Uncached, u16>::new_uncached(),
    );
    let mut out = [0; 5];
    assert_eq!(raw.read(OWNER, &mut out), Some(5));
    assert_eq!(
        &out, b"nwner",
        "the payload must pass the map CRC before authentication rejects it"
    );
    let mut mounted = store(&flash);
    flash.arm(&[]);
    assert!(mounted.mount().is_err());
    assert!(flash.events().iter().all(|(io, _, _)| *io == Io::Read));
    assert_eq!(flash.image(), image);
}

#[test]
fn live_snapshot_bytes_do_not_count_as_reclaimable_history() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut mounted = store(&flash);
    mounted
        .administer(StorageAction::Initialize, [0x4B; 16])
        .unwrap();
    for fid in OWNER..OWNER + 50 {
        mounted.write(fid, b"owner").unwrap();
    }
    let layout = Layout::new(MAIN_END..MAIN_END + AUTHORITY_BYTES).unwrap();
    let capacity = layout.main[0].end - layout.main[0].start;
    while scans(&flash)[0].next < capacity / 2 {
        mounted.write(OWNER, b"owner").unwrap();
    }
    let before = scans(&flash);
    flash.arm(&[]);
    mounted.mount().unwrap();
    assert!(
        flash.events().iter().all(|(io, _, _)| *io == Io::Read),
        "live snapshot bytes must not cause early erasure"
    );
    assert_eq!(scans(&flash), before);
}

#[test]
fn a_short_peer_does_not_hide_the_other_banks_reclaimable_history() {
    let flash = from_history();
    let original = scans(&flash);
    let old = flash.image();
    store(&flash).mount().unwrap();
    let short = flash.image();
    let layout = Layout::new(MAIN_END..MAIN_END + AUTHORITY_BYTES).unwrap();
    for selected in 0..2 {
        let range = &layout.main[selected];
        let mut asymmetric = short.clone();
        asymmetric[range.start as usize..range.end as usize]
            .copy_from_slice(&old[range.start as usize..range.end as usize]);
        flash.replace_image_before_read(0, asymmetric);
        let mut mounted = store(&flash);
        mounted.mount().unwrap();
        let current = scans(&flash);
        assert!(current.iter().all(|scan| scan.next < original[0].next / 2));
        values(&mut mounted);
    }
}

#[test]
fn unreadable_root_refuses_mount_before_any_history_erasure() {
    let flash = from_history();
    let mut mounted = Managed::new_unmounted(
        flash.clone(),
        0..MAIN_END,
        MAIN_END..MAIN_END + AUTHORITY_BYTES,
        KeySource::new(SERIAL_HASH, |_| RootRead::Unreadable, false),
        Cache::<Uncached, Uncached, Uncached, u16>::new_uncached,
    );
    flash.arm(&[]);
    assert!(mounted.mount().is_err());
    assert!(flash.events().iter().all(|(io, _, _)| *io == Io::Read));
}

#[test]
fn short_history_mount_hint_skips_only_optional_maintenance_io() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut mounted = store(&flash);
    mounted
        .administer(StorageAction::Initialize, [0x4B; 16])
        .unwrap();
    mounted.write(OWNER, b"owner").unwrap();
    let layout = Layout::new(MAIN_END..MAIN_END + AUTHORITY_BYTES).unwrap();
    let header_reads = || {
        flash
            .events()
            .into_iter()
            .filter(|(io, at, len)| {
                *io == Io::Read
                    && *len == super::super::super::CHECKPOINT_BYTES
                    && layout.main.iter().any(|range| range.start == *at)
            })
            .collect::<Vec<_>>()
    };
    flash.arm(&[]);
    mounted.open_authority().unwrap();
    let active = mounted.active.as_mut().unwrap();
    active.repair_activation().unwrap();
    active.close_pre_otp().unwrap();
    let required = header_reads();
    assert!(!required.is_empty());
    flash.arm(&[]);
    mounted.mount().unwrap();
    assert_eq!(
        header_reads(),
        required,
        "a real short-history mount must not add a checkpoint scan"
    );
    flash.arm(&[Rule {
        io: Io::Read,
        skip: 0,
        effect: Effect::Refuse,
        latched: true,
    }]);
    assert_eq!(mounted.read(OWNER, &mut [0; 32]), None);
    assert!(
        mounted.last_error(),
        "the maintenance hint must not authorize a backend read"
    );
    assert!(flash.hits()[0] > 0);
}

#[test]
fn checkpoint_threshold_counts_exactly_half_a_bank_of_obsolete_history() {
    for (owners, expected_history_delta, reclaim) in [(9, -32, false), (8, 0, true), (7, 32, true)]
    {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let mut mounted = store(&flash);
        mounted
            .administer(StorageAction::Initialize, [0x4B; 16])
            .unwrap();
        for index in 0..89 {
            mounted.write(OWNER + index % owners, b"owner").unwrap();
        }
        let before = scans(&flash);
        let layout = Layout::new(MAIN_END..MAIN_END + AUTHORITY_BYTES).unwrap();
        let capacity = layout.main[0].end - layout.main[0].start;
        let snapshot = super::super::super::CHECKPOINT_BYTES
            + super::super::super::ENTRY_BYTES * directory(&flash).len();
        assert_eq!(
            i64::from(before[0].next) - i64::try_from(snapshot).unwrap(),
            i64::from(capacity / 2) + expected_history_delta
        );
        flash.arm(&[]);
        mounted.mount().unwrap();
        let erased = flash.events().iter().any(|(io, _, _)| *io == Io::Erase);
        assert_eq!(erased, reclaim, "threshold case {expected_history_delta}");
        assert_eq!(scans(&flash)[0].next < before[0].next, reclaim);
    }
}

#[test]
fn payload_read_refusal_aborts_mount_before_the_first_erase() {
    let baseline = from_history();
    baseline.arm(&[]);
    store(&baseline).mount().unwrap();
    let events = baseline.events();
    let erase = events
        .iter()
        .position(|(io, _, _)| *io == Io::Erase)
        .unwrap();
    let payload = events[..erase]
        .iter()
        .rposition(|(io, at, len)| *io == Io::Read && *at < MAIN_END && *len > 4)
        .unwrap();
    let skip = events[..payload]
        .iter()
        .filter(|(io, _, _)| *io == Io::Read)
        .count();
    let flash = from_history();
    flash.arm(&[Rule {
        io: Io::Read,
        skip,
        effect: Effect::Refuse,
        latched: true,
    }]);
    assert!(store(&flash).mount().is_err());
    assert_eq!(flash.hits()[0], 1);
    assert!(flash.events().iter().all(|(io, _, _)| *io == Io::Read));
}
