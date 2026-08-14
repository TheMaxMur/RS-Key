// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The store, off the board. What is under test is the vendored
//! `sequential-storage` fork the device runs — the same library, the same map
//! partitions; only the NOR chip beneath it is a fake.
//!
//! That fake is written here rather than taken from the fork's own `mock_flash`
//! (as `fuzz/` and `tools/emu` take it) because those are detached workspaces and
//! this crate is a root member: the `_test` feature that carries `mock_flash`
//! unifies onto the same `sequential-storage` build the firmware links, so
//! `cargo vet` reads its 16-crate tree as shipped, not as dev-only. See the
//! manifest. It also buys something the library's mock cannot do: fail a READ,
//! which is the one fault [`Storage::last_error`] exists to report (audit run-36).

extern crate std;

use core::cell::{Cell, RefCell};
use std::rc::Rc;
use std::vec;
use std::vec::Vec;

use embedded_storage_async::nor_flash::{
    ErrorType, NorFlashError, NorFlashErrorKind, ReadNorFlash,
};
use sequential_storage::cache::Cache;
use sequential_storage::cache::key_pointers::ArrayKeyPointers;
use sequential_storage::cache::page_pointers::ArrayPagePointers;
use sequential_storage::cache::page_states::ArrayPageStates;

use super::*;

/// Program granularity, matching the RP2350 QSPI the device runs on.
const WORD: usize = 4;
/// Twelve sectors: eight for the main ring, four for the counters. Small on
/// purpose — page reclaim, where a log-structured store gets its behaviour, has
/// to happen inside a test rather than after a megabyte of writes.
const MAIN_PAGES: u32 = 8;
const COUNTER_PAGES: u32 = 4;
const MAIN: Range<u32> = 0..(MAIN_PAGES * SECTOR as u32);
const COUNTER: Range<u32> = MAIN.end..(MAIN.end + COUNTER_PAGES * SECTOR as u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlashFault;

impl NorFlashError for FlashFault {
    fn kind(&self) -> NorFlashErrorKind {
        NorFlashErrorKind::Other
    }
}

/// A NOR flash in RAM, shared by both partitions the way the device's one chip is
/// (`MapStorage` takes the flash by value, twice). Erased bits are 1 and a program
/// can only clear them — the property the log-structured store is built on, and
/// one a mock that simply overwrote would hide.
#[derive(Clone)]
struct SharedMock {
    bytes: Rc<RefCell<Vec<u8>>>,
    /// Every read from here on fails. A NOR power cut never produces this (a torn
    /// write yields deterministic bytes, not a read error), so it stands for the
    /// real thing: a chip or bus fault, which `Fs` must not memoise as absence.
    fail_reads: Rc<Cell<bool>>,
    written: Rc<Cell<u64>>,
}

impl SharedMock {
    fn new() -> Self {
        Self {
            bytes: Rc::new(RefCell::new(vec![0xFF; COUNTER.end as usize])),
            fail_reads: Rc::new(Cell::new(false)),
            written: Rc::new(Cell::new(0)),
        }
    }

    /// A copy of one flash window, for asserting a region was left alone.
    fn snapshot(&self, range: Range<u32>) -> Vec<u8> {
        self.bytes.borrow()[range.start as usize..range.end as usize].to_vec()
    }

    /// Whether `needle` appears anywhere in the window — the raw-dump question,
    /// which is the only one an at-rest claim can be settled by.
    fn contains(&self, range: Range<u32>, needle: &[u8]) -> bool {
        self.bytes.borrow()[range.start as usize..range.end as usize]
            .windows(needle.len())
            .any(|w| w == needle)
    }

    fn bytes_written(&self) -> u64 {
        self.written.get()
    }
}

impl ErrorType for SharedMock {
    type Error = FlashFault;
}

impl ReadNorFlash for SharedMock {
    const READ_SIZE: usize = 1;
    async fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result2<()> {
        if self.fail_reads.get() {
            return Err(FlashFault);
        }
        let src = self.bytes.borrow();
        let start = offset as usize;
        let end = start + bytes.len();
        if end > src.len() {
            return Err(FlashFault);
        }
        bytes.copy_from_slice(&src[start..end]);
        Ok(())
    }
    fn capacity(&self) -> usize {
        self.bytes.borrow().len()
    }
}

impl NorFlash for SharedMock {
    const WRITE_SIZE: usize = WORD;
    const ERASE_SIZE: usize = SECTOR;

    async fn erase(&mut self, from: u32, to: u32) -> Result2<()> {
        if !(from as usize).is_multiple_of(SECTOR) || !(to as usize).is_multiple_of(SECTOR) {
            return Err(FlashFault);
        }
        let mut bytes = self.bytes.borrow_mut();
        if to as usize > bytes.len() || from > to {
            return Err(FlashFault);
        }
        bytes[from as usize..to as usize].fill(0xFF);
        Ok(())
    }

    async fn write(&mut self, offset: u32, data: &[u8]) -> Result2<()> {
        if !(offset as usize).is_multiple_of(WORD) || !data.len().is_multiple_of(WORD) {
            return Err(FlashFault);
        }
        let mut bytes = self.bytes.borrow_mut();
        let start = offset as usize;
        if start + data.len() > bytes.len() {
            return Err(FlashFault);
        }
        // A program can only clear bits; the sector erase is what sets them.
        for (cell, &b) in bytes[start..start + data.len()].iter_mut().zip(data) {
            *cell &= b;
        }
        self.written.set(self.written.get() + data.len() as u64);
        Ok(())
    }
}

impl MultiwriteNorFlash for SharedMock {}

type Result2<T> = core::result::Result<T, FlashFault>;

type MainCache = Cache<
    ArrayPageStates<{ MAIN_PAGES as usize }>,
    ArrayPagePointers<{ MAIN_PAGES as usize }>,
    ArrayKeyPointers<u16, 32>,
    u16,
>;
type CounterCache = Cache<
    ArrayPageStates<{ COUNTER_PAGES as usize }>,
    ArrayPagePointers<{ COUNTER_PAGES as usize }>,
    ArrayKeyPointers<u16, 4>,
    u16,
>;

type TestStore = SeqStorage<SharedMock, MainCache, CounterCache>;

/// Mount the store over `flash`. Called again on the same flash to model a
/// reboot: the caches are RAM and do not survive one.
fn mount(flash: &SharedMock) -> TestStore {
    SeqStorage::new(
        flash.clone(),
        MAIN,
        COUNTER,
        MainCache::new(
            ArrayPageStates::new(),
            ArrayPagePointers::new(),
            ArrayKeyPointers::new(),
        ),
        CounterCache::new(
            ArrayPageStates::new(),
            ArrayPagePointers::new(),
            ArrayKeyPointers::new(),
        ),
    )
}

fn read_vec(store: &mut TestStore, fid: u16) -> Option<Vec<u8>> {
    let mut buf = [0u8; rsk_fs::MAX_VALUE_BYTES];
    let n = store.read(fid, &mut buf)?;
    Some(buf[..n].to_vec())
}

fn keys(store: &mut TestStore) -> (Vec<u16>, bool) {
    let mut found = Vec::new();
    let complete = store.for_each_key(&mut |k| found.push(k));
    found.sort_unstable();
    (found, complete)
}

/// A main-partition FID (a FIDO credential slot) and a counter-routed one.
const CRED: u16 = 0xCF00;
const CTR: u16 = 0xC000;

// --- the routing table -----------------------------------------------------

#[test]
fn only_the_four_hot_counters_leave_the_main_partition() {
    // The split is this crate's whole reason to exist, and the table is a copy of
    // four other crates' FIDs: `EF_COUNTER` / `EF_CRED_CTR` (rsk-fido 0xC000 /
    // 0xC001), OpenPGP's signature counter (0x0093) and the vendor test counter
    // (0xCC01). A missing entry is invisible — the value still stores, it just
    // stores in the pages holding the credentials. The `power_cut` target's
    // hand-written mirror was missing 0xC001, rewritten on every getAssertion.
    for fid in [0xC000, 0xC001, 0x0093, 0xCC01] {
        assert!(is_counter_fid(fid), "{fid:#06x} must be a counter");
    }
    // Their neighbours must NOT be: an off-by-one entry would quietly route a
    // credential into the churn partition, or a counter into the credential pages.
    for fid in [0xBFFF, 0xC002, 0x0092, 0x0094, 0xCC00, 0xCC02, CRED] {
        assert!(!is_counter_fid(fid), "{fid:#06x} must stay in main");
    }
    assert!(
        !is_counter_fid(rsk_fs::EF_SCRUB_FILLER),
        "the lap churns main"
    );
}

// --- the Storage contract --------------------------------------------------

#[test]
fn a_value_round_trips_through_each_partition() {
    let flash = SharedMock::new();
    let mut store = mount(&flash);
    store.write(CRED, b"credential").unwrap();
    store.write(CTR, b"\x00\x00\x00\x07").unwrap();
    assert_eq!(
        read_vec(&mut store, CRED).as_deref(),
        Some(&b"credential"[..])
    );
    assert_eq!(store.size(CTR), Some(4));
    assert!(!store.last_error());
}

#[test]
fn a_stored_value_survives_a_reboot() {
    // The caches are RAM; the bytes are what the next boot mounts.
    let flash = SharedMock::new();
    let mut store = mount(&flash);
    store.write(CRED, b"credential").unwrap();
    store.write(CTR, b"\x00\x00\x00\x07").unwrap();
    let mut store = mount(&flash);
    assert_eq!(
        read_vec(&mut store, CRED).as_deref(),
        Some(&b"credential"[..])
    );
    assert_eq!(
        read_vec(&mut store, CTR).as_deref(),
        Some(&b"\x00\x00\x00\x07"[..])
    );
}

#[test]
fn a_read_of_an_absent_key_is_an_absence_not_an_error() {
    let flash = SharedMock::new();
    let mut store = mount(&flash);
    assert_eq!(store.read(CRED, &mut [0u8; 8]), None);
    assert!(
        !store.last_error(),
        "an absence reported as a fault would make `Fs` re-read for ever"
    );
    assert_eq!(store.size(CRED), None);
    assert!(!store.last_error());
}

#[test]
fn a_removed_key_is_gone_from_both_the_read_and_the_walk() {
    let flash = SharedMock::new();
    let mut store = mount(&flash);
    store.write(CRED, b"credential").unwrap();
    store.write(CTR, b"\x00\x00\x00\x07").unwrap();
    store.remove(CRED).unwrap();
    store.remove(CTR).unwrap();
    assert_eq!(store.read(CRED, &mut [0u8; 8]), None);
    assert_eq!(store.read(CTR, &mut [0u8; 8]), None);
    assert_eq!(keys(&mut store).0, Vec::<u16>::new());
}

#[test]
fn a_short_buffer_still_reports_the_whole_length() {
    // `Fs` sizes its reads from this, so a truncated copy that also under-reported
    // its length would silently shorten a record.
    let flash = SharedMock::new();
    let mut store = mount(&flash);
    store.write(CRED, b"0123456789").unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(store.read(CRED, &mut buf), Some(10));
    assert_eq!(&buf, b"0123");
}

#[test]
fn the_published_ceiling_is_the_one_the_scratch_can_hold() {
    // `Storage::MAX_VALUE` is what callers size themselves against; a value at it
    // must store, and the scratch is exactly two bytes larger for the FID.
    let flash = SharedMock::new();
    let mut store = mount(&flash);
    let at_the_limit = vec![0x5A; TestStore::MAX_VALUE];
    store.write(CRED, &at_the_limit).unwrap();
    assert_eq!(read_vec(&mut store, CRED), Some(at_the_limit));
    assert!(
        store
            .write(CRED + 1, &vec![0x5A; TestStore::MAX_VALUE + 1])
            .is_err(),
        "a value past the ceiling must be refused, not truncated"
    );
}

#[test]
fn the_walk_yields_both_partitions_and_says_it_finished() {
    let flash = SharedMock::new();
    let mut store = mount(&flash);
    store.write(CRED, b"a").unwrap();
    store.write(CRED + 1, b"b").unwrap();
    store.write(CTR, b"\x00\x00\x00\x01").unwrap();
    store.write(0xCC01, b"\x00\x00\x00\x02").unwrap();
    let (found, complete) = keys(&mut store);
    assert_eq!(found, vec![0xC000, 0xCC01, CRED, CRED + 1]);
    assert!(complete, "`Fs::scan` only trusts a complete enumeration");
}

// --- a read fault is not an absence ----------------------------------------

#[test]
fn a_faulted_read_is_reported_as_a_fault() {
    // Audit run-36: both outcomes collapse into `None`, and `Fs` memoises the
    // second as a decided fact — so a transient fault became a permanent "file
    // absent" for the rest of the boot, and every gate that reads `has_data`
    // opened, `clientpin::set_pin` among them.
    let flash = SharedMock::new();
    let mut store = mount(&flash);
    store.write(CRED, b"credential").unwrap();
    flash.fail_reads.set(true);
    assert_eq!(store.read(CRED, &mut [0u8; 16]), None);
    assert!(store.last_error());
    assert_eq!(store.size(CRED), None);
    assert!(store.last_error());
    flash.fail_reads.set(false);
    assert_eq!(
        read_vec(&mut store, CRED).as_deref(),
        Some(&b"credential"[..])
    );
    assert!(
        !store.last_error(),
        "the flag tracks the LAST read, not any read"
    );
}

#[test]
fn a_faulted_walk_reports_itself_incomplete() {
    // A `false` here is what stops `Fs::scan` deciding that the keys it never saw
    // are absent.
    let flash = SharedMock::new();
    let mut store = mount(&flash);
    store.write(CRED, b"credential").unwrap();
    flash.fail_reads.set(true);
    let (_, complete) = keys(&mut store);
    assert!(!complete);
}

// --- the partition split ---------------------------------------------------

#[test]
fn counter_churn_never_touches_the_credential_pages() {
    // The reason for the second partition: the per-operation counters are
    // rewritten on every single operation, and if their churn advanced the main
    // ring it would drag the credential pages into a multi-second cold migration.
    let flash = SharedMock::new();
    let mut store = mount(&flash);
    store.write(CRED, b"credential").unwrap();
    let main_before = flash.snapshot(MAIN);

    // Comfortably more than one counter partition's worth of writes, so its own
    // ring wraps and reclaims several times over.
    for i in 0..2_000u32 {
        store.write(CTR, &i.to_be_bytes()).unwrap();
    }
    assert_eq!(
        read_vec(&mut store, CTR).as_deref(),
        Some(&1_999u32.to_be_bytes()[..])
    );
    assert_eq!(
        flash.snapshot(MAIN),
        main_before,
        "the main partition must be byte-identical after 2000 counter writes"
    );
}

// --- the scrub lap ---------------------------------------------------------

#[test]
fn the_scrub_lap_destroys_a_superseded_secret() {
    // `store_item` only appends and `remove_item` only flips a header, so the old
    // payload stays readable in a raw dump until its page is reclaimed. This is
    // what physically destroys the chip-serial-sealed pre-OTP seed after the
    // migration re-seals it under the OTP root.
    const OLD: &[u8] = b"the-pre-otp-sealed-seed-0123456789";
    const NEW: &[u8] = b"the-otp-sealed-seed-9876543210____";
    let flash = SharedMock::new();
    let mut store = mount(&flash);
    store.write(CRED, OLD).unwrap();
    store.write(CRED, NEW).unwrap();
    assert!(
        flash.contains(MAIN, OLD),
        "precondition: the superseded copy is still in flash"
    );

    store.compact().unwrap();
    assert!(
        !flash.contains(MAIN, OLD),
        "the superseded copy survived the lap"
    );
    assert_eq!(read_vec(&mut store, CRED).as_deref(), Some(NEW));
}

#[test]
fn the_scrub_lap_keeps_every_live_record() {
    // It drives a full ring lap of throwaway writes; live items are migrated ahead
    // of the head, and losing one here is losing a key.
    let flash = SharedMock::new();
    let mut store = mount(&flash);
    let live: Vec<(u16, Vec<u8>)> = (0..8u16)
        .map(|i| (CRED + i, vec![i as u8; 64 + i as usize]))
        .collect();
    for (fid, value) in &live {
        store.write(*fid, value).unwrap();
    }
    store.write(CTR, b"\x00\x00\x00\x07").unwrap();

    store.compact().unwrap();

    for (fid, value) in &live {
        assert_eq!(
            read_vec(&mut store, *fid).as_ref(),
            Some(value),
            "{fid:#06x}"
        );
    }
    assert_eq!(
        read_vec(&mut store, CTR).as_deref(),
        Some(&b"\x00\x00\x00\x07"[..]),
        "the counter partition is not swept and must be untouched"
    );
}

#[test]
fn the_scrub_lap_leaves_no_filler_behind() {
    // Audit run-36: a filler record left live is counted by `Fs::scan` against the
    // dynamic-file budget, and no applet reset ever removes it — `is_fido_fid`
    // does not cover the FID.
    let flash = SharedMock::new();
    let mut store = mount(&flash);
    store.write(CRED, b"credential").unwrap();
    store.compact().unwrap();
    let (found, complete) = keys(&mut store);
    assert!(complete);
    assert_eq!(found, vec![CRED], "the lap's own records are all gone");
    assert_eq!(store.read(rsk_fs::EF_SCRUB_FILLER, &mut [0u8; 8]), None);
}

#[test]
fn a_second_lap_is_harmless() {
    // It is one-shot and gated by `EF_HARDENED`, but the gate is crash-safe by
    // being re-runnable — an interrupted lap simply runs again on the next boot.
    let flash = SharedMock::new();
    let mut store = mount(&flash);
    store.write(CRED, b"credential").unwrap();
    store.compact().unwrap();
    store.compact().unwrap();
    assert_eq!(
        read_vec(&mut store, CRED).as_deref(),
        Some(&b"credential"[..])
    );
    assert_eq!(keys(&mut store).0, vec![CRED]);
}

#[test]
fn the_lap_is_sized_from_the_partition_it_sweeps() {
    // Taken from the range, not a build constant: this ring is eight pages against
    // the board's hundreds. A lap sized for a bigger ring wears the flash out on
    // every provisioning; one sized for a smaller ring leaves pages unswept, which
    // is a secret left readable. Bounding the write volume catches the first
    // directly, and `the_scrub_lap_destroys_a_superseded_secret` the second.
    let flash = SharedMock::new();
    let mut store = mount(&flash);
    store.write(CRED, b"credential").unwrap();
    let before = flash.bytes_written();
    store.compact().unwrap();
    let written = flash.bytes_written() - before;
    let ring = (MAIN.end - MAIN.start) as u64;
    assert!(
        written >= ring,
        "wrote {written} B for a {ring} B ring — short of one lap, so pages stay unswept"
    );
    assert!(
        written < 3 * ring,
        "wrote {written} B for a {ring} B ring — sized for someone else's partition"
    );
}

/// A store whose partitions are swapped: its main ring is the physical COUNTER
/// range and its counter ring the physical MAIN one. Writing a counter fid through
/// it therefore lands that fid in the physical MAIN range — the state a device
/// reaches for real when the routing table changes under it, which
/// [`is_counter_fid`] did once (`EF_CRED_CTR` moved into the counter set at 0x0821
/// after 0x081D had written it to main).
fn mount_misrouted(flash: &SharedMock) -> SeqStorage<SharedMock, CounterCache, MainCache> {
    SeqStorage::new(
        flash.clone(),
        COUNTER,
        MAIN,
        CounterCache::new(
            ArrayPageStates::new(),
            ArrayPagePointers::new(),
            ArrayKeyPointers::new(),
        ),
        MainCache::new(
            ArrayPageStates::new(),
            ArrayPagePointers::new(),
            ArrayKeyPointers::new(),
        ),
    )
}

#[test]
fn remove_clears_a_fid_the_routing_no_longer_points_at() {
    // The failure this pins is not a lost byte: `for_each_key` walks BOTH rings, so
    // a copy in the ring `remove` does not target is yielded on every pass forever
    // while `read` cannot see it. `authenticatorReset` sweeps until its predicate's
    // range comes back empty, so one such record is a reset that never finishes.
    let flash = SharedMock::new();
    let mut wrong = mount_misrouted(&flash);
    wrong.write(CTR, b"stranded").unwrap();
    drop(wrong);

    let mut store = mount(&flash);
    assert_eq!(
        keys(&mut store).0,
        vec![CTR],
        "the walk sees the stranded copy"
    );
    assert_eq!(read_vec(&mut store, CTR), None, "but a read routes past it");

    store.remove(CTR).unwrap();
    assert_eq!(
        keys(&mut store).0,
        Vec::<u16>::new(),
        "a record the walk keeps yielding after a delete is one no sweep can finish"
    );
}
