// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The emulator's flash: `sequential-storage`'s own mock NOR device, with the
//! device's geometry, behind the device's store ([`rsk_store::SeqStorage`]).
//!
//! It used to be a `BTreeMap` that overwrote in place, which meant every suite
//! ran against a store with no log structure, no page migration and no superseded
//! records — the three things the real backend has and the three the bugs lived
//! in. Now the only thing standing in for hardware is the medium: writes clear
//! bits and never set them, a page must be erased before it is rewritten, and the
//! ring migrates and reclaims exactly as it does on the board.
//!
//! The mock's own byte array is what gets persisted, so a restart re-mounts the
//! same flash image rather than a replayed history. Its write-once *tracking* is
//! not persisted — that is bookkeeping the medium does not carry either; what a
//! real chip remembers is the bits, and those are in the file.

use std::cell::RefCell;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::rc::Rc;

use embassy_futures::block_on;
use embedded_storage_async::nor_flash::{ErrorType, MultiwriteNorFlash, NorFlash, ReadNorFlash};
use sequential_storage::cache::Cache;
use sequential_storage::cache::key_pointers::ArrayKeyPointers;
use sequential_storage::cache::page_pointers::ArrayPagePointers;
use sequential_storage::cache::page_states::ArrayPageStates;
use sequential_storage::mock_flash::{MockFlashBase, MockFlashError, WriteCountCheck};

/// The RP2350's geometry: 4 KiB erase sectors of 4-byte words, and the firmware's
/// own partition split — 1408 KiB main, 128 KiB counter. Same numbers as
/// `firmware/src/flash_storage.rs`, because a store sized differently would
/// migrate and reclaim at different moments than the device does.
const WORD: usize = 4;
const PAGE_WORDS: usize = 1024;
const SECTOR: u32 = (WORD * PAGE_WORDS) as u32;
const MAIN_PAGES: usize = 352;
const COUNTER_PAGES: usize = 32;
const PAGES: usize = MAIN_PAGES + COUNTER_PAGES;

const MAIN_RANGE: std::ops::Range<u32> = 0..(MAIN_PAGES as u32 * SECTOR);
const COUNTER_RANGE: std::ops::Range<u32> = (MAIN_PAGES as u32 * SECTOR)..(PAGES as u32 * SECTOR);

/// Cache geometry, mirroring the firmware's: main must cover every live
/// main-partition file or a full device pays the O(flash) fetch cliff.
const MAIN_CACHE_KEYS: usize = rsk_fs::MAX_DYNAMIC_FILES + 1;
const COUNTER_CACHE_KEYS: usize = 16;

type Mock = MockFlashBase<PAGES, WORD, PAGE_WORDS>;
type MainCache = Cache<
    ArrayPageStates<MAIN_PAGES>,
    ArrayPagePointers<MAIN_PAGES>,
    ArrayKeyPointers<u16, MAIN_CACHE_KEYS>,
    u16,
>;
type CounterCache = Cache<
    ArrayPageStates<COUNTER_PAGES>,
    ArrayPagePointers<COUNTER_PAGES>,
    ArrayKeyPointers<u16, COUNTER_CACHE_KEYS>,
    u16,
>;

/// The store the emulator runs — the firmware's, over the mock medium.
pub type EmuStore = rsk_store::SeqStorage<FlashFile, MainCache, CounterCache>;

/// File magic + layout version. A flash image is only meaningful to the geometry
/// that wrote it, so a mismatch is refused rather than mounted.
const MAGIC: &[u8; 16] = b"RSKEMU-FLASH\x00\x00\x01\x02";

/// One mock flash, shared by both partitions (`MapStorage` takes its flash by
/// value) and mirrored to a file after every mutation.
#[derive(Clone)]
pub struct FlashFile {
    flash: Rc<RefCell<Mock>>,
    path: Option<Rc<PathBuf>>,
}

impl FlashFile {
    /// Mount the image at `path` (a blank chip when absent), or a purely
    /// in-memory one when `path` is `None`.
    pub fn open(path: Option<PathBuf>, power_cut_after: Option<u32>) -> io::Result<Self> {
        // `Twice`, not `OnceOnly`: the store is a `MultiwriteNorFlash` on purpose —
        // `remove_item` clears bits in an already-written header rather than
        // erasing, which is a legal 1→0 NOR write and the second one a word gets.
        // `OnceOnly` refused it and turned PIV RESET into a memory failure; the
        // `power_cut` fuzz target reached the same conclusion first.
        let mut flash = Mock::new(WriteCountCheck::Twice, power_cut_after, true);
        if let Some(p) = &path
            && p.exists()
        {
            let raw = fs::read(p)?;
            let want = MAGIC.len() + flash.as_bytes().len();
            if raw.len() != want || &raw[..MAGIC.len()] != MAGIC {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "not an rsk-emu flash image of this geometry",
                ));
            }
            flash.as_bytes_mut().copy_from_slice(&raw[MAGIC.len()..]);
        }
        Ok(Self {
            flash: Rc::new(RefCell::new(flash)),
            path: path.map(Rc::new),
        })
    }

    fn persist(&self) {
        let Some(p) = &self.path else { return };
        let flash = self.flash.borrow();
        let mut out = Vec::with_capacity(MAGIC.len() + flash.as_bytes().len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(flash.as_bytes());
        if let Err(e) = fs::write(p.as_path(), &out) {
            eprintln!("emu: cannot write the flash image {}: {e}", p.display());
        }
    }
}

impl ErrorType for FlashFile {
    type Error = MockFlashError;
}

impl ReadNorFlash for FlashFile {
    const READ_SIZE: usize = <Mock as ReadNorFlash>::READ_SIZE;
    async fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        block_on(self.flash.borrow_mut().read(offset, bytes))
    }
    fn capacity(&self) -> usize {
        self.flash.borrow().capacity()
    }
}

impl NorFlash for FlashFile {
    const WRITE_SIZE: usize = <Mock as NorFlash>::WRITE_SIZE;
    const ERASE_SIZE: usize = <Mock as NorFlash>::ERASE_SIZE;
    async fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        let r = block_on(self.flash.borrow_mut().erase(from, to));
        self.persist();
        r
    }
    async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        let r = block_on(self.flash.borrow_mut().write(offset, bytes));
        // Persist even on the failure path: a torn write leaves bytes behind, and
        // the whole point of the image is that the next mount sees them.
        self.persist();
        r
    }
}

impl MultiwriteNorFlash for FlashFile {}

/// Build the store over a fresh mount of `path`.
pub fn open(path: Option<PathBuf>, power_cut_after: Option<u32>) -> io::Result<EmuStore> {
    let flash = FlashFile::open(path, power_cut_after)?;
    Ok(EmuStore::new(
        flash,
        MAIN_RANGE,
        COUNTER_RANGE,
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
    ))
}
