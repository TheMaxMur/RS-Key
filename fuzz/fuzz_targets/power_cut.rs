// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Power-cut torture for the rsk-fs flash stack. `fs_ops` proves the `Fs`
//! bookkeeping over clean reboots; this target cuts the power *mid-write* and
//! *mid-erase*. The stack is the device's own — [`rsk_store::SeqStorage`], the
//! same two `sequential-storage` map partitions with the same FID routing — over
//! `MockFlashBase` and its byte-granular `bytes_until_shutoff` injector, sized
//! small (8 + 4 pages) so page migration and reclaim, where a torn write hurts
//! most, happen within a fuzz exec.
//!
//! It used to be a hand-written mirror of `firmware/src/flash_storage.rs`, which
//! could only ever be as right as whoever last synced it — and it had drifted: no
//! `last_error` (so the torture could not see a read fault reported as one), no
//! `compact` (the scrub lap went unfuzzed), and one counter FID missing from the
//! routing. Torturing the shipped code removes that whole class of doubt.
//!
//! What is left here is the *medium*: a mock NOR chip that can lose power inside
//! a write or an erase, and the decoder that turns fuzzer bytes into operations.
//! The oracle — the shadow model, the legal post-cut states, the durability
//! sweep — is [`rsk_fs::powercut`], where a unit test and the emulator can reach
//! it too. It lived in this file for as long as it did only because nobody moved
//! it, and that made every property it asserts reachable by fuzzing and by
//! nothing else.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use embassy_futures::block_on;
use embedded_storage_async::nor_flash::{ErrorType, MultiwriteNorFlash, NorFlash, ReadNorFlash};
use libfuzzer_sys::fuzz_target;
use rsk_fs::Fs;
use rsk_fs::powercut::{Device, Op, PowerCutModel};
use rsk_store::SeqStorage;
use sequential_storage::cache::Cache;
use sequential_storage::cache::key_pointers::ArrayKeyPointers;
use sequential_storage::cache::page_pointers::ArrayPagePointers;
use sequential_storage::cache::page_states::ArrayPageStates;
use sequential_storage::mock_flash::{MockFlashBase, MockFlashError, Operation, WriteCountCheck};

// One 48 KiB flash: pages 0..8 main, 8..12 counter (4 KiB pages, 4-byte words).
const WORD: usize = 4;
const PAGE_WORDS: usize = 1024;
type Mock = MockFlashBase<12, WORD, PAGE_WORDS>;
const MAIN_RANGE: core::ops::Range<u32> = 0..(8 * 4096);
const COUNTER_RANGE: core::ops::Range<u32> = (8 * 4096)..(12 * 4096);

type MainCache = Cache<ArrayPageStates<8>, ArrayPagePointers<8>, ArrayKeyPointers<u16, 32>, u16>;
type CounterCache = Cache<ArrayPageStates<4>, ArrayPagePointers<4>, ArrayKeyPointers<u16, 4>, u16>;

/// `fs.rs`'s private `META_MAX`: what `EF_META` holds in total. The model needs
/// it to predict whether a rebuilt blob would have fit; widening the crate's own
/// constant would be a change to a file the firmware compiles, for a testing
/// convenience, so it is passed in — as this target has always spelled it.
const META_MAX: usize = 1024;

// Five main-partition FIDs plus every counter-routed one
// (`rsk_store::is_counter_fid`) — both partitions get torn. The mirror this
// replaced listed only three of the four; `EF_CRED_CTR` (0xC001), rewritten on
// every getAssertion, was the one it missed.
const FIDS: [u16; 9] = [
    0xB000, 0xB001, 0xB002, 0xB003, 0xB004, 0xC000, 0xC001, 0x0093, 0xCC01,
];

/// The `SharedFlash` analog: one mock flash shared by both partitions, plus
/// the power latch. Mutations after a fired cut fail without touching flash.
#[derive(Clone)]
struct SharedMock {
    flash: Rc<RefCell<Mock>>,
    dead: Rc<Cell<bool>>,
}

impl ErrorType for SharedMock {
    type Error = MockFlashError;
}
impl ReadNorFlash for SharedMock {
    const READ_SIZE: usize = <Mock as ReadNorFlash>::READ_SIZE;
    async fn read(
        &mut self,
        offset: u32,
        bytes: &mut [u8],
    ) -> core::result::Result<(), Self::Error> {
        block_on(self.flash.borrow_mut().read(offset, bytes))
    }
    fn capacity(&self) -> usize {
        self.flash.borrow().capacity()
    }
}
impl NorFlash for SharedMock {
    const WRITE_SIZE: usize = <Mock as NorFlash>::WRITE_SIZE;
    const ERASE_SIZE: usize = <Mock as NorFlash>::ERASE_SIZE;
    async fn erase(&mut self, from: u32, to: u32) -> core::result::Result<(), Self::Error> {
        if self.dead.get() {
            return Err(MockFlashError::EarlyShutoff(from, Operation::Erase));
        }
        let r = block_on(self.flash.borrow_mut().erase(from, to));
        if matches!(r, Err(MockFlashError::EarlyShutoff(..))) {
            self.dead.set(true);
        }
        r
    }
    async fn write(&mut self, offset: u32, bytes: &[u8]) -> core::result::Result<(), Self::Error> {
        if self.dead.get() {
            return Err(MockFlashError::EarlyShutoff(offset, Operation::Write));
        }
        let r = block_on(self.flash.borrow_mut().write(offset, bytes));
        if matches!(r, Err(MockFlashError::EarlyShutoff(..))) {
            self.dead.set(true);
        }
        r
    }
}
impl MultiwriteNorFlash for SharedMock {}

/// The device's store over the cuttable mock. Errors are collapsed exactly as
/// the firmware collapses them, because this *is* the firmware's collapsing.
type TortureStorage = SeqStorage<SharedMock, MainCache, CounterCache>;

fn new_storage(flash: SharedMock) -> TortureStorage {
    TortureStorage::new(
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
    )
}

/// The mock chip as a whole device: a boot rebuilds the store with FRESH caches
/// over the same flash bytes, because RAM does not survive a power cycle.
struct MockDevice {
    shared: SharedMock,
}

impl Device for MockDevice {
    type Storage = TortureStorage;

    fn boot(&mut self) -> Fs<TortureStorage> {
        Fs::new(new_storage(self.shared.clone()))
    }

    fn dead(&self) -> bool {
        self.shared.dead.get()
    }

    fn revive(&mut self) {
        self.shared.dead.set(false);
    }
}

/// A payload of the requested length, tagged so a stale value cannot pass for a
/// fresh one.
fn payload(it: &mut impl Iterator<Item = u8>, tag: u8) -> Vec<u8> {
    let len = (it.next().unwrap_or(0) as usize).min(64);
    (0..len).map(|j| (j as u8) ^ tag).collect()
}

fuzz_target!(|data: &[u8]| {
    let flash = Rc::new(RefCell::new(Mock::new(
        // Twice, not OnceOnly: remove_item rewrites the header once (erase_data,
        // crc=None), which OnceOnly would false-flag; this catches a 3rd write.
        WriteCountCheck::Twice,
        None,
        true,
    )));
    let mut dev = MockDevice {
        shared: SharedMock {
            flash: flash.clone(),
            dead: Rc::new(Cell::new(false)),
        },
    };
    let mut fs = Fs::new(new_storage(dev.shared.clone()));
    fs.scan();
    let mut model = PowerCutModel::new(&FIDS, META_MAX);
    let mut tag: u8 = 0;

    let mut it = data.iter().copied();
    while let Some(b) = it.next() {
        let fid = FIDS[((b >> 3) & 7) as usize];
        tag = tag.wrapping_add(0x35);

        // Bit 6 arms the power cut: the budget (in flash bytes touched by
        // writes/erases) decides where inside the op — or a later one, or the
        // next mount's repair — the lights go out.
        if b & 0x40 != 0 {
            let unarmed = flash.borrow().bytes_until_shutoff.is_none();
            if unarmed && !dev.shared.dead.get() {
                let hi = it.next().unwrap_or(0);
                let lo = it.next().unwrap_or(64);
                flash.borrow_mut().bytes_until_shutoff =
                    Some(u32::from_be_bytes([0, 0, hi & 0x0F, lo]));
            }
        }

        let op = match b & 7 {
            0 => Op::Put(fid, payload(&mut it, tag)),
            1 => Op::Read(fid, (it.next().unwrap_or(0) as usize).min(255)),
            2 => Op::Delete(fid),
            3 => Op::MetaAdd(fid, payload(&mut it, tag)),
            4 => Op::MetaFind(fid),
            5 => Op::MetaDelete(fid),
            6 => Op::Reboot,
            // A zero-length buffer: the length a present file reports must not
            // depend on there being room for it.
            _ => Op::Read(fid, 0),
        };
        model.step(&mut dev, &mut fs, op);
    }
});
