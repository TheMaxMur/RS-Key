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
//!
//! One input class drives the complete FIDO reset over the same cuttable store.
//! After a real reboot it checks `ResetNeverWeakensSurvivingState` and its three
//! clauses: `ResetKeepsThePinGate`, `ResetKeepsTheAlwaysUvGate`, and
//! `ResetKeepsTheBackupSeal`. This is the byte-granular half of the phase-6
//! cross-reset pilot; the ordinary operation decoder remains the common path.

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
use sequential_storage::mock_flash::{
    FlashStatsSnapshot, MockFlashBase, MockFlashError, Operation, WriteCountCheck,
};

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
//
// The selector below is `% FIDS.len()`, not `& 7`: three bits index 0..7, so the
// ninth entry — `0xCC01`, a counter FID — could never be written by any input,
// while the sweep asserted it absent on every one of them. A whole partition
// routing was in the roster and out of the reach of the fuzzer.
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
    /// How many boots this exec has needed. Reported, never asserted on.
    boots: u32,
}

impl Device for MockDevice {
    type Storage = TortureStorage;

    fn boot(&mut self) -> Fs<TortureStorage> {
        self.boots += 1;
        Fs::new(new_storage(self.shared.clone()))
    }

    fn dead(&self) -> bool {
        self.shared.dead.get()
    }

    fn revive(&mut self) {
        self.shared.dead.set(false);
    }
}

struct ResetRng(u8);

impl rsk_fido::Rng for ResetRng {
    fn fill(&mut self, out: &mut [u8]) {
        self.0 = self.0.wrapping_add(1);
        out.fill(self.0);
    }
}

fn record<S: rsk_fs::Storage>(fs: &mut Fs<S>, fid: u16) -> Vec<u8> {
    let mut out = [0u8; 128];
    let Some(n) = fs.read(fid, &mut out) else {
        return Vec::new();
    };
    out[..n.min(out.len())].to_vec()
}

fn reset_property_holds<S: rsk_fs::Storage>(fs: &mut Fs<S>, owner_seed: &[u8]) -> bool {
    use rsk_fido::consts::{
        EF_ALWAYS_UV, EF_BACKUP_SEALED, EF_CRED, EF_KEY_DEV, EF_KEY_DEV_ENC, EF_PIN,
    };

    let owner_reachable = record(fs, EF_KEY_DEV.get()) == owner_seed
        || record(fs, EF_KEY_DEV_ENC.get()) == owner_seed;
    let credential_usable = owner_reachable && fs.has_data(EF_CRED);
    (!credential_usable || (fs.has_data(EF_PIN) && fs.has_data(EF_ALWAYS_UV)))
        && (!owner_reachable || fs.has_data(EF_BACKUP_SEALED))
}

/// Drive the real `authenticatorReset`, cut at a byte inside its store writes,
/// then mount a fresh `Fs` and run boot-time seed provisioning. A second boot
/// checks that the verdict is stable across more than the recovery mount.
fn reset_probe(data: &[u8]) {
    use rsk_fido::consts::{EF_ALWAYS_UV, EF_BACKUP_SEALED, EF_CRED, EF_KEY_DEV, EF_PIN};

    let flash = Rc::new(RefCell::new(Mock::new(WriteCountCheck::Twice, None, true)));
    let mut dev = MockDevice {
        shared: SharedMock {
            flash: flash.clone(),
            dead: Rc::new(Cell::new(false)),
        },
        boots: 0,
    };
    let mut fs = Fs::new(new_storage(dev.shared.clone()));
    fs.scan();
    let mut rng = ResetRng(1);
    let identity = rsk_crypto::Device {
        serial_hash: &[0xa5; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    };
    rsk_fido::seed::ensure_seed(&identity, &mut fs, &mut rng).unwrap();
    fs.put(EF_CRED, &[0x5a; 96]).unwrap();
    fs.put(EF_PIN, &[8, 4, 1, 0, 0]).unwrap();
    fs.put(EF_ALWAYS_UV, &[1]).unwrap();
    fs.put(EF_BACKUP_SEALED, &[1]).unwrap();
    let owner_seed = record(&mut fs, EF_KEY_DEV.get());
    assert!(!owner_seed.is_empty());

    let budget = u32::from_be_bytes([
        0,
        data.get(1).copied().unwrap_or(0) & 0x0f,
        data.get(2).copied().unwrap_or(0),
        data.get(3).copied().unwrap_or(0),
    ]);
    flash.borrow_mut().bytes_until_shutoff = Some(budget);

    let mut state = rsk_fido::FidoState::new();
    if data.get(4).is_some_and(|b| b & 1 != 0) {
        state.keydev_dec = rsk_fido::seed::load_keydev(&identity, &mut fs);
    }
    let mut presence = rsk_fido::AlwaysConfirm;
    let mut ctx = rsk_fido::Ctx {
        dev: identity,
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
        presence: &mut presence,
    };
    let _ = rsk_fido::reset::reset(&mut ctx);
    assert!(state.keydev_dec.is_none());
    assert!(!state.paut.in_use);

    if dev.shared.dead.get() {
        flash.borrow_mut().bytes_until_shutoff = None;
        dev.revive();
        fs = dev.boot();
        fs.scan();
        rsk_fido::seed::ensure_seed(&identity, &mut fs, &mut rng).unwrap();
        state = rsk_fido::FidoState::new();
    }
    assert!(reset_property_holds(&mut fs, &owner_seed));

    fs = dev.boot();
    fs.scan();
    assert!(reset_property_holds(&mut fs, &owner_seed));
    assert!(state.keydev_dec.is_none());
}

/// One line per exec on stderr when `RSK_POWER_CUT_STATS` is set, for
/// `scripts/fuzz-dimensions.py` to bucket over a whole corpus.
///
/// A diagnostic, not a check. Nothing in this tree gates on fuzz coverage —
/// `scripts/fuzz-coverage.sh` has no coverage floor at all — and a reporter that
/// looks like a gate is worse than none, because someone eventually believes it.
/// Wasefire computes the same log-bucket histograms in Rust; here the axes are
/// printed and the bucketing is a script, which keeps the histogram testable and
/// the target free of anything that runs during fuzzing.
fn report(
    dirty: usize,
    ops: u32,
    fids: u32,
    from: FlashStatsSnapshot,
    dev: &MockDevice,
    model: &PowerCutModel,
) {
    if std::env::var_os("RSK_POWER_CUT_STATS").is_none() {
        return;
    }
    let stats = from.compare_to(dev.shared.flash.borrow().stats_snapshot());
    eprintln!(
        "power-cut-stats dirty={dirty} ops={ops} fids={fids} boots={} live={} \
erases={} writes={} bytes_written={}",
        dev.boots,
        model.live(),
        stats.erases,
        stats.writes,
        stats.bytes_written,
    );
}

/// A payload of the requested length, tagged so a stale value cannot pass for a
/// fresh one.
fn payload(it: &mut impl Iterator<Item = u8>, tag: u8) -> Vec<u8> {
    let len = (it.next().unwrap_or(0) as usize).min(64);
    (0..len).map(|j| (j as u8) ^ tag).collect()
}

/// Scribble `len` bytes of the input over the front of the flash before the
/// store has ever seen it, so the mount meets a storage it did not write.
///
/// Wasefire's `DirtyLength` dimension. Theirs then stops checking the model
/// entirely ("should not crash but may misbehave"); ours keeps it, because the
/// model can be *adopted* from whatever the first stable mount reports. What the
/// store decides an invalid storage means is its own business; that it stays
/// self-consistent and power-cut-safe from that point on is still a property, and
/// it is the one this target is about.
fn scribble(flash: &mut Mock, len: usize, seed: &[u8]) {
    if len == 0 || seed.is_empty() {
        return;
    }
    let bytes = flash.as_bytes_mut();
    let len = len.min(bytes.len());
    for (i, cell) in bytes[..len].iter_mut().enumerate() {
        *cell = seed[i % seed.len()] ^ (i as u8).rotate_left(3);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.first().is_some_and(|b| b & 0xf0 == 0xf0) {
        reset_probe(data);
        return;
    }
    let flash = Rc::new(RefCell::new(Mock::new(
        // Twice, not OnceOnly: remove_item rewrites the header once (erase_data,
        // crc=None), which OnceOnly would false-flag; this catches a 3rd write.
        WriteCountCheck::Twice,
        None,
        true,
    )));
    // Two header bytes choose how much of the storage is invalid before init.
    // Zero for most inputs — the clean-storage case has to stay the common one —
    // and up to a page and a half otherwise, which crosses the first partition's
    // page boundary where a half-written header hurts.
    let dirty = match data.split_first() {
        Some((&head, rest)) if head & 0x80 != 0 => {
            let width = rest.first().copied().unwrap_or(0) as usize;
            width * 24
        }
        _ => 0,
    };
    scribble(&mut flash.borrow_mut(), dirty, data);
    let mut dev = MockDevice {
        shared: SharedMock {
            flash: flash.clone(),
            dead: Rc::new(Cell::new(false)),
        },
        boots: 0,
    };
    let mut fs = Fs::new(new_storage(dev.shared.clone()));
    fs.scan();
    let mut model = PowerCutModel::new(&FIDS, META_MAX);
    if dirty > 0 {
        // Whatever the store made of the garbage is the committed truth from here.
        model.adopt(&mut dev, &mut fs);
    }
    let mut tag: u8 = 0;
    let (mut ops, mut touched) = (0u32, 0u16);
    let from = flash.borrow().stats_snapshot();

    let mut it = data.iter().copied();
    while let Some(b) = it.next() {
        ops += 1;
        let index = (b >> 3) as usize % FIDS.len();
        let fid = FIDS[index];
        touched |= 1 << index;
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
    report(dirty, ops, touched.count_ones(), from, &dev, &model);
});
