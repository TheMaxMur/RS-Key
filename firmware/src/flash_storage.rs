// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `rsk_fs::Storage` (FID -> bytes) backed by `sequential-storage` maps over the
//! reserved flash partitions.

use core::cell::RefCell;
use core::ops::Range;

use embassy_embedded_hal::adapter::BlockingAsync;
use embassy_futures::block_on;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::peripherals::FLASH;
use embedded_storage_async::nor_flash::{ErrorType, MultiwriteNorFlash, NorFlash, ReadNorFlash};
use sequential_storage::cache::key_pointers::ArrayKeyPointers;
use sequential_storage::cache::page_pointers::ArrayPagePointers;
use sequential_storage::cache::page_states::ArrayPageStates;
use sequential_storage::cache::{Cache, CacheImpl};
use sequential_storage::map::{MapConfig, MapStorage};

use rsk_fs::Storage;
use rsk_sdk::error::{Error, Result};

/// External QSPI flash size in bytes — `FLASH_SIZE` at build time (default 4 MB,
/// the Waveshare RP2350-One), baked by build.rs as `PK_FLASH_SIZE`. The same
/// value drives the generated `memory.x`, so the KV partitions track the chip.
pub const FLASH_SIZE: usize = crate::env_u32(env!("PK_FLASH_SIZE")) as usize;

/// Scratch for one map op; must fit the largest stored key+value (EF_META ≤ 1 KiB).
const KV_BUF: usize = 2048;

/// Flash erase-sector size (RP2350 QSPI), = one `sequential-storage` page.
const SECTOR: usize = 4096;

// The KV store is split into two flash partitions (see `memory.x`) so the hot
// counters can't force the credential pages to migrate:
//
// * **main** (KVMAIN, 1408 KiB by default) — credentials, keys, OpenPGP data objects.
//   Written only on registration / key generation / personalisation, so its pages fill
//   slowly and a (cold, expensive) page migration is rare. The `KVMAIN` build knob
//   shrinks it to free code space on a small flash (a 2 MB board); the size is baked as
//   `PK_KVMAIN_LEN` and MUST match `memory.x`'s KVMAIN LENGTH (build.rs writes both).
// * **counter** (128 KiB) — the per-operation counters (FIDO `EF_COUNTER`, OpenPGP
//   `EF_SIG_COUNT`, the vendor counter), rewritten on *every* signature/assertion.
//   That churn is what fills flash; isolating it here means it reclaims only its own
//   small pages (cheap — a handful of always-cached keys) instead of advancing the
//   main partition's ring into the credential pages (a multi-second cold-migration
//   stall). Fixed size — the counters need their own churn-isolated pages on any board.
const MAIN_LEN: usize = crate::env_u32(env!("PK_KVMAIN_LEN")) as usize;
const COUNTER_LEN: usize = 128 * 1024;
const MAIN_PAGES: usize = MAIN_LEN / SECTOR; // KVMAIN / SECTOR (352 at the 1408K default)
const COUNTER_PAGES: usize = COUNTER_LEN / SECTOR; // 32

/// Transient FID the [`Storage::compact`] lap churns to advance the main ring.
/// Routed to main (not a counter FID), it never reaches `Fs` and is removed at
/// the end of the lap — pick a slot no protocol uses (the FIDO 0xCExx fixed-file
/// block tops out at `EF_DEVICE_PIN` 0xCE20; creds start at 0xCF00, so 0xCEFE is free).
const SCRUB_FILLER_FID: u16 = 0xCEFE;
/// One throwaway record's payload during the scrub lap. Larger ⇒ fewer
/// `store_item` calls; must fit `KV_BUF` alongside the 2-byte key.
const SCRUB_FILLER: [u8; 1024] = [0xA5; 1024];

/// Cached key→location maps. A hit lets `store_item`'s `migrate_items` take the O(1)
/// path per item instead of a full-partition scan — the difference between a ~0.2 s
/// and a multi-second migration. Main must cover EVERY live main-partition file, so
/// keep it `>= rsk_fs::MAX_DYNAMIC_FILES`: sized for the full applet union (256
/// passkeys + 256 EF_RP + 256 nicks + PIV key/cert pairs + OATH creds + OpenPGP DOs)
/// so a fully-provisioned device never demotes to the cliff. The `+ 1` covers
/// `EF_META`, the one live main-partition key `scan` does NOT count against the
/// dynamic-file budget — without it a maxed device holds 1281 main keys against a
/// 1280-slot cache and one key pays the O(flash) first fetch. Counter only needs its
/// few keys.
const MAIN_CACHE_KEYS: usize = rsk_fs::MAX_DYNAMIC_FILES + 1;
const COUNTER_CACHE_KEYS: usize = 16;

pub type AsyncFlash = BlockingAsync<Flash<'static, FLASH, Blocking, FLASH_SIZE>>;
// sequential-storage 8.0 replaced the `KeyPointerCache` alias with a composite
// `Cache` of three sub-caches (page states + page pointers + key pointers); the
// key-pointer array is the one that maps FID -> flash address for O(1) reads.
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

/// A `'static`, shared handle to the one flash peripheral, so the two partitions can
/// each own a `MapStorage` over it. `MapStorage` takes its flash *by value* and the
/// `Flash` peripheral is a singleton, so the two maps share it through this `RefCell`.
/// It is borrowed only inside one synchronous `block_on` op — `BlockingAsync` resolves
/// on the first poll and `block_on` never yields to another task, so the borrow can't
/// overlap with the other partition's.
#[derive(Clone, Copy)]
pub struct SharedFlash {
    inner: &'static RefCell<AsyncFlash>,
}

impl ErrorType for SharedFlash {
    type Error = <AsyncFlash as ErrorType>::Error;
}
// The inner `BlockingAsync` futures are ready on the first poll, so each op is driven
// to completion by an inner `block_on` *inside* the borrow scope — the `RefCell` guard
// is created and dropped within that synchronous call, never held across a real
// suspension. (This also satisfies clippy's `await_holding_refcell_ref`; there is no
// live `.await` here.)
impl ReadNorFlash for SharedFlash {
    const READ_SIZE: usize = <AsyncFlash as ReadNorFlash>::READ_SIZE;
    async fn read(
        &mut self,
        offset: u32,
        bytes: &mut [u8],
    ) -> core::result::Result<(), Self::Error> {
        block_on(self.inner.borrow_mut().read(offset, bytes))
    }
    fn capacity(&self) -> usize {
        self.inner.borrow().capacity()
    }
}
impl NorFlash for SharedFlash {
    const WRITE_SIZE: usize = <AsyncFlash as NorFlash>::WRITE_SIZE;
    const ERASE_SIZE: usize = <AsyncFlash as NorFlash>::ERASE_SIZE;
    async fn erase(&mut self, from: u32, to: u32) -> core::result::Result<(), Self::Error> {
        block_on(self.inner.borrow_mut().erase(from, to))
    }
    async fn write(&mut self, offset: u32, bytes: &[u8]) -> core::result::Result<(), Self::Error> {
        block_on(self.inner.borrow_mut().write(offset, bytes))
    }
}
impl MultiwriteNorFlash for SharedFlash {}

/// Wrap the raw blocking flash for the `'static` `RefCell` the two partitions share
/// (called once from `main` before constructing [`FlashStorage`]).
pub fn wrap_flash(flash: Flash<'static, FLASH, Blocking, FLASH_SIZE>) -> AsyncFlash {
    BlockingAsync::new(flash)
}

/// FID → bytes persistence over the two flash partitions (see [`is_counter_fid`]).
pub struct FlashStorage {
    main: MapStorage<u16, SharedFlash, MainCache>,
    counter: MapStorage<u16, SharedFlash, CounterCache>,
    buf: [u8; KV_BUF],
}

/// Route the hot per-operation counters to the dedicated counter partition so their
/// churn never reclaims a credential/key page in the main partition. Values are
/// `EF_COUNTER` (FIDO 0xC000), `EF_CRED_CTR` (FIDO per-credential signature counters,
/// 0xC001 — rewritten on every getAssertion), `EF_SIG_COUNT` (OpenPGP 0x0093) and the
/// vendor test counter (0xCC01).
fn is_counter_fid(fid: u16) -> bool {
    matches!(fid, 0xC000 | 0xC001 | 0x0093 | 0xCC01)
}

impl FlashStorage {
    /// `main_range` / `counter_range` are erase-aligned, non-overlapping flash-offset
    /// windows (from `memory.x`); `flash` is the shared `'static` handle.
    pub fn new(
        flash: &'static RefCell<AsyncFlash>,
        main_range: Range<u32>,
        counter_range: Range<u32>,
    ) -> Self {
        debug_assert!((main_range.end - main_range.start) as usize == MAIN_LEN);
        debug_assert!((counter_range.end - counter_range.start) as usize == COUNTER_LEN);
        let flash = SharedFlash { inner: flash };
        Self {
            main: MapStorage::new(
                flash,
                MapConfig::new(main_range),
                MainCache::new(
                    ArrayPageStates::new(),
                    ArrayPagePointers::new(),
                    ArrayKeyPointers::new(),
                ),
            ),
            counter: MapStorage::new(
                flash,
                MapConfig::new(counter_range),
                CounterCache::new(
                    ArrayPageStates::new(),
                    ArrayPagePointers::new(),
                    ArrayKeyPointers::new(),
                ),
            ),
            buf: [0; KV_BUF],
        }
    }
}

// sequential-storage is async-only; the blocking flash is wrapped in BlockingAsync,
// whose futures are ready on first poll, so block_on drives them synchronously.
impl Storage for FlashStorage {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        let value = if is_counter_fid(fid) {
            block_on(self.counter.fetch_item::<&[u8]>(&mut self.buf, &fid)).ok()??
        } else {
            block_on(self.main.fetch_item::<&[u8]>(&mut self.buf, &fid)).ok()??
        };
        let n = value.len().min(buf.len());
        buf[..n].copy_from_slice(&value[..n]);
        Some(value.len())
    }

    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        if is_counter_fid(fid) {
            block_on(self.counter.store_item::<&[u8]>(&mut self.buf, &fid, &data))
        } else {
            block_on(self.main.store_item::<&[u8]>(&mut self.buf, &fid, &data))
        }
        .map_err(|_| Error::MemoryFatal)
    }

    fn remove(&mut self, fid: u16) -> Result<()> {
        if is_counter_fid(fid) {
            block_on(self.counter.remove_item(&mut self.buf, &fid))
        } else {
            block_on(self.main.remove_item(&mut self.buf, &fid))
        }
        .map_err(|_| Error::MemoryFatal)
    }

    fn size(&mut self, fid: u16) -> Option<usize> {
        let value = if is_counter_fid(fid) {
            block_on(self.counter.fetch_item::<&[u8]>(&mut self.buf, &fid)).ok()??
        } else {
            block_on(self.main.fetch_item::<&[u8]>(&mut self.buf, &fid)).ok()??
        };
        Some(value.len())
    }

    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        // Both partitions must complete before an un-yielded FID counts as absent:
        // `Fs::scan`'s `decided.fill` trusts only a globally complete enumeration.
        // Run both regardless of the first's result so `f` still sees every key it
        // can (the `&&` here is over the outcomes, not a short-circuit of the walk).
        let main_done = for_each_in(&mut self.main, &mut self.buf, f);
        let counter_done = for_each_in(&mut self.counter, &mut self.buf, f);
        main_done && counter_done
    }

    /// Physically scrub superseded records from the **main** partition (where
    /// every secret lives) by driving its `sequential-storage` ring a full lap.
    ///
    /// The library's `store_item` (overwrite) only appends, and `remove_item`
    /// only flips a header CRC — both leave the prior payload in flash, readable
    /// from a raw dump until the page is reclaimed. A page is reclaimed (its live
    /// items migrated forward, then the whole 4 KiB sector erased) only when the
    /// ring head needs it. So we write one partition's worth of throwaway records
    /// to force the head all the way around: every page that held data at entry
    /// is swept and erased, and the superseded copy of any migrated secret — in
    /// particular the chip-serial-sealed pre-OTP seed left by
    /// `migrate_keydev_boot` — is physically destroyed.
    ///
    /// One lap needs at most `MAIN_LEN` bytes of fresh writes (less by however
    /// much live data is relocated en route), so `MAIN_LEN + SECTOR` guarantees a
    /// full sweep no matter how full the partition is. The counter partition holds
    /// only non-secret counters and churns on its own, so it is left untouched.
    /// This is a one-shot, multi-second provisioning cost (see the `EF_HARDENED`
    /// gate in `main`); it is crash-safe — an interrupted lap leaves the store in
    /// a valid state and re-runs on the next boot.
    fn compact(&mut self) -> Result<()> {
        let writes = (MAIN_LEN + SECTOR).div_ceil(SCRUB_FILLER.len());
        for i in 0..writes {
            let mut v = SCRUB_FILLER;
            v[0] = i as u8; // distinct payloads (defensive; store always appends)
            block_on(self.main.store_item::<&[u8]>(
                &mut self.buf,
                &SCRUB_FILLER_FID,
                &v.as_slice(),
            ))
            .map_err(|_| Error::MemoryFatal)?;
        }
        block_on(self.main.remove_item(&mut self.buf, &SCRUB_FILLER_FID))
            .map_err(|_| Error::MemoryFatal)?;
        Ok(())
    }
}

/// Iterate every live key in one partition (used by `for_each_key` over both).
/// Returns `true` iff the walk reached its natural `None` terminator, i.e. it
/// enumerated every live key. `MapItemIter::next` reaches `None` only after
/// cycling the full ring; the sole early exit is a genuine flash READ FAULT
/// (`Err`), which a NOR power cut never produces (a torn write yields deterministic
/// bytes, not a read error). A `false` return therefore flags a truncated
/// enumeration the caller must not read as "those keys are absent".
fn for_each_in<C: CacheImpl<u16>>(
    map: &mut MapStorage<u16, SharedFlash, C>,
    buf: &mut [u8],
    f: &mut dyn FnMut(u16),
) -> bool {
    let Ok(mut iter) = block_on(map.fetch_all_items(buf)) else {
        return false;
    };
    loop {
        match block_on(iter.next::<&[u8]>(buf)) {
            Ok(Some((key, _))) => f(key),
            Ok(None) => return true,
            Err(_) => return false,
        }
    }
}
