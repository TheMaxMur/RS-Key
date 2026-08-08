// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! This board's instance of the store: the one flash peripheral shared by both
//! partitions, and the cache sizes its partitions need. The backend itself —
//! the two `sequential-storage` maps, the counter routing and the scrub lap — is
//! [`rsk_store`], where the fuzzer can cut its power and the emulator can run it.

use core::cell::RefCell;
use core::ops::Range;

use embassy_embedded_hal::adapter::BlockingAsync;
use embassy_futures::block_on;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::peripherals::FLASH;
use embedded_storage_async::nor_flash::{ErrorType, MultiwriteNorFlash, NorFlash, ReadNorFlash};
use sequential_storage::cache::Cache;
use sequential_storage::cache::key_pointers::ArrayKeyPointers;
use sequential_storage::cache::page_pointers::ArrayPagePointers;
use sequential_storage::cache::page_states::ArrayPageStates;

/// External QSPI flash size in bytes — `FLASH_SIZE` at build time (default 4 MB,
/// the Waveshare RP2350-One), baked by build.rs as `PK_FLASH_SIZE`. The same
/// value drives the generated `memory.x`, so the KV partitions track the chip.
pub const FLASH_SIZE: usize = crate::env_u32(env!("PK_FLASH_SIZE")) as usize;

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

/// The store this board runs.
pub type FlashStorage = rsk_store::SeqStorage<SharedFlash, MainCache, CounterCache>;

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
/// (called once from `main` before constructing the store).
pub fn wrap_flash(flash: Flash<'static, FLASH, Blocking, FLASH_SIZE>) -> AsyncFlash {
    BlockingAsync::new(flash)
}

/// Build the store over this board's two partitions. `main_range` /
/// `counter_range` are the erase-aligned windows from `memory.x`.
pub fn new_storage(
    flash: &'static RefCell<AsyncFlash>,
    main_range: Range<u32>,
    counter_range: Range<u32>,
) -> FlashStorage {
    debug_assert!((main_range.end - main_range.start) as usize == MAIN_LEN);
    debug_assert!((counter_range.end - counter_range.start) as usize == COUNTER_LEN);
    FlashStorage::new(
        SharedFlash { inner: flash },
        main_range,
        counter_range,
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
