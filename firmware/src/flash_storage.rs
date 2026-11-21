// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! This board's instance of the store: the one flash peripheral shared by both
//! partitions, and the cache sizes its partitions need. The backend itself —
//! the two `sequential-storage` maps, the counter routing and the scrub lap — is
//! [`rsk_store`], where the fuzzer can cut its power and the emulator can run it.

mod quad;
mod sha256;
mod stream;

use core::cell::{Cell, RefCell, RefMut};
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
// * **counter** (128 KiB) — the counters in `rsk_fs::counter` (FIDO's two, OpenPGP's
//   `EF_SIG_COUNT`, the vendor's), rewritten on *every* signature/assertion.
//   That churn is what fills flash; isolating it here means it reclaims only its own
//   small pages (cheap — a handful of always-cached keys) instead of advancing the
//   main partition's ring into the credential pages (a multi-second cold-migration
//   stall). Fixed size — the counters need their own churn-isolated pages on any board.
const MAIN_LEN: usize = crate::env_u32(env!("PK_KVMAIN_LEN")) as usize;
const COUNTER_LEN: usize = 128 * 1024;
const MAIN_PAGES: usize = MAIN_LEN / SECTOR; // KVMAIN / SECTOR (352 at the 1408K default)

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
const MAIN_CACHE_KEYS: usize = rsk_store::authenticated::MAX_MAIN_ENTRIES;

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
/// The store this board runs.
type Backend = rsk_store::authenticated::Managed<SharedFlash, MainCache>;
pub struct FlashStorage;

#[derive(Clone, Copy)]
struct Context {
    inner: &'static RefCell<AsyncFlash>,
    sha256: &'static RefCell<sha256::Engine>,
    quad: &'static RefCell<quad::Engine>,
    backend: &'static RefCell<Backend>,
}

struct Core0Context {
    context: Cell<Option<Context>>,
}

// SAFETY: every accessor checks core0 before the cell; installation is
// single-shot before storage boot, and RefCell borrows cannot cross cores.
unsafe impl Sync for Core0Context {}

impl Core0Context {
    fn install(&self, context: Context) {
        assert_eq!(rp_pac::SIO.cpuid().read(), 0);
        assert!(self.context.get().is_none());
        self.context.set(Some(context));
    }

    fn get(&self) -> Context {
        assert_eq!(rp_pac::SIO.cpuid().read(), 0);
        self.context
            .get()
            .expect("flash context must precede storage boot")
    }

    fn backend(&self) -> RefMut<'_, Backend> {
        self.get().backend.borrow_mut()
    }
}

static CONTEXT: Core0Context = Core0Context {
    context: Cell::new(None),
};

#[cfg(not(rsk_small_flash))]
const fn unbound_storage() -> Backend {
    let main_start = crate::env_u32(env!("PK_KVMAIN_START"));
    let counter_start = crate::env_u32(env!("PK_KVCNT_START"));
    let layout = match rsk_store::authenticated::StoreLayout::new(
        main_start..counter_start,
        counter_start..counter_start + COUNTER_LEN as u32,
        FLASH_SIZE,
    ) {
        Ok(layout) => layout,
        Err(_) => panic!("invalid static storage layout"),
    };
    Backend::new_unbound(
        SharedFlash,
        layout,
        main_cache(),
        Some(sha256::digest),
        Some(sha256::erased),
    )
}

/// A `'static`, shared handle to the one flash peripheral, so the two partitions can
/// each own a `MapStorage` over it. `MapStorage` takes its flash *by value* and the
/// `Flash` peripheral is a singleton, so the two maps share it through this `RefCell`.
/// It is borrowed only inside one synchronous `block_on` op — `BlockingAsync` resolves
/// on the first poll and `block_on` never yields to another task, so the borrow can't
/// overlap with the other partition's.
#[derive(Clone, Copy)]
pub struct SharedFlash;

impl SharedFlash {
    fn context(&self) -> Context {
        CONTEXT.get()
    }
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
        let context = self.context();
        if let [byte] = bytes {
            let _owner = context.inner.borrow_mut();
            *byte = stream::read_byte(offset)?;
            return Ok(());
        }
        if let [first, second] = bytes {
            let _owner = context.inner.borrow_mut();
            [*first, *second] = stream::read_pair(offset)?;
            return Ok(());
        }
        if bytes.len() >= rsk_store::authenticated::ENTRY_BYTES
            && offset.is_multiple_of(4)
            && bytes.len().is_multiple_of(4)
        {
            context.quad.borrow_mut().ensure_mode();
            let _owner = context.inner.borrow_mut();
            return stream::read(offset, bytes);
        }
        block_on(context.inner.borrow_mut().read(offset, bytes))
    }
    fn capacity(&self) -> usize {
        FLASH_SIZE
    }
}
impl NorFlash for SharedFlash {
    const WRITE_SIZE: usize = <AsyncFlash as NorFlash>::WRITE_SIZE;
    const ERASE_SIZE: usize = <AsyncFlash as NorFlash>::ERASE_SIZE;
    async fn erase(&mut self, from: u32, to: u32) -> core::result::Result<(), Self::Error> {
        {
            crate::trustzone::mpu::with_flash_code(|| {
                block_on(self.context().inner.borrow_mut().erase(from, to))
            })
        }
    }
    async fn write(&mut self, offset: u32, bytes: &[u8]) -> core::result::Result<(), Self::Error> {
        {
            crate::trustzone::mpu::with_flash_code(|| {
                block_on(self.context().inner.borrow_mut().write(offset, bytes))
            })
        }
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
pub fn initialize_storage(
    flash: &'static RefCell<AsyncFlash>,
    main_range: Range<u32>,
    counter_range: Range<u32>,
    source: rsk_store::authenticated::KeySource,
) {
    debug_assert!((main_range.end - main_range.start) as usize == MAIN_LEN);
    debug_assert!((counter_range.end - counter_range.start) as usize == COUNTER_LEN);
    static QUAD: static_cell::StaticCell<RefCell<quad::Engine>> = static_cell::StaticCell::new();
    let quad = QUAD.init(RefCell::new(quad::Engine::new(flash)));
    static HASH: static_cell::StaticCell<RefCell<sha256::Engine>> = static_cell::StaticCell::new();
    let sha256 = HASH.init(RefCell::new(sha256::Engine::new()));
    #[cfg(not(rsk_small_flash))]
    static BACKEND: static_cell::ConstStaticCell<RefCell<Backend>> =
        static_cell::ConstStaticCell::new(RefCell::new(unbound_storage()));
    #[cfg(not(rsk_small_flash))]
    let backend = BACKEND.take();
    #[cfg(rsk_small_flash)]
    let backend = {
        // Runtime layout fields keep the large zero arrays out of the flash image.
        static BACKEND: static_cell::StaticCell<RefCell<Backend>> = static_cell::StaticCell::new();
        BACKEND.init_with(|| {
            let layout = rsk_store::authenticated::StoreLayout::new(
                main_range.clone(),
                counter_range.clone(),
                flash.borrow().capacity(),
            )
            .expect("invalid storage layout");
            RefCell::new(Backend::new_unbound(
                SharedFlash,
                layout,
                main_cache(),
                Some(sha256::digest),
                Some(sha256::erased),
            ))
        })
    };
    CONTEXT.install(Context {
        inner: flash,
        sha256,
        quad,
        backend,
    });
    let main_start = crate::env_u32(env!("PK_KVMAIN_START"));
    let counter_start = crate::env_u32(env!("PK_KVCNT_START"));
    assert_eq!(main_range, main_start..counter_start);
    assert_eq!(
        counter_range,
        counter_start..counter_start + COUNTER_LEN as u32
    );
    assert!(CONTEXT.backend().bind_source(source).is_ok());
}

impl rsk_fs::Storage for FlashStorage {
    const MAX_VALUE: usize = Backend::MAX_VALUE;

    fn mount(&mut self) -> rsk_sdk::error::Result<()> {
        CONTEXT.backend().mount()
    }
    fn boot(&mut self, epoch: [u8; 16]) -> rsk_sdk::error::Result<()> {
        CONTEXT.backend().boot(epoch)
    }
    fn state(&self) -> rsk_fs::storage::StorageState {
        CONTEXT.backend().state()
    }
    fn root_closed(&self) -> bool {
        CONTEXT.backend().root_closed()
    }
    fn administer(
        &mut self,
        action: rsk_fs::storage::StorageAction,
        epoch: [u8; 16],
    ) -> rsk_sdk::error::Result<()> {
        CONTEXT.backend().administer(action, epoch)
    }
    fn read(&mut self, fid: u16, bytes: &mut [u8]) -> Option<usize> {
        CONTEXT.backend().read(fid, bytes)
    }
    fn write(&mut self, fid: u16, bytes: &[u8]) -> rsk_sdk::error::Result<()> {
        CONTEXT.backend().write(fid, bytes)
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        CONTEXT.backend().remove(fid)
    }
    fn read_bound_counter(
        &mut self,
        fid: u16,
        out: &mut [u8],
    ) -> rsk_sdk::error::Result<Option<usize>> {
        CONTEXT.backend().read_bound_counter(fid, out)
    }
    fn write_bound_counter(&mut self, fid: u16, sealed: &[u8]) -> rsk_sdk::error::Result<bool> {
        CONTEXT.backend().write_bound_counter(fid, sealed)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        CONTEXT.backend().size(fid)
    }
    fn exists(&mut self, fid: u16) -> bool {
        CONTEXT.backend().exists(fid)
    }
    fn last_error(&self) -> bool {
        CONTEXT.backend().last_error()
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        CONTEXT.backend().for_each_key(f)
    }
    fn compact(&mut self) -> rsk_sdk::error::Result<()> {
        CONTEXT.backend().compact()
    }
}

const fn main_cache() -> MainCache {
    MainCache::new(
        ArrayPageStates::new(),
        ArrayPagePointers::new(),
        ArrayKeyPointers::new(),
    )
}

pub fn read_storage_root(out: &mut [u8; 32]) -> rsk_store::authenticated::RootRead {
    use rsk_rescue::otp_lock::KeyRows;
    use rsk_store::authenticated::RootRead;
    match crate::otp_keys::read_boot_mkek(out) {
        KeyRows::Blank => RootRead::Blank,
        KeyRows::Fused => RootRead::Fused,
        KeyRows::Unreadable => RootRead::Unreadable,
    }
}
