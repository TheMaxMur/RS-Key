//! Module implementing all things cache related

use core::marker::PhantomData;
use core::{fmt::Debug, ops::Range};

use embedded_storage_async::nor_flash::NorFlash;

use crate::cache::key_pointers::KeyPointersCache;
use crate::cache::page_pointers::SealedPagePointersCache;
use crate::cache::page_states::SealedPageStatesCache;
use crate::{PageState, item::ItemHeader};

use key_pointers::SealedKeyPointersCache;
use page_pointers::PagePointersCache;
use page_states::PageStatesCache;

pub mod key_pointers;
pub mod page_pointers;
pub mod page_states;

mod tests;

/// Trait so we can collapse generics
pub(crate) trait SealedCacheImpl {
    /// True if the cache might be inconsistent
    fn is_dirty(&mut self) -> bool;
    /// Mark the cache as potentially inconsistent with reality
    fn mark_dirty(&mut self);
    /// Mark the cache as being consistent with reality
    fn unmark_dirty(&mut self);

    /// Get the cache state of the requested page
    fn get_page_state(&mut self, page_index: usize) -> Option<PageState>;
    /// Let the cache know a page state changed
    ///
    /// The dirty flag should be true if the page state is actually going to be changed.
    /// Keep it false if we're only discovering the state.
    fn notice_page_state(&mut self, page_index: usize, new_state: PageState, dirty: bool);

    /// Get the cached address of the first non-erased item in the requested page.
    ///
    /// This is purely for the items that get erased from start to end.
    fn first_item_after_erased(&mut self, page_index: usize) -> Option<u32>;
    /// Get the cached address of the first free unwritten item in the requested page.
    fn first_item_after_written(&mut self, page_index: usize) -> Option<u32>;
    /// Let the cache know that an item has been written to flash
    fn notice_item_written<S: NorFlash>(
        &mut self,
        flash_range: Range<u32>,
        item_address: u32,
        item_header: &ItemHeader,
    );
    /// Let the cache know that an item has been erased from flash
    fn notice_item_erased<S: NorFlash>(
        &mut self,
        flash_range: Range<u32>,
        item_address: u32,
        item_header: &ItemHeader,
    );
    /// Erase all cache information. Something was found that means the cache doesn't hold up anymore.
    fn invalidate_cache_state(&mut self);
}
pub(crate) trait SealedKeyCacheImpl<KEY> {
    /// Get the location of the item with the given key
    fn key_location(&mut self, key: &KEY) -> Option<u32>;
    /// Let the cache know that an item was found with the given key at the given address
    fn notice_key_location(&mut self, key: &KEY, item_address: u32, dirty: bool);
    /// The item with the given key was erased
    fn notice_key_erased(&mut self, key: &KEY);
}

#[allow(private_bounds)]
/// Trait for collapsing multiple generics into one.
/// Wherever this trait is used, pass an instance of [Cache].
pub trait CacheImpl<KEY>: SealedCacheImpl + SealedKeyCacheImpl<KEY> {}

/// A cache object of which the various things it keeps track of can be configured..
///
/// This cache has to be kept around and passed to *every* api call to the same memory region until the cache gets discarded.
///
/// Valid usecase:\
/// `Create cache 1` -> `use 1` -> `use 1` -> `create cache 2` -> `use 2` -> `use 2`
///
/// Invalid usecase:\
/// `Create cache 1` -> `use 1` -> `create cache 2` -> `use 2` -> `❌ use 1 ❌`
///
/// Make sure the page count is correct when it has to be provided.
/// If the number is lower than the actual amount, the code will panic.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Cache<
    PAGE: PageStatesCache,
    POINTERS: PagePointersCache,
    KEYS: KeyPointersCache<KEY>,
    KEY = (),
> {
    dirt_tracker: DirtTracker,
    page_states: PAGE,
    page_pointers: POINTERS,
    key_pointers: KEYS,
    _phantom: PhantomData<KEY>,
}

impl<PAGE: PageStatesCache, POINTERS: PagePointersCache, KEYS: KeyPointersCache<KEY>, KEY>
    Cache<PAGE, POINTERS, KEYS, KEY>
{
    /// Create a new cache object from the given subcaches
    pub const fn new(page_states: PAGE, page_pointers: POINTERS, key_pointers: KEYS) -> Self {
        Self {
            dirt_tracker: DirtTracker::new(),
            page_states,
            page_pointers,
            key_pointers,
            _phantom: PhantomData,
        }
    }
}

impl<KEY> Cache<Uncached, Uncached, Uncached, KEY> {
    /// Create a new cache object that doesn't cache anything
    pub const fn new_uncached() -> Self {
        Self {
            dirt_tracker: DirtTracker::new(),
            page_states: Uncached,
            page_pointers: Uncached,
            key_pointers: Uncached,
            _phantom: PhantomData,
        }
    }
}

impl<PAGE: PageStatesCache, POINTERS: PagePointersCache, KEYS: KeyPointersCache<KEY>, KEY>
    SealedCacheImpl for Cache<PAGE, POINTERS, KEYS, KEY>
{
    /// True if the cache might be inconsistent
    fn is_dirty(&mut self) -> bool {
        self.dirt_tracker.is_dirty()
    }

    /// Mark the cache as potentially inconsistent with reality
    fn mark_dirty(&mut self) {
        self.dirt_tracker.mark_dirty();
    }

    /// Mark the cache as being consistent with reality
    fn unmark_dirty(&mut self) {
        self.dirt_tracker.unmark_dirty();
    }

    /// Get the cache state of the requested page
    fn get_page_state(&mut self, page_index: usize) -> Option<PageState> {
        self.page_states.get_page_state(page_index)
    }

    /// Let the cache know a page state changed
    ///
    /// The dirty flag should be true if the page state is actually going to be changed.
    /// Keep it false if we're only discovering the state.
    fn notice_page_state(&mut self, page_index: usize, new_state: PageState, dirty: bool) {
        if dirty {
            self.mark_dirty();
        }
        self.page_states.notice_page_state(page_index, new_state);
        self.page_pointers.notice_page_state(page_index, new_state);
    }

    /// Get the cached address of the first non-erased item in the requested page.
    ///
    /// This is purely for the items that get erased from start to end.
    fn first_item_after_erased(&mut self, page_index: usize) -> Option<u32> {
        self.page_pointers.first_item_after_erased(page_index)
    }

    /// Get the cached address of the first free unwritten item in the requested page.
    fn first_item_after_written(&mut self, page_index: usize) -> Option<u32> {
        self.page_pointers.first_item_after_written(page_index)
    }

    /// Let the cache know that an item has been written to flash
    fn notice_item_written<S: NorFlash>(
        &mut self,
        flash_range: Range<u32>,
        item_address: u32,
        item_header: &ItemHeader,
    ) {
        self.mark_dirty();
        self.page_pointers
            .notice_item_written::<S>(flash_range, item_address, item_header);
    }

    /// Let the cache know that an item has been erased from flash
    fn notice_item_erased<S: NorFlash>(
        &mut self,
        flash_range: Range<u32>,
        item_address: u32,
        item_header: &ItemHeader,
    ) {
        self.mark_dirty();
        self.page_pointers
            .notice_item_erased::<S>(flash_range, item_address, item_header);
    }

    fn invalidate_cache_state(&mut self) {
        self.dirt_tracker.unmark_dirty();
        self.page_states.invalidate_cache_state();
        self.page_pointers.invalidate_cache_state();
        self.key_pointers.invalidate_cache_state();
    }
}

impl<PAGE: PageStatesCache, POINTERS: PagePointersCache, KEYS: KeyPointersCache<KEY>, KEY>
    SealedKeyCacheImpl<KEY> for Cache<PAGE, POINTERS, KEYS, KEY>
{
    fn key_location(&mut self, key: &KEY) -> Option<u32> {
        self.key_pointers.key_location(key)
    }

    fn notice_key_location(&mut self, key: &KEY, item_address: u32, dirty: bool) {
        if dirty {
            self.mark_dirty();
        }
        self.key_pointers.notice_key_location(key, item_address);
    }

    fn notice_key_erased(&mut self, key: &KEY) {
        self.mark_dirty();
        self.key_pointers.notice_key_erased(key);
    }
}

impl<PAGE: PageStatesCache, POINTERS: PagePointersCache, KEYS: KeyPointersCache<KEY>, KEY>
    CacheImpl<KEY> for Cache<PAGE, POINTERS, KEYS, KEY>
{
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct DirtTracker {
    /// Managed from the library code.
    ///
    /// When true, the cache and/or flash has changed and things might not be fully
    /// consistent if there's an early return due to error.
    dirty: bool,
}

impl DirtTracker {
    pub const fn new() -> Self {
        DirtTracker { dirty: false }
    }

    /// True if the cache might be inconsistent
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark the cache as potentially inconsistent with reality
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Mark the cache as being consistent with reality
    pub fn unmark_dirty(&mut self) {
        self.dirty = false;
    }
}

/// A cache object implementing no cache.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Uncached;

impl SealedPageStatesCache for Uncached {
    fn get_page_state(&self, _page_index: usize) -> Option<PageState> {
        None
    }
    fn notice_page_state(&mut self, _page_index: usize, _new_state: PageState) {}
    fn invalidate_cache_state(&mut self) {}
}
impl PageStatesCache for Uncached {}

impl SealedPagePointersCache for Uncached {
    fn first_item_after_erased(&self, _page_index: usize) -> Option<u32> {
        None
    }
    fn first_item_after_written(&self, _page_index: usize) -> Option<u32> {
        None
    }
    fn notice_item_written<S: NorFlash>(
        &mut self,
        _flash_range: Range<u32>,
        _item_address: u32,
        _item_header: &ItemHeader,
    ) {
    }
    fn notice_item_erased<S: NorFlash>(
        &mut self,
        _flash_range: Range<u32>,
        _item_address: u32,
        _item_header: &ItemHeader,
    ) {
    }
    fn notice_page_state(&mut self, _page_index: usize, _new_state: PageState) {}
    fn invalidate_cache_state(&mut self) {}
}
impl PagePointersCache for Uncached {}

impl<KEY> SealedKeyPointersCache<KEY> for Uncached {
    fn key_location(&self, _key: &KEY) -> Option<u32> {
        None
    }
    fn notice_key_location(&mut self, _key: &KEY, _item_address: u32) {}
    fn notice_key_erased(&mut self, _key: &KEY) {}
    fn invalidate_cache_state(&mut self) {}
}
impl<KEY> KeyPointersCache<KEY> for Uncached {}
