#![cfg_attr(not(any(test, doctest, feature = "std", fuzzing)), no_std)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]
#![allow(clippy::cast_possible_truncation)]

use core::num::NonZeroUsize;
use core::{
    fmt::Debug,
    marker::PhantomData,
    ops::{Deref, DerefMut, Range},
};
use embedded_storage_async::nor_flash::NorFlash;
use map::SerializationError;

#[cfg(feature = "alloc")]
mod alloc_impl;
#[cfg(feature = "arrayvec")]
mod arrayvec_impl;
pub mod cache;
#[cfg(feature = "heapless-09")]
mod heapless_09_impl;
#[cfg(feature = "heapless")]
mod heapless_impl;
mod item;
pub mod map;
pub mod queue;

#[cfg(any(test, doctest, feature = "_test"))]
/// An in-memory flash type that can be used for mocking.
pub mod mock_flash;

/// The biggest wordsize we support.
///
/// Stm32 internal flash has 256-bit words, so 32 bytes.
/// Many flashes have 4-byte or 1-byte words.
const MAX_WORD_SIZE: usize = 32;

// Four cleared bits tolerate partial marker writes and occasional bit flips.
fn marker_marked(bytes: &[u8]) -> bool {
    const HALF_MARKER_BITS: u32 = 4;
    bytes.iter().map(|byte| byte.count_zeros()).sum::<u32>() >= HALF_MARKER_BITS
}

/// The generic object that manages the flash.
/// This is mostly an internal type.
///
/// To create real instances, call:
/// - map: [`map::MapStorage::new`]
/// - queue: [`queue::QueueStorage::new`]
///
/// You can [`Self::destroy`] this type to get back the flash and the cache.
struct GenericStorage<S: NorFlash, C: CacheImpl<KEY>, KEY> {
    flash: S,
    flash_range: Range<u32>,
    cache: C,
    _phantom: PhantomData<KEY>,
}

impl<S: NorFlash, C: CacheImpl<KEY>, KEY> GenericStorage<S, C, KEY> {
    /// Resets the flash in the entire given flash range.
    ///
    /// This is just a thin helper function as it just calls the flash's erase function.
    pub async fn erase_all(&mut self) -> Result<(), Error<S::Error>> {
        self.flash
            .erase(self.flash_range.start, self.flash_range.end)
            .await
            .map_err(|e| Error::Storage {
                value: e,
                #[cfg(feature = "_test")]
                backtrace: std::backtrace::Backtrace::capture(),
            })
    }

    /// Get the minimal overhead size per stored item for the given flash type.
    ///
    /// The associated data of each item is additionally padded to a full flash word size, but that's not part of this number.\
    /// This means the full item length is `returned number + (data length).next_multiple_of(S::WORD_SIZE)`.
    #[must_use]
    pub const fn item_overhead_size() -> u32 {
        item::ItemHeader::data_address::<S>(0)
    }

    async fn try_general_repair(&mut self) -> Result<(), Error<S::Error>> {
        // Loop through the pages and get their state. If one returns the corrupted error,
        // the page is likely half-erased. Fix for that is to re-erase again to hopefully finish the job.
        for page_index in self.get_pages(0) {
            if matches!(
                self.get_page_state(page_index).await,
                Err(Error::Corrupted { .. })
            ) {
                self.open_page(page_index).await?;
            }
        }

        #[cfg(fuzzing)]
        eprintln!("General repair has been called");

        Ok(())
    }

    /// Find the first page that is in the given page state.
    ///
    /// The search starts at `starting_page_index` (and wraps around back to 0 if required)
    async fn find_first_page(
        &mut self,
        starting_page_index: usize,
        page_state: PageState,
    ) -> Result<Option<usize>, Error<S::Error>> {
        for page_index in self.get_pages(starting_page_index) {
            if page_state == self.get_page_state_cached(page_index).await? {
                return Ok(Some(page_index));
            }
        }

        Ok(None)
    }

    fn page_count(&self) -> NonZeroUsize {
        let page_count = self.flash_range.len() / S::ERASE_SIZE;
        // Do a max 1 on the page count to prevent a panic. We know it's never 0 because it's checked in the constructor, but the compiler doesn't know
        NonZeroUsize::new(page_count.max(1)).unwrap()
    }

    /// Get all pages in the flash range from the given start to end (that might wrap back to 0)
    fn get_pages(
        &self,
        starting_page_index: usize,
    ) -> impl DoubleEndedIterator<Item = usize> + use<S, C, KEY> {
        let page_count = self.page_count();
        (0..page_count.get()).map(move |index| (index + starting_page_index) % page_count)
    }

    /// Get the next page index (wrapping around to 0 if required)
    fn next_page(&self, page_index: usize) -> usize {
        let page_count = self.page_count();
        (page_index + 1) % page_count
    }

    /// Get the previous page index (wrapping around to the biggest page if required)
    fn previous_page(&self, page_index: usize) -> usize {
        let page_count = self.page_count();

        match page_index.checked_sub(1) {
            Some(new_page_index) => new_page_index,
            None => page_count.get() - 1,
        }
    }

    /// Get the state of the page located at the given index
    async fn get_page_state_cached(
        &mut self,
        page_index: usize,
    ) -> Result<PageState, Error<S::Error>> {
        if let Some(cached_page_state) = self.cache.get_page_state(page_index) {
            if cfg!(feature = "_check-cache") {
                let discovered_state = self.get_page_state(page_index).await?;
                assert_eq!(
                    cached_page_state, discovered_state,
                    "At page index: {page_index}",
                );
            }

            return Ok(cached_page_state);
        }

        let discovered_state = self.get_page_state(page_index).await?;

        // Not dirty because nothing changed and nothing can be inconsistent
        self.cache
            .notice_page_state(page_index, discovered_state, false);

        Ok(discovered_state)
    }

    /// Get the state of the page located at the given index
    async fn get_page_state(&mut self, page_index: usize) -> Result<PageState, Error<S::Error>> {
        let page_address = calculate_page_address::<S>(self.flash_range.clone(), page_index);

        let mut buffer = [0; MAX_WORD_SIZE];
        self.flash
            .read(page_address, &mut buffer[..S::READ_SIZE])
            .await
            .map_err(|e| Error::Storage {
                value: e,
                #[cfg(feature = "_test")]
                backtrace: std::backtrace::Backtrace::capture(),
            })?;
        let start_marked = marker_marked(&buffer[..S::READ_SIZE]);

        self.flash
            .read(
                page_address + (S::ERASE_SIZE - S::READ_SIZE) as u32,
                &mut buffer[..S::READ_SIZE],
            )
            .await
            .map_err(|e| Error::Storage {
                value: e,
                #[cfg(feature = "_test")]
                backtrace: std::backtrace::Backtrace::capture(),
            })?;
        let end_marked = marker_marked(&buffer[..S::READ_SIZE]);

        let discovered_state = match (start_marked, end_marked) {
            (true, true) => PageState::Closed,
            (true, false) => PageState::PartialOpen,
            // Probably an interrupted erase
            (false, true) => {
                return Err(Error::Corrupted {
                    #[cfg(feature = "_test")]
                    backtrace: std::backtrace::Backtrace::capture(),
                });
            }
            (false, false) => PageState::Open,
        };

        Ok(discovered_state)
    }

    /// Erase the page to open it again
    async fn open_page(&mut self, page_index: usize) -> Result<(), Error<S::Error>> {
        self.cache
            .notice_page_state(page_index, PageState::Open, true);

        let page_address = calculate_page_address::<S>(self.flash_range.clone(), page_index);
        let page_end_address =
            calculate_page_end_address::<S>(self.flash_range.clone(), page_index);

        self.flash
            .erase(page_address, page_end_address)
            .await
            .map_err(|e| Error::Storage {
                value: e,
                #[cfg(feature = "_test")]
                backtrace: std::backtrace::Backtrace::capture(),
            })?;

        Ok(())
    }

    /// Fully closes a page by writing both the start and end marker
    async fn close_page(&mut self, page_index: usize) -> Result<(), Error<S::Error>> {
        let current_state = self.partial_close_page(page_index).await?;

        if current_state != PageState::PartialOpen {
            return Ok(());
        }

        self.cache
            .notice_page_state(page_index, PageState::Closed, true);

        let buffer = AlignedBuf([MARKER; MAX_WORD_SIZE]);
        let page_end_address =
            calculate_page_end_address::<S>(self.flash_range.clone(), page_index)
                - S::WORD_SIZE as u32;
        // Close the end marker
        self.flash
            .write(page_end_address, &buffer[..S::WORD_SIZE])
            .await
            .map_err(|e| Error::Storage {
                value: e,
                #[cfg(feature = "_test")]
                backtrace: std::backtrace::Backtrace::capture(),
            })?;

        Ok(())
    }

    /// Partially close a page by writing the start marker
    async fn partial_close_page(
        &mut self,
        page_index: usize,
    ) -> Result<PageState, Error<S::Error>> {
        let current_state = self.get_page_state_cached(page_index).await?;

        if current_state != PageState::Open {
            return Ok(current_state);
        }

        let new_state = match current_state {
            PageState::Closed => PageState::Closed,
            PageState::PartialOpen | PageState::Open => PageState::PartialOpen,
        };

        self.cache.notice_page_state(page_index, new_state, true);

        let buffer = AlignedBuf([MARKER; MAX_WORD_SIZE]);
        let page_start_address = calculate_page_address::<S>(self.flash_range.clone(), page_index);
        // Close the start marker
        self.flash
            .write(page_start_address, &buffer[..S::WORD_SIZE])
            .await
            .map_err(|e| Error::Storage {
                value: e,
                #[cfg(feature = "_test")]
                backtrace: std::backtrace::Backtrace::capture(),
            })?;

        Ok(new_state)
    }

    #[cfg(any(test, feature = "std", fuzzing))]
    /// Print all items in flash to the returned string
    pub async fn print_items(&mut self) -> String {
        use crate::NorFlashExt;
        use std::fmt::Write;

        let mut buf = [0; 1024 * 16];

        let mut s = String::new();

        writeln!(s, "Items in flash:").unwrap();

        for page_index in self.get_pages(0) {
            writeln!(
                s,
                "  Page {page_index} ({}):",
                match self.get_page_state(page_index).await {
                    Ok(value) => format!("{value:?}"),
                    Err(e) => format!("Error ({e:?})"),
                },
            )
            .unwrap();
            let page_data_start =
                crate::calculate_page_address::<S>(self.flash_range.clone(), page_index)
                    + S::WORD_SIZE as u32;
            let page_data_end =
                crate::calculate_page_end_address::<S>(self.flash_range.clone(), page_index)
                    - S::WORD_SIZE as u32;

            let mut it = crate::item::ItemHeaderIter::new(page_data_start, page_data_end);
            while let (Some(header), item_address) =
                it.traverse(&mut self.flash, |_, _| false).await.unwrap()
            {
                let next_item_address = header.next_item_address::<S>(item_address);
                let maybe_item = match header
                    .read_item(&mut self.flash, &mut buf, item_address, page_data_end)
                    .await
                {
                    Ok(maybe_item) => maybe_item,
                    Err(e) => {
                        writeln!(
                            s,
                            "   Item COULD NOT BE READ at {item_address}..{next_item_address}"
                        )
                        .unwrap();

                        println!("{s}");
                        panic!("{e:?}");
                    }
                };

                writeln!(
                    s,
                    "   Item {maybe_item:?} at {item_address}..{next_item_address}"
                )
                .unwrap();
            }
        }

        s
    }

    /// Destroy the instance to get back the flash and the cache.
    ///
    /// The cache can be passed to a new storage instance, but only for the same flash region and if nothing has changed in flash.
    pub fn destroy(self) -> (S, C) {
        (self.flash, self.cache)
    }

    /// Get a reference to the flash. Mutating the memory is at your own risk.
    pub const fn flash(&mut self) -> &mut S {
        &mut self.flash
    }

    /// Get the flash range being used
    pub const fn flash_range(&self) -> Range<u32> {
        self.flash_range.start..self.flash_range.end
    }
}

/// Round up the the given number to align with the wordsize of the flash.
/// If the number is already aligned, it is not changed.
const fn round_up_to_alignment<S: NorFlash>(value: u32) -> u32 {
    value.next_multiple_of(S::WORD_SIZE as u32)
}

/// Round up the the given number to align with the wordsize of the flash.
/// If the number is already aligned, it is not changed.
const fn round_up_to_alignment_usize<S: NorFlash>(value: usize) -> usize {
    value.next_multiple_of(S::WORD_SIZE)
}

/// Round down the the given number to align with the wordsize of the flash.
/// If the number is already aligned, it is not changed.
const fn round_down_to_alignment<S: NorFlash>(value: u32) -> u32 {
    let alignment = S::WORD_SIZE as u32;
    (value / alignment) * alignment
}

/// Round down the the given number to align with the wordsize of the flash.
/// If the number is already aligned, it is not changed.
const fn round_down_to_alignment_usize<S: NorFlash>(value: usize) -> usize {
    round_down_to_alignment::<S>(value as u32) as usize
}

/// Calculate the first address of the given page
const fn calculate_page_address<S: NorFlash>(flash_range: Range<u32>, page_index: usize) -> u32 {
    flash_range.start + (S::ERASE_SIZE * page_index) as u32
}

/// Calculate the last address (exclusive) of the given page
const fn calculate_page_end_address<S: NorFlash>(
    flash_range: Range<u32>,
    page_index: usize,
) -> u32 {
    flash_range.start + (S::ERASE_SIZE * (page_index + 1)) as u32
}

/// Get the page index from any address located inside that page
const fn calculate_page_index<S: NorFlash>(flash_range: Range<u32>, address: u32) -> usize {
    (address - flash_range.start) as usize / S::ERASE_SIZE
}

const fn calculate_page_size<S: NorFlash>() -> usize {
    // Page minus the two page status words
    S::ERASE_SIZE - S::WORD_SIZE * 2
}

/// The marker being used for page states
const MARKER: u8 = 0;

/// The state of a page
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PageState {
    /// This page was fully written and has now been sealed
    Closed,
    /// This page has been written to, but may have some space left over
    PartialOpen,
    /// This page is fully erased
    Open,
}

#[allow(dead_code)]
impl PageState {
    /// Returns `true` if the page state is [`Closed`].
    ///
    /// [`Closed`]: PageState::Closed
    #[must_use]
    fn is_closed(self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Returns `true` if the page state is [`PartialOpen`].
    ///
    /// [`PartialOpen`]: PageState::PartialOpen
    #[must_use]
    fn is_partial_open(self) -> bool {
        matches!(self, Self::PartialOpen)
    }

    /// Returns `true` if the page state is [`Open`].
    ///
    /// [`Open`]: PageState::Open
    #[must_use]
    fn is_open(self) -> bool {
        matches!(self, Self::Open)
    }
}

/// The main error type
#[non_exhaustive]
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error<S> {
    /// An error in the storage (flash)
    Storage {
        /// The error value
        value: S,
        #[cfg(feature = "_test")]
        /// Backtrace made at the construction of the error
        backtrace: std::backtrace::Backtrace,
    },
    /// The item cannot be stored anymore because the storage is full.
    FullStorage,
    /// It's been detected that the memory is likely corrupted.
    /// You may want to erase the memory to recover.
    Corrupted {
        #[cfg(feature = "_test")]
        /// Backtrace made at the construction of the error
        backtrace: std::backtrace::Backtrace,
    },
    /// There's a bug in the logic of the crate. Please report!
    /// This would otherwise have been a panic
    LogicBug {
        #[cfg(feature = "_test")]
        /// Backtrace made at the construction of the error
        backtrace: std::backtrace::Backtrace,
    },
    /// A provided buffer was to big to be used
    BufferTooBig,
    /// A provided buffer was to small to be used (usize is size needed)
    BufferTooSmall(usize),
    /// A serialization error (from the key or value)
    SerializationError(SerializationError),
    /// The item does not fit in flash, ever.
    /// This is different from [`Error::FullStorage`] because this item is too big to fit even in empty flash.
    ///
    /// See the readme for more info about the constraints on item sizes.
    ItemTooBig,
}

impl<S> From<SerializationError> for Error<S> {
    fn from(v: SerializationError) -> Self {
        Self::SerializationError(v)
    }
}

impl<S: PartialEq> PartialEq for Error<S> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Storage { value: l_value, .. }, Self::Storage { value: r_value, .. }) => {
                l_value == r_value
            }
            (Self::BufferTooSmall(l0), Self::BufferTooSmall(r0)) => l0 == r0,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

impl<S> core::fmt::Display for Error<S>
where
    S: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Storage { value, .. } => write!(f, "Storage error: {value}"),
            Error::FullStorage => write!(f, "Storage is full"),
            #[cfg(not(feature = "_test"))]
            Error::Corrupted { .. } => write!(f, "Storage is corrupted"),
            #[cfg(feature = "_test")]
            Error::Corrupted { backtrace } => write!(f, "Storage is corrupted\n{backtrace}"),
            #[cfg(not(feature = "_test"))]
            Error::LogicBug { .. } => write!(f, "Logic bug"),
            #[cfg(feature = "_test")]
            Error::LogicBug { backtrace } => write!(f, "Logic bug\n{backtrace}"),
            Error::BufferTooBig => write!(f, "A provided buffer was to big to be used"),
            Error::BufferTooSmall(needed) => write!(
                f,
                "A provided buffer was to small to be used. Needed was {needed}"
            ),
            Error::SerializationError(value) => write!(f, "Map value error: {value}"),
            Error::ItemTooBig => write!(f, "The item is too big to fit in the flash"),
        }
    }
}

impl<S> core::error::Error for Error<S> where S: core::fmt::Display + core::fmt::Debug {}

// Type representing buffer aligned to 4 byte boundary.
#[repr(align(4))]
pub(crate) struct AlignedBuf<const SIZE: usize>(pub(crate) [u8; SIZE]);
impl<const SIZE: usize> Deref for AlignedBuf<SIZE> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const SIZE: usize> DerefMut for AlignedBuf<SIZE> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Extension trait to get the overall word size, which is the largest of the write and read word size
trait NorFlashExt {
    /// The largest of the write and read word size
    const WORD_SIZE: usize;
}

impl<S: NorFlash> NorFlashExt for S {
    const WORD_SIZE: usize = {
        assert_read_write_sizes(Self::WRITE_SIZE, Self::READ_SIZE);

        if Self::WRITE_SIZE > Self::READ_SIZE {
            Self::WRITE_SIZE
        } else {
            Self::READ_SIZE
        }
    };
}

#[track_caller]
const fn assert_read_write_sizes(write_size: usize, read_size: usize) {
    assert!(
        write_size.is_multiple_of(read_size) || read_size.is_multiple_of(write_size),
        "Only flash with read and write sizes that are multiple of each other are supported"
    );
}

macro_rules! run_with_auto_repair {
    (function = $function:expr, repair = $repair_function:expr) => {
        match $function {
            Err(Error::Corrupted {
                #[cfg(feature = "_test")]
                    backtrace: _backtrace,
                ..
            }) => {
                #[cfg(all(feature = "_test", fuzzing))]
                eprintln!(
                    "### Encountered curruption! Repairing now. Originated from:\n{_backtrace:#}"
                );
                $repair_function;
                $function
            }
            val => val,
        }
    };
}

pub(crate) use run_with_auto_repair;

use crate::cache::CacheImpl;

#[cfg(test)]
mod tests {
    use crate::cache::Cache;

    use super::*;
    use futures_test::test;

    type MockFlash = mock_flash::MockFlashBase<4, 4, 64>;

    async fn write_aligned(
        flash: &mut MockFlash,
        offset: u32,
        bytes: &[u8],
    ) -> Result<(), mock_flash::MockFlashError> {
        let mut buf = AlignedBuf([0; 256]);
        buf[..bytes.len()].copy_from_slice(bytes);
        flash.write(offset, &buf[..bytes.len()]).await
    }

    #[test]
    async fn test_find_pages() {
        // Page setup:
        // 0: closed
        // 1: closed
        // 2: partial-open
        // 3: open

        let mut flash = MockFlash::default();

        // Page 0 markers
        write_aligned(&mut flash, 0x000, &[MARKER, 0, 0, 0])
            .await
            .unwrap();
        write_aligned(&mut flash, 0x100 - 4, &[0, 0, 0, MARKER])
            .await
            .unwrap();
        // Page 1 markers
        write_aligned(&mut flash, 0x100, &[MARKER, 0, 0, 0])
            .await
            .unwrap();
        write_aligned(&mut flash, 0x200 - 4, &[0, 0, 0, MARKER])
            .await
            .unwrap();
        // Page 2 markers
        write_aligned(&mut flash, 0x200, &[MARKER, 0, 0, 0])
            .await
            .unwrap();

        let mut storage = GenericStorage {
            flash: flash,
            flash_range: 0x000..0x400,
            cache: Cache::new_uncached(),
            _phantom: PhantomData::<()>,
        };

        assert_eq!(
            storage.find_first_page(0, PageState::Open).await.unwrap(),
            Some(3)
        );
        assert_eq!(
            storage
                .find_first_page(0, PageState::PartialOpen)
                .await
                .unwrap(),
            Some(2)
        );
        assert_eq!(
            storage
                .find_first_page(1, PageState::PartialOpen)
                .await
                .unwrap(),
            Some(2)
        );
        assert_eq!(
            storage
                .find_first_page(2, PageState::PartialOpen)
                .await
                .unwrap(),
            Some(2)
        );
        assert_eq!(
            storage.find_first_page(3, PageState::Open).await.unwrap(),
            Some(3)
        );

        storage.flash_range = 0x000..0x200;
        assert_eq!(
            storage
                .find_first_page(0, PageState::PartialOpen)
                .await
                .unwrap(),
            None
        );
        storage.flash_range = 0x000..0x400;

        assert_eq!(
            storage.find_first_page(0, PageState::Closed).await.unwrap(),
            Some(0)
        );
        assert_eq!(
            storage.find_first_page(1, PageState::Closed).await.unwrap(),
            Some(1)
        );
        assert_eq!(
            storage.find_first_page(2, PageState::Closed).await.unwrap(),
            Some(0)
        );
        assert_eq!(
            storage.find_first_page(3, PageState::Closed).await.unwrap(),
            Some(0)
        );

        storage.flash_range = 0x200..0x400;
        assert_eq!(
            storage.find_first_page(0, PageState::Closed).await.unwrap(),
            None
        );
    }

    #[test]
    async fn read_write_sizes() {
        assert_read_write_sizes(1, 1);
        assert_read_write_sizes(1, 4);
        assert_read_write_sizes(4, 4);
        assert_read_write_sizes(4, 1);
    }
}
