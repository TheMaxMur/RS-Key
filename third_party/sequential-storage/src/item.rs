//! Module that implements storing raw items in flash.
//! This module is page-unaware. This means that start and end addresses should be the actual
//! start and end addresses that don't include the page markers.
//!
//! Memory layout of item:
//! ```text
//! ┌──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┐
//! │      :      :      :      │      :      │      :      │  :  :  :  :  :  │  :  :  :  :  :  :  :  :  :  │  :  :  :  :  :  │
//! │            CRC            │   Length    │   Length'   │Pad to word align│            Data             │Pad to word align│
//! │      :      :      :      │      :      │      :      │  :  :  :  :  :  │  :  :  :  :  :   :  :  :  : │  :  :  :  :  :  │
//! └──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴───┴──┴──┴──┴─┴──┴──┴──┴──┴──┴──┘
//! 0      1      2      3      4      5      6      7      8                 8+padding                     8+padding+length  8+padding+length+endpadding
//! ```
//!
//! An item consists of an [`ItemHeader`] and some data.
//! The header has a length field that encodes the length of the data, a [`crc16`] of the length (`Length'`)
//! and a crc field that encodes the checksum of the data.
//!
//! If the crc is 0, then the item is counted as being erased.
//! The crc is calculated by [`adapted_crc32`] which never produces a 0 value on its own
//! and has some other modifications to make corruption less likely to happen.
//!

use core::num::{NonZero, NonZeroU32};
use core::ops::Range;

use embedded_storage_async::nor_flash::{MultiwriteNorFlash, NorFlash};

use crate::{
    AlignedBuf, Error, GenericStorage, MAX_WORD_SIZE, NorFlashExt, PageState,
    cache::{CacheImpl, SealedCacheImpl},
    calculate_page_address, calculate_page_end_address, calculate_page_index,
    round_down_to_alignment, round_down_to_alignment_usize, round_up_to_alignment,
    round_up_to_alignment_usize,
};

#[derive(Debug, Clone)]
pub(crate) struct ItemHeader {
    /// Length of the item payload (so not including the header and not including word alignment)
    pub(crate) length: u16,
    pub(crate) crc: Option<NonZeroU32>,
}

impl ItemHeader {
    const LENGTH: usize = 8;

    const DATA_CRC_FIELD: Range<usize> = 0..4;
    const LENGTH_FIELD: Range<usize> = 4..6;
    const LENGTH_CRC_FIELD: Range<usize> = 6..8;

    /// Read the header from the flash at the given address.
    ///
    /// If the item doesn't exist or doesn't fit between the address and the end address, none is returned.
    pub(crate) async fn read_new<S: NorFlash>(
        flash: &mut S,
        address: u32,
        end_address: u32,
    ) -> Result<Option<Self>, Error<S::Error>> {
        let mut buffer = [0; MAX_WORD_SIZE];
        let header_slice_len = round_up_to_alignment_usize::<S>(Self::LENGTH);

        if address + header_slice_len as u32 > end_address {
            return Ok(None);
        }

        let mut retry = false;
        loop {
            flash
                .read(address, &mut buffer[..header_slice_len])
                .await
                .map_err(|e| Error::Storage {
                    value: e,
                    #[cfg(feature = "_test")]
                    backtrace: std::backtrace::Backtrace::capture(),
                })?;

            if buffer.iter().take(header_slice_len).all(|b| *b == 0xFF) {
                // What we read was fully erased bytes, so there's no header here
                return Ok(None);
            }

            let length_crc = u16::from_le_bytes(buffer[Self::LENGTH_CRC_FIELD].try_into().unwrap());
            let calculated_length_crc = crc16(&buffer[Self::LENGTH_FIELD]);

            if calculated_length_crc != length_crc {
                if retry {
                    return Err(Error::Corrupted {
                        #[cfg(feature = "_test")]
                        backtrace: std::backtrace::Backtrace::capture(),
                    });
                }

                retry = true;
                continue;
            }

            break;
        }

        let header = Self {
            length: u16::from_le_bytes(buffer[Self::LENGTH_FIELD].try_into().unwrap()),
            crc: {
                match u32::from_le_bytes(buffer[Self::DATA_CRC_FIELD].try_into().unwrap()) {
                    0 => None,
                    value => Some(NonZeroU32::new(value).unwrap()),
                }
            },
        };

        if header.next_item_address::<S>(address) > end_address {
            // We have a header here that's claims it's larger than is possible
            // This is never written. So either it's a bug or there's a CRC collision
            // Let's assume the latter
            return Err(Error::Corrupted {
                #[cfg(feature = "_test")]
                backtrace: std::backtrace::Backtrace::capture(),
            });
        }

        Ok(Some(header))
    }

    pub(crate) async fn read_item<'d, S: NorFlash>(
        self,
        flash: &mut S,
        data_buffer: &'d mut [u8],
        address: u32,
        end_address: u32,
    ) -> Result<MaybeItem<'d>, Error<S::Error>> {
        match self.crc {
            None => Ok(MaybeItem::Erased(self, data_buffer)),
            Some(header_crc) => {
                let data_address = ItemHeader::data_address::<S>(address);
                let read_len = round_up_to_alignment_usize::<S>(self.length as usize);
                if data_address + read_len as u32 > end_address {
                    return Ok(MaybeItem::Corrupted(self, data_buffer));
                }
                if data_buffer.len() < read_len {
                    return Err(Error::BufferTooSmall(read_len));
                }

                let mut retry = false;
                loop {
                    if read_len != 0 {
                        flash
                            .read(data_address, &mut data_buffer[..read_len])
                            .await
                            .map_err(|e| Error::Storage {
                                value: e,
                                #[cfg(feature = "_test")]
                                backtrace: std::backtrace::Backtrace::capture(),
                            })?;
                    }

                    let data = &data_buffer[..self.length as usize];
                    let data_crc = adapted_crc32(data);

                    break if data_crc == header_crc {
                        Ok(MaybeItem::Present(Item {
                            header: self,
                            item_data_buffer: data_buffer,
                        }))
                    } else {
                        if !retry {
                            retry = true;
                            continue;
                        }
                        Ok(MaybeItem::Corrupted(self, data_buffer))
                    };
                }
            }
        }
    }

    async fn write<S: NorFlash>(&self, flash: &mut S, address: u32) -> Result<(), Error<S::Error>> {
        let mut buffer = AlignedBuf([0xFF; MAX_WORD_SIZE]);

        buffer[Self::DATA_CRC_FIELD]
            .copy_from_slice(&self.crc.map_or(0, NonZero::get).to_le_bytes());
        buffer[Self::LENGTH_FIELD].copy_from_slice(&self.length.to_le_bytes());
        buffer[Self::LENGTH_CRC_FIELD]
            .copy_from_slice(&crc16(&self.length.to_le_bytes()).to_le_bytes());

        flash
            .write(
                address,
                &buffer[..round_up_to_alignment_usize::<S>(Self::LENGTH)],
            )
            .await
            .map_err(|e| Error::Storage {
                value: e,
                #[cfg(feature = "_test")]
                backtrace: std::backtrace::Backtrace::capture(),
            })
    }

    /// Erase this item by setting the crc to none and overwriting the header with it
    pub(crate) async fn erase_data<S: MultiwriteNorFlash>(
        mut self,
        flash: &mut S,
        flash_range: Range<u32>,
        cache: &mut impl SealedCacheImpl,
        address: u32,
    ) -> Result<Self, Error<S::Error>> {
        self.crc = None;
        cache.notice_item_erased::<S>(flash_range.clone(), address, &self);
        self.write(flash, address).await?;
        Ok(self)
    }

    /// Get the address of the start of the data for this item
    pub(crate) const fn data_address<S: NorFlash>(address: u32) -> u32 {
        address + round_up_to_alignment::<S>(Self::LENGTH as u32)
    }

    /// Get the location of the next item in flash
    pub(crate) const fn next_item_address<S: NorFlash>(&self, address: u32) -> u32 {
        let data_address = ItemHeader::data_address::<S>(address);
        data_address + round_up_to_alignment::<S>(self.length as u32)
    }

    /// Calculates the amount of bytes available for data.
    /// Essentially, it's the given amount minus the header and minus some alignment padding.
    pub(crate) const fn available_data_bytes<S: NorFlash>(total_available: u32) -> Option<u32> {
        let data_start = Self::data_address::<S>(0);
        let data_end = round_down_to_alignment::<S>(total_available);

        data_end.checked_sub(data_start)
    }
}

pub(crate) struct Item<'d> {
    pub(crate) header: ItemHeader,
    /// The part of the data buffer that contains the item only
    item_data_buffer: &'d mut [u8],
}

impl<'d> core::fmt::Debug for Item<'d> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Item")
            .field("header", &self.header)
            .field(
                "item_data_buffer",
                &&self.item_data_buffer[..self.header.length as usize],
            )
            .finish()
    }
}

impl<'d> Item<'d> {
    pub(crate) fn data(&self) -> &[u8] {
        self.item_data_buffer
    }

    pub(crate) fn data_mut(&mut self) -> &mut [u8] {
        self.item_data_buffer
    }

    pub(crate) fn data_owned(self) -> &'d mut [u8] {
        self.item_data_buffer
    }

    pub(crate) fn header_and_data_owned(self) -> (ItemHeader, &'d mut [u8]) {
        (self.header, self.item_data_buffer)
    }

    pub(crate) async fn write_new<S: NorFlash>(
        flash: &mut S,
        flash_range: Range<u32>,
        cache: &mut impl SealedCacheImpl,
        address: u32,
        data: &'d [u8],
    ) -> Result<ItemHeader, Error<S::Error>> {
        let header = ItemHeader {
            length: data.len() as u16,
            crc: Some(adapted_crc32(data)),
        };

        Self::write_raw(flash, flash_range, cache, &header, data, address).await?;

        Ok(header)
    }

    async fn write_raw<S: NorFlash>(
        flash: &mut S,
        flash_range: Range<u32>,
        cache: &mut impl SealedCacheImpl,
        header: &ItemHeader,
        data: &[u8],
        address: u32,
    ) -> Result<(), Error<S::Error>> {
        cache.notice_item_written::<S>(flash_range, address, header);
        header.write(flash, address).await?;

        let Some((data_block, data_left)) =
            data.split_at_checked(round_down_to_alignment_usize::<S>(data.len()))
        else {
            debug_assert!(false);
            return Err(Error::LogicBug {
                #[cfg(feature = "_test")]
                backtrace: std::backtrace::Backtrace::capture(),
            });
        };

        let data_address = ItemHeader::data_address::<S>(address);
        if !data_block.is_empty() {
            flash
                .write(data_address, data_block)
                .await
                .map_err(|e| Error::Storage {
                    value: e,
                    #[cfg(feature = "_test")]
                    backtrace: std::backtrace::Backtrace::capture(),
                })?;
        }

        if !data_left.is_empty() {
            let mut buffer = AlignedBuf([0; MAX_WORD_SIZE]);

            let extend_len = round_up_to_alignment_usize::<S>(data_left.len());

            if extend_len > buffer.len() {
                debug_assert!(false);
                return Err(Error::LogicBug {
                    #[cfg(feature = "_test")]
                    backtrace: std::backtrace::Backtrace::capture(),
                });
            }

            buffer[..data_left.len()].copy_from_slice(data_left);
            flash
                .write(
                    data_address + data_block.len() as u32,
                    &buffer[..extend_len],
                )
                .await
                .map_err(|e| Error::Storage {
                    value: e,
                    #[cfg(feature = "_test")]
                    backtrace: std::backtrace::Backtrace::capture(),
                })?;
        }

        Ok(())
    }

    pub(crate) async fn write<S: NorFlash>(
        &self,
        flash: &mut S,
        flash_range: Range<u32>,
        cache: &mut impl SealedCacheImpl,
        address: u32,
    ) -> Result<(), Error<S::Error>> {
        Self::write_raw(
            flash,
            flash_range,
            cache,
            &self.header,
            self.data(),
            address,
        )
        .await
    }

    pub(crate) fn unborrow(self) -> ItemUnborrowed {
        ItemUnborrowed {
            header: self.header,
        }
    }
}

/// A version of [Item] that does not borrow the data. This is to circumvent the borrowchecker in some places.
pub(crate) struct ItemUnborrowed {
    pub(crate) header: ItemHeader,
}

impl ItemUnborrowed {
    /// Reborrows the data. Watch out! Make sure the data buffer hasn't changed since unborrowing!
    ///
    /// Returns None if the data buffer is too small. This should never happen, but we don't want to panic
    pub(crate) fn reborrow(self, data_buffer: &mut [u8]) -> Option<Item<'_>> {
        let length = self.header.length as usize;
        Some(Item {
            header: self.header,
            item_data_buffer: data_buffer.get_mut(..length)?,
        })
    }
}

pub(crate) enum MaybeItem<'d> {
    Corrupted(ItemHeader, &'d mut [u8]),
    Erased(ItemHeader, &'d mut [u8]),
    Present(Item<'d>),
}

impl core::fmt::Debug for MaybeItem<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Corrupted(arg0, arg1) => f
                .debug_tuple("Corrupted")
                .field(arg0)
                .field(&arg1.get(..arg0.length as usize))
                .finish(),
            Self::Erased(arg0, _) => f.debug_tuple("Erased").field(arg0).finish(),
            Self::Present(arg0) => f.debug_tuple("Present").field(arg0).finish(),
        }
    }
}

impl<'d> MaybeItem<'d> {
    pub(crate) fn unwrap<E>(self) -> Result<Item<'d>, Error<E>> {
        match self {
            MaybeItem::Corrupted(_, _) => Err(Error::Corrupted {
                #[cfg(feature = "_test")]
                backtrace: std::backtrace::Backtrace::capture(),
            }),
            MaybeItem::Erased(_, _) => {
                // Cannot unwrap an erased item
                Err(Error::LogicBug {
                    #[cfg(feature = "_test")]
                    backtrace: std::backtrace::Backtrace::capture(),
                })
            }
            MaybeItem::Present(item) => Ok(item),
        }
    }
}

/// A crc that never returns 0xFFFF
fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0xffff;
    for byte in data {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0x1a2e; // CRC-16F/4.2 @ https://users.ece.cmu.edu/~koopman/crc/crc16.html
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^= 0xffff;
    match crc {
        0xFFFF => 0xFFFE,
        other => other,
    }
}

/// Calculate the crc32 of the data as used by the crate.
fn adapted_crc32(data: &[u8]) -> NonZeroU32 {
    match crc32(data) {
        // CRC may not be 0 as that already means 'erased'
        0 => NonZeroU32::new(1).unwrap(),
        // To aid in early shutoff/cancellation, we make sure that if the first byte of
        // the crc is erased, it has to be wrong already.
        // Also, if the first byte is written, it must not be all 0xFF.
        value if value.to_le_bytes()[0] == 0 || value.to_le_bytes()[0] == 0xFF => {
            NonZeroU32::new(value ^ 1).unwrap()
        }
        value => NonZeroU32::new(value).unwrap(),
    }
}

fn crc32(data: &[u8]) -> u32 {
    // We use a modified initial value because the normal 0xFFFFFFF does not pass
    // the `crc32_all_ones_resistant` test
    crc32_with_initial(data, 0xEEEE_EEEE)
}

fn crc32_with_initial(data: &[u8], initial: u32) -> u32 {
    const POLY: u32 = 0x82f6_3b78; // Castagnoli

    let mut crc = initial;

    for byte in data {
        crc ^= u32::from(*byte);

        for _ in 0..8 {
            let lowest_bit_set = crc & 1 > 0;
            crc >>= 1;
            if lowest_bit_set {
                crc ^= POLY;
            }
        }
    }

    !crc
}

impl<S: NorFlash, C: CacheImpl<KEY>, KEY> GenericStorage<S, C, KEY> {
    /// Scans through the items to find the first spot that is free to store a new item.
    ///
    /// - `end_address` is exclusive.
    pub(crate) async fn find_next_free_item_spot(
        &mut self,
        start_address: u32,
        end_address: u32,
        data_length: u32,
    ) -> Result<Option<u32>, Error<S::Error>> {
        let page_index = calculate_page_index::<S>(self.flash_range.clone(), start_address);

        let free_item_address = match self.cache.first_item_after_written(page_index) {
            Some(free_item_address) => free_item_address,
            None => {
                ItemHeaderIter::new(
                    self.cache
                        .first_item_after_erased(page_index)
                        .unwrap_or(0)
                        .max(start_address),
                    end_address,
                )
                .traverse(&mut self.flash, |_, _| true)
                .await?
                .1
            }
        };

        if let Some(available) =
            ItemHeader::available_data_bytes::<S>(end_address - free_item_address)
        {
            if available >= data_length {
                Ok(Some(free_item_address))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Checks if the page is open or closed with all items erased.
    /// By definition a partial-open page is not empty since it can still be written.
    ///
    /// The page state can optionally be given if it's already known.
    /// In that case the state will not be checked again.
    pub(crate) async fn is_page_empty(
        &mut self,
        page_index: usize,
        page_state: Option<PageState>,
    ) -> Result<bool, Error<S::Error>> {
        let page_state = match page_state {
            Some(page_state) => page_state,
            None => self.get_page_state_cached(page_index).await?,
        };

        match page_state {
            PageState::Closed => {
                let page_data_start_address =
                    calculate_page_address::<S>(self.flash_range.clone(), page_index)
                        + S::WORD_SIZE as u32;
                let page_data_end_address =
                    calculate_page_end_address::<S>(self.flash_range.clone(), page_index)
                        - S::WORD_SIZE as u32;

                Ok(ItemHeaderIter::new(
                    self.cache
                        .first_item_after_erased(page_index)
                        .unwrap_or(page_data_start_address),
                    page_data_end_address,
                )
                .traverse(&mut self.flash, |header, _| header.crc.is_none())
                .await?
                .0
                .is_none())
            }
            PageState::PartialOpen => Ok(false),
            PageState::Open => Ok(true),
        }
    }
}

pub(crate) struct ItemIter {
    header: ItemHeaderIter,
}

impl ItemIter {
    pub(crate) fn new(start_address: u32, end_address: u32) -> Self {
        Self {
            header: ItemHeaderIter::new(start_address, end_address),
        }
    }

    pub(crate) async fn next<'d, S: NorFlash>(
        &mut self,
        flash: &mut S,
        data_buffer: &'d mut [u8],
    ) -> Result<Option<(Item<'d>, u32)>, Error<S::Error>> {
        let mut data_buffer = Some(data_buffer);
        while let (Some(header), address) = self.header.next(flash).await? {
            let buffer = data_buffer.take().unwrap();
            match header
                .read_item(flash, buffer, address, self.header.end_address)
                .await?
            {
                MaybeItem::Corrupted(_, buffer) | MaybeItem::Erased(_, buffer) => {
                    data_buffer.replace(buffer);
                }
                MaybeItem::Present(item) => {
                    return Ok(Some((item, address)));
                }
            }
        }
        Ok(None)
    }

    // Keep ordinary lookup futures small even when their pointer cache misses.
    // The filtered walk is used only by retirement and must not enlarge them.
    pub(crate) async fn next_unless<'d, S: NorFlash>(
        &mut self, flash: &mut S, data_buffer: &'d mut [u8],
        prefix_len: Option<usize>, skip: impl Fn(&[u8]) -> bool,
    ) -> Result<Option<(Item<'d>, u32)>, Error<S::Error>> {
        let mut data_buffer = Some(data_buffer);
        while let (Some(header), address) = self.header.next(flash).await? {
            let buffer = data_buffer.take().unwrap();
            if let Some(length) = prefix_len.filter(|length| *length <= usize::from(header.length)) {
                let read_len = round_up_to_alignment_usize::<S>(length);
                if header.crc.is_some() && read_len != 0 && read_len <= buffer.len() {
                    flash.read(ItemHeader::data_address::<S>(address), &mut buffer[..read_len])
                        .await.map_err(|value| Error::Storage {
                            value,
                            #[cfg(feature = "_test")]
                            backtrace: std::backtrace::Backtrace::capture(),
                        })?;
                    if skip(&buffer[..length]) {
                        data_buffer.replace(buffer);
                        continue;
                    }
                }
            }
            match header
                .read_item(flash, buffer, address, self.header.end_address)
                .await?
            {
                MaybeItem::Corrupted(_, buffer) | MaybeItem::Erased(_, buffer) => {
                    data_buffer.replace(buffer);
                }
                MaybeItem::Present(item) => {
                    return Ok(Some((item, address)));
                }
            }
        }
        Ok(None)
    }
}

pub(crate) struct ItemHeaderIter {
    current_address: u32,
    end_address: u32,
}

impl ItemHeaderIter {
    pub(crate) fn new(start_address: u32, end_address: u32) -> Self {
        Self {
            current_address: start_address,
            end_address,
        }
    }

    /// Fetch next item
    pub(crate) async fn next<S: NorFlash>(
        &mut self,
        flash: &mut S,
    ) -> Result<(Option<ItemHeader>, u32), Error<S::Error>> {
        self.traverse(flash, |_, _| false).await
    }

    /// Traverse headers until the callback returns false. If the callback returns true,
    /// the element is skipped and traversal continues.
    ///
    /// If the end of the headers is reached, a `None` item header is returned.
    pub(crate) async fn traverse<S: NorFlash>(
        &mut self,
        flash: &mut S,
        callback: impl Fn(&ItemHeader, u32) -> bool,
    ) -> Result<(Option<ItemHeader>, u32), Error<S::Error>> {
        loop {
            match ItemHeader::read_new(flash, self.current_address, self.end_address).await {
                Ok(Some(header)) => {
                    let next_address = header.next_item_address::<S>(self.current_address);
                    if callback(&header, self.current_address) {
                        self.current_address = next_address;
                    } else {
                        let current_address = self.current_address;
                        self.current_address = next_address;
                        return Ok((Some(header), current_address));
                    }
                }
                Ok(None) => {
                    return Ok((None, self.current_address));
                }
                Err(Error::Corrupted { .. }) => {
                    self.current_address += S::WORD_SIZE as u32;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_all_ones_resistant() {
        const DATA: [u8; 1024] = [0xFF; 1024];

        // Note: This should hold for all lengths up to the max item length
        // We do not test that because it takes too long.
        // Instead we only test the first couple because those are most likely to go bad.
        for length in 0..DATA.len() {
            let crc = crc32(&DATA[..length]);

            // println!("Num 0xFF bytes: {length}, crc: {crc:08X}");

            assert_ne!(crc, u32::MAX);
        }
    }
}
