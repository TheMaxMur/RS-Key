// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use core::ops::Range;

use embassy_futures::block_on;
use embedded_storage_async::nor_flash::{MultiwriteNorFlash, NorFlash, ReadNorFlash};
use rsk_sdk::error::{Error, Result};
use rsk_secret::Secret;

use crate::verified_flash::VerifiedFlash;

const IO_CHUNK: usize = 256;

/// A raw authority window. Metadata reads never invoke map repair or CRC filtering.
pub struct RawBank<F: NorFlash + MultiwriteNorFlash> {
    flash: VerifiedFlash<F>,
    range: Range<u32>,
}

impl<F: NorFlash + MultiwriteNorFlash> RawBank<F> {
    pub fn new(flash: F, range: Range<u32>) -> Result<Self> {
        let erase = u32::try_from(F::ERASE_SIZE).map_err(|_| Error::MemoryFatal)?;
        if erase == 0
            || F::READ_SIZE == 0
            || F::READ_SIZE > IO_CHUNK
            || !IO_CHUNK.is_multiple_of(F::READ_SIZE)
            || F::WRITE_SIZE == 0
            || F::WRITE_SIZE > IO_CHUNK
            || !IO_CHUNK.is_multiple_of(F::WRITE_SIZE)
            || !F::ERASE_SIZE.is_multiple_of(F::READ_SIZE)
            || !F::ERASE_SIZE.is_multiple_of(F::WRITE_SIZE)
            || range.start >= range.end
            || !range.start.is_multiple_of(erase)
            || !range.end.is_multiple_of(erase)
            || usize::try_from(range.end).map_err(|_| Error::MemoryFatal)? > flash.capacity()
        {
            return Err(Error::MemoryFatal);
        }
        Ok(Self {
            flash: VerifiedFlash::new(flash),
            range,
        })
    }

    pub fn range(&self) -> Range<u32> {
        self.range.clone()
    }

    pub fn capacity(&self) -> u32 {
        self.range.end - self.range.start
    }

    fn span(&self, offset: u32, length: usize) -> Result<Range<u32>> {
        let length = u32::try_from(length).map_err(|_| Error::MemoryFatal)?;
        let start = self
            .range
            .start
            .checked_add(offset)
            .ok_or(Error::MemoryFatal)?;
        let end = start.checked_add(length).ok_or(Error::MemoryFatal)?;
        if start < self.range.start || end > self.range.end {
            return Err(Error::MemoryFatal);
        }
        Ok(start..end)
    }

    pub fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<()> {
        let span = self.span(offset, out.len())?;
        let read_size = u32::try_from(F::READ_SIZE).map_err(|_| Error::MemoryFatal)?;
        let mut scratch = Secret::<[u8; IO_CHUNK]>::zeroed();
        let mut at = span.start;
        let mut copied = 0;
        while at < span.end {
            let aligned = at - at % read_size;
            let prefix = usize::try_from(at - aligned).map_err(|_| Error::MemoryFatal)?;
            let remaining = usize::try_from(span.end - at).map_err(|_| Error::MemoryFatal)?;
            let count = remaining.min(IO_CHUNK - prefix);
            let read_count = (prefix + count).div_ceil(F::READ_SIZE) * F::READ_SIZE;
            let bytes = scratch
                .expose_mut()
                .get_mut(..read_count)
                .ok_or(Error::MemoryFatal)?;
            block_on(self.flash.read(aligned, bytes)).map_err(|_| Error::MemoryFatal)?;
            out.get_mut(copied..copied + count)
                .ok_or(Error::MemoryFatal)?
                .copy_from_slice(
                    bytes
                        .get(prefix..prefix + count)
                        .ok_or(Error::MemoryFatal)?,
                );
            at = at
                .checked_add(u32::try_from(count).map_err(|_| Error::MemoryFatal)?)
                .ok_or(Error::MemoryFatal)?;
            copied += count;
        }
        scratch.wipe();
        Ok(())
    }

    pub fn program(&mut self, offset: u32, data: &[u8]) -> Result<()> {
        let span = self.span(offset, data.len())?;
        let write_size = u32::try_from(F::WRITE_SIZE).map_err(|_| Error::MemoryFatal)?;
        let mut scratch = Secret::<[u8; IO_CHUNK]>::zeroed();
        let mut at = span.start;
        let mut copied = 0;
        while at < span.end {
            let aligned = at - at % write_size;
            let prefix = usize::try_from(at - aligned).map_err(|_| Error::MemoryFatal)?;
            let remaining = usize::try_from(span.end - at).map_err(|_| Error::MemoryFatal)?;
            let count = remaining.min(IO_CHUNK - prefix);
            let write_count = (prefix + count).div_ceil(F::WRITE_SIZE) * F::WRITE_SIZE;
            let buffer = scratch
                .expose_mut()
                .get_mut(..write_count)
                .ok_or(Error::MemoryFatal)?;
            buffer.fill(0xFF);
            self.read(aligned - self.range.start, buffer)?;
            let input = data.get(copied..copied + count).ok_or(Error::MemoryFatal)?;
            let output = buffer
                .get_mut(prefix..prefix + count)
                .ok_or(Error::MemoryFatal)?;
            if output
                .iter()
                .zip(input)
                .any(|(&old, &new)| old & new != new)
            {
                return Err(Error::MemoryFatal);
            }
            output.copy_from_slice(input);
            block_on(self.flash.write(aligned, buffer)).map_err(|_| Error::MemoryFatal)?;
            at = at
                .checked_add(u32::try_from(count).map_err(|_| Error::MemoryFatal)?)
                .ok_or(Error::MemoryFatal)?;
            copied += count;
        }
        scratch.wipe();
        Ok(())
    }

    pub fn read_erased(&mut self, offset: u32) -> Result<bool> {
        if offset > self.capacity() {
            return Err(Error::MemoryFatal);
        }
        let mut scratch = Secret::<[u8; IO_CHUNK]>::zeroed();
        let mut at = offset;
        while at < self.capacity() {
            let count = usize::try_from(self.capacity() - at)
                .map_err(|_| Error::MemoryFatal)?
                .min(IO_CHUNK);
            let buffer = scratch
                .expose_mut()
                .get_mut(..count)
                .ok_or(Error::MemoryFatal)?;
            self.read(at, buffer)?;
            if buffer.iter().any(|&byte| byte != 0xFF) {
                scratch.wipe();
                return Ok(false);
            }
            at = at
                .checked_add(u32::try_from(count).map_err(|_| Error::MemoryFatal)?)
                .ok_or(Error::MemoryFatal)?;
        }
        scratch.wipe();
        Ok(true)
    }

    pub fn erase(&mut self) -> Result<()> {
        block_on(self.flash.erase(self.range.start, self.range.end)).map_err(|_| Error::MemoryFatal)
    }
}
