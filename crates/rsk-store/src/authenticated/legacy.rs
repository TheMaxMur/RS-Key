// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use core::ops::Range;
use embedded_storage_async::nor_flash::{ErrorType, MultiwriteNorFlash, NorFlash, ReadNorFlash};
use rsk_sdk::error::{Error, Result};
use rsk_secret::Secret;

use super::RawBank;
use crate::verified_flash::VerifyError;

const E10_BYTES: usize = 256;
const E10_BYTE: u8 = 0xEF;

/// SDK UF2s can leave the E10 absolute block aliased at the end of a smaller chip.
pub(super) fn read_e10_padding<F: NorFlash + MultiwriteNorFlash + Clone>(
    flash: F,
    range: Range<u32>,
) -> Result<Option<Range<u32>>> {
    let mut bank = RawBank::new(flash, range.clone())?;
    let sector = u32::try_from(F::ERASE_SIZE).map_err(|_| Error::MemoryFatal)?;
    let size = u32::try_from(E10_BYTES).map_err(|_| Error::MemoryFatal)?;
    if sector < size {
        return Ok(None);
    }
    let tail = bank
        .capacity()
        .checked_sub(size)
        .ok_or(Error::MemoryFatal)?;
    let mut bytes = Secret::<[u8; E10_BYTES]>::zeroed();
    bank.read(tail, bytes.expose_mut())?;
    if !bytes.expose().iter().all(|&byte| byte == E10_BYTE) {
        return Ok(None);
    }
    let mut at = bank
        .capacity()
        .checked_sub(sector)
        .ok_or(Error::MemoryFatal)?;
    while at < tail {
        let count = usize::try_from(tail - at)
            .map_err(|_| Error::MemoryFatal)?
            .min(E10_BYTES);
        let chunk = bytes
            .expose_mut()
            .get_mut(..count)
            .ok_or(Error::MemoryFatal)?;
        bank.read(at, chunk)?;
        if chunk.iter().any(|&byte| byte != 0xFF) {
            return Ok(None);
        }
        at = at
            .checked_add(u32::try_from(count).map_err(|_| Error::MemoryFatal)?)
            .ok_or(Error::MemoryFatal)?;
    }
    bytes.wipe();
    Ok(Some(
        range.end.checked_sub(size).ok_or(Error::MemoryFatal)?..range.end,
    ))
}

/// Only the legacy reader sees the proven-unused E10 suffix as erased metadata.
#[derive(Clone)]
pub(super) struct CounterFlash<F> {
    flash: F,
    padding: Option<Range<u32>>,
}

impl<F> CounterFlash<F> {
    pub fn new(flash: F, padding: Option<Range<u32>>) -> Self {
        Self { flash, padding }
    }
}
impl<F: NorFlash> ErrorType for CounterFlash<F> {
    type Error = VerifyError<F::Error>;
}
impl<F: NorFlash> ReadNorFlash for CounterFlash<F> {
    const READ_SIZE: usize = F::READ_SIZE;
    async fn read(
        &mut self,
        offset: u32,
        bytes: &mut [u8],
    ) -> core::result::Result<(), Self::Error> {
        self.flash
            .read(offset, bytes)
            .await
            .map_err(VerifyError::Flash)?;
        if let Some(padding) = &self.padding {
            for (index, byte) in bytes.iter_mut().enumerate() {
                let address = offset
                    .checked_add(u32::try_from(index).map_err(|_| VerifyError::Mismatch)?)
                    .ok_or(VerifyError::Mismatch)?;
                if padding.contains(&address) {
                    *byte = 0xFF;
                }
            }
        }
        Ok(())
    }
    fn capacity(&self) -> usize {
        self.flash.capacity()
    }
}
impl<F: NorFlash> NorFlash for CounterFlash<F> {
    const WRITE_SIZE: usize = F::WRITE_SIZE;
    const ERASE_SIZE: usize = F::ERASE_SIZE;
    async fn write(&mut self, _: u32, _: &[u8]) -> core::result::Result<(), Self::Error> {
        Err(VerifyError::Mismatch)
    }
    async fn erase(&mut self, _: u32, _: u32) -> core::result::Result<(), Self::Error> {
        Err(VerifyError::Mismatch)
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "Fixed mock buffers prove both mask boundaries and fail immediately on setup errors"
)]
#[path = "legacy_tests.rs"]
mod tests;
