// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::Authenticated;
use super::bound_counter::{
    BUFFER_BYTES, PublicPinState, Slot, VALUE_BYTES, apply_retries, only_retries_changed,
    pack_retries, public_pin,
};
use embedded_storage_async::nor_flash::{MultiwriteNorFlash, NorFlash};
use rsk_sdk::error::{Error, Result};
use rsk_secret::Secret;
use sequential_storage::cache::CacheImpl;

impl<F: NorFlash + MultiwriteNorFlash + Clone, C: CacheImpl<u16>> Authenticated<F, C> {
    pub(super) fn read_public_pin(&mut self, fid: u16, out: &mut [u8]) -> Result<Option<usize>> {
        match self.read_published_pin(fid, out)? {
            PublicPinState::Legacy => self.read_pin(fid, out),
            PublicPinState::Absent => Ok(None),
            PublicPinState::Present(length) => Ok(Some(length)),
        }
    }

    pub(super) fn read_published_pin(
        &mut self,
        fid: u16,
        out: &mut [u8],
    ) -> Result<PublicPinState> {
        let mut bytes = [0; VALUE_BYTES + 1];
        let Some(length) = self.counters.read_with_source(
            self.source,
            self.counter_arm,
            public_pin(fid).ok_or(Error::MemoryFatal)?,
            &mut bytes,
        )?
        else {
            return Ok(PublicPinState::Legacy);
        };
        let value = match bytes.get(..length).ok_or(Error::MemoryFatal)? {
            [0] => return Ok(PublicPinState::Absent),
            [1, value @ ..] => value,
            _ => return Err(Error::MemoryFatal),
        };
        let count = value.len().min(out.len());
        out.get_mut(..count)
            .ok_or(Error::MemoryFatal)?
            .copy_from_slice(value.get(..count).ok_or(Error::MemoryFatal)?);
        Ok(PublicPinState::Present(value.len()))
    }

    // These two records contain policy and retry bytes, never PIN verifiers.
    pub(super) fn write_public_pin(&mut self, fid: u16, value: Option<&[u8]>) -> Result<()> {
        let mut bytes = [0; VALUE_BYTES + 1];
        let length = if let Some(value) = value {
            *bytes.first_mut().ok_or(Error::MemoryFatal)? = 1;
            bytes
                .get_mut(1..1 + value.len())
                .ok_or(Error::MemoryFatal)?
                .copy_from_slice(value);
            1 + value.len()
        } else {
            1
        };
        self.counters.write_with_source(
            self.source,
            self.counter_arm,
            public_pin(fid).ok_or(Error::MemoryFatal)?,
            Some(bytes.get(..length).ok_or(Error::MemoryFatal)?),
        )
    }

    fn read_slot(&mut self, slot: Slot, generation: u64, out: &mut [u8]) -> Result<Option<usize>> {
        let mut bytes = Secret::<[u8; BUFFER_BYTES]>::zeroed();
        let Some(length) = self.counters.read_with_source(
            self.source,
            self.counter_arm,
            slot.bucket,
            bytes.expose_mut(),
        )?
        else {
            return Ok(None);
        };
        slot.read(
            bytes.expose().get(..length).ok_or(Error::MemoryFatal)?,
            generation,
            out,
        )
    }

    fn write_slot(&mut self, slot: Slot, generation: u64, value: &[u8]) -> Result<()> {
        let mut bytes = Secret::<[u8; BUFFER_BYTES]>::zeroed();
        if let Some(length) = self.counters.read_with_source(
            self.source,
            self.counter_arm,
            slot.bucket,
            bytes.expose_mut(),
        )? && length != slot.bytes()
        {
            return Err(Error::MemoryFatal);
        }
        let bucket = bytes
            .expose_mut()
            .get_mut(..slot.bytes())
            .ok_or(Error::MemoryFatal)?;
        slot.replace(bucket, generation, value)?;
        self.counters
            .write_with_source(self.source, self.counter_arm, slot.bucket, Some(bucket))
    }

    pub(super) fn read_pin(&mut self, fid: u16, out: &mut [u8]) -> Result<Option<usize>> {
        // Retry updates cannot create or remove their main-file owner.
        if out.is_empty() {
            return self
                .main
                .read_with_source(self.source, self.main_arm, fid, out);
        }
        let mut base = Secret::<[u8; VALUE_BYTES]>::zeroed();
        let Some(length) =
            self.main
                .read_with_source(self.source, self.main_arm, fid, base.expose_mut())?
        else {
            return Ok(None);
        };
        if length > VALUE_BYTES {
            return self
                .main
                .read_with_source(self.source, self.main_arm, fid, out);
        }
        let generation = self
            .main
            .directory
            .find(fid)
            .ok_or(Error::MemoryFatal)?
            .generation();
        let mut retries = [0; 3];
        if let Some(n) = self.read_slot(
            Slot::pin(fid).ok_or(Error::MemoryFatal)?,
            generation,
            &mut retries,
        )? {
            apply_retries(
                fid,
                base.expose_mut()
                    .get_mut(..length)
                    .ok_or(Error::MemoryFatal)?,
                retries.get(..n).ok_or(Error::MemoryFatal)?,
            )?;
        }
        let value = base.expose().get(..length).ok_or(Error::MemoryFatal)?;
        let count = out.len().min(length);
        out.get_mut(..count)
            .ok_or(Error::MemoryFatal)?
            .copy_from_slice(value.get(..count).ok_or(Error::MemoryFatal)?);
        Ok(Some(length))
    }

    pub(super) fn write_pin(&mut self, fid: u16, value: &[u8]) -> Result<bool> {
        let mut base = Secret::<[u8; VALUE_BYTES]>::zeroed();
        let Some(length) =
            self.main
                .read_with_source(self.source, self.main_arm, fid, base.expose_mut())?
        else {
            return Ok(false);
        };
        let Some(base) = base.expose().get(..length) else {
            return Ok(false);
        };
        if !only_retries_changed(fid, base, value) {
            return Ok(false);
        }
        let generation = self
            .main
            .directory
            .find(fid)
            .ok_or(Error::MemoryFatal)?
            .generation();
        let mut retries = [0; 3];
        let n = pack_retries(fid, value, &mut retries)?;
        self.write_slot(
            Slot::pin(fid).ok_or(Error::MemoryFatal)?,
            generation,
            retries.get(..n).ok_or(Error::MemoryFatal)?,
        )?;
        Ok(true)
    }

    fn bound_generation(&mut self, fid: u16) -> Result<u64> {
        self.main
            .read_with_source(self.source, self.main_arm, fid, &mut [])?
            .ok_or(Error::MemoryFatal)?;
        Ok(self
            .main
            .directory
            .find(fid)
            .ok_or(Error::MemoryFatal)?
            .generation())
    }

    pub(super) fn read_oath_counter(&mut self, fid: u16, out: &mut [u8]) -> Result<Option<usize>> {
        let slot = Slot::oath(fid).ok_or(Error::Blocked)?;
        let generation = self.bound_generation(fid)?;
        self.read_slot(slot, generation, out)
    }

    pub(super) fn write_oath_counter(&mut self, fid: u16, sealed: &[u8]) -> Result<bool> {
        let slot = Slot::oath(fid).ok_or(Error::Blocked)?;
        if sealed.len() != VALUE_BYTES {
            return Err(Error::MemoryFatal);
        }
        let generation = self.bound_generation(fid)?;
        self.write_slot(slot, generation, sealed)?;
        Ok(true)
    }
}

#[cfg(test)]
#[path = "bound_storage_tests.rs"]
mod tests;
