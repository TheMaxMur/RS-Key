// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use rsk_fs::counter::{
    DEVICE_PIN, FIDO_PIN, OATH_FIRST, OATH_PIN, OATH_SLOTS, OPENPGP_RETRIES, PIV_RETRIES,
};
use rsk_sdk::error::{Error, Result};

use super::record::{field, take};

pub(super) const FIRST_BUCKET: u16 = 0xCD00;
const OATH_PER_BUCKET: usize = 8;
const OATH_BUCKETS: usize = (OATH_SLOTS as usize).div_ceil(OATH_PER_BUCKET);
pub(super) const PUBLIC_PINS: [u16; 2] = [PIV_RETRIES, OPENPGP_RETRIES];
pub(crate) const BUCKETS: usize = 1 + OATH_BUCKETS + PUBLIC_PINS.len();
pub(super) const VALUE_BYTES: usize = 36;
const SLOT_BYTES: usize = 48;
const PIN_SLOT_BYTES: usize = 16;
const LENGTH_OFFSET: usize = 8;
const VALUE_OFFSET: usize = LENGTH_OFFSET + 1;
const RESERVED_BYTES: usize = 3;
pub(super) const BUFFER_BYTES: usize = OATH_PER_BUCKET * SLOT_BYTES;

pub(crate) fn bucket_index(fid: u16) -> Option<usize> {
    let index = usize::from(fid.checked_sub(FIRST_BUCKET)?);
    (index < BUCKETS).then_some(index)
}

pub(super) fn public_pin(fid: u16) -> Option<u16> {
    let index = PUBLIC_PINS.iter().position(|&owner| owner == fid)?;
    Some(FIRST_BUCKET + u16::try_from(1 + OATH_BUCKETS + index).ok()?)
}

pub(super) enum PublicPinState {
    Legacy,
    Absent,
    Present(usize),
}

#[derive(Clone, Copy)]
pub(super) struct Slot {
    pub bucket: u16,
    index: usize,
    slots: usize,
    stride: usize,
}

impl Slot {
    pub fn pin(fid: u16) -> Option<Self> {
        let index = match fid {
            PIV_RETRIES => 0,
            OPENPGP_RETRIES => 1,
            FIDO_PIN => 2,
            DEVICE_PIN => 3,
            OATH_PIN => 4,
            _ => return None,
        };
        Some(Self {
            bucket: FIRST_BUCKET,
            index,
            slots: 5,
            stride: PIN_SLOT_BYTES,
        })
    }

    pub fn oath(fid: u16) -> Option<Self> {
        let index = usize::from(fid.checked_sub(OATH_FIRST)?);
        if index >= usize::from(OATH_SLOTS) {
            return None;
        }
        Some(Self {
            bucket: FIRST_BUCKET + 1 + u16::try_from(index / OATH_PER_BUCKET).ok()?,
            index: index % OATH_PER_BUCKET,
            slots: OATH_PER_BUCKET,
            stride: SLOT_BYTES,
        })
    }

    pub fn bytes(self) -> usize {
        self.slots * self.stride
    }

    fn checked(self, bytes: &[u8]) -> Result<&[u8]> {
        if bytes.len() != self.bytes() {
            return Err(Error::MemoryFatal);
        }
        for slot in bytes.chunks_exact(self.stride) {
            let length = usize::from(*slot.get(LENGTH_OFFSET).ok_or(Error::MemoryFatal)?);
            if length > self.stride - VALUE_OFFSET - RESERVED_BYTES
                || !slot
                    .get(VALUE_OFFSET + length..)
                    .ok_or(Error::MemoryFatal)?
                    .iter()
                    .all(|&b| b == 0)
                || length == 0 && slot.iter().any(|&b| b != 0)
            {
                return Err(Error::MemoryFatal);
            }
        }
        bytes
            .get(self.index * self.stride..(self.index + 1) * self.stride)
            .ok_or(Error::MemoryFatal)
    }

    pub fn read(self, bytes: &[u8], generation: u64, out: &mut [u8]) -> Result<Option<usize>> {
        let slot = self.checked(bytes)?;
        let length = usize::from(*slot.get(LENGTH_OFFSET).ok_or(Error::MemoryFatal)?);
        if length == 0 || u64::from_le_bytes(take(slot, 0)?) != generation {
            return Ok(None);
        }
        let count = out.len().min(length);
        out.get_mut(..count)
            .ok_or(Error::MemoryFatal)?
            .copy_from_slice(
                slot.get(VALUE_OFFSET..VALUE_OFFSET + count)
                    .ok_or(Error::MemoryFatal)?,
            );
        Ok(Some(length))
    }

    pub fn replace(self, bytes: &mut [u8], generation: u64, value: &[u8]) -> Result<()> {
        self.checked(bytes)?;
        if value.is_empty() || value.len() > self.stride - VALUE_OFFSET - RESERVED_BYTES {
            return Err(Error::MemoryFatal);
        }
        let slot = bytes
            .get_mut(self.index * self.stride..(self.index + 1) * self.stride)
            .ok_or(Error::MemoryFatal)?;
        slot.fill(0);
        field(slot, 0, &generation.to_le_bytes())?;
        field(
            slot,
            LENGTH_OFFSET,
            &[u8::try_from(value.len()).map_err(|_| Error::MemoryFatal)?],
        )?;
        field(slot, VALUE_OFFSET, value)
    }
}

pub(super) fn only_retries_changed(fid: u16, before: &[u8], after: &[u8]) -> bool {
    if before.is_empty() || before.len() != after.len() || before.len() > VALUE_BYTES {
        return false;
    }
    let Some(indices) = retry_indices(fid, before.len()) else {
        return false;
    };
    before
        .iter()
        .zip(after)
        .enumerate()
        .all(|(index, (old, new))| indices.contains(&index) || old == new)
}

fn retry_indices(fid: u16, length: usize) -> Option<&'static [usize]> {
    match fid {
        PIV_RETRIES if length == 4 => Some(&[1, 3]),
        OPENPGP_RETRIES if (7..=8).contains(&length) => Some(&[4, 5, 6]),
        FIDO_PIN | DEVICE_PIN | OATH_PIN if (1..=VALUE_BYTES).contains(&length) => Some(&[0]),
        _ => None,
    }
}

pub(super) fn pack_retries(fid: u16, value: &[u8], out: &mut [u8; 3]) -> Result<usize> {
    let indices = retry_indices(fid, value.len()).ok_or(Error::MemoryFatal)?;
    for (&index, byte) in indices.iter().zip(out) {
        *byte = *value.get(index).ok_or(Error::MemoryFatal)?;
    }
    Ok(indices.len())
}

pub(super) fn apply_retries(fid: u16, value: &mut [u8], retries: &[u8]) -> Result<()> {
    let indices = retry_indices(fid, value.len()).ok_or(Error::MemoryFatal)?;
    if indices.len() != retries.len() {
        return Err(Error::MemoryFatal);
    }
    for (&index, &byte) in indices.iter().zip(retries) {
        *value.get_mut(index).ok_or(Error::MemoryFatal)? = byte;
    }
    Ok(())
}

#[cfg(test)]
#[path = "bound_counter_tests.rs"]
mod tests;
