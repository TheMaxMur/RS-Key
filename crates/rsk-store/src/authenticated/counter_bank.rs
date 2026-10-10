// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use embedded_storage_async::nor_flash::{MultiwriteNorFlash, NorFlash};
use rsk_crypto::ct_eq;
use rsk_sdk::error::{Error, Result};
use rsk_secret::Secret;

use super::{CHECKPOINT_BYTES, Checkpoint, Directory, ENTRY_BYTES, Entry, JournalStatus};
use super::{MAX_COUNTER_ENTRIES, Partition, RawBank};

const VALUE_ALIGNMENT: usize = 16;
const VALUE_BUFFER: usize = crate::KV_BUF;

/// The header precedes the complete value, although the value is programmed first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CounterLocation {
    pub entry: Entry,
    pub value_offset: u32,
}

/// A dirty bank keeps authenticated progress but cannot supply an older value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CounterScan {
    pub status: JournalStatus,
    pub checkpoint: Option<Checkpoint>,
    pub sequence: Option<u64>,
    pub lower_bound: Option<u64>,
    pub next: u32,
    pub locations: [Option<CounterLocation>; MAX_COUNTER_ENTRIES],
}

/// Inline counter authority avoids a separate payload mutation and intent journal.
pub struct CounterBank<F: NorFlash + MultiwriteNorFlash> {
    bank: RawBank<F>,
}

impl<F: NorFlash + MultiwriteNorFlash> CounterBank<F> {
    pub fn new(bank: RawBank<F>) -> Self {
        Self { bank }
    }
    pub fn capacity(&self) -> u32 {
        self.bank.capacity()
    }

    pub fn read_header(&mut self) -> Result<[u8; CHECKPOINT_BYTES]> {
        let mut bytes = [0; CHECKPOINT_BYTES];
        self.bank.read(0, &mut bytes)?;
        Ok(bytes)
    }

    fn counter_index(fid: u16) -> Result<usize> {
        rsk_fs::counter::COUNTER_FIDS
            .iter()
            .position(|counter| counter.get() == fid)
            .ok_or(Error::MemoryFatal)
    }

    fn padded_length(entry: Entry) -> Result<usize> {
        let length = entry.length().unwrap_or(0);
        if length > rsk_fs::MAX_VALUE_BYTES {
            return Err(Error::MemoryFatal);
        }
        Ok(length.div_ceil(VALUE_ALIGNMENT) * VALUE_ALIGNMENT)
    }

    fn read_entry_value(
        &mut self,
        entry: Entry,
        offset: u32,
        checkpoint: Checkpoint,
        key: &[u8; 32],
        buffer: &mut [u8; VALUE_BUFFER],
    ) -> Result<Option<usize>> {
        let padded = Self::padded_length(entry)?;
        let length = entry.length().unwrap_or(0);
        let bytes = buffer.get_mut(..padded).ok_or(Error::MemoryFatal)?;
        self.bank.read(offset, bytes)?;
        if !bytes
            .get(length..)
            .ok_or(Error::MemoryFatal)?
            .iter()
            .all(|&byte| byte == 0xFF)
        {
            return Ok(None);
        }
        if entry
            .verify(
                checkpoint.identity,
                key,
                bytes.get(..length).ok_or(Error::MemoryFatal)?,
            )
            .is_err()
        {
            return Ok(None);
        }
        Ok(Some(padded))
    }

    pub fn scan(
        &mut self,
        key: &[u8; 32],
        directory: &mut Directory<MAX_COUNTER_ENTRIES>,
    ) -> Result<CounterScan> {
        directory.clear();
        let header = self.read_header()?;
        let mut scan = CounterScan {
            status: JournalStatus::Dirty,
            checkpoint: None,
            sequence: None,
            lower_bound: None,
            next: 0,
            locations: [None; MAX_COUNTER_ENTRIES],
        };
        if header.iter().all(|&byte| byte == 0xFF) {
            if self.bank.read_erased(0)? {
                scan.status = JournalStatus::Empty;
            }
            return Ok(scan);
        }
        let Ok(checkpoint) = Checkpoint::verify(&header, key) else {
            return Ok(scan);
        };
        if checkpoint.identity.partition != Partition::Counter {
            return Ok(scan);
        }
        scan.checkpoint = Some(checkpoint);
        scan.lower_bound = Some(checkpoint.sequence);
        let mut scratch = Secret::<[u8; VALUE_BUFFER]>::zeroed();
        let mut at = u32::try_from(CHECKPOINT_BYTES).map_err(|_| Error::MemoryFatal)?;
        for _ in 0..checkpoint.entries {
            let mut encoded = [0; ENTRY_BYTES];
            self.bank.read(at, &mut encoded)?;
            let Ok(entry) = Entry::decode(&encoded) else {
                return Ok(scan);
            };
            let Ok(index) = Self::counter_index(entry.fid()) else {
                return Ok(scan);
            };
            if entry.length().is_none()
                || directory.push_snapshot(entry, checkpoint.sequence).is_err()
            {
                return Ok(scan);
            }
            let value_at = at
                .checked_add(u32::try_from(ENTRY_BYTES).map_err(|_| Error::MemoryFatal)?)
                .ok_or(Error::MemoryFatal)?;
            let Some(padded) =
                self.read_entry_value(entry, value_at, checkpoint, key, scratch.expose_mut())?
            else {
                return Ok(scan);
            };
            *scan.locations.get_mut(index).ok_or(Error::MemoryFatal)? = Some(CounterLocation {
                entry,
                value_offset: value_at,
            });
            at = value_at
                .checked_add(u32::try_from(padded).map_err(|_| Error::MemoryFatal)?)
                .ok_or(Error::MemoryFatal)?;
        }
        if !ct_eq(
            &directory.digest(checkpoint.identity, key, checkpoint.sequence)?,
            &checkpoint.digest,
        ) {
            return Ok(scan);
        }
        scan.sequence = Some(checkpoint.sequence);
        scan.next = at;
        while at < self.bank.capacity() {
            if self.bank.capacity() - at
                < u32::try_from(ENTRY_BYTES).map_err(|_| Error::MemoryFatal)?
            {
                if self.bank.read_erased(at)? {
                    scan.status = JournalStatus::Complete;
                }
                return Ok(scan);
            }
            let mut encoded = [0; ENTRY_BYTES];
            self.bank.read(at, &mut encoded)?;
            if encoded.iter().all(|&byte| byte == 0xFF) {
                if self.bank.read_erased(at)? {
                    scan.status = JournalStatus::Complete;
                }
                return Ok(scan);
            }
            let Ok(entry) = Entry::decode(&encoded) else {
                return Ok(scan);
            };
            let Ok(index) = Self::counter_index(entry.fid()) else {
                return Ok(scan);
            };
            let sequence = scan
                .sequence
                .ok_or(Error::MemoryFatal)?
                .checked_add(1)
                .ok_or(Error::MemoryFatal)?;
            if entry.generation() != sequence {
                return Ok(scan);
            }
            let value_at = at
                .checked_add(u32::try_from(ENTRY_BYTES).map_err(|_| Error::MemoryFatal)?)
                .ok_or(Error::MemoryFatal)?;
            let Some(padded) =
                self.read_entry_value(entry, value_at, checkpoint, key, scratch.expose_mut())?
            else {
                return Ok(scan);
            };
            if directory.apply(entry).is_err() {
                return Ok(scan);
            }
            *scan.locations.get_mut(index).ok_or(Error::MemoryFatal)? =
                entry.length().map(|_| CounterLocation {
                    entry,
                    value_offset: value_at,
                });
            at = value_at
                .checked_add(u32::try_from(padded).map_err(|_| Error::MemoryFatal)?)
                .ok_or(Error::MemoryFatal)?;
            scan.sequence = Some(sequence);
            scan.lower_bound = Some(sequence);
            scan.next = at;
        }
        scratch.wipe();
        scan.status = JournalStatus::Complete;
        Ok(scan)
    }

    pub fn read_value(
        &mut self,
        scan: CounterScan,
        key: &[u8; 32],
        fid: u16,
        out: &mut [u8],
    ) -> Result<Option<usize>> {
        if scan.status != JournalStatus::Complete {
            return Err(Error::MemoryFatal);
        }
        let checkpoint = scan.checkpoint.ok_or(Error::MemoryFatal)?;
        let index = Self::counter_index(fid)?;
        let Some(location) = *scan.locations.get(index).ok_or(Error::MemoryFatal)? else {
            return Ok(None);
        };
        let mut scratch = Secret::<[u8; VALUE_BUFFER]>::zeroed();
        if location.entry.fid() != fid
            || self
                .read_entry_value(
                    location.entry,
                    location.value_offset,
                    checkpoint,
                    key,
                    scratch.expose_mut(),
                )?
                .is_none()
        {
            return Err(Error::MemoryFatal);
        }
        let length = location.entry.length().ok_or(Error::MemoryFatal)?;
        let count = out.len().min(length);
        out.get_mut(..count)
            .ok_or(Error::MemoryFatal)?
            .copy_from_slice(scratch.expose().get(..count).ok_or(Error::MemoryFatal)?);
        scratch.wipe();
        Ok(Some(length))
    }

    pub fn write_snapshot(
        &mut self,
        checkpoint: Checkpoint,
        key: &[u8; 32],
        directory: &Directory<MAX_COUNTER_ENTRIES>,
        mut load: impl FnMut(Entry, &mut [u8]) -> Result<()>,
    ) -> Result<()> {
        if checkpoint.identity.partition != Partition::Counter
            || usize::try_from(checkpoint.entries).map_err(|_| Error::MemoryFatal)?
                != directory.entries().len()
            || !ct_eq(
                &directory.digest(checkpoint.identity, key, checkpoint.sequence)?,
                &checkpoint.digest,
            )
            || directory.entries().iter().any(|entry| {
                entry.length().is_none()
                    || entry.generation() > checkpoint.sequence
                    || Self::counter_index(entry.fid()).is_err()
            })
        {
            return Err(Error::MemoryFatal);
        }
        let mut end = CHECKPOINT_BYTES;
        for entry in directory.entries() {
            end = end
                .checked_add(ENTRY_BYTES)
                .and_then(|end| end.checked_add(Self::padded_length(*entry).ok()?))
                .ok_or(Error::MemoryFatal)?;
        }
        if u32::try_from(end).map_err(|_| Error::MemoryFatal)? > self.bank.capacity() {
            return Err(Error::NoMemory);
        }
        let header = checkpoint.encode(key)?;
        self.bank.erase()?;
        let mut scratch = Secret::<[u8; VALUE_BUFFER]>::zeroed();
        let mut at = u32::try_from(CHECKPOINT_BYTES).map_err(|_| Error::MemoryFatal)?;
        for entry in directory.entries() {
            let length = entry.length().ok_or(Error::MemoryFatal)?;
            let padded = Self::padded_length(*entry)?;
            scratch.expose_mut().fill(0xFF);
            let value = scratch
                .expose_mut()
                .get_mut(..length)
                .ok_or(Error::MemoryFatal)?;
            load(*entry, value)?;
            entry.verify(checkpoint.identity, key, value)?;
            let value_at = at
                .checked_add(u32::try_from(ENTRY_BYTES).map_err(|_| Error::MemoryFatal)?)
                .ok_or(Error::MemoryFatal)?;
            self.bank.program(
                value_at,
                scratch.expose().get(..padded).ok_or(Error::MemoryFatal)?,
            )?;
            self.bank.program(at, &entry.encode()?)?;
            at = value_at
                .checked_add(u32::try_from(padded).map_err(|_| Error::MemoryFatal)?)
                .ok_or(Error::MemoryFatal)?;
        }
        scratch.wipe();
        self.bank
            .program(0, header.get(..80).ok_or(Error::MemoryFatal)?)?;
        self.bank
            .program(80, header.get(80..96).ok_or(Error::MemoryFatal)?)?;
        Ok(())
    }

    pub fn append(
        &mut self,
        scan: CounterScan,
        key: &[u8; 32],
        entry: Entry,
        value: &[u8],
    ) -> Result<()> {
        if scan.status != JournalStatus::Complete {
            return Err(Error::MemoryFatal);
        }
        let checkpoint = scan.checkpoint.ok_or(Error::MemoryFatal)?;
        let sequence = scan
            .sequence
            .ok_or(Error::MemoryFatal)?
            .checked_add(1)
            .ok_or(Error::MemoryFatal)?;
        Self::counter_index(entry.fid())?;
        if entry.generation() != sequence {
            return Err(Error::MemoryFatal);
        }
        entry.verify(checkpoint.identity, key, value)?;
        let padded = Self::padded_length(entry)?;
        let value_at = scan
            .next
            .checked_add(u32::try_from(ENTRY_BYTES).map_err(|_| Error::MemoryFatal)?)
            .ok_or(Error::MemoryFatal)?;
        let end = value_at
            .checked_add(u32::try_from(padded).map_err(|_| Error::MemoryFatal)?)
            .ok_or(Error::MemoryFatal)?;
        if end > self.bank.capacity() {
            return Err(Error::NoMemory);
        }
        let mut scratch = Secret::<[u8; VALUE_BUFFER]>::zeroed();
        scratch.expose_mut().fill(0xFF);
        scratch
            .expose_mut()
            .get_mut(..value.len())
            .ok_or(Error::MemoryFatal)?
            .copy_from_slice(value);
        self.bank.program(
            value_at,
            scratch.expose().get(..padded).ok_or(Error::MemoryFatal)?,
        )?;
        scratch.wipe();
        self.bank.program(scan.next, &entry.encode()?)?;
        Ok(())
    }
}
