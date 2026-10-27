// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use embedded_storage_async::nor_flash::{MultiwriteNorFlash, NorFlash};
use rsk_crypto::{ct_eq, hash::Sha256State, hmac_sha256};
use rsk_sdk::error::{Error, Result};
use rsk_secret::Secret;

use super::{CHECKPOINT_BYTES, Checkpoint, Directory, ENTRY_BYTES, Entry, JournalStatus};
use super::{MAX_COUNTER_ENTRIES, Partition, RawBank};

#[path = "counter_scan.rs"]
mod scan;

const RAW_DOMAIN: &[u8; 8] = b"RSKV2CTR";

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
    pub(crate) fingerprint: Option<[u8; 32]>,
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

    pub(super) fn set_digest(&mut self, digest: super::BankDigest<F>) {
        self.bank.digest = Some(digest);
    }

    pub(super) fn fingerprint(&mut self, key: &[u8; 32], end: u32) -> Result<Option<[u8; 32]>> {
        let prefix = self.fingerprint_prefix()?;
        Ok(self
            .bank
            .digest_if_erased_tail(end, &prefix)?
            .map(|digest| hmac_sha256(key, &digest)))
    }

    fn fingerprint_prefix(&self) -> Result<[u8; RAW_DOMAIN.len() + core::mem::size_of::<u32>()]> {
        let mut prefix = [0; RAW_DOMAIN.len() + core::mem::size_of::<u32>()];
        prefix
            .get_mut(..RAW_DOMAIN.len())
            .ok_or(Error::MemoryFatal)?
            .copy_from_slice(RAW_DOMAIN);
        prefix
            .get_mut(RAW_DOMAIN.len()..)
            .ok_or(Error::MemoryFatal)?
            .copy_from_slice(&self.capacity().to_le_bytes());
        Ok(prefix)
    }

    pub(super) fn confirm_append(
        &mut self,
        mut scan: CounterScan,
        key: &[u8; 32],
        entry: Entry,
        value: &[u8],
    ) -> Result<Option<CounterScan>> {
        let index = Self::counter_index(entry.fid())?;
        let padded = Self::padded_length(entry)?;
        let padding = padded.checked_sub(value.len()).ok_or(Error::MemoryFatal)?;
        let erased = [0xff; VALUE_ALIGNMENT];
        let prefix = self.fingerprint_prefix()?;
        let Some(tag) = self.bank.confirm_append(
            key,
            scan.next,
            &[
                &entry.encode()?,
                value,
                erased.get(..padding).ok_or(Error::MemoryFatal)?,
            ],
            &prefix,
        )?
        else {
            return Ok(None);
        };
        let value_offset = scan
            .next
            .checked_add(u32::try_from(ENTRY_BYTES).map_err(|_| Error::MemoryFatal)?)
            .ok_or(Error::MemoryFatal)?;
        *scan.locations.get_mut(index).ok_or(Error::MemoryFatal)? =
            entry.length().map(|_| CounterLocation {
                entry,
                value_offset,
            });
        scan.next = value_offset
            .checked_add(u32::try_from(padded).map_err(|_| Error::MemoryFatal)?)
            .ok_or(Error::MemoryFatal)?;
        scan.sequence = Some(entry.generation());
        scan.lower_bound = scan.sequence;
        scan.fingerprint = Some(tag);
        Ok(Some(scan))
    }

    pub fn read_header(&mut self) -> Result<[u8; CHECKPOINT_BYTES]> {
        let mut bytes = [0; CHECKPOINT_BYTES];
        self.bank.read(0, &mut bytes)?;
        Ok(bytes)
    }

    fn counter_index(fid: u16) -> Result<usize> {
        scan::counter_index(fid)
    }

    fn padded_length(entry: Entry) -> Result<usize> {
        scan::padded_length(entry)
    }

    fn read_entry_value(
        &mut self,
        entry: Entry,
        offset: u32,
        checkpoint: Checkpoint,
        key: &[u8; 32],
        buffer: &mut [u8; VALUE_BUFFER],
    ) -> Result<Option<usize>> {
        scan::read_entry_value(&mut self.bank, entry, offset, checkpoint, key, buffer)
    }

    pub fn scan(
        &mut self,
        key: &[u8; 32],
        directory: &mut Directory<MAX_COUNTER_ENTRIES>,
    ) -> Result<CounterScan> {
        scan::scan(&mut self.bank, key, directory)
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
