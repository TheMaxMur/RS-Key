// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use embedded_storage_async::nor_flash::{MultiwriteNorFlash, NorFlash};
use rsk_crypto::{ct_eq, hash::Sha256State};
use rsk_sdk::error::{Error, Result};
use rsk_secret::Secret;

use super::{CHECKPOINT_BYTES, Checkpoint, Directory, ENTRY_BYTES, Entry, JournalStatus};
use super::{MAX_COUNTER_ENTRIES, Partition, RawBank};

#[path = "counter_scan.rs"]
mod scan;
#[path = "counter_snapshot.rs"]
mod snapshot;

const RAW_DOMAIN: &[u8; 8] = b"RSKV2CTR";

pub(super) const VALUE_ALIGNMENT: usize = 16;
const VALUE_BUFFER: usize = crate::KV_BUF;

/// The header precedes the value; its MAC authenticates the complete record.
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
    pub(crate) raw_fingerprint: Option<[u8; 32]>,
}

impl CounterScan {
    pub(super) const fn new() -> Self {
        Self {
            status: JournalStatus::Dirty,
            checkpoint: None,
            sequence: None,
            lower_bound: None,
            next: 0,
            locations: [None; MAX_COUNTER_ENTRIES],
            fingerprint: None,
            raw_fingerprint: None,
        }
    }

    pub(super) fn entry(&self, fid: u16) -> Option<Entry> {
        self.locations
            .get(scan::counter_index(fid).ok()?)?
            .as_ref()
            .filter(|location| location.entry.fid() == fid)
            .map(|location| location.entry)
    }
}

/// Inline counter authority avoids a separate payload mutation and intent journal.
pub struct CounterBank<F: NorFlash + MultiwriteNorFlash> {
    bank: RawBank<F>,
}

impl<F: NorFlash + MultiwriteNorFlash> CounterBank<F> {
    pub const fn new(bank: RawBank<F>) -> Self {
        Self { bank }
    }
    pub fn capacity(&self) -> u32 {
        self.bank.capacity()
    }

    pub(super) fn set_digest(&mut self, digest: super::BankDigest<F>) {
        self.bank.digest = Some(digest);
    }

    pub(super) fn set_erased(&mut self, erased: super::BankErased<F>) {
        self.bank.erased = Some(erased);
    }

    pub(super) fn raw_fingerprint(&mut self, end: u32) -> Result<Option<[u8; 32]>> {
        let prefix = self.fingerprint_prefix()?;
        self.bank.digest_if_erased_tail(end, &prefix)
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
        scan: &mut CounterScan,
        key: &[u8; 32],
        entry: Entry,
        value: &[u8],
    ) -> Result<bool> {
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
            return Ok(false);
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
        scan.raw_fingerprint = self
            .bank
            .append_proof
            .as_ref()
            .map(|proof| proof.raw_digest());
        Ok(true)
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

    pub fn scan(
        &mut self,
        key: &[u8; 32],
        directory: &mut Directory<MAX_COUNTER_ENTRIES>,
    ) -> Result<CounterScan> {
        let mut scan = const { CounterScan::new() };
        self.scan_into(key, directory, &mut scan)?;
        Ok(scan)
    }

    pub(super) fn scan_into(
        &mut self,
        key: &[u8; 32],
        directory: &mut Directory<MAX_COUNTER_ENTRIES>,
        scan: &mut CounterScan,
    ) -> Result<()> {
        scan::scan_into(&mut self.bank, key, directory, scan)
    }

    pub fn read_value(
        &mut self,
        scan: &CounterScan,
        key: &[u8; 32],
        fid: u16,
        out: &mut [u8],
    ) -> Result<Option<usize>> {
        let checkpoint = scan.checkpoint.ok_or(Error::MemoryFatal)?;
        self.read_checked(scan, fid, out, |entry, value| {
            entry.verify(checkpoint.identity, key, value).map(|_| ())
        })
    }

    pub(super) fn read_checked(
        &mut self,
        scan: &CounterScan,
        fid: u16,
        out: &mut [u8],
        verify: impl FnOnce(Entry, &[u8]) -> Result<()>,
    ) -> Result<Option<usize>> {
        if scan.status != JournalStatus::Complete {
            return Err(Error::MemoryFatal);
        }
        let index = Self::counter_index(fid)?;
        let Some(location) = *scan.locations.get(index).ok_or(Error::MemoryFatal)? else {
            return Ok(None);
        };
        if location.entry.fid() != fid {
            return Err(Error::MemoryFatal);
        }
        if Self::padded_length(location.entry)? <= VALUE_ALIGNMENT {
            self.copy_checked::<VALUE_ALIGNMENT>(location, out, verify)
        } else {
            self.copy_checked::<VALUE_BUFFER>(location, out, verify)
        }
    }

    #[inline(never)]
    fn copy_checked<const N: usize>(
        &mut self,
        location: CounterLocation,
        out: &mut [u8],
        verify: impl FnOnce(Entry, &[u8]) -> Result<()>,
    ) -> Result<Option<usize>> {
        let mut scratch = Secret::new(crate::FlashBuf::<N>::new());
        let (_, value) = scan::read_payload(
            &mut self.bank,
            location.entry,
            location.value_offset,
            scratch.expose_mut(),
        )?
        .ok_or(Error::MemoryFatal)?;
        verify(location.entry, value)?;
        let length = location.entry.length().ok_or(Error::MemoryFatal)?;
        let count = out.len().min(length);
        out.get_mut(..count)
            .ok_or(Error::MemoryFatal)?
            .copy_from_slice(scratch.expose().get(..count).ok_or(Error::MemoryFatal)?);
        scratch.wipe();
        Ok(Some(length))
    }

    pub(super) fn read_bound_frame(
        &mut self,
        scan: &CounterScan,
        fid: u16,
        out: &mut [u8],
    ) -> Result<Option<Entry>> {
        if scan.status != JournalStatus::Complete
            || super::bound_counter::bucket_index(fid).is_none()
        {
            return Err(Error::MemoryFatal);
        }
        let Some(location) = *scan
            .locations
            .get(Self::counter_index(fid)?)
            .ok_or(Error::MemoryFatal)?
        else {
            return Ok(None);
        };
        let entry = location.entry;
        let length = entry.length().ok_or(Error::MemoryFatal)?;
        let padded = Self::padded_length(entry)?;
        let offset = location
            .value_offset
            .checked_sub(u32::try_from(ENTRY_BYTES).map_err(|_| Error::MemoryFatal)?)
            .ok_or(Error::MemoryFatal)?;
        let bytes = out
            .get_mut(..ENTRY_BYTES + padded)
            .ok_or(Error::MemoryFatal)?;
        self.bank.read(offset, bytes)?;
        if entry.fid() != fid
            || !ct_eq(
                bytes.get(..ENTRY_BYTES).ok_or(Error::MemoryFatal)?,
                &entry.encode()?,
            )
            || !bytes
                .get(ENTRY_BYTES + length..)
                .ok_or(Error::MemoryFatal)?
                .iter()
                .all(|&byte| byte == 0xff)
        {
            return Err(Error::MemoryFatal);
        }
        Ok(Some(entry))
    }

    pub fn write_snapshot(
        &mut self,
        checkpoint: Checkpoint,
        key: &[u8; 32],
        directory: &Directory<MAX_COUNTER_ENTRIES>,
        load: impl FnMut(Entry, &mut [u8]) -> Result<()>,
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
        snapshot::write_entries(self, checkpoint, key, directory, load)?;
        self.bank
            .program(0, header.get(..80).ok_or(Error::MemoryFatal)?)?;
        self.bank
            .program(80, header.get(80..96).ok_or(Error::MemoryFatal)?)?;
        Ok(())
    }

    pub fn append(
        &mut self,
        scan: &CounterScan,
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
        let header = entry.encode()?;
        let padding = [0xFF; VALUE_ALIGNMENT];
        let fill = padded.checked_sub(value.len()).ok_or(Error::MemoryFatal)?;
        // A torn header cannot publish the generation without the full payload MAC.
        self.bank.program_parts(
            scan.next,
            &[
                &header,
                value,
                padding.get(..fill).ok_or(Error::MemoryFatal)?,
            ],
        )
    }
}
