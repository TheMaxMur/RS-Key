// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use embedded_storage_async::nor_flash::{MultiwriteNorFlash, NorFlash};
use rsk_crypto::{ct_eq, sha256};
use rsk_sdk::error::{Error, Result};

use super::{CHECKPOINT_BYTES, Checkpoint, DELTA_BYTES, Delta, Directory, ENTRY_BYTES, Entry};
use super::{Partition, RawBank, TransactionState};

/// Invalid bytes never become an authoritative older complete prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalStatus {
    Empty,
    Complete,
    Dirty,
}

/// Authenticated progress survives a dirty suffix as a minimum freshness bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalScan {
    pub status: JournalStatus,
    pub checkpoint: Option<Checkpoint>,
    pub state: Option<TransactionState>,
    pub lower_bound: Option<u64>,
    pub next: u32,
}

/// A main-directory snapshot followed by a linked intent/publication journal.
pub struct Journal<F: NorFlash + MultiwriteNorFlash> {
    bank: RawBank<F>,
    partition: Partition,
}

impl<F: NorFlash + MultiwriteNorFlash> Journal<F> {
    pub fn new(bank: RawBank<F>, partition: Partition) -> Self {
        Self { bank, partition }
    }

    pub fn capacity(&self) -> u32 {
        self.bank.capacity()
    }

    pub fn read_header(&mut self) -> Result<[u8; CHECKPOINT_BYTES]> {
        let mut bytes = [0; CHECKPOINT_BYTES];
        self.bank.read(0, &mut bytes)?;
        Ok(bytes)
    }

    pub fn scan<const N: usize>(
        &mut self,
        key: &[u8; 32],
        directory: &mut Directory<N>,
    ) -> Result<JournalScan> {
        directory.clear();
        let header = self.read_header()?;
        let mut scan = JournalScan {
            status: JournalStatus::Dirty,
            checkpoint: None,
            state: None,
            lower_bound: None,
            next: 0,
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
        if checkpoint.identity.partition != self.partition {
            return Ok(scan);
        }
        scan.checkpoint = Some(checkpoint);
        scan.lower_bound = Some(checkpoint.sequence);
        let count = usize::try_from(checkpoint.entries).map_err(|_| Error::MemoryFatal)?;
        let snapshot_size = count
            .checked_mul(ENTRY_BYTES)
            .and_then(|bytes| bytes.checked_add(CHECKPOINT_BYTES))
            .and_then(|bytes| u32::try_from(bytes).ok())
            .ok_or(Error::MemoryFatal)?;
        if snapshot_size > self.bank.capacity() {
            return Ok(scan);
        }
        let mut at = u32::try_from(CHECKPOINT_BYTES).map_err(|_| Error::MemoryFatal)?;
        for _ in 0..count {
            let mut bytes = [0; ENTRY_BYTES];
            self.bank.read(at, &mut bytes)?;
            let Ok(entry) = Entry::decode(&bytes) else {
                return Ok(scan);
            };
            if (self.partition == Partition::Counter) != crate::is_counter_fid(entry.fid())
                || directory.push_snapshot(entry, checkpoint.sequence).is_err()
            {
                return Ok(scan);
            }
            at = at
                .checked_add(u32::try_from(ENTRY_BYTES).map_err(|_| Error::MemoryFatal)?)
                .ok_or(Error::MemoryFatal)?;
        }
        if !ct_eq(
            &directory.digest(checkpoint.identity, key, checkpoint.sequence)?,
            &checkpoint.digest,
        ) {
            return Ok(scan);
        }
        let mut state = TransactionState::new(self.partition, checkpoint.sequence, sha256(&header));
        scan.state = Some(state);
        scan.next = at;
        while at < self.bank.capacity() {
            if self.bank.capacity() - at
                < u32::try_from(DELTA_BYTES).map_err(|_| Error::MemoryFatal)?
            {
                if self.bank.read_erased(at)? {
                    scan.status = JournalStatus::Complete;
                }
                return Ok(scan);
            }
            let mut bytes = [0; DELTA_BYTES];
            self.bank.read(at, &mut bytes)?;
            if bytes.iter().all(|&byte| byte == 0xFF) {
                if self.bank.read_erased(at)? {
                    scan.status = JournalStatus::Complete;
                }
                return Ok(scan);
            }
            let Ok(published) = state.apply(&bytes, key) else {
                return Ok(scan);
            };
            if let Some(entry) = published
                && directory.apply(entry).is_err()
            {
                return Ok(scan);
            }
            at = at
                .checked_add(u32::try_from(DELTA_BYTES).map_err(|_| Error::MemoryFatal)?)
                .ok_or(Error::MemoryFatal)?;
            scan.state = Some(state);
            scan.lower_bound = Some(state.sequence());
            scan.next = at;
        }
        scan.status = JournalStatus::Complete;
        Ok(scan)
    }

    pub fn write_snapshot<const N: usize>(
        &mut self,
        checkpoint: Checkpoint,
        key: &[u8; 32],
        directory: &Directory<N>,
    ) -> Result<JournalScan> {
        if checkpoint.identity.partition != self.partition
            || usize::try_from(checkpoint.entries).map_err(|_| Error::MemoryFatal)?
                != directory.entries().len()
            || !ct_eq(
                &directory.digest(checkpoint.identity, key, checkpoint.sequence)?,
                &checkpoint.digest,
            )
        {
            return Err(Error::MemoryFatal);
        }
        let end = directory
            .entries()
            .len()
            .checked_mul(ENTRY_BYTES)
            .and_then(|bytes| bytes.checked_add(CHECKPOINT_BYTES))
            .and_then(|bytes| bytes.checked_add(2 * DELTA_BYTES))
            .and_then(|bytes| u32::try_from(bytes).ok())
            .ok_or(Error::MemoryFatal)?;
        if end > self.bank.capacity() {
            return Err(Error::NoMemory);
        }
        if directory.entries().iter().any(|entry| {
            entry.length().is_none()
                || entry.generation() > checkpoint.sequence
                || (self.partition == Partition::Counter) != crate::is_counter_fid(entry.fid())
        }) {
            return Err(Error::MemoryFatal);
        }
        let header = checkpoint.encode(key)?;
        self.bank.erase()?;
        let mut at = u32::try_from(CHECKPOINT_BYTES).map_err(|_| Error::MemoryFatal)?;
        for entry in directory.entries() {
            self.bank.program(at, &entry.encode()?)?;
            at = at
                .checked_add(u32::try_from(ENTRY_BYTES).map_err(|_| Error::MemoryFatal)?)
                .ok_or(Error::MemoryFatal)?;
        }
        // The tag is the publication point; all snapshot bytes precede it.
        self.bank
            .program(0, header.get(..80).ok_or(Error::MemoryFatal)?)?;
        self.bank
            .program(80, header.get(80..96).ok_or(Error::MemoryFatal)?)?;
        Ok(JournalScan {
            status: JournalStatus::Complete,
            checkpoint: Some(checkpoint),
            state: Some(TransactionState::new(
                self.partition,
                checkpoint.sequence,
                sha256(&header),
            )),
            lower_bound: Some(checkpoint.sequence),
            next: at,
        })
    }

    pub fn append(&mut self, next: u32, delta: Delta, key: &[u8; 32]) -> Result<()> {
        if delta.partition != self.partition {
            return Err(Error::MemoryFatal);
        }
        let end = next
            .checked_add(u32::try_from(DELTA_BYTES).map_err(|_| Error::MemoryFatal)?)
            .ok_or(Error::MemoryFatal)?;
        if end > self.bank.capacity() {
            return Err(Error::NoMemory);
        }
        let bytes = delta.encode(key)?;
        self.bank
            .program(next, bytes.get(..96).ok_or(Error::MemoryFatal)?)?;
        self.bank
            .program(next + 96, bytes.get(96..112).ok_or(Error::MemoryFatal)?)?;
        Ok(())
    }
}
