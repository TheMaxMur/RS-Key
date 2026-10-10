// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use heapless::Vec;
use rsk_crypto::hmac_sha256;
use rsk_sdk::error::{Error, Result};

use super::record::field;
use super::{ENTRY_BYTES, Entry, Identity};

const DIRECTORY_DOMAIN: &[u8; 8] = b"RSKV2DIR";

/// A complete live-key set. Absence is authoritative only after its digest verifies.
pub struct Directory<const N: usize> {
    entries: Vec<Entry, N>,
}

impl<const N: usize> Default for Directory<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Directory<N> {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn find(&self, fid: u16) -> Option<Entry> {
        let index = self
            .entries
            .binary_search_by_key(&fid, |entry| entry.fid())
            .ok()?;
        self.entries.get(index).copied()
    }

    pub fn apply(&mut self, entry: Entry) -> Result<()> {
        let index = self
            .entries
            .binary_search_by_key(&entry.fid(), |item| item.fid());
        match (index, entry.length()) {
            (Ok(index), Some(_)) => {
                *self.entries.get_mut(index).ok_or(Error::MemoryFatal)? = entry;
            }
            (Ok(index), None) => {
                self.entries.remove(index);
            }
            (Err(index), Some(_)) => {
                self.entries
                    .insert(index, entry)
                    .map_err(|_| Error::NoMemory)?;
            }
            (Err(_), None) => {}
        }
        Ok(())
    }

    pub fn push_snapshot(&mut self, entry: Entry, sequence: u64) -> Result<()> {
        if entry.length().is_none()
            || entry.generation() > sequence
            || self
                .entries
                .last()
                .is_some_and(|last| last.fid() >= entry.fid())
        {
            return Err(Error::MemoryFatal);
        }
        self.entries.push(entry).map_err(|_| Error::NoMemory)
    }

    pub fn digest(&self, identity: Identity, key: &[u8; 32], sequence: u64) -> Result<[u8; 32]> {
        let mut prefix = [0; 40];
        field(&mut prefix, 0, DIRECTORY_DOMAIN)?;
        field(&mut prefix, 8, &[super::FORMAT, identity.partition.code()])?;
        field(&mut prefix, 12, &identity.epoch)?;
        field(&mut prefix, 28, &sequence.to_le_bytes())?;
        let count = u32::try_from(self.entries.len()).map_err(|_| Error::MemoryFatal)?;
        field(&mut prefix, 36, &count.to_le_bytes())?;
        let mut digest = hmac_sha256(key, &prefix);
        let mut frame = [0; 32 + ENTRY_BYTES];
        for entry in &self.entries {
            field(&mut frame, 0, &digest)?;
            field(&mut frame, 32, &entry.encode()?)?;
            digest = hmac_sha256(key, &frame);
        }
        Ok(digest)
    }
}
