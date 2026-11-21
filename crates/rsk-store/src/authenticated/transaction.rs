// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use rsk_crypto::{ct_eq, hmac_sha256, sha256};
use rsk_sdk::error::{Error, Result};

use super::record::{field, take};
use super::{Entry, FORMAT, Partition};

const DELTA_MAGIC: &[u8; 8] = b"RSKTXN02";
pub const DELTA_BYTES: usize = 128;
const TAG_OFFSET: usize = 96;
const TAG_END: usize = 112;

/// An authenticated intent precedes all candidate programming.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeltaKind {
    Prepare,
    Commit,
    Abort,
}

impl DeltaKind {
    const fn code(self) -> u8 {
        match self {
            Self::Prepare => 0,
            Self::Commit => 1,
            Self::Abort => 2,
        }
    }

    fn decode(code: u8) -> Result<Self> {
        match code {
            0 => Ok(Self::Prepare),
            1 => Ok(Self::Commit),
            2 => Ok(Self::Abort),
            _ => Err(Error::MemoryFatal),
        }
    }
}

/// One linked journal record. The entry MAC binds the format epoch and full payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delta {
    pub kind: DeltaKind,
    pub partition: Partition,
    pub sequence: u64,
    pub address: u32,
    pub entry: Entry,
    pub previous: [u8; 32],
}

impl Delta {
    pub fn encode(self, key: &[u8; 32]) -> Result<[u8; DELTA_BYTES]> {
        self.check_entry()?;
        let mut bytes = [0xFF; DELTA_BYTES];
        field(&mut bytes, 0, DELTA_MAGIC)?;
        field(
            &mut bytes,
            8,
            &[self.kind.code(), self.partition.code(), FORMAT],
        )?;
        field(&mut bytes, 12, &self.sequence.to_le_bytes())?;
        field(&mut bytes, 20, &self.address.to_le_bytes())?;
        field(&mut bytes, 24, &self.entry.encode()?)?;
        field(&mut bytes, 56, &self.previous)?;
        let tag = hmac_sha256(key, bytes.get(..TAG_OFFSET).ok_or(Error::MemoryFatal)?);
        field(
            &mut bytes,
            TAG_OFFSET,
            tag.get(..super::TAG_BYTES).ok_or(Error::MemoryFatal)?,
        )?;
        Ok(bytes)
    }

    pub fn verify(bytes: &[u8], key: &[u8; 32]) -> Result<Self> {
        if bytes.len() != DELTA_BYTES
            || bytes.get(..8) != Some(DELTA_MAGIC.as_slice())
            || bytes.get(10) != Some(&FORMAT)
            || bytes.get(11) != Some(&0xFF)
            || !bytes
                .get(88..TAG_OFFSET)
                .ok_or(Error::MemoryFatal)?
                .iter()
                .all(|&b| b == 0xFF)
            || !bytes
                .get(TAG_END..)
                .ok_or(Error::MemoryFatal)?
                .iter()
                .all(|&b| b == 0xFF)
        {
            return Err(Error::MemoryFatal);
        }
        let tag = hmac_sha256(key, bytes.get(..TAG_OFFSET).ok_or(Error::MemoryFatal)?);
        if !ct_eq(
            tag.get(..super::TAG_BYTES).ok_or(Error::MemoryFatal)?,
            bytes.get(TAG_OFFSET..TAG_END).ok_or(Error::MemoryFatal)?,
        ) {
            return Err(Error::MemoryFatal);
        }
        let delta = Self {
            kind: DeltaKind::decode(*bytes.get(8).ok_or(Error::MemoryFatal)?)?,
            partition: Partition::decode(*bytes.get(9).ok_or(Error::MemoryFatal)?)?,
            sequence: u64::from_le_bytes(take(bytes, 12)?),
            address: u32::from_le_bytes(take(bytes, 20)?),
            entry: Entry::decode(bytes.get(24..56).ok_or(Error::MemoryFatal)?)?,
            previous: take(bytes, 56)?,
        };
        delta.check_entry()?;
        Ok(delta)
    }

    fn check_entry(self) -> Result<()> {
        if self.entry.generation() != self.sequence
            || self.sequence == 0
            || (self.partition == Partition::Counter) != crate::is_counter_fid(self.entry.fid())
            || (self.entry.length().is_none() && self.address != 0)
        {
            return Err(Error::MemoryFatal);
        }
        Ok(())
    }
}

/// Recovery retains the exact authenticated candidate instead of removing its FID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prepared {
    pub entry: Entry,
    pub address: u32,
}

/// Intent/publication sequencing, kept separate from physical flash operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionState {
    partition: Partition,
    sequence: u64,
    chain: [u8; 32],
    pending: Option<Prepared>,
}

impl TransactionState {
    pub const fn new(partition: Partition, sequence: u64, chain: [u8; 32]) -> Self {
        Self {
            partition,
            sequence,
            chain,
            pending: None,
        }
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    pub const fn chain(self) -> [u8; 32] {
        self.chain
    }
    pub const fn pending(self) -> Option<Prepared> {
        self.pending
    }

    pub fn next_sequence(self) -> Result<u64> {
        self.sequence.checked_add(1).ok_or(Error::MemoryFatal)
    }

    pub fn apply(&mut self, bytes: &[u8], key: &[u8; 32]) -> Result<Option<Entry>> {
        let delta = Delta::verify(bytes, key)?;
        if delta.partition != self.partition
            || delta.sequence != self.next_sequence()?
            || !ct_eq(&delta.previous, &self.chain)
        {
            return Err(Error::MemoryFatal);
        }
        let prepared = Prepared {
            entry: delta.entry,
            address: delta.address,
        };
        let result = match (delta.kind, self.pending) {
            (DeltaKind::Prepare, None) => {
                self.pending = Some(prepared);
                None
            }
            (DeltaKind::Commit, Some(expected)) if expected == prepared => {
                self.pending = None;
                self.sequence = delta.sequence;
                Some(delta.entry)
            }
            (DeltaKind::Abort, Some(expected)) if expected == prepared => {
                self.pending = None;
                self.sequence = delta.sequence;
                None
            }
            _ => return Err(Error::MemoryFatal),
        };
        self.chain = sha256(bytes);
        Ok(result)
    }
}
