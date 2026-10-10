// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use rsk_crypto::{ct_eq, hmac_sha256};
use rsk_sdk::error::{Error, Result};

use super::record::{field, take};
use super::{FORMAT, Identity, MAX_COUNTER_ENTRIES, MAX_MAIN_ENTRIES, Partition, RootArm};

const CHECKPOINT_MAGIC: &[u8; 8] = b"RSKCAT02";
pub const CHECKPOINT_BYTES: usize = 128;
const TAG_OFFSET: usize = 80;
const TAG_END: usize = 96;

/// The snapshot is written and read back before this authenticated header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub identity: Identity,
    pub arm: RootArm,
    pub sequence: u64,
    pub entries: u32,
    pub digest: [u8; 32],
}

impl Checkpoint {
    pub fn encode(self, key: &[u8; 32]) -> Result<[u8; CHECKPOINT_BYTES]> {
        self.check_count()?;
        let mut bytes = [0xFF; CHECKPOINT_BYTES];
        field(&mut bytes, 0, CHECKPOINT_MAGIC)?;
        field(
            &mut bytes,
            8,
            &[self.identity.partition.code(), self.arm.code(), FORMAT],
        )?;
        field(&mut bytes, 12, &self.entries.to_le_bytes())?;
        field(&mut bytes, 16, &self.identity.epoch)?;
        field(&mut bytes, 32, &self.sequence.to_le_bytes())?;
        field(&mut bytes, 40, &self.digest)?;
        let tag = hmac_sha256(key, bytes.get(..TAG_OFFSET).ok_or(Error::MemoryFatal)?);
        field(
            &mut bytes,
            TAG_OFFSET,
            tag.get(..super::TAG_BYTES).ok_or(Error::MemoryFatal)?,
        )?;
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CHECKPOINT_BYTES
            || bytes.get(..8) != Some(CHECKPOINT_MAGIC.as_slice())
            || bytes.get(10) != Some(&FORMAT)
            || bytes.get(11) != Some(&0xFF)
            || !bytes
                .get(72..TAG_OFFSET)
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
        let checkpoint = Self {
            identity: Identity {
                partition: Partition::decode(*bytes.get(8).ok_or(Error::MemoryFatal)?)?,
                epoch: take(bytes, 16)?,
            },
            arm: RootArm::decode(*bytes.get(9).ok_or(Error::MemoryFatal)?)?,
            entries: u32::from_le_bytes(take(bytes, 12)?),
            sequence: u64::from_le_bytes(take(bytes, 32)?),
            digest: take(bytes, 40)?,
        };
        checkpoint.check_count()?;
        Ok(checkpoint)
    }

    pub fn verify(bytes: &[u8], key: &[u8; 32]) -> Result<Self> {
        let checkpoint = Self::decode(bytes)?;
        let tag = hmac_sha256(key, bytes.get(..TAG_OFFSET).ok_or(Error::MemoryFatal)?);
        if ct_eq(
            tag.get(..super::TAG_BYTES).ok_or(Error::MemoryFatal)?,
            bytes.get(TAG_OFFSET..TAG_END).ok_or(Error::MemoryFatal)?,
        ) {
            Ok(checkpoint)
        } else {
            Err(Error::MemoryFatal)
        }
    }

    fn check_count(self) -> Result<()> {
        let ceiling = match self.identity.partition {
            Partition::Main => MAX_MAIN_ENTRIES,
            Partition::Counter => MAX_COUNTER_ENTRIES,
        };
        if usize::try_from(self.entries).map_err(|_| Error::MemoryFatal)? > ceiling {
            return Err(Error::MemoryFatal);
        }
        Ok(())
    }
}
