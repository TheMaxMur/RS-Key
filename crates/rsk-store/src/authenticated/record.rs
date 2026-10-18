// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use rsk_crypto::{ct_eq, hmac_sha256, sha256};
use rsk_sdk::error::{Error, Result};

use super::{ENTRY_BYTES, EPOCH_BYTES, FORMAT, TAG_BYTES};

const RECORD_DOMAIN: &[u8; 8] = b"RSKV2REC";
const DELETED_LENGTH: u16 = u16::MAX;
const AUTH_BYTES: usize = 72;

#[cfg(test)]
#[path = "record_tests.rs"]
mod tests;

/// A partition's authority cannot authorize a value from its neighbor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Partition {
    Main,
    Counter,
}

impl Partition {
    pub const fn code(self) -> u8 {
        match self {
            Self::Main => 0,
            Self::Counter => 1,
        }
    }

    pub fn decode(code: u8) -> Result<Self> {
        match code {
            0 => Ok(Self::Main),
            1 => Ok(Self::Counter),
            _ => Err(Error::MemoryFatal),
        }
    }
}

/// The context under which the complete value and its metadata are authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub partition: Partition,
    pub epoch: [u8; EPOCH_BYTES],
}

/// A published value, including empty values, or an authenticated deletion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    fid: u16,
    length: u16,
    generation: u64,
    tag: [u8; TAG_BYTES],
}

impl Entry {
    pub fn live(
        identity: Identity,
        key: &[u8; 32],
        fid: u16,
        generation: u64,
        data: &[u8],
    ) -> Result<Self> {
        if data.len() > rsk_fs::MAX_VALUE_BYTES {
            return Err(Error::MemoryFatal);
        }
        let length = u16::try_from(data.len()).map_err(|_| Error::MemoryFatal)?;
        let mut entry = Self {
            fid,
            length,
            generation,
            tag: [0; TAG_BYTES],
        };
        entry.tag = entry.authenticate(identity, key, data)?;
        Ok(entry)
    }

    pub fn deleted(identity: Identity, key: &[u8; 32], fid: u16, generation: u64) -> Result<Self> {
        let mut entry = Self {
            fid,
            length: DELETED_LENGTH,
            generation,
            tag: [0; TAG_BYTES],
        };
        entry.tag = entry.authenticate(identity, key, &[])?;
        Ok(entry)
    }

    pub const fn fid(self) -> u16 {
        self.fid
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn length(self) -> Option<usize> {
        if self.length == DELETED_LENGTH {
            None
        } else {
            Some(self.length as usize)
        }
    }

    pub fn verify(self, identity: Identity, key: &[u8; 32], data: &[u8]) -> Result<()> {
        self.verify_with(identity, data, |frame| hmac_sha256(key, frame))
            .map(|_| ())
    }

    pub(super) fn verify_with_mac(
        self,
        identity: Identity,
        mac: &rsk_crypto::mac::HmacSha256,
        data: &[u8],
    ) -> Result<[u8; 32]> {
        self.verify_with(identity, data, |frame| mac.tag(frame))
    }

    fn verify_with(
        self,
        identity: Identity,
        data: &[u8],
        tag: impl FnOnce(&[u8]) -> [u8; 32],
    ) -> Result<[u8; 32]> {
        match self.length() {
            Some(length) if length == data.len() => {}
            None if data.is_empty() => {}
            _ => return Err(Error::MemoryFatal),
        }
        let digest = sha256(data);
        let expected = self.authenticate_digest(identity, &digest, tag)?;
        if ct_eq(&expected, &self.tag) {
            Ok(digest)
        } else {
            Err(Error::MemoryFatal)
        }
    }

    fn authenticate(
        self,
        identity: Identity,
        key: &[u8; 32],
        data: &[u8],
    ) -> Result<[u8; TAG_BYTES]> {
        self.authenticate_with(identity, data, |frame| hmac_sha256(key, frame))
    }

    fn authenticate_with(
        self,
        identity: Identity,
        data: &[u8],
        tag: impl FnOnce(&[u8]) -> [u8; 32],
    ) -> Result<[u8; TAG_BYTES]> {
        self.authenticate_digest(identity, &sha256(data), tag)
    }

    fn authenticate_digest(
        self,
        identity: Identity,
        digest: &[u8; 32],
        tag: impl FnOnce(&[u8]) -> [u8; 32],
    ) -> Result<[u8; TAG_BYTES]> {
        let mut frame = [0; AUTH_BYTES];
        field(&mut frame, 0, RECORD_DOMAIN)?;
        field(&mut frame, 8, &[FORMAT, identity.partition.code()])?;
        field(&mut frame, 10, &self.length.to_le_bytes())?;
        field(&mut frame, 12, &identity.epoch)?;
        field(&mut frame, 28, &self.generation.to_le_bytes())?;
        field(&mut frame, 36, &self.fid.to_le_bytes())?;
        field(&mut frame, 40, digest)?;
        let full_tag = tag(&frame);
        let mut tag = [0; TAG_BYTES];
        tag.copy_from_slice(full_tag.get(..TAG_BYTES).ok_or(Error::MemoryFatal)?);
        Ok(tag)
    }

    pub fn encode(self) -> Result<[u8; ENTRY_BYTES]> {
        let mut out = [0xFF; ENTRY_BYTES];
        field(&mut out, 0, &self.fid.to_le_bytes())?;
        field(&mut out, 2, &self.length.to_le_bytes())?;
        field(&mut out, 4, &self.generation.to_le_bytes())?;
        field(&mut out, 12, &self.tag)?;
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ENTRY_BYTES
            || !bytes
                .get(28..)
                .ok_or(Error::MemoryFatal)?
                .iter()
                .all(|&byte| byte == 0xFF)
        {
            return Err(Error::MemoryFatal);
        }
        let fid = u16::from_le_bytes(take(bytes, 0)?);
        let length = u16::from_le_bytes(take(bytes, 2)?);
        let generation = u64::from_le_bytes(take(bytes, 4)?);
        let tag = take(bytes, 12)?;
        if length != DELETED_LENGTH && usize::from(length) > rsk_fs::MAX_VALUE_BYTES {
            return Err(Error::MemoryFatal);
        }
        Ok(Self {
            fid,
            length,
            generation,
            tag,
        })
    }
}

pub(super) fn field(out: &mut [u8], offset: usize, bytes: &[u8]) -> Result<()> {
    let end = offset.checked_add(bytes.len()).ok_or(Error::MemoryFatal)?;
    out.get_mut(offset..end)
        .ok_or(Error::MemoryFatal)?
        .copy_from_slice(bytes);
    Ok(())
}

pub(super) fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let end = offset.checked_add(N).ok_or(Error::MemoryFatal)?;
    bytes
        .get(offset..end)
        .ok_or(Error::MemoryFatal)?
        .try_into()
        .map_err(|_| Error::MemoryFatal)
}
