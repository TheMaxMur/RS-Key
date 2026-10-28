// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use core::ops::Range;

use embassy_futures::block_on;
use embedded_storage_async::nor_flash::{MultiwriteNorFlash, NorFlash, ReadNorFlash};
use rsk_crypto::hash::Sha256State;
use rsk_sdk::error::{Error, Result};
use rsk_secret::Secret;

use super::append_proof::AppendProof;
use crate::FlashBuf;
use crate::verified_flash::VerifiedFlash;

const IO_CHUNK: usize = 256;

/// Check every byte without a branch for each flash word.
#[inline(always)]
pub fn all_erased(bytes: &[u8]) -> bool {
    let (groups, rest) = bytes.as_chunks::<32>();
    for group in groups {
        let [a, b, c, d, e, f, g, h] = group.as_chunks::<4>().0 else {
            return false;
        };
        if u32::from_ne_bytes(*a)
            & u32::from_ne_bytes(*b)
            & u32::from_ne_bytes(*c)
            & u32::from_ne_bytes(*d)
            & u32::from_ne_bytes(*e)
            & u32::from_ne_bytes(*f)
            & u32::from_ne_bytes(*g)
            & u32::from_ne_bytes(*h)
            != u32::MAX
        {
            return false;
        }
    }
    rest.iter().all(|&byte| byte == 0xFF)
}

/// Hash `prefix || bank[..end] || end.to_le_bytes()`; a non-erased tail returns `None`.
/// The callback reads the supplied flash afresh; it never receives a root key.
pub type BankDigest<F> = fn(&mut F, Range<u32>, u32, &[u8]) -> Result<Option<[u8; 32]>>;

/// Read every byte of the supplied flash range and require erased contents.
pub type BankErased<F> = fn(&mut F, Range<u32>) -> Result<bool>;

/// A raw authority window. Metadata reads never invoke map repair or CRC filtering.
pub struct RawBank<F: NorFlash + MultiwriteNorFlash> {
    flash: VerifiedFlash<F>,
    range: Range<u32>,
    pub(super) digest: Option<BankDigest<F>>,
    pub(super) erased: Option<BankErased<F>>,
    pub(super) append_proof: Option<AppendProof>,
}

impl<F: NorFlash + MultiwriteNorFlash> RawBank<F> {
    pub fn new(flash: F, range: Range<u32>) -> Result<Self> {
        let erase = u32::try_from(F::ERASE_SIZE).map_err(|_| Error::MemoryFatal)?;
        if erase == 0
            || F::READ_SIZE == 0
            || F::READ_SIZE > IO_CHUNK
            || !IO_CHUNK.is_multiple_of(F::READ_SIZE)
            || F::WRITE_SIZE == 0
            || F::WRITE_SIZE > IO_CHUNK
            || !IO_CHUNK.is_multiple_of(F::WRITE_SIZE)
            || !F::ERASE_SIZE.is_multiple_of(F::READ_SIZE)
            || !F::ERASE_SIZE.is_multiple_of(F::WRITE_SIZE)
            || range.start >= range.end
            || !range.start.is_multiple_of(erase)
            || !range.end.is_multiple_of(erase)
            || usize::try_from(range.end).map_err(|_| Error::MemoryFatal)? > flash.capacity()
        {
            return Err(Error::MemoryFatal);
        }
        Ok(Self {
            flash: VerifiedFlash::new(flash),
            range,
            digest: None,
            erased: None,
            append_proof: None,
        })
    }

    pub fn range(&self) -> Range<u32> {
        self.range.clone()
    }

    pub fn capacity(&self) -> u32 {
        self.range.end - self.range.start
    }

    fn span(&self, offset: u32, length: usize) -> Result<Range<u32>> {
        let length = u32::try_from(length).map_err(|_| Error::MemoryFatal)?;
        let start = self
            .range
            .start
            .checked_add(offset)
            .ok_or(Error::MemoryFatal)?;
        let end = start.checked_add(length).ok_or(Error::MemoryFatal)?;
        if start < self.range.start || end > self.range.end {
            return Err(Error::MemoryFatal);
        }
        Ok(start..end)
    }

    pub fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<()> {
        let span = self.span(offset, out.len())?;
        if out.is_empty() {
            return Ok(());
        }
        if offset.is_multiple_of(u32::try_from(F::READ_SIZE).map_err(|_| Error::MemoryFatal)?)
            && out.len().is_multiple_of(F::READ_SIZE)
            && out
                .as_ptr()
                .addr()
                .is_multiple_of(core::mem::align_of::<FlashBuf<1>>())
        {
            return block_on(self.flash.read(span.start, out)).map_err(|_| Error::MemoryFatal);
        }
        let read_size = u32::try_from(F::READ_SIZE).map_err(|_| Error::MemoryFatal)?;
        let mut scratch = Secret::new(FlashBuf::<IO_CHUNK>::new());
        let mut at = span.start;
        let mut copied = 0;
        while at < span.end {
            let aligned = at - at % read_size;
            let prefix = usize::try_from(at - aligned).map_err(|_| Error::MemoryFatal)?;
            let remaining = usize::try_from(span.end - at).map_err(|_| Error::MemoryFatal)?;
            let count = remaining.min(IO_CHUNK - prefix);
            let read_count = (prefix + count).div_ceil(F::READ_SIZE) * F::READ_SIZE;
            let bytes = scratch
                .expose_mut()
                .get_mut(..read_count)
                .ok_or(Error::MemoryFatal)?;
            block_on(self.flash.read(aligned, bytes)).map_err(|_| Error::MemoryFatal)?;
            out.get_mut(copied..copied + count)
                .ok_or(Error::MemoryFatal)?
                .copy_from_slice(
                    bytes
                        .get(prefix..prefix + count)
                        .ok_or(Error::MemoryFatal)?,
                );
            at = at
                .checked_add(u32::try_from(count).map_err(|_| Error::MemoryFatal)?)
                .ok_or(Error::MemoryFatal)?;
            copied += count;
        }
        Ok(())
    }

    pub(super) fn digest(&mut self, end: u32, prefix: &[u8]) -> Result<[u8; 32]> {
        self.digest_if_erased_tail(end, prefix)?
            .ok_or(Error::MemoryFatal)
    }

    pub(super) fn remember_prefix(
        &mut self,
        state: Sha256State,
        end: u32,
        key: &[u8; 32],
    ) -> [u8; 32] {
        let proof = AppendProof::new(state, end, key);
        let tag = proof.tag();
        self.append_proof = Some(proof);
        tag
    }

    // Both replicas share this pass instead of duplicating hash framing in callers.
    #[inline(never)]
    pub(super) fn confirm_append(
        &mut self,
        key: &[u8; 32],
        start: u32,
        parts: &[&[u8]],
        prefix: &[u8],
    ) -> Result<Option<[u8; 32]>> {
        let Some(proof) = self.append_proof.take() else {
            return Ok(None);
        };
        let mut tail = [0; 64];
        let bytes = tail.get_mut(..proof.tail()).ok_or(Error::MemoryFatal)?;
        let tail_at = proof
            .end()
            .checked_sub(u32::try_from(bytes.len()).map_err(|_| Error::MemoryFatal)?)
            .ok_or(Error::MemoryFatal)?;
        self.read(tail_at, bytes)?;
        let expected = proof.extend(key, start, bytes, parts)?;
        // extend verified the saved HMAC before deriving this expected digest.
        let fresh = self.digest(expected.end(), prefix)?;
        if !rsk_crypto::ct_eq(&fresh, &expected.raw_digest()) {
            return Err(Error::MemoryFatal);
        }
        let tag = expected.tag();
        self.append_proof = Some(expected);
        Ok(Some(tag))
    }

    pub(super) fn digest_if_erased_tail(
        &mut self,
        end: u32,
        prefix: &[u8],
    ) -> Result<Option<[u8; 32]>> {
        self.span(0, usize::try_from(end).map_err(|_| Error::MemoryFatal)?)?;
        if let Some(digest) = self.digest {
            return digest(self.flash.inner_mut(), self.range.clone(), end, prefix);
        }
        let mut hash = Sha256State::new();
        hash.update(prefix);
        let mut buffer = [0; IO_CHUNK];
        let mut at = 0;
        while at < end {
            let count = usize::try_from(end - at)
                .map_err(|_| Error::MemoryFatal)?
                .min(buffer.len());
            let bytes = buffer.get_mut(..count).ok_or(Error::MemoryFatal)?;
            self.read(at, bytes)?;
            hash.update(bytes);
            at += u32::try_from(count).map_err(|_| Error::MemoryFatal)?;
        }
        if !self.read_erased(end)? {
            return Ok(None);
        }
        hash.update(&end.to_le_bytes());
        Ok(Some(hash.finish()))
    }

    pub fn program(&mut self, offset: u32, data: &[u8]) -> Result<()> {
        self.program_parts(offset, &[data])
    }

    pub fn program_parts(&mut self, offset: u32, parts: &[&[u8]]) -> Result<()> {
        let length = parts.iter().try_fold(0usize, |length, part| {
            length.checked_add(part.len()).ok_or(Error::MemoryFatal)
        })?;
        let span = self.span(offset, length)?;
        let write_size = u32::try_from(F::WRITE_SIZE).map_err(|_| Error::MemoryFatal)?;
        let chunk_size = u32::try_from(IO_CHUNK).map_err(|_| Error::MemoryFatal)?;
        let mut scratch = Secret::new(FlashBuf::<IO_CHUNK>::new());
        let mut at = span.start;
        let mut input = parts.iter().flat_map(|part| part.iter().copied());
        while at < span.end {
            let aligned = at - at % write_size;
            let prefix = usize::try_from(at - aligned).map_err(|_| Error::MemoryFatal)?;
            let remaining = usize::try_from(span.end - at).map_err(|_| Error::MemoryFatal)?;
            // A byte-writable backend can still program whole physical pages.
            // End each chunk at a page boundary to avoid programming one twice.
            let chunk_offset = usize::try_from(at % chunk_size).map_err(|_| Error::MemoryFatal)?;
            let count = remaining.min(IO_CHUNK - chunk_offset);
            let write_count = (prefix + count).div_ceil(F::WRITE_SIZE) * F::WRITE_SIZE;
            let buffer = scratch
                .expose_mut()
                .get_mut(..write_count)
                .ok_or(Error::MemoryFatal)?;
            buffer.fill(0xFF);
            self.read(aligned - self.range.start, buffer)?;
            let output = buffer
                .get_mut(prefix..prefix + count)
                .ok_or(Error::MemoryFatal)?;
            for (old, new) in output.iter_mut().zip(input.by_ref()) {
                if *old & new != new {
                    return Err(Error::MemoryFatal);
                }
                *old = new;
            }
            block_on(self.flash.write(aligned, buffer)).map_err(|_| Error::MemoryFatal)?;
            at = at
                .checked_add(u32::try_from(count).map_err(|_| Error::MemoryFatal)?)
                .ok_or(Error::MemoryFatal)?;
        }
        scratch.wipe();
        Ok(())
    }

    pub fn read_erased(&mut self, offset: u32) -> Result<bool> {
        if offset > self.capacity() {
            return Err(Error::MemoryFatal);
        }
        if let Some(erased) = self.erased {
            let start = self.span(offset, 0)?.start;
            return erased(self.flash.inner_mut(), start..self.range.end);
        }
        let mut scratch = Secret::new(FlashBuf::<IO_CHUNK>::new());
        let mut at = offset;
        while at < self.capacity() {
            let count = usize::try_from(self.capacity() - at)
                .map_err(|_| Error::MemoryFatal)?
                .min(IO_CHUNK);
            let buffer = scratch
                .expose_mut()
                .get_mut(..count)
                .ok_or(Error::MemoryFatal)?;
            self.read(at, buffer)?;
            if !all_erased(buffer) {
                return Ok(false);
            }
            at = at
                .checked_add(u32::try_from(count).map_err(|_| Error::MemoryFatal)?)
                .ok_or(Error::MemoryFatal)?;
        }
        Ok(true)
    }

    pub fn erase(&mut self) -> Result<()> {
        self.append_proof = None;
        block_on(self.flash.erase(self.range.start, self.range.end)).map_err(|_| Error::MemoryFatal)
    }
}

#[cfg(test)]
#[path = "bank_tests.rs"]
mod tests;
