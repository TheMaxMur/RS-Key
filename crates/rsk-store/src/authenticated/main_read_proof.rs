// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::authenticated::KeySource;

impl<F: NorFlash + MultiwriteNorFlash, C: CacheImpl<u16>> Main<F, C> {
    pub(in crate::authenticated) fn read_with_source(
        &mut self,
        source: KeySource,
        arm: RootArm,
        fid: u16,
        out: &mut [u8],
    ) -> Result<Option<usize>> {
        let result = if arm == self.arm {
            self.read_proven(source, fid, out)
        } else {
            Err(Error::MemoryFatal)
        };
        if result.is_err() {
            self.invalidate_read_cache();
        }
        result
    }

    #[inline(never)]
    fn read_proven(
        &mut self,
        source: KeySource,
        fid: u16,
        out: &mut [u8],
    ) -> Result<Option<usize>> {
        let Some(current) = self.read_cache else {
            let key = source.key(self.arm)?;
            return self.read(key.expose(), fid, out);
        };
        self.journals
            .get(current.source)
            .ok_or(Error::MemoryFatal)?;
        let bound = self.authority.read_bound(self.identity, self.arm)?;
        let Some(entry) = self.directory.find(fid) else {
            let cached = self.read_tags.mount_tag(bound);
            let proof = source.prepare_read(self.arm, cached.is_none())?;
            if let Some(expected) = cached {
                proof.verify_mount(bound, &expected)?;
            } else {
                let mac = rsk_crypto::mac::HmacSha256::new(proof.persisted_key()?);
                self.authority
                    .verify_read_with_mac(&mac, self.identity, self.arm)?;
                self.read_tags.bind(bound, proof.mount_tag(bound)?);
            }
            return Ok(None);
        };
        let cached = self.read_tags.find(bound, entry);
        let proof = source.prepare_read(self.arm, cached.is_none())?;
        let persisted = if cached.is_none() {
            let mac = rsk_crypto::mac::HmacSha256::new(proof.persisted_key()?);
            self.authority
                .verify_read_with_mac(&mac, self.identity, self.arm)?;
            Some(mac)
        } else {
            None
        };
        let length = entry.length().ok_or(Error::MemoryFatal)?;
        let capacity = length
            .checked_add(core::mem::size_of::<u16>())
            .and_then(|length| length.checked_next_multiple_of(F::READ_SIZE.max(F::WRITE_SIZE)))
            .ok_or(Error::MemoryFatal)?;
        {
            let mut scratch = WipeGuard::new(
                self.buffer
                    .expose_mut()
                    .get_mut(..capacity)
                    .ok_or(Error::MemoryFatal)?,
            );
            match block_on(self.map.fetch_item_unrepaired::<&[u8]>(&mut scratch, &fid)) {
                Ok(Some(value)) => {
                    let digest = match &persisted {
                        Some(mac) => entry.verify_with_mac(self.identity, mac, value).ok(),
                        None if value.len() == length => Some(rsk_crypto::sha256(value)),
                        None => return Err(Error::MemoryFatal),
                    };
                    if let Some(digest) = digest {
                        let tag = proof.payload_tag(bound, entry, &digest)?;
                        if cached.is_some_and(|expected| !ct_eq(&expected, &tag)) {
                            return Err(Error::MemoryFatal);
                        }
                        let count = out.len().min(length);
                        out.get_mut(..count)
                            .ok_or(Error::MemoryFatal)?
                            .copy_from_slice(value.get(..count).ok_or(Error::MemoryFatal)?);
                        if cached.is_none() {
                            self.read_tags.bind(bound, proof.mount_tag(bound)?);
                            self.read_tags.insert(bound, entry, tag);
                        }
                        return Ok(Some(length));
                    }
                }
                Ok(None)
                | Err(
                    sequential_storage::Error::Corrupted { .. }
                    | sequential_storage::Error::BufferTooSmall(_),
                ) => {}
                Err(_) => return Err(Error::MemoryFatal),
            }
        }
        let result = if cached.is_some() {
            let expected = self.read_tags.mount_tag(bound).ok_or(Error::MemoryFatal)?;
            // The first observation must pass before recovery verifies the second.
            proof.verify_mount(bound, &expected)?;
            let key = source.key(self.arm)?;
            self.read_inner(key.expose(), fid, out)
        } else {
            self.read_inner(proof.persisted_key()?, fid, out)
        };
        self.buffer.wipe();
        result
    }
}
