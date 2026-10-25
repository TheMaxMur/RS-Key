// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use core::ops::Range;
use embassy_futures::block_on;
use embedded_storage_async::nor_flash::{MultiwriteNorFlash, NorFlash};
use rsk_crypto::{ct_eq, hmac_sha256};
use rsk_sdk::error::{Error, Result};
use rsk_secret::Secret;
use sequential_storage::cache::{Cache, Uncached};
use sequential_storage::map::{MapConfig, MapStorage};

use super::legacy::{CounterFlash, read_e10_padding};
use super::record::{field, take};
use super::{
    Authenticated, Directory, Entry, Identity, KeySource, MAX_MAIN_ENTRIES, Partition, RootArm,
};
use crate::verified_flash::VerifiedFlash;

pub(super) const MANIFEST_FID: u16 = 0xCEF8;
const BACKUP_FIRST: u16 = 0xCEF9;
pub(super) const ACTIVATION_FID: u16 = 0xCEFD;
const MANIFEST_BYTES: usize = 320;
const BODY_BYTES: usize = MANIFEST_BYTES - 32;
const MAGIC: &[u8; 8] = b"RSKIMP02";
const ACTIVATION_MAGIC: &[u8; 8] = b"RSKACT02";

pub(super) fn activation_bytes(epoch: [u8; super::EPOCH_BYTES]) -> Result<[u8; 32]> {
    let mut bytes = [0xFF; 32];
    field(&mut bytes, 0, ACTIVATION_MAGIC)?;
    field(&mut bytes, 8, &[super::FORMAT])?;
    field(&mut bytes, 16, &epoch)?;
    Ok(bytes)
}
type LegacyMap<F> = MapStorage<u16, VerifiedFlash<F>, Cache<Uncached, Uncached, Uncached, u16>>;

struct Manifest {
    epoch: [u8; 16],
    arm: RootArm,
    main_digest: [u8; 32],
    counters: [Entry; super::MAX_COUNTER_ENTRIES],
}

impl Manifest {
    fn encode(
        &self,
        key: &[u8; 32],
        main: &Range<u32>,
        counter: &Range<u32>,
    ) -> Result<[u8; MANIFEST_BYTES]> {
        let mut bytes = [0xFF; MANIFEST_BYTES];
        field(&mut bytes, 0, MAGIC)?;
        field(&mut bytes, 8, &[super::FORMAT, self.arm.code()])?;
        field(&mut bytes, 16, &self.epoch)?;
        field(&mut bytes, 32, &self.main_digest)?;
        for (index, value) in [main.start, main.end, counter.start, counter.end]
            .iter()
            .enumerate()
        {
            field(&mut bytes, 64 + index * 4, &value.to_le_bytes())?;
        }
        for (index, entry) in self.counters.iter().enumerate() {
            field(
                &mut bytes,
                80 + index * super::ENTRY_BYTES,
                &entry.encode()?,
            )?;
        }
        let tag = hmac_sha256(key, bytes.get(..BODY_BYTES).ok_or(Error::MemoryFatal)?);
        field(&mut bytes, BODY_BYTES, &tag)?;
        Ok(bytes)
    }

    fn verify(
        bytes: &[u8],
        source: KeySource,
        main: &Range<u32>,
        counter: &Range<u32>,
    ) -> Result<Self> {
        if bytes.len() != MANIFEST_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8) != Some(&super::FORMAT)
        {
            return Err(Error::MemoryFatal);
        }
        let arm = RootArm::decode(*bytes.get(9).ok_or(Error::MemoryFatal)?)?;
        let mut key = source.key(arm)?;
        let tag = hmac_sha256(
            key.expose(),
            bytes.get(..BODY_BYTES).ok_or(Error::MemoryFatal)?,
        );
        key.wipe();
        if !ct_eq(&tag, bytes.get(BODY_BYTES..).ok_or(Error::MemoryFatal)?) {
            return Err(Error::MemoryFatal);
        }
        for (index, value) in [main.start, main.end, counter.start, counter.end]
            .iter()
            .enumerate()
        {
            if u32::from_le_bytes(take(bytes, 64 + index * 4)?) != *value {
                return Err(Error::MemoryFatal);
            }
        }
        let epoch = take(bytes, 16)?;
        let mut counters = [Entry::decode(bytes.get(80..112).ok_or(Error::MemoryFatal)?)?;
            super::MAX_COUNTER_ENTRIES];
        for (index, slot) in counters.iter_mut().enumerate() {
            *slot = Entry::decode(
                bytes
                    .get(80 + index * super::ENTRY_BYTES..80 + (index + 1) * super::ENTRY_BYTES)
                    .ok_or(Error::MemoryFatal)?,
            )?;
            if slot.fid()
                != rsk_fs::counter::COUNTER_FIDS
                    .get(index)
                    .ok_or(Error::MemoryFatal)?
                    .get()
                || slot.generation() != 0
            {
                return Err(Error::MemoryFatal);
            }
        }
        Ok(Self {
            epoch,
            arm,
            main_digest: take(bytes, 32)?,
            counters,
        })
    }
}

/// The manifest is published before backups; no counter sector is erased until all verify.
pub(super) struct Import<F: NorFlash + MultiwriteNorFlash + Clone> {
    main: LegacyMap<F>,
    counter: LegacyMap<CounterFlash<F>>,
    flash: F,
    main_range: Range<u32>,
    counter_range: Range<u32>,
    source: KeySource,
    buffer: Secret<[u8; crate::KV_BUF]>,
}

impl<F: NorFlash + MultiwriteNorFlash + Clone> Import<F> {
    pub fn new(flash: F, main: Range<u32>, counter: Range<u32>, source: KeySource) -> Result<Self> {
        Ok(Self {
            main: MapStorage::new(
                VerifiedFlash::new(flash.clone()),
                MapConfig::try_new(main.clone()).map_err(|_| Error::MemoryFatal)?,
                Cache::new_uncached(),
            ),
            counter: MapStorage::new(
                VerifiedFlash::new(CounterFlash::new(flash.clone(), None)),
                MapConfig::try_new(counter.clone()).map_err(|_| Error::MemoryFatal)?,
                Cache::new_uncached(),
            ),
            main_range: main,
            counter_range: counter,
            source,
            buffer: Secret::zeroed(),
            flash,
        })
    }

    pub fn has_manifest(&mut self) -> Result<bool> {
        Ok(block_on(
            self.main
                .fetch_item_unrepaired::<&[u8]>(self.buffer.expose_mut(), &MANIFEST_FID),
        )
        .map_err(|_| Error::MemoryFatal)?
        .is_some())
    }

    pub fn has_activation(&mut self) -> Result<bool> {
        Ok(block_on(
            self.main
                .fetch_item_unrepaired::<&[u8]>(self.buffer.expose_mut(), &ACTIVATION_FID),
        )
        .map_err(|_| Error::MemoryFatal)?
        .is_some())
    }

    fn directory(
        &mut self,
        epoch: [u8; 16],
        key: &[u8; 32],
        directory: &mut Directory<MAX_MAIN_ENTRIES>,
    ) -> Result<()> {
        directory.clear();
        let identity = Identity {
            partition: Partition::Main,
            epoch,
        };
        let mut iterator =
            block_on(self.main.fetch_all_items_unrepaired()).map_err(|_| Error::MemoryFatal)?;
        while let Some((fid, value)) = block_on(iterator.next::<&[u8]>(self.buffer.expose_mut()))
            .map_err(|_| Error::MemoryFatal)?
        {
            if rsk_fs::STORE_INTERNAL_FIDS.contains(&fid)
                || fid == crate::SCRUB_FILLER_FID
                || crate::is_counter_fid(fid)
            {
                continue;
            }
            directory.apply(Entry::live(identity, key, fid, 0, value)?)?;
        }
        for entry in directory.entries() {
            let value = block_on(
                self.main
                    .fetch_item_unrepaired::<&[u8]>(self.buffer.expose_mut(), &entry.fid()),
            )
            .map_err(|_| Error::MemoryFatal)?
            .ok_or(Error::MemoryFatal)?;
            entry.verify(identity, key, value)?;
        }
        Ok(())
    }

    pub fn stage(&mut self, epoch: [u8; 16]) -> Result<()> {
        if self.has_activation()? || self.has_manifest()? {
            return Err(Error::Blocked);
        }
        self.counter_view()?;
        for fid in BACKUP_FIRST..ACTIVATION_FID {
            if block_on(
                self.main
                    .fetch_item_unrepaired::<&[u8]>(self.buffer.expose_mut(), &fid),
            )
            .map_err(|_| Error::MemoryFatal)?
            .is_some()
            {
                return Err(Error::Blocked);
            }
        }
        let arm = self.source.current_arm()?;
        let mut key = self.source.key(arm)?;
        let identity = Identity {
            partition: Partition::Counter,
            epoch,
        };
        let mut main = Directory::new();
        self.directory(epoch, key.expose(), &mut main)?;
        let mut counters = [Entry::deleted(
            identity,
            key.expose(),
            rsk_fs::counter::COUNTER_FIDS
                .first()
                .ok_or(Error::MemoryFatal)?
                .get(),
            0,
        )?; super::MAX_COUNTER_ENTRIES];
        for (index, slot) in counters.iter_mut().enumerate() {
            let fid = rsk_fs::counter::COUNTER_FIDS
                .get(index)
                .ok_or(Error::MemoryFatal)?
                .get();
            let value = block_on(
                self.counter
                    .fetch_item_unrepaired::<&[u8]>(self.buffer.expose_mut(), &fid),
            )
            .map_err(|_| Error::MemoryFatal)?;
            *slot = match value {
                Some(value) => Entry::live(identity, key.expose(), fid, 0, value)?,
                None => Entry::deleted(identity, key.expose(), fid, 0)?,
            };
        }
        let manifest = Manifest {
            epoch,
            arm,
            main_digest: main.digest(
                Identity {
                    partition: Partition::Main,
                    epoch,
                },
                key.expose(),
                0,
            )?,
            counters,
        };
        let bytes = manifest.encode(key.expose(), &self.main_range, &self.counter_range)?;
        key.wipe();
        block_on(
            self.main
                .store_item(self.buffer.expose_mut(), &MANIFEST_FID, &bytes.as_slice()),
        )
        .map_err(|_| Error::NoMemory)?;
        self.load_manifest()?;
        Ok(())
    }

    fn load_manifest(&mut self) -> Result<Manifest> {
        let bytes = block_on(
            self.main
                .fetch_item_unrepaired::<&[u8]>(self.buffer.expose_mut(), &MANIFEST_FID),
        )
        .map_err(|_| Error::MemoryFatal)?
        .ok_or(Error::MemoryFatal)?;
        Manifest::verify(bytes, self.source, &self.main_range, &self.counter_range)
    }

    pub fn resume<C: sequential_storage::cache::CacheImpl<u16>>(
        &mut self,
        authenticated: &mut Authenticated<F, C>,
    ) -> Result<()> {
        let manifest = self.load_manifest()?;
        let mut key = self.source.key(manifest.arm)?;
        let main_identity = Identity {
            partition: Partition::Main,
            epoch: manifest.epoch,
        };
        let counter_identity = Identity {
            partition: Partition::Counter,
            epoch: manifest.epoch,
        };
        authenticated.configure(manifest.epoch, manifest.arm, manifest.arm);
        self.directory(
            manifest.epoch,
            key.expose(),
            &mut authenticated.main.directory,
        )?;
        if authenticated
            .main
            .directory
            .digest(main_identity, key.expose(), 0)?
            != manifest.main_digest
        {
            return Err(Error::MemoryFatal);
        }
        let activation = activation_bytes(manifest.epoch)?;
        let activation_entry =
            Entry::live(main_identity, key.expose(), ACTIVATION_FID, 0, &activation)?;
        let digest = authenticated.main.directory.digest_replacing(
            main_identity,
            key.expose(),
            0,
            activation_entry,
        )?;
        authenticated
            .main
            .admit_import(key.expose(), manifest.epoch, manifest.arm, digest)?;
        let ready = self.has_activation()?;
        if !ready {
            self.counter_view()?;
        }
        let mut counters = Directory::new();
        for (index, entry) in manifest.counters.iter().enumerate() {
            let Some(length) = entry.length() else {
                continue;
            };
            let backup = BACKUP_FIRST
                .checked_add(u16::try_from(index).map_err(|_| Error::MemoryFatal)?)
                .ok_or(Error::MemoryFatal)?;
            let existing = block_on(
                self.main
                    .fetch_item_unrepaired::<&[u8]>(self.buffer.expose_mut(), &backup),
            )
            .map_err(|_| Error::MemoryFatal)?;
            let complete = existing
                .is_some_and(|value| entry.verify(counter_identity, key.expose(), value).is_ok());
            if !complete {
                if ready {
                    return Err(Error::MemoryFatal);
                }
                let value = block_on(
                    self.counter
                        .fetch_item_unrepaired::<&[u8]>(self.buffer.expose_mut(), &entry.fid()),
                )
                .map_err(|_| Error::MemoryFatal)?
                .ok_or(Error::MemoryFatal)?;
                entry.verify(counter_identity, key.expose(), value)?;
                let mut copy = Secret::<[u8; crate::KV_BUF]>::zeroed();
                copy.expose_mut()
                    .get_mut(..length)
                    .ok_or(Error::MemoryFatal)?
                    .copy_from_slice(value);
                block_on(self.main.store_item(
                    self.buffer.expose_mut(),
                    &backup,
                    &copy.expose().get(..length).ok_or(Error::MemoryFatal)?,
                ))
                .map_err(|_| Error::NoMemory)?;
                copy.wipe();
            }
            let value = block_on(
                self.main
                    .fetch_item_unrepaired::<&[u8]>(self.buffer.expose_mut(), &backup),
            )
            .map_err(|_| Error::MemoryFatal)?
            .ok_or(Error::MemoryFatal)?;
            entry.verify(counter_identity, key.expose(), value)?;
            counters.apply(*entry)?;
        }
        // Backup appends can relocate main values; check the frozen set again before erasing.
        self.directory(
            manifest.epoch,
            key.expose(),
            &mut authenticated.main.directory,
        )?;
        if authenticated
            .main
            .directory
            .digest(main_identity, key.expose(), 0)?
            != manifest.main_digest
        {
            return Err(Error::MemoryFatal);
        }
        if ready {
            let stored = block_on(
                self.main
                    .fetch_item_unrepaired::<&[u8]>(self.buffer.expose_mut(), &ACTIVATION_FID),
            )
            .map_err(|_| Error::MemoryFatal)?
            .ok_or(Error::MemoryFatal)?;
            if stored != activation {
                return Err(Error::MemoryFatal);
            }
        } else {
            block_on(self.main.store_item(
                self.buffer.expose_mut(),
                &ACTIVATION_FID,
                &activation.as_slice(),
            ))
            .map_err(|_| Error::NoMemory)?;
        }
        authenticated.main.directory.apply(activation_entry)?;
        key.wipe();
        authenticated.initialize_import(&counters, |entry, out| {
            let index = rsk_fs::counter::COUNTER_FIDS
                .iter()
                .position(|fid| fid.get() == entry.fid())
                .ok_or(Error::MemoryFatal)?;
            let backup = BACKUP_FIRST
                .checked_add(u16::try_from(index).map_err(|_| Error::MemoryFatal)?)
                .ok_or(Error::MemoryFatal)?;
            let value = block_on(
                self.main
                    .fetch_item_unrepaired::<&[u8]>(self.buffer.expose_mut(), &backup),
            )
            .map_err(|_| Error::MemoryFatal)?
            .ok_or(Error::MemoryFatal)?;
            if value.len() != out.len() {
                return Err(Error::MemoryFatal);
            }
            out.copy_from_slice(value);
            Ok(())
        })?;
        Ok(())
    }

    pub fn cleanup(&mut self) -> Result<()> {
        // Removing the manifest first prevents any later boot from replaying generation zero.
        block_on(
            self.main
                .remove_item(self.buffer.expose_mut(), &MANIFEST_FID),
        )
        .map_err(|_| Error::MemoryFatal)?;
        for fid in BACKUP_FIRST..ACTIVATION_FID {
            block_on(self.main.remove_item(self.buffer.expose_mut(), &fid))
                .map_err(|_| Error::MemoryFatal)?;
        }
        self.buffer.wipe();
        Ok(())
    }

    fn counter_view(&mut self) -> Result<()> {
        let padding = read_e10_padding(self.flash.clone(), self.counter_range.clone())?;
        self.counter = MapStorage::new(
            VerifiedFlash::new(CounterFlash::new(self.flash.clone(), padding)),
            MapConfig::try_new(self.counter_range.clone()).map_err(|_| Error::MemoryFatal)?,
            Cache::new_uncached(),
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "import_tests.rs"]
mod tests;
