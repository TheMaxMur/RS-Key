// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use embassy_futures::block_on;
use embedded_storage_async::nor_flash::{MultiwriteNorFlash, NorFlash};
use rsk_crypto::ct_eq;
use rsk_sdk::error::{Error, Result};
use rsk_secret::Secret;
use sequential_storage::cache::CacheImpl;
use sequential_storage::map::{MapStorage, ReservedItem};

use super::{Checkpoint, DELTA_BYTES, Delta, DeltaKind, Directory, Entry, Identity};
use super::{Journal, JournalScan, JournalStatus, MAX_MAIN_ENTRIES, Partition, Prepared, RootArm};
use crate::verified_flash::VerifiedFlash;

struct Current {
    source: usize,
    scans: [JournalScan; 2],
    sequence: u64,
}

#[derive(Clone, Copy)]
struct ReadCache {
    source: usize,
    ends: [u32; 2],
    fingerprints: [[u8; 32]; 2],
}

/// Root-selected payload versions remain live until their replacement is published.
pub struct Main<F: NorFlash + MultiwriteNorFlash, C: CacheImpl<u16>> {
    map: MapStorage<u16, VerifiedFlash<F>, C>,
    journals: [Journal<F>; 2],
    pub(super) directory: Directory<MAX_MAIN_ENTRIES>,
    buffer: Secret<[u8; crate::KV_BUF]>,
    identity: Identity,
    arm: RootArm,
    read_cache: Option<ReadCache>,
}

impl<F: NorFlash + MultiwriteNorFlash, C: CacheImpl<u16>> Main<F, C> {
    #[inline(always)]
    pub fn new(
        map: MapStorage<u16, VerifiedFlash<F>, C>,
        journals: [Journal<F>; 2],
        epoch: [u8; super::EPOCH_BYTES],
        arm: RootArm,
    ) -> Self {
        Self {
            map,
            journals,
            directory: Directory::new(),
            buffer: Secret::zeroed(),
            identity: Identity {
                partition: Partition::Main,
                epoch,
            },
            arm,
            read_cache: None,
        }
    }

    #[cfg(test)]
    fn set_digest(&mut self, digest: super::BankDigest<F>) {
        self.read_cache = None;
        for journal in &mut self.journals {
            journal.set_digest(digest);
        }
    }

    pub(super) fn configure(&mut self, epoch: [u8; super::EPOCH_BYTES], arm: RootArm) {
        self.identity = Identity {
            partition: Partition::Main,
            epoch,
        };
        self.arm = arm;
        self.directory.clear();
        self.read_cache = None;
        self.buffer.wipe();
        self.map.invalidate_cache();
    }

    pub(super) fn publish_import(&mut self, key: &[u8; 32]) -> Result<()> {
        self.with_buffer(|this| this.snapshots(key, 0, 0).map(|_| ()))
    }

    fn checkpoint(&self, key: &[u8; 32], sequence: u64) -> Result<Checkpoint> {
        Ok(Checkpoint {
            identity: self.identity,
            arm: self.arm,
            sequence,
            entries: u32::try_from(self.directory.entries().len())
                .map_err(|_| Error::MemoryFatal)?,
            digest: self.directory.digest(self.identity, key, sequence)?,
        })
    }

    fn published_value(&mut self, key: &[u8; 32], entry: Entry) -> Result<usize> {
        let fetched = block_on(
            self.map
                .fetch_item_unrepaired::<&[u8]>(self.buffer.expose_mut(), &entry.fid()),
        );
        let value = match fetched {
            Ok(Some(value)) if entry.verify(self.identity, key, value).is_ok() => value,
            Ok(_) | Err(sequential_storage::Error::Corrupted { .. }) => {
                let identity = self.identity;
                block_on(self.map.fetch_matching_item(
                    self.buffer.expose_mut(),
                    &entry.fid(),
                    |value| entry.verify(identity, key, value).is_ok(),
                ))
                .map_err(|_| Error::MemoryFatal)?
                .ok_or(Error::MemoryFatal)?
            }
            Err(_) => return Err(Error::MemoryFatal),
        };
        let length = value.len();
        // The payload map's key occupies the first two scratch bytes.
        self.buffer.expose_mut().copy_within(2..2 + length, 0);
        Ok(length)
    }

    fn validate_values(&mut self, key: &[u8; 32]) -> Result<()> {
        self.validate_retained_values(key, None)
    }

    fn mapped_value(&mut self, key: &[u8; 32], entry: Entry) -> Result<usize> {
        let value = block_on(
            self.map
                .fetch_item_unrepaired::<&[u8]>(self.buffer.expose_mut(), &entry.fid()),
        )
        .map_err(|_| Error::MemoryFatal)?
        .ok_or(Error::MemoryFatal)?;
        entry.verify(self.identity, key, value)?;
        let length = value.len();
        self.buffer.expose_mut().copy_within(2..2 + length, 0);
        Ok(length)
    }

    fn validate_retained_values(&mut self, key: &[u8; 32], skip: Option<u16>) -> Result<()> {
        for index in 0..self.directory.entries().len() {
            let entry = *self
                .directory
                .entries()
                .get(index)
                .ok_or(Error::MemoryFatal)?;
            if skip == Some(entry.fid()) {
                continue;
            }
            self.mapped_value(key, entry)?;
        }
        self.buffer.wipe();
        Ok(())
    }

    pub(super) fn repair_activation(&mut self, key: &[u8; 32]) -> Result<()> {
        self.with_buffer(|this| {
            this.resolve(key)?.ok_or(Error::MemoryFatal)?;
            let fid = super::import::ACTIVATION_FID;
            let entry = this.directory.find(fid).ok_or(Error::MemoryFatal)?;
            let canonical = super::import::activation_bytes(this.identity.epoch)?;
            entry.verify(this.identity, key, &canonical)?;
            if this.mapped_value(key, entry).is_ok() {
                return Ok(());
            }
            this.validate_retained_values(key, Some(fid))?;
            let reserved = block_on(this.map.reserve_item(
                this.buffer.expose_mut(),
                &fid,
                &canonical.as_slice(),
            ))
            .map_err(|_| Error::MemoryFatal)?;
            this.validate_retained_values(key, Some(fid))?;
            // The current authority already signs these exact, reconstructible bytes.
            block_on(this.map.append_reserved(
                this.buffer.expose_mut(),
                &fid,
                &canonical.as_slice(),
                reserved,
            ))
            .map_err(|_| Error::MemoryFatal)?;
            let value = block_on(
                this.map
                    .read_reserved(this.buffer.expose_mut(), &fid, reserved),
            )
            .map_err(|_| Error::MemoryFatal)?
            .ok_or(Error::MemoryFatal)?;
            entry.verify(this.identity, key, value)?;
            this.validate_values(key)
        })
    }

    fn snapshots(&mut self, key: &[u8; 32], sequence: u64, source: usize) -> Result<Current> {
        for index in 0..self.directory.entries().len() {
            let entry = *self
                .directory
                .entries()
                .get(index)
                .ok_or(Error::MemoryFatal)?;
            if entry.fid() == super::import::ACTIVATION_FID {
                entry.verify(
                    self.identity,
                    key,
                    &super::import::activation_bytes(self.identity.epoch)?,
                )?;
            } else {
                self.mapped_value(key, entry)?;
            }
        }
        self.buffer.wipe();
        let checkpoint = self.checkpoint(key, sequence)?;
        let [zero, one] = &mut self.journals;
        let (target, origin) = match source {
            0 => (one, zero),
            1 => (zero, one),
            _ => return Err(Error::MemoryFatal),
        };
        let target_scan = target.write_snapshot(checkpoint, key, &self.directory)?;
        let origin_scan = origin.write_snapshot(checkpoint, key, &self.directory)?;
        let scans = if source == 0 {
            [origin_scan, target_scan]
        } else {
            [target_scan, origin_scan]
        };
        Ok(Current {
            source,
            scans,
            sequence,
        })
    }

    fn candidate_complete(&mut self, key: &[u8; 32], prepared: Prepared) -> Result<bool> {
        let Some(length) = prepared.entry.length() else {
            return Ok(true);
        };
        let serialized = length
            .checked_add(2)
            .and_then(|length| u16::try_from(length).ok())
            .ok_or(Error::MemoryFatal)?;
        let reserved = ReservedItem::resume(prepared.address, serialized);
        match block_on(self.map.read_reserved(
            self.buffer.expose_mut(),
            &prepared.entry.fid(),
            reserved,
        )) {
            Ok(Some(value)) => Ok(prepared.entry.verify(self.identity, key, value).is_ok()),
            Ok(None) | Err(sequential_storage::Error::Corrupted { .. }) => Ok(false),
            Err(_) => Err(Error::MemoryFatal),
        }
    }

    fn recover_pending(
        &mut self,
        key: &[u8; 32],
        prepared: Prepared,
        current: Current,
    ) -> Result<Current> {
        let Current {
            source,
            scans,
            sequence,
        } = current;
        let next = sequence.checked_add(1).ok_or(Error::MemoryFatal)?;
        let complete = self.candidate_complete(key, prepared)?;
        if complete {
            self.directory.apply(prepared.entry)?;
        } else {
            if scans.iter().any(|scan| {
                scan.status == JournalStatus::Dirty
                    && scan.state.is_some_and(|state| {
                        state.sequence() == sequence && state.pending() == Some(prepared)
                    })
            }) {
                return Err(Error::MemoryFatal);
            }
            let length = prepared
                .entry
                .length()
                .ok_or(Error::MemoryFatal)?
                .checked_add(2)
                .and_then(|length| u16::try_from(length).ok())
                .ok_or(Error::MemoryFatal)?;
            block_on(
                self.map
                    .discard_reserved(ReservedItem::resume(prepared.address, length)),
            )
            .map_err(|_| Error::MemoryFatal)?;
        }
        self.buffer.wipe();
        let result = self.snapshots(key, next, source)?;
        if complete && prepared.entry.length().is_none() {
            block_on(
                self.map
                    .remove_item(self.buffer.expose_mut(), &prepared.entry.fid()),
            )
            .map_err(|_| Error::MemoryFatal)?;
        }
        Ok(result)
    }

    fn resolve(&mut self, key: &[u8; 32]) -> Result<Option<Current>> {
        let [zero, one] = &mut self.journals;
        let zero_scan = zero.scan(key, &mut self.directory)?;
        let zero_digest = zero_scan
            .state
            .map(|_| self.directory.digest(self.identity, key, 0))
            .transpose()?;
        let one_scan = one.scan(key, &mut self.directory)?;
        let one_digest = one_scan
            .state
            .map(|_| self.directory.digest(self.identity, key, 0))
            .transpose()?;
        let scans = [zero_scan, one_scan];
        for scan in &scans {
            if let Some(header) = scan.checkpoint
                && (header.identity != self.identity || header.arm != self.arm)
            {
                return Err(Error::MemoryFatal);
            }
        }
        if scans.iter().all(|scan| scan.status == JournalStatus::Empty) {
            return Ok(None);
        }
        let zero_seq = (zero_scan.status == JournalStatus::Complete)
            .then_some(zero_scan.state)
            .flatten()
            .map(|state| state.sequence());
        let one_seq = (one_scan.status == JournalStatus::Complete)
            .then_some(one_scan.state)
            .flatten()
            .map(|state| state.sequence());
        let (source, sequence) = match (zero_seq, one_seq) {
            (Some(zero), Some(one)) if one > zero => (1, one),
            (Some(zero), _) => (0, zero),
            (None, Some(one)) => (1, one),
            (None, None) => return Err(Error::MemoryFatal),
        };
        if scans
            .iter()
            .filter_map(|scan| scan.lower_bound)
            .any(|bound| bound > sequence)
        {
            return Err(Error::MemoryFatal);
        }
        if zero_seq == one_seq
            && zero_seq == Some(sequence)
            && !ct_eq(
                &zero_digest.ok_or(Error::MemoryFatal)?,
                &one_digest.ok_or(Error::MemoryFatal)?,
            )
        {
            return Err(Error::MemoryFatal);
        }
        let selected_scan = *scans.get(source).ok_or(Error::MemoryFatal)?;
        if source == 0 {
            let [zero, _] = &mut self.journals;
            let rescanned = zero.scan(key, &mut self.directory)?;
            if rescanned != selected_scan
                || self.directory.digest(self.identity, key, 0)?
                    != zero_digest.ok_or(Error::MemoryFatal)?
            {
                return Err(Error::MemoryFatal);
            }
        }
        let mut pending = selected_scan.state.ok_or(Error::MemoryFatal)?.pending();
        for scan in &scans {
            if let Some(state) = scan.state
                && state.sequence() == sequence
                && let Some(other) = state.pending()
            {
                if pending.is_some_and(|known| known != other) {
                    return Err(Error::MemoryFatal);
                }
                pending = Some(other);
            }
        }
        if let Some(prepared) = pending {
            return self
                .recover_pending(
                    key,
                    prepared,
                    Current {
                        source,
                        scans,
                        sequence,
                    },
                )
                .map(Some);
        }
        if block_on(self.map.needs_repair()).map_err(|_| Error::MemoryFatal)? {
            let mut keys = heapless::Vec::<u16, MAX_MAIN_ENTRIES>::new();
            for entry in self.directory.entries() {
                if entry.fid() == super::import::ACTIVATION_FID {
                    entry.verify(
                        self.identity,
                        key,
                        &super::import::activation_bytes(self.identity.epoch)?,
                    )?;
                } else {
                    keys.push(entry.fid()).map_err(|_| Error::MemoryFatal)?;
                }
            }
            let directory = &self.directory;
            let identity = self.identity;
            block_on(
                self.map
                    .repair_preserving(self.buffer.expose_mut(), &keys, |fid, value| {
                        directory
                            .find(*fid)
                            .is_some_and(|entry| entry.verify(identity, key, value).is_ok())
                    }),
            )
            .map_err(|_| Error::MemoryFatal)?;
            self.validate_retained_values(key, Some(super::import::ACTIVATION_FID))?;
        }
        let synchronized = zero_seq == Some(sequence) && one_seq == Some(sequence);
        if synchronized {
            return Ok(Some(Current {
                source,
                scans,
                sequence,
            }));
        }
        Ok(Some(self.snapshots(key, sequence, source)?))
    }

    fn with_buffer<T>(&mut self, operation: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        self.read_cache = None;
        let result = operation(self);
        self.buffer.wipe();
        result
    }

    pub fn initialize(
        &mut self,
        key: &[u8; 32],
        sequence: u64,
        directory: &Directory<MAX_MAIN_ENTRIES>,
    ) -> Result<()> {
        self.with_buffer(|this| this.initialize_inner(key, sequence, directory))
    }

    pub fn read(&mut self, key: &[u8; 32], fid: u16, out: &mut [u8]) -> Result<Option<usize>> {
        let result = self.read_inner(key, fid, out);
        self.buffer.wipe();
        if result.is_err() {
            self.read_cache = None;
        }
        result
    }

    pub fn write(&mut self, key: &[u8; 32], fid: u16, data: Option<&[u8]>) -> Result<()> {
        self.with_buffer(|this| this.write_inner(key, fid, data))
    }

    pub fn for_each_key(&mut self, key: &[u8; 32], visit: impl FnMut(u16)) -> Result<()> {
        self.with_buffer(|this| this.for_each_key_inner(key, visit))
    }

    pub fn compact(&mut self, key: &[u8; 32]) -> Result<()> {
        self.with_buffer(|this| this.compact_inner(key))
    }

    pub fn rekey(&mut self, old: &[u8; 32], new: &[u8; 32], arm: RootArm) -> Result<()> {
        self.with_buffer(|this| {
            let current = this.resolve(old)?.ok_or(Error::MemoryFatal)?;
            let sequence = current.sequence.checked_add(1).ok_or(Error::MemoryFatal)?;
            for index in 0..this.directory.entries().len() {
                let owner = *this
                    .directory
                    .entries()
                    .get(index)
                    .ok_or(Error::MemoryFatal)?;
                let length = this.published_value(old, owner)?;
                let replacement = Entry::live(
                    this.identity,
                    new,
                    owner.fid(),
                    sequence,
                    this.buffer
                        .expose()
                        .get(..length)
                        .ok_or(Error::MemoryFatal)?,
                )?;
                this.directory.apply(replacement)?;
            }
            this.arm = arm;
            this.snapshots(new, sequence, current.source)?;
            Ok(())
        })
    }

    fn retire_unpublished(&mut self, key: &[u8; 32]) -> Result<()> {
        self.validate_values(key)?;
        let mut retired = heapless::Vec::<u16, MAX_MAIN_ENTRIES>::new();
        let mut iterator = block_on(self.map.fetch_all_items(self.buffer.expose_mut()))
            .map_err(|_| Error::MemoryFatal)?;
        while let Some((fid, _)) = block_on(iterator.next::<&[u8]>(self.buffer.expose_mut()))
            .map_err(|_| Error::MemoryFatal)?
        {
            if self.directory.find(fid).is_none() && !retired.contains(&fid) {
                retired.push(fid).map_err(|_| Error::MemoryFatal)?;
            }
        }
        for fid in retired {
            block_on(self.map.remove_item(self.buffer.expose_mut(), &fid))
                .map_err(|_| Error::MemoryFatal)?;
        }
        self.validate_values(key)
    }

    fn initialize_inner(
        &mut self,
        key: &[u8; 32],
        sequence: u64,
        directory: &Directory<MAX_MAIN_ENTRIES>,
    ) -> Result<()> {
        self.directory.clear();
        for entry in directory.entries() {
            self.directory.push_snapshot(*entry, sequence)?;
        }
        self.snapshots(key, sequence, 0)?;
        Ok(())
    }

    fn read_inner(&mut self, key: &[u8; 32], fid: u16, out: &mut [u8]) -> Result<Option<usize>> {
        if let Some(current) = self.read_cache {
            // The directory came from verified scans; these checks only veto reuse.
            // Check the selected bank after its peer so its authority is fresh last.
            for index in [current.source ^ 1, current.source] {
                let journal = self.journals.get_mut(index).ok_or(Error::MemoryFatal)?;
                let end = *current.ends.get(index).ok_or(Error::MemoryFatal)?;
                let fingerprint = current.fingerprints.get(index).ok_or(Error::MemoryFatal)?;
                if !ct_eq(&journal.fingerprint(key, end)?, fingerprint) {
                    return Err(Error::MemoryFatal);
                }
            }
            if block_on(self.map.needs_repair()).map_err(|_| Error::MemoryFatal)? {
                self.read_cache = None;
            }
        }
        if self.read_cache.is_none() {
            let current = self.resolve(key)?.ok_or(Error::MemoryFatal)?;
            if current.scans.iter().all(|scan| {
                scan.status == JournalStatus::Complete
                    && scan.fingerprint.is_some()
                    && scan.state.is_some_and(|state| state.pending().is_none())
            }) {
                let [zero, one] = current.scans;
                self.read_cache = Some(ReadCache {
                    source: current.source,
                    ends: [zero.next, one.next],
                    fingerprints: [
                        zero.fingerprint.ok_or(Error::MemoryFatal)?,
                        one.fingerprint.ok_or(Error::MemoryFatal)?,
                    ],
                });
            }
        }
        let Some(entry) = self.directory.find(fid) else {
            return Ok(None);
        };
        let length = self.published_value(key, entry)?;
        let count = out.len().min(length);
        out.get_mut(..count)
            .ok_or(Error::MemoryFatal)?
            .copy_from_slice(
                self.buffer
                    .expose()
                    .get(..count)
                    .ok_or(Error::MemoryFatal)?,
            );
        Ok(Some(length))
    }

    fn write_inner(&mut self, key: &[u8; 32], fid: u16, data: Option<&[u8]>) -> Result<()> {
        if crate::is_counter_fid(fid) {
            return Err(Error::MemoryFatal);
        }
        let mut current = self.resolve(key)?.ok_or(Error::MemoryFatal)?;
        let sequence = current.sequence.checked_add(1).ok_or(Error::MemoryFatal)?;
        let entry = match data {
            Some(value) => Entry::live(self.identity, key, fid, sequence, value)?,
            None => Entry::deleted(self.identity, key, fid, sequence)?,
        };
        let needs = u32::try_from(2 * DELTA_BYTES).map_err(|_| Error::MemoryFatal)?;
        if !current
            .scans
            .iter()
            .zip(&self.journals)
            .all(|(scan, journal)| journal.capacity().saturating_sub(scan.next) >= needs)
        {
            if data.is_none() {
                self.directory.apply(entry)?;
                self.snapshots(key, sequence, current.source)?;
                block_on(self.map.remove_item(self.buffer.expose_mut(), &fid))
                    .map_err(|_| Error::MemoryFatal)?;
                return Ok(());
            }
            current = self.snapshots(key, current.sequence, current.source)?;
        }
        if data.is_some()
            && self.directory.find(fid).is_none()
            && self.directory.entries().len() == MAX_MAIN_ENTRIES
        {
            return Err(Error::NoMemory);
        }
        if data.is_some() {
            self.retire_unpublished(key)?;
        }
        let reserved = if let Some(value) = data {
            let reserved = block_on(self.map.reserve_item::<&[u8]>(
                self.buffer.expose_mut(),
                &fid,
                &value,
            ))
            .map_err(|_| Error::MemoryFatal)?;
            self.validate_values(key)?;
            Some(reserved)
        } else {
            None
        };
        let address = reserved.map_or(0, ReservedItem::address);
        let [zero, one] = &mut self.journals;
        let [zero_scan, one_scan] = current.scans;
        let prepare_zero = Delta {
            kind: DeltaKind::Prepare,
            partition: Partition::Main,
            sequence,
            address,
            entry,
            previous: zero_scan.state.ok_or(Error::MemoryFatal)?.chain(),
        };
        let prepare_one = Delta {
            previous: one_scan.state.ok_or(Error::MemoryFatal)?.chain(),
            ..prepare_zero
        };
        zero.append(zero_scan.next, prepare_zero, key)?;
        one.append(one_scan.next, prepare_one, key)?;
        if let (Some(value), Some(reserved)) = (data, reserved) {
            block_on(
                self.map
                    .append_reserved(self.buffer.expose_mut(), &fid, &value, reserved),
            )
            .map_err(|_| Error::MemoryFatal)?;
            let Some(candidate) = block_on(self.map.read_reserved(
                self.buffer.expose_mut(),
                &fid,
                reserved,
            ))
            .map_err(|_| Error::MemoryFatal)?
            else {
                return Err(Error::MemoryFatal);
            };
            entry.verify(self.identity, key, candidate)?;
        }
        let zero_chain = rsk_crypto::sha256(&prepare_zero.encode(key)?);
        let one_chain = rsk_crypto::sha256(&prepare_one.encode(key)?);
        let commit_zero = Delta {
            kind: DeltaKind::Commit,
            previous: zero_chain,
            ..prepare_zero
        };
        let commit_one = Delta {
            kind: DeltaKind::Commit,
            previous: one_chain,
            ..prepare_one
        };
        let [zero, one] = &mut self.journals;
        zero.append(
            zero_scan.next + u32::try_from(DELTA_BYTES).map_err(|_| Error::MemoryFatal)?,
            commit_zero,
            key,
        )?;
        one.append(
            one_scan.next + u32::try_from(DELTA_BYTES).map_err(|_| Error::MemoryFatal)?,
            commit_one,
            key,
        )?;
        self.buffer.wipe();
        self.resolve(key)?.ok_or(Error::MemoryFatal)?;
        if data.is_none() {
            self.validate_values(key)?;
            block_on(self.map.remove_item(self.buffer.expose_mut(), &fid))
                .map_err(|_| Error::MemoryFatal)?;
        }
        Ok(())
    }

    fn for_each_key_inner(&mut self, key: &[u8; 32], mut visit: impl FnMut(u16)) -> Result<()> {
        self.resolve(key)?.ok_or(Error::MemoryFatal)?;
        for entry in self.directory.entries() {
            visit(entry.fid());
        }
        Ok(())
    }

    fn compact_inner(&mut self, key: &[u8; 32]) -> Result<()> {
        self.resolve(key)?.ok_or(Error::MemoryFatal)?;
        self.retire_unpublished(key)?;
        let range = self.map.flash_range();
        let bytes = usize::try_from(range.end - range.start).map_err(|_| Error::MemoryFatal)?;
        let writes = bytes
            .checked_add(crate::SECTOR)
            .ok_or(Error::MemoryFatal)?
            .div_ceil(crate::SCRUB_FILLER.len());
        let mut outcome = Ok(());
        for iteration in 0..writes {
            let mut filler = crate::SCRUB_FILLER;
            let counter = u64::try_from(iteration)
                .map_err(|_| Error::MemoryFatal)?
                .to_le_bytes();
            filler
                .get_mut(..counter.len())
                .ok_or(Error::MemoryFatal)?
                .copy_from_slice(&counter);
            if block_on(self.map.store_item::<&[u8]>(
                self.buffer.expose_mut(),
                &crate::SCRUB_FILLER_FID,
                &filler.as_slice(),
            ))
            .is_err()
            {
                outcome = Err(Error::MemoryFatal);
                break;
            }
        }
        block_on(
            self.map
                .remove_item(self.buffer.expose_mut(), &crate::SCRUB_FILLER_FID),
        )
        .map_err(|_| Error::MemoryFatal)?;
        self.validate_values(key)?;
        outcome
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "Private store fixtures check invalid API arguments and exact journal boundaries."
)]
#[path = "main_tests.rs"]
mod tests;
