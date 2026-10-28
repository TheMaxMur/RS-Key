// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use embassy_futures::block_on;
use embedded_storage_async::nor_flash::{MultiwriteNorFlash, NorFlash};
use rsk_crypto::ct_eq;
use rsk_sdk::error::{Error, Result};
use rsk_secret::{Secret, WipeGuard};
use sequential_storage::cache::CacheImpl;
use sequential_storage::map::{MapStorage, ReservedItem};

use super::authority::{Authority, Pending, Snapshot};
use super::{Checkpoint, DELTA_BYTES, Delta, DeltaKind, Directory, Entry, Identity};
use super::{Journal, JournalScan, JournalStatus, MAX_MAIN_ENTRIES, Partition, Prepared, RootArm};
use crate::verified_flash::VerifiedFlash;

#[path = "main_read_proof.rs"]
mod read_proof;

struct Current {
    source: usize,
    scans: [JournalScan; 2],
    sequence: u64,
}

#[derive(Clone, Copy)]
struct WritePosition {
    source: usize,
    sequence: u64,
    ends: [u32; 2],
    chains: [[u8; 32]; 2],
}

impl WritePosition {
    fn from_current(current: &Current) -> Result<Self> {
        let [zero, one] = current.scans;
        Ok(Self {
            source: current.source,
            sequence: current.sequence,
            ends: [zero.next, one.next],
            chains: [
                zero.state.ok_or(Error::MemoryFatal)?.chain(),
                one.state.ok_or(Error::MemoryFatal)?.chain(),
            ],
        })
    }
}

#[derive(Clone, Copy)]
struct ReadCache {
    position: WritePosition,
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
    read_tags: super::read_tags::ReadTags,
    authority: Authority,
    // Only skips optional mount maintenance; reads never consult this hint.
    checkpoint_due: bool,
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
            read_tags: super::read_tags::ReadTags::new(),
            authority: Authority::New,
            checkpoint_due: true,
        }
    }

    #[cfg(test)]
    fn set_digest(&mut self, digest: super::BankDigest<F>) {
        self.invalidate_read_cache();
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
        self.invalidate_read_cache();
        self.checkpoint_due = true;
        self.buffer.wipe();
        self.map.invalidate_cache();
    }

    pub(super) fn publish_import(&mut self, key: &[u8; 32]) -> Result<()> {
        self.with_buffer(key, |this, _current| this.snapshots(key, 0, 0).map(|_| ()))
    }

    pub(super) fn invalidate_read_cache(&mut self) {
        self.read_cache = None;
        self.read_tags.clear();
    }

    pub(super) fn has_authority(&self) -> bool {
        self.authority.established()
    }

    pub(super) fn admit_import(
        &mut self,
        key: &[u8; 32],
        epoch: [u8; super::EPOCH_BYTES],
        arm: RootArm,
        digest: [u8; 32],
    ) -> Result<()> {
        self.invalidate_read_cache();
        self.authority.admit(
            key,
            Snapshot {
                identity: Identity {
                    partition: Partition::Main,
                    epoch,
                },
                arm,
                sequence: 0,
                digest,
            },
            None,
        )
    }

    fn mounted_snapshot(&self, key: &[u8; 32], sequence: u64) -> Result<Snapshot> {
        Ok(Snapshot {
            identity: self.identity,
            arm: self.arm,
            sequence,
            digest: self.directory.digest(self.identity, key, 0)?,
        })
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
        self.with_buffer(key, |this, _current| {
            let current = this.resolve(key)?.ok_or(Error::MemoryFatal)?;
            let fid = super::import::ACTIVATION_FID;
            let entry = this.directory.find(fid).ok_or(Error::MemoryFatal)?;
            let canonical = super::import::activation_bytes(this.identity.epoch)?;
            entry.verify(this.identity, key, &canonical)?;
            if this.mapped_value(key, entry).is_ok() {
                this.checkpoint_due = this.history_reclaimable(&current)?;
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
            this.validate_values(key)?;
            this.checkpoint_due = this.history_reclaimable(&current)?;
            Ok(())
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
        let mounted = self.mounted_snapshot(key, sequence)?;
        self.authority.check_snapshot(key, mounted)?;
        let [zero, one] = &mut self.journals;
        let (target, origin) = match source {
            0 => (one, zero),
            1 => (zero, one),
            _ => return Err(Error::MemoryFatal),
        };
        let target_scan = target.write_snapshot(checkpoint, key, &self.directory)?;
        self.authority.admit(key, mounted, None)?;
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
        self.invalidate_read_cache();
        let current = self.resolve_inner(key)?;
        if let Some(current) = &current {
            if !current.scans.iter().all(|scan| {
                scan.status == JournalStatus::Complete
                    && scan.state.is_some_and(|state| {
                        state.sequence() == current.sequence && state.pending().is_none()
                    })
            }) {
                return Err(Error::MemoryFatal);
            }
            let snapshot = self.mounted_snapshot(key, current.sequence)?;
            self.authority.cancel_unpublished(key, snapshot)?;
            self.authority.finish(key, snapshot)?;
        } else if self.authority.established() {
            return Err(Error::MemoryFatal);
        }
        Ok(current)
    }

    fn resolve_inner(&mut self, key: &[u8; 32]) -> Result<Option<Current>> {
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
            if self.authority.established() {
                return Err(Error::MemoryFatal);
            }
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
        let mounted = self.mounted_snapshot(key, sequence)?;
        let admitted = pending
            .map(|prepared| {
                Ok(Pending {
                    prepared,
                    digest: self.directory.digest_replacing(
                        self.identity,
                        key,
                        0,
                        prepared.entry,
                    )?,
                })
            })
            .transpose()?;
        self.authority.admit(key, mounted, admitted)?;
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

    fn with_buffer<T>(
        &mut self,
        key: &[u8; 32],
        operation: impl FnOnce(&mut Self, Option<WritePosition>) -> Result<T>,
    ) -> Result<T> {
        let cached = self.read_cache.take();
        self.read_tags.clear();
        self.checkpoint_due = true;
        let result = (|| {
            if let Some(current) = cached {
                self.authority.verify_read(key, self.identity, self.arm)?;
                self.check_banks(key, current)?;
            }
            operation(self, cached.map(|value| value.position))
        })();
        self.buffer.wipe();
        if result.is_err() {
            self.invalidate_read_cache();
        }
        result
    }

    fn check_banks(&mut self, key: &[u8; 32], current: ReadCache) -> Result<()> {
        for index in [current.source ^ 1, current.source] {
            let journal = self.journals.get_mut(index).ok_or(Error::MemoryFatal)?;
            let end = *current.ends.get(index).ok_or(Error::MemoryFatal)?;
            let fingerprint = current.fingerprints.get(index).ok_or(Error::MemoryFatal)?;
            if !ct_eq(&journal.fingerprint(key, end)?, fingerprint) {
                return Err(Error::MemoryFatal);
            }
        }
        Ok(())
    }

    pub fn initialize(
        &mut self,
        key: &[u8; 32],
        sequence: u64,
        directory: &Directory<MAX_MAIN_ENTRIES>,
    ) -> Result<()> {
        self.with_buffer(key, |this, _current| {
            this.initialize_inner(key, sequence, directory)
        })
    }

    pub fn read(&mut self, key: &[u8; 32], fid: u16, out: &mut [u8]) -> Result<Option<usize>> {
        let result = if let Some(current) = self.read_cache {
            self.read_mounted(key, current, fid, out)
        } else {
            let result = self.read_inner(key, fid, out);
            self.buffer.wipe();
            result
        };
        if result.is_err() {
            self.invalidate_read_cache();
        }
        result
    }

    #[inline(never)]
    fn read_mounted(
        &mut self,
        key: &[u8; 32],
        current: ReadCache,
        fid: u16,
        out: &mut [u8],
    ) -> Result<Option<usize>> {
        self.journals
            .get(current.source)
            .ok_or(Error::MemoryFatal)?;
        let mac = rsk_crypto::mac::HmacSha256::new(key);
        self.authority
            .verify_read_with_mac(&mac, self.identity, self.arm)?;
        let Some(entry) = self.directory.find(fid) else {
            return Ok(None);
        };
        let length = entry.length().ok_or(Error::MemoryFatal)?;
        let capacity = length
            .checked_add(core::mem::size_of::<u16>())
            .and_then(|length| length.checked_next_multiple_of(F::READ_SIZE.max(F::WRITE_SIZE)))
            .ok_or(Error::MemoryFatal)?;
        // Cold and mutation paths clear the entire scratch before a mount can be reused.
        {
            let mut scratch = WipeGuard::new(
                self.buffer
                    .expose_mut()
                    .get_mut(..capacity)
                    .ok_or(Error::MemoryFatal)?,
            );
            match block_on(self.map.fetch_item_unrepaired::<&[u8]>(&mut scratch, &fid)) {
                Ok(Some(value)) if entry.verify_with_mac(self.identity, &mac, value).is_ok() => {
                    let count = out.len().min(length);
                    out.get_mut(..count)
                        .ok_or(Error::MemoryFatal)?
                        .copy_from_slice(value.get(..count).ok_or(Error::MemoryFatal)?);
                    return Ok(Some(length));
                }
                Ok(_)
                | Err(
                    sequential_storage::Error::Corrupted { .. }
                    | sequential_storage::Error::BufferTooSmall(_),
                ) => {}
                Err(_) => return Err(Error::MemoryFatal),
            }
        }
        let result = self.read_inner(key, fid, out);
        self.buffer.wipe();
        result
    }

    pub fn write(&mut self, key: &[u8; 32], fid: u16, data: Option<&[u8]>) -> Result<()> {
        self.with_buffer(key, |this, current| {
            this.write_inner(key, fid, data, current)
        })
    }

    pub fn for_each_key(&mut self, key: &[u8; 32], visit: impl FnMut(u16)) -> Result<()> {
        self.with_buffer(key, |this, _current| this.for_each_key_inner(key, visit))
    }

    pub fn compact(&mut self, key: &[u8; 32]) -> Result<()> {
        self.with_buffer(key, |this, _current| this.compact_inner(key))
    }

    pub fn rekey(&mut self, old: &[u8; 32], new: &[u8; 32], arm: RootArm) -> Result<()> {
        self.with_buffer(old, |this, _current| {
            let current = this.resolve(old)?.ok_or(Error::MemoryFatal)?;
            let sequence = current.sequence.checked_add(1).ok_or(Error::MemoryFatal)?;
            for index in 0..this.directory.entries().len() {
                let owner = *this
                    .directory
                    .entries()
                    .get(index)
                    .ok_or(Error::MemoryFatal)?;
                let length = this.published_value(old, owner)?;
                // Re-keying preserves the payload incarnation used by bound counters.
                let replacement = Entry::live(
                    this.identity,
                    new,
                    owner.fid(),
                    owner.generation(),
                    this.buffer
                        .expose()
                        .get(..length)
                        .ok_or(Error::MemoryFatal)?,
                )?;
                this.directory.apply(replacement)?;
            }
            let target = Snapshot {
                arm,
                ..this.mounted_snapshot(new, sequence)?
            };
            this.authority.stage_replace(old, new, target)?;
            this.arm = arm;
            this.snapshots(new, sequence, current.source)?;
            Ok(())
        })
    }

    fn retire_unpublished(&mut self, key: &[u8; 32]) -> Result<()> {
        let mut retired = heapless::Vec::<u16, MAX_MAIN_ENTRIES>::new();
        let mut iterator =
            block_on(self.map.fetch_all_items_unrepaired()).map_err(|_| Error::MemoryFatal)?;
        while let Some((fid, _)) = block_on(
            iterator.next_unless::<&[u8]>(self.buffer.expose_mut(), |fid| {
                self.directory.find(*fid).is_some()
            }),
        )
        .map_err(|_| Error::MemoryFatal)?
        {
            if self.directory.find(fid).is_none() && !retired.contains(&fid) {
                retired.push(fid).map_err(|_| Error::MemoryFatal)?;
            }
        }
        self.validate_values(key)?;
        if retired.is_empty() {
            return Ok(());
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

    fn cache_resolved(&mut self, current: &Current) -> Result<()> {
        if current.scans.iter().all(|scan| {
            scan.status == JournalStatus::Complete
                && scan.fingerprint.is_some()
                && scan.state.is_some_and(|state| state.pending().is_none())
        }) {
            let [zero, one] = current.scans;
            self.read_cache = Some(ReadCache {
                position: WritePosition::from_current(current)?,
                source: current.source,
                ends: [zero.next, one.next],
                fingerprints: [
                    zero.fingerprint.ok_or(Error::MemoryFatal)?,
                    one.fingerprint.ok_or(Error::MemoryFatal)?,
                ],
            });
        }
        Ok(())
    }

    fn read_inner(&mut self, key: &[u8; 32], fid: u16, out: &mut [u8]) -> Result<Option<usize>> {
        if let Some(current) = self.read_cache {
            self.journals
                .get(current.source)
                .ok_or(Error::MemoryFatal)?;
            self.authority.verify_read(key, self.identity, self.arm)?;
        }
        if self.read_cache.is_none() {
            let current = self.resolve(key)?.ok_or(Error::MemoryFatal)?;
            self.cache_resolved(&current)?;
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

    fn history_reclaimable(&self, current: &Current) -> Result<bool> {
        if !current
            .scans
            .iter()
            .all(|scan| scan.status == JournalStatus::Complete)
        {
            return Ok(false);
        }
        let snapshot = self
            .directory
            .entries()
            .len()
            .checked_mul(super::ENTRY_BYTES)
            .and_then(|bytes| bytes.checked_add(super::CHECKPOINT_BYTES))
            .and_then(|bytes| u32::try_from(bytes).ok())
            .ok_or(Error::MemoryFatal)?;
        let mut reclaim = false;
        for (scan, journal) in current.scans.iter().zip(&self.journals) {
            let history = scan.next.checked_sub(snapshot).ok_or(Error::MemoryFatal)?;
            // Reclaim at least half a bank, rather than halving live-key headroom.
            reclaim |= history >= journal.capacity().div_ceil(2);
        }
        Ok(reclaim)
    }

    pub(super) fn checkpoint_history(&mut self, key: &[u8; 32]) -> Result<()> {
        if !self.checkpoint_due {
            return Ok(());
        }
        self.with_buffer(key, |this, _current| {
            let current = this.resolve(key)?.ok_or(Error::MemoryFatal)?;
            if this.history_reclaimable(&current)? {
                this.snapshots(key, current.sequence, current.source)?;
            }
            this.checkpoint_due = false;
            Ok(())
        })
    }

    fn write_inner(
        &mut self,
        key: &[u8; 32],
        fid: u16,
        data: Option<&[u8]>,
        verified: Option<WritePosition>,
    ) -> Result<()> {
        if crate::is_counter_fid(fid) {
            return Err(Error::MemoryFatal);
        }
        let mut current = if let Some(current) = verified
            && !block_on(self.map.needs_repair()).map_err(|_| Error::MemoryFatal)?
        {
            self.authority
                .finish(key, self.mounted_snapshot(key, current.sequence)?)?;
            current
        } else {
            WritePosition::from_current(&self.resolve(key)?.ok_or(Error::MemoryFatal)?)?
        };
        let sequence = current.sequence.checked_add(1).ok_or(Error::MemoryFatal)?;
        let entry = match data {
            Some(value) => Entry::live(self.identity, key, fid, sequence, value)?,
            None => Entry::deleted(self.identity, key, fid, sequence)?,
        };
        let target = Snapshot {
            sequence,
            digest: self
                .directory
                .digest_replacing(self.identity, key, 0, entry)?,
            identity: self.identity,
            arm: self.arm,
        };
        let needs = u32::try_from(2 * DELTA_BYTES).map_err(|_| Error::MemoryFatal)?;
        if !current
            .ends
            .iter()
            .zip(&self.journals)
            .all(|(end, journal)| journal.capacity().saturating_sub(*end) >= needs)
        {
            if data.is_none() {
                self.authority.stage_replace(key, key, target)?;
                self.directory.apply(entry)?;
                self.snapshots(key, sequence, current.source)?;
                block_on(self.map.remove_item(self.buffer.expose_mut(), &fid))
                    .map_err(|_| Error::MemoryFatal)?;
                return Ok(());
            }
            current = WritePosition::from_current(&self.snapshots(
                key,
                current.sequence,
                current.source,
            )?)?;
        }
        if data.is_some()
            && self.directory.find(fid).is_none()
            && self.directory.entries().len() == MAX_MAIN_ENTRIES
        {
            return Err(Error::NoMemory);
        }
        self.authority.stage_write(key, entry, target.digest)?;
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
        self.authority.locate(Prepared { entry, address })?;
        let [zero, one] = &mut self.journals;
        let [zero_end, one_end] = current.ends;
        let [zero_previous, one_previous] = current.chains;
        let prepare_zero = Delta {
            kind: DeltaKind::Prepare,
            partition: Partition::Main,
            sequence,
            address,
            entry,
            previous: zero_previous,
        };
        let prepare_one = Delta {
            previous: one_previous,
            ..prepare_zero
        };
        zero.append(zero_end, prepare_zero, key)?;
        self.authority.observe_prepare()?;
        one.append(one_end, prepare_one, key)?;
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
            zero_end + u32::try_from(DELTA_BYTES).map_err(|_| Error::MemoryFatal)?,
            commit_zero,
            key,
        )?;
        self.authority.admit(key, target, None)?;
        one.append(
            one_end + u32::try_from(DELTA_BYTES).map_err(|_| Error::MemoryFatal)?,
            commit_one,
            key,
        )?;
        self.buffer.wipe();
        let confirmed_zero = zero.confirm_append(key, zero_end, prepare_zero, commit_zero)?;
        let confirmed_one = one.confirm_append(key, one_end, prepare_one, commit_one)?;
        if let (Some(zero), Some(one)) = (confirmed_zero, confirmed_one)
            && !block_on(self.map.needs_repair()).map_err(|_| Error::MemoryFatal)?
        {
            self.directory.apply(entry)?;
            self.authority
                .finish(key, self.mounted_snapshot(key, sequence)?)?;
            let ends = [zero_end + needs, one_end + needs];
            if data.is_some() {
                self.read_cache = Some(ReadCache {
                    position: WritePosition {
                        source: current.source,
                        sequence,
                        ends,
                        chains: [
                            rsk_crypto::sha256(&commit_zero.encode(key)?),
                            rsk_crypto::sha256(&commit_one.encode(key)?),
                        ],
                    },
                    source: current.source,
                    ends,
                    fingerprints: [zero, one],
                });
            }
        } else {
            let current = self.resolve(key)?.ok_or(Error::MemoryFatal)?;
            if data.is_some() {
                self.cache_resolved(&current)?;
            }
        }
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
