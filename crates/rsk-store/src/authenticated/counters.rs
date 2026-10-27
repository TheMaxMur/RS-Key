// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use embedded_storage_async::nor_flash::{MultiwriteNorFlash, NorFlash};
use rsk_crypto::ct_eq;
use rsk_sdk::error::{Error, Result};

use super::{Checkpoint, CounterBank, CounterScan, Directory, ENTRY_BYTES, Entry, Identity};
use super::{JournalStatus, MAX_COUNTER_ENTRIES, Partition, RootArm};

struct Current {
    source: usize,
    scans: [CounterScan; 2],
    directory: Directory<MAX_COUNTER_ENTRIES>,
}

/// Both replicas must agree durably before any counter value is acknowledged.
pub struct Counters<F: NorFlash + MultiwriteNorFlash> {
    banks: [CounterBank<F>; 2],
    identity: Identity,
    arm: RootArm,
    mount: Option<[CounterScan; 2]>,
}

impl<F: NorFlash + MultiwriteNorFlash> Counters<F> {
    pub fn new(banks: [CounterBank<F>; 2], identity: Identity, arm: RootArm) -> Result<Self> {
        if identity.partition != Partition::Counter {
            return Err(Error::MemoryFatal);
        }
        Ok(Self {
            banks,
            identity,
            arm,
            mount: None,
        })
    }

    pub(super) fn configure(&mut self, epoch: [u8; super::EPOCH_BYTES], arm: RootArm) {
        self.mount = None;
        self.identity = Identity {
            partition: Partition::Counter,
            epoch,
        };
        self.arm = arm;
    }

    fn source_target(
        &mut self,
        source: usize,
    ) -> Result<(&mut CounterBank<F>, &mut CounterBank<F>)> {
        let [zero, one] = &mut self.banks;
        match source {
            0 => Ok((zero, one)),
            1 => Ok((one, zero)),
            _ => Err(Error::MemoryFatal),
        }
    }

    fn checkpoint(
        &self,
        directory: &Directory<MAX_COUNTER_ENTRIES>,
        key: &[u8; 32],
        sequence: u64,
    ) -> Result<Checkpoint> {
        Ok(Checkpoint {
            identity: self.identity,
            arm: self.arm,
            sequence,
            entries: u32::try_from(directory.entries().len()).map_err(|_| Error::MemoryFatal)?,
            digest: directory.digest(self.identity, key, sequence)?,
        })
    }

    fn resolve(&mut self, key: &[u8; 32]) -> Result<Option<Current>> {
        if let Some(scans) = self.mount.take() {
            let mut unchanged = true;
            for (bank, scan) in self.banks.iter_mut().zip(scans) {
                let fingerprint = bank.fingerprint(key, scan.next)?;
                unchanged &= scan
                    .fingerprint
                    .zip(fingerprint)
                    .is_some_and(|(expected, fresh)| ct_eq(&expected, &fresh));
            }
            if unchanged {
                let mut directory = Directory::new();
                for location in scans
                    .first()
                    .ok_or(Error::MemoryFatal)?
                    .locations
                    .iter()
                    .flatten()
                {
                    directory.apply(location.entry)?;
                }
                self.mount = Some(scans);
                return Ok(Some(Current {
                    source: 0,
                    scans,
                    directory,
                }));
            }
        }
        let current = self.resolve_uncached(key)?;
        if let Some(current) = &current {
            self.mount = Some(current.scans);
        }
        Ok(current)
    }

    fn resolve_uncached(&mut self, key: &[u8; 32]) -> Result<Option<Current>> {
        let [zero, one] = &mut self.banks;
        let mut zero_dir = Directory::new();
        let mut one_dir = Directory::new();
        let zero_scan = zero.scan(key, &mut zero_dir)?;
        let one_scan = one.scan(key, &mut one_dir)?;
        let scans = [zero_scan, one_scan];
        for scan in &scans {
            if let Some(header) = scan.checkpoint
                && (header.identity != self.identity || header.arm != self.arm)
            {
                return Err(Error::MemoryFatal);
            }
        }
        if zero_scan.status == JournalStatus::Empty && one_scan.status == JournalStatus::Empty {
            return Ok(None);
        }
        let zero_seq = (zero_scan.status == JournalStatus::Complete)
            .then_some(zero_scan.sequence)
            .flatten();
        let one_seq = (one_scan.status == JournalStatus::Complete)
            .then_some(one_scan.sequence)
            .flatten();
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
        let zero_digest = zero_dir.digest(self.identity, key, sequence)?;
        let one_digest = one_dir.digest(self.identity, key, sequence)?;
        let synchronized = zero_seq == Some(sequence) && one_seq == Some(sequence);
        if synchronized && !ct_eq(&zero_digest, &one_digest) {
            return Err(Error::MemoryFatal);
        }
        let directory = if source == 0 { zero_dir } else { one_dir };
        if synchronized {
            return Ok(Some(Current {
                source,
                scans,
                directory,
            }));
        }
        let checkpoint = self.checkpoint(&directory, key, sequence)?;
        let source_scan = *scans.get(source).ok_or(Error::MemoryFatal)?;
        let (read, write) = self.source_target(source)?;
        write.write_snapshot(checkpoint, key, &directory, |entry, out| {
            let length = read.read_value(source_scan, key, entry.fid(), out)?;
            if length != Some(out.len()) {
                return Err(Error::MemoryFatal);
            }
            Ok(())
        })?;
        let mut repaired = Directory::new();
        let repaired_scan = write.scan(key, &mut repaired)?;
        if repaired_scan.status != JournalStatus::Complete
            || repaired_scan.sequence != Some(sequence)
            || !ct_eq(
                &repaired.digest(checkpoint.identity, key, sequence)?,
                &directory.digest(checkpoint.identity, key, sequence)?,
            )
        {
            return Err(Error::MemoryFatal);
        }
        let mut scans = scans;
        *scans.get_mut(1 - source).ok_or(Error::MemoryFatal)? = repaired_scan;
        Ok(Some(Current {
            source,
            scans,
            directory,
        }))
    }

    pub fn initialize(
        &mut self,
        key: &[u8; 32],
        directory: &Directory<MAX_COUNTER_ENTRIES>,
        sequence: u64,
        mut load: impl FnMut(Entry, &mut [u8]) -> Result<()>,
    ) -> Result<()> {
        self.mount = None;
        let checkpoint = self.checkpoint(directory, key, sequence)?;
        let [zero, one] = &mut self.banks;
        zero.write_snapshot(checkpoint, key, directory, &mut load)?;
        one.write_snapshot(checkpoint, key, directory, &mut load)?;
        self.resolve(key)?.ok_or(Error::MemoryFatal)?;
        Ok(())
    }

    pub fn read(&mut self, key: &[u8; 32], fid: u16, out: &mut [u8]) -> Result<Option<usize>> {
        let current = self.resolve(key)?.ok_or(Error::MemoryFatal)?;
        let scan = *current
            .scans
            .get(current.source)
            .ok_or(Error::MemoryFatal)?;
        let (source, _) = self.source_target(current.source)?;
        let result = source.read_value(scan, key, fid, out);
        if result.is_err() {
            self.mount = None;
        }
        result
    }

    pub fn rekey(&mut self, old: &[u8; 32], new: &[u8; 32], arm: RootArm) -> Result<()> {
        let current = self.resolve(old)?.ok_or(Error::MemoryFatal)?;
        self.mount = None;
        let source_scan = *current
            .scans
            .get(current.source)
            .ok_or(Error::MemoryFatal)?;
        let sequence = source_scan
            .sequence
            .ok_or(Error::MemoryFatal)?
            .checked_add(1)
            .ok_or(Error::MemoryFatal)?;
        let mut directory = Directory::new();
        let mut buffer = rsk_secret::Secret::<[u8; crate::KV_BUF]>::zeroed();
        for entry in current.directory.entries() {
            let (source, _) = self.source_target(current.source)?;
            let length = source
                .read_value(source_scan, old, entry.fid(), buffer.expose_mut())?
                .ok_or(Error::MemoryFatal)?;
            directory.apply(Entry::live(
                self.identity,
                new,
                entry.fid(),
                sequence,
                buffer.expose().get(..length).ok_or(Error::MemoryFatal)?,
            )?)?;
        }
        buffer.wipe();
        self.arm = arm;
        let checkpoint = self.checkpoint(&directory, new, sequence)?;
        let (source, peer) = self.source_target(current.source)?;
        peer.write_snapshot(checkpoint, new, &directory, |entry, out| {
            if source.read_value(source_scan, old, entry.fid(), out)? != Some(out.len()) {
                return Err(Error::MemoryFatal);
            }
            Ok(())
        })?;
        let mut peer_directory = Directory::new();
        let scan = peer.scan(new, &mut peer_directory)?;
        if scan.status != JournalStatus::Complete || scan.sequence != Some(sequence) {
            return Err(Error::MemoryFatal);
        }
        source.write_snapshot(checkpoint, new, &directory, |entry, out| {
            if peer.read_value(scan, new, entry.fid(), out)? != Some(out.len()) {
                return Err(Error::MemoryFatal);
            }
            Ok(())
        })?;
        Ok(())
    }

    pub fn write(&mut self, key: &[u8; 32], fid: u16, value: Option<&[u8]>) -> Result<()> {
        let mut current = self.resolve(key)?.ok_or(Error::MemoryFatal)?;
        self.mount = None;
        let source_scan = *current
            .scans
            .get(current.source)
            .ok_or(Error::MemoryFatal)?;
        let sequence = source_scan
            .sequence
            .ok_or(Error::MemoryFatal)?
            .checked_add(1)
            .ok_or(Error::MemoryFatal)?;
        let entry = match value {
            Some(data) => Entry::live(self.identity, key, fid, sequence, data)?,
            None => Entry::deleted(self.identity, key, fid, sequence)?,
        };
        if !crate::is_counter_fid(fid) {
            return Err(Error::MemoryFatal);
        }
        let data = value.unwrap_or(&[]);
        let needed = ENTRY_BYTES
            .checked_add(data.len().div_ceil(16) * 16)
            .ok_or(Error::MemoryFatal)?;
        let space = current.scans.iter().zip(&self.banks).all(|(scan, bank)| {
            u32::try_from(needed)
                .ok()
                .is_some_and(|needed| bank.capacity().saturating_sub(scan.next) >= needed)
        });
        if space {
            let peer_scan = *current
                .scans
                .get(1 - current.source)
                .ok_or(Error::MemoryFatal)?;
            let (source, peer) = self.source_target(current.source)?;
            peer.append(peer_scan, key, entry, data)?;
            source.append(source_scan, key, entry, data)?;
            let zero = self
                .banks
                .first_mut()
                .ok_or(Error::MemoryFatal)?
                .confirm_append(
                    *current.scans.first().ok_or(Error::MemoryFatal)?,
                    key,
                    entry,
                    data,
                )?;
            let one = self
                .banks
                .get_mut(1)
                .ok_or(Error::MemoryFatal)?
                .confirm_append(
                    *current.scans.get(1).ok_or(Error::MemoryFatal)?,
                    key,
                    entry,
                    data,
                )?;
            if let (Some(zero), Some(one)) = (zero, one) {
                self.mount = Some([zero, one]);
                return Ok(());
            }
        } else {
            current.directory.apply(entry)?;
            let checkpoint = self.checkpoint(&current.directory, key, sequence)?;
            let (source, peer) = self.source_target(current.source)?;
            peer.write_snapshot(checkpoint, key, &current.directory, |owner, out| {
                if owner.fid() == fid {
                    out.copy_from_slice(data);
                } else if source.read_value(source_scan, key, owner.fid(), out)? != Some(out.len())
                {
                    return Err(Error::MemoryFatal);
                }
                Ok(())
            })?;
            let mut peer_dir = Directory::new();
            let new_scan = peer.scan(key, &mut peer_dir)?;
            if new_scan.status != JournalStatus::Complete || new_scan.sequence != Some(sequence) {
                return Err(Error::MemoryFatal);
            }
            source.write_snapshot(checkpoint, key, &current.directory, |owner, out| {
                if peer.read_value(new_scan, key, owner.fid(), out)? != Some(out.len()) {
                    return Err(Error::MemoryFatal);
                }
                Ok(())
            })?;
        }
        self.resolve(key)?.ok_or(Error::MemoryFatal)?;
        Ok(())
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Counter API fixtures retain exact bank geometry and deliberate authenticated contradictions."
)]
#[path = "counters_tests.rs"]
mod tests;
