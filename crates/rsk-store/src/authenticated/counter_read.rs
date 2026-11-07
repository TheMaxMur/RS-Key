// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::super::KeySource;
use super::super::counter_bank::VALUE_ALIGNMENT;
use super::*;

#[path = "counter_read_tags.rs"]
pub(super) mod tags;

impl<F: NorFlash + MultiwriteNorFlash> Counters<F> {
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
            self.mount = None;
            self.read_cache.clear();
        }
        result
    }

    fn read_proven(
        &mut self,
        source: KeySource,
        fid: u16,
        out: &mut [u8],
    ) -> Result<Option<usize>> {
        let bound = self.authority.read_bound(self.identity, self.arm).ok();
        let mount = bound.and_then(|bound| self.read_cache.mount(bound));
        let addressed = super::super::bound_counter::bucket_index(fid).is_some();
        let warm = self
            .mount
            .as_ref()
            .filter(|scans| {
                scans.iter().all(|scan| {
                    scan.entry(fid)
                        .is_none_or(|entry| self.read_cache.find(entry).is_some())
                })
            })
            .zip(bound)
            .zip(mount);
        if let Some(((scans, bound), mount)) = warm {
            let proof = source.prepare_read(self.arm, false)?;
            let value_binds_mount = scans
                .first()
                .and_then(|scan| scan.entry(fid))
                .and_then(|entry| self.read_cache.find(entry))
                .is_some_and(|cached| cached.binds(bound));
            // A current payload tag already authenticates the complete mounted bound.
            if !value_binds_mount {
                proof.verify_mount(bound, &mount)?;
            }
            if addressed {
                if scans
                    .first()
                    .and_then(|scan| scan.entry(fid))
                    .and_then(Entry::length)
                    .is_none_or(|length| length <= VALUE_ALIGNMENT)
                {
                    return Self::read_mirrored::<{ ENTRY_BYTES + VALUE_ALIGNMENT }>(
                        &mut self.banks,
                        &mut self.read_cache,
                        scans,
                        &proof,
                        bound,
                        fid,
                        out,
                    );
                }
                return Self::read_mirrored::<
                    { ENTRY_BYTES + super::super::bound_counter::BUFFER_BYTES },
                >(
                    &mut self.banks,
                    &mut self.read_cache,
                    scans,
                    &proof,
                    bound,
                    fid,
                    out,
                );
            }
            for (bank, scan) in self.banks.iter_mut().zip(scans) {
                if !scan
                    .raw_fingerprint
                    .zip(bank.raw_fingerprint(scan.next)?)
                    .is_some_and(|(expected, fresh)| ct_eq(&expected, &fresh))
                {
                    return Err(Error::MemoryFatal);
                }
            }
            let verify = |entry, value: &[u8]| self.read_cache.verify(&proof, bound, entry, value);
            return self
                .banks
                .first_mut()
                .ok_or(Error::MemoryFatal)?
                .read_checked(scans.first().ok_or(Error::MemoryFatal)?, fid, out, verify);
        }
        let proof = source.prepare_read(self.arm, true)?;
        let key = proof.persisted_key()?;
        let mut current = const { Current::new() };
        self.resolve(key, &mut current)?;
        let bound = self.authority.read_bound(self.identity, self.arm)?;
        self.read_cache.bind(&proof, bound)?;
        let scan = current
            .scans
            .get(current.source)
            .ok_or(Error::MemoryFatal)?;
        let bank = self
            .banks
            .get_mut(current.source)
            .ok_or(Error::MemoryFatal)?;
        bank.read_checked(scan, fid, out, |entry, value| {
            entry.verify(self.identity, key, value)?;
            self.read_cache.remember(&proof, bound, entry, value)
        })
    }

    #[inline(never)]
    fn read_mirrored<const FRAME: usize>(
        banks: &mut [CounterBank<F>; 2],
        cache: &mut tags::ReadCache,
        scans: &[CounterScan; 2],
        proof: &super::super::read_proof::ReadProof,
        bound: super::super::authority::Bound,
        fid: u16,
        out: &mut [u8],
    ) -> Result<Option<usize>> {
        use rsk_secret::Secret;
        let mut primary = Secret::new(crate::FlashBuf::<FRAME>::new());
        let mut peer = Secret::new(crate::FlashBuf::<FRAME>::new());
        let [zero, one] = banks;
        let entry = zero.read_bound_frame(
            scans.first().ok_or(Error::MemoryFatal)?,
            fid,
            primary.expose_mut(),
        )?;
        let other = one.read_bound_frame(
            scans.get(1).ok_or(Error::MemoryFatal)?,
            fid,
            peer.expose_mut(),
        )?;
        if entry != other || !ct_eq(primary.expose(), peer.expose()) {
            return Err(Error::MemoryFatal);
        }
        let Some(entry) = entry else { return Ok(None) };
        let length = entry.length().ok_or(Error::MemoryFatal)?;
        let value = primary
            .expose()
            .get(ENTRY_BYTES..ENTRY_BYTES + length)
            .ok_or(Error::MemoryFatal)?;
        cache.verify(proof, bound, entry, value)?;
        let count = length.min(out.len());
        out.get_mut(..count)
            .ok_or(Error::MemoryFatal)?
            .copy_from_slice(value.get(..count).ok_or(Error::MemoryFatal)?);
        Ok(Some(length))
    }

    pub(in crate::authenticated) fn write_with_source(
        &mut self,
        source: KeySource,
        arm: RootArm,
        fid: u16,
        value: Option<&[u8]>,
    ) -> Result<()> {
        let result = (|| {
            if arm != self.arm {
                return Err(Error::MemoryFatal);
            }
            let proof = source.prepare_read(self.arm, true)?;
            self.write(proof.persisted_key()?, fid, value)?;
            let bound = self.authority.read_bound(self.identity, self.arm)?;
            self.read_cache.bind(&proof, bound)?;
            if let Some(value) = value {
                let scan = self
                    .mount
                    .as_ref()
                    .and_then(|scans| scans.first())
                    .ok_or(Error::MemoryFatal)?;
                self.read_cache.remember(
                    &proof,
                    bound,
                    scan.entry(fid).ok_or(Error::MemoryFatal)?,
                    value,
                )?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.mount = None;
            self.read_cache.clear();
        }
        result
    }
}
