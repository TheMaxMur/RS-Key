// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use core::ops::Range;
use embedded_storage_async::nor_flash::{MultiwriteNorFlash, NorFlash};
use rsk_fs::Storage;
use rsk_fs::storage::{StorageAction, StorageState};
use rsk_sdk::error::{Error, Result};
use sequential_storage::PageState;
use sequential_storage::cache::CacheImpl;

use super::import::Import;
use super::{Authenticated, Checkpoint, KeySource, Layout, Partition, RawBank, RootArm};

/// Established authority never falls back to importing unauthenticated records.
pub struct Managed<F: NorFlash + MultiwriteNorFlash + Clone, C: CacheImpl<u16>> {
    active: Option<Authenticated<F, C>>,
    flash: F,
    main_range: Range<u32>,
    counter_range: Range<u32>,
    source: KeySource,
    ready: bool,
    last_error: bool,
}

impl<F: NorFlash + MultiwriteNorFlash + Clone, C: CacheImpl<u16>> Managed<F, C> {
    #[inline(always)]
    pub fn new(
        flash: F,
        main_range: Range<u32>,
        counter_range: Range<u32>,
        source: KeySource,
        cache: fn() -> C,
    ) -> Self {
        let mut storage = Self::new_unmounted(flash, main_range, counter_range, source, cache);
        let _mount_failed = storage.mount().is_err();
        storage
    }

    /// Construct without I/O; mount after placing the large value in its final owner.
    #[inline(always)]
    pub fn new_unmounted(
        flash: F,
        main_range: Range<u32>,
        counter_range: Range<u32>,
        source: KeySource,
        cache: fn() -> C,
    ) -> Self {
        Self::new_unmounted_with_digest(flash, main_range, counter_range, source, cache, None)
    }

    /// Construct in place with the board's public-metadata SHA-256 backend.
    #[inline(always)]
    pub fn new_unmounted_with_digest(
        flash: F,
        main_range: Range<u32>,
        counter_range: Range<u32>,
        source: KeySource,
        cache: fn() -> C,
        digest: Option<super::BankDigest<F>>,
    ) -> Self {
        Self {
            active: Authenticated::new_arms(
                flash.clone(),
                main_range.clone(),
                counter_range.clone(),
                cache(),
                source,
                [0; super::EPOCH_BYTES],
                RootArm::PreOtp,
                RootArm::PreOtp,
                digest,
            )
            .ok(),
            ready: false,
            flash,
            main_range,
            counter_range,
            source,
            last_error: false,
        }
    }

    fn headers(&mut self) -> Result<[Option<Checkpoint>; 4]> {
        self.source.current_arm()?;
        let layout = Layout::new(self.counter_range.clone())?;
        let [main_zero, main_one] = layout.main;
        let [counter_zero, counter_one] = layout.counter;
        let mut headers = [None; 4];
        for (index, range) in [main_zero, main_one, counter_zero, counter_one]
            .into_iter()
            .enumerate()
        {
            let mut bytes = [0; super::CHECKPOINT_BYTES];
            RawBank::new(self.flash.clone(), range)?.read(0, &mut bytes)?;
            let Ok(decoded) = Checkpoint::decode(&bytes) else {
                continue;
            };
            let expected = if index < 2 {
                Partition::Main
            } else {
                Partition::Counter
            };
            let Ok(mut key) = self.source.key(decoded.arm) else {
                continue;
            };
            let verified = Checkpoint::verify(&bytes, key.expose());
            key.wipe();
            if let Ok(header) = verified {
                if header.identity.partition != expected {
                    return Err(Error::MemoryFatal);
                }
                *headers.get_mut(index).ok_or(Error::MemoryFatal)? = Some(header);
            }
        }
        Ok(headers)
    }

    fn open_authority(&mut self) -> Result<()> {
        let headers = self.headers()?;
        let epoch = headers
            .iter()
            .flatten()
            .next()
            .ok_or(Error::MemoryFatal)?
            .identity
            .epoch;
        if headers
            .iter()
            .flatten()
            .any(|header| header.identity.epoch != epoch)
        {
            return Err(Error::MemoryFatal);
        }
        let arm = |pair: &[Option<Checkpoint>]| -> Result<RootArm> {
            if pair
                .iter()
                .flatten()
                .any(|header| header.arm == RootArm::Otp)
            {
                Ok(RootArm::Otp)
            } else if pair
                .iter()
                .flatten()
                .any(|header| header.arm == RootArm::PreOtp)
            {
                Ok(RootArm::PreOtp)
            } else {
                Err(Error::MemoryFatal)
            }
        };
        let main_arm = arm(headers.get(..2).ok_or(Error::MemoryFatal)?)?;
        let counter_arm = arm(headers.get(2..).ok_or(Error::MemoryFatal)?)?;
        let active = self.active.as_mut().ok_or(Error::MemoryFatal)?;
        active.configure(epoch, main_arm, counter_arm);
        if !active.for_each_key(&mut |_| {}) {
            return Err(Error::MemoryFatal);
        }
        Ok(())
    }

    fn mount_inner(&mut self) -> Result<()> {
        self.ready = false;
        let mut import = Import::new(
            self.flash.clone(),
            self.main_range.clone(),
            self.counter_range.clone(),
            self.source,
        )?;
        match self.open_authority() {
            Ok(()) => {}
            Err(_) => {
                // Only a previously authenticated, explicitly started import may resume.
                self.source.current_arm()?;
                if !import.has_manifest()? {
                    return Err(Error::MemoryFatal);
                }
                self.check_import_progress()?;
                import.resume(self.active.as_mut().ok_or(Error::MemoryFatal)?)?
            }
        }
        if import.has_manifest()? {
            import.cleanup()?;
            self.open_authority()?;
        }
        let active = self.active.as_mut().ok_or(Error::MemoryFatal)?;
        active.repair_activation()?;
        active.close_pre_otp()?;
        active.checkpoint_history()?;
        self.ready = true;
        self.last_error = false;
        Ok(())
    }

    fn check_import_progress(&mut self) -> Result<()> {
        let layout = Layout::new(self.counter_range.clone())?;
        let headers = self.headers()?;
        for (index, range) in layout.main.into_iter().chain(layout.counter).enumerate() {
            let Some(header) = headers.get(index).copied().flatten() else {
                continue;
            };
            let mut key = self.source.key(header.arm)?;
            let result = if index < 2 {
                let directory = &mut self
                    .active
                    .as_mut()
                    .ok_or(Error::MemoryFatal)?
                    .main
                    .directory;
                let scan =
                    super::Journal::new(RawBank::new(self.flash.clone(), range)?, Partition::Main)
                        .scan(key.expose(), directory)?;
                scan.lower_bound.is_some_and(|sequence| sequence > 0)
                    || scan
                        .state
                        .is_some_and(|state| state.sequence() > 0 || state.pending().is_some())
                    || scan.status == super::JournalStatus::Dirty && scan.state.is_some()
            } else {
                let mut directory = super::Directory::<{ super::MAX_COUNTER_ENTRIES }>::new();
                let scan = super::CounterBank::new(RawBank::new(self.flash.clone(), range)?)
                    .scan(key.expose(), &mut directory)?;
                scan.lower_bound.is_some_and(|sequence| sequence > 0)
                    || scan.status == super::JournalStatus::Dirty && scan.sequence.is_some()
            };
            key.wipe();
            if result {
                return Err(Error::MemoryFatal);
            }
        }
        Ok(())
    }

    pub fn root_closed(&self) -> bool {
        self.ready && self.active.as_ref().is_some_and(Authenticated::root_closed)
    }

    fn legacy_page(&mut self, range: Range<u32>) -> Result<PageState> {
        let mut bank = RawBank::new(self.flash.clone(), range)?;
        let mut bytes = [0; super::CHECKPOINT_BYTES];
        let word = F::WRITE_SIZE.max(F::READ_SIZE);
        let marker = bytes.get_mut(..word).ok_or(Error::MemoryFatal)?;
        bank.read(0, marker)?;
        let start_erased = marker.iter().all(|&byte| byte == 0xFF);
        if !start_erased && !marker.iter().all(|&byte| byte == 0) {
            return Err(Error::MemoryFatal);
        }
        let tail = bank
            .capacity()
            .checked_sub(u32::try_from(word).map_err(|_| Error::MemoryFatal)?)
            .ok_or(Error::MemoryFatal)?;
        bank.read(tail, marker)?;
        let end_erased = marker.iter().all(|&byte| byte == 0xFF);
        if !end_erased && !marker.iter().all(|&byte| byte == 0) {
            return Err(Error::MemoryFatal);
        }
        match (start_erased, end_erased) {
            (true, true) if bank.read_erased(0)? => Ok(PageState::Open),
            (false, true) => Ok(PageState::PartialOpen),
            (false, false) => Ok(PageState::Closed),
            _ => Err(Error::MemoryFatal),
        }
    }

    fn check_legacy_pages(&mut self) -> Result<()> {
        let sector = u32::try_from(F::ERASE_SIZE).map_err(|_| Error::MemoryFatal)?;
        let padding =
            super::legacy::read_e10_padding(self.flash.clone(), self.counter_range.clone())?;
        for range in [self.main_range.clone(), self.counter_range.clone()] {
            let mut at = range.start;
            let mut partial = 0;
            let mut open = false;
            while at < range.end {
                let end = at.checked_add(sector).ok_or(Error::MemoryFatal)?;
                let state = if range == self.counter_range && end == range.end && padding.is_some()
                {
                    PageState::Open
                } else {
                    self.legacy_page(at..end)?
                };
                match state {
                    PageState::Open => open = true,
                    PageState::PartialOpen => partial += 1,
                    PageState::Closed => {}
                }
                at = end;
            }
            if partial > 1 || partial == 0 && !open {
                return Err(Error::MemoryFatal);
            }
        }
        Ok(())
    }
}

impl<F: NorFlash + MultiwriteNorFlash + Clone, C: CacheImpl<u16>> Storage for Managed<F, C> {
    fn mount(&mut self) -> Result<()> {
        self.mount_inner()
    }
    fn boot(&mut self, epoch: [u8; 16]) -> Result<()> {
        self.ready = false;
        let mut import = Import::new(
            self.flash.clone(),
            self.main_range.clone(),
            self.counter_range.clone(),
            self.source,
        )?;
        self.source.current_arm()?;
        if import.has_manifest()?
            || import.has_activation()?
            || self.headers()?.iter().any(Option::is_some)
        {
            return self.mount();
        }
        // Reject raw v2 banks and incomplete legacy erasures before any map repair.
        self.check_legacy_pages()?;
        self.administer(StorageAction::ImportLegacy, epoch)
    }
    fn root_closed(&self) -> bool {
        Managed::root_closed(self)
    }
    fn state(&self) -> StorageState {
        if self.ready {
            StorageState::Ready
        } else {
            StorageState::Recovery
        }
    }

    fn administer(&mut self, action: StorageAction, epoch: [u8; 16]) -> Result<()> {
        if self.ready {
            return Err(Error::Blocked);
        }
        self.source.current_arm()?;
        let mut import = Import::new(
            self.flash.clone(),
            self.main_range.clone(),
            self.counter_range.clone(),
            self.source,
        )?;
        if import.has_manifest()? {
            return self.mount();
        }
        if import.has_activation()? || self.headers()?.iter().any(Option::is_some) {
            return Err(Error::Blocked);
        }
        if self
            .active
            .as_ref()
            .is_some_and(|active| active.main.has_authority())
        {
            return Err(Error::Blocked);
        }
        if action == StorageAction::Initialize
            && (!RawBank::new(self.flash.clone(), self.main_range.clone())?.read_erased(0)?
                || !RawBank::new(self.flash.clone(), self.counter_range.clone())?.read_erased(0)?)
        {
            return Err(Error::Blocked);
        }
        import.stage(epoch)?;
        self.mount()
    }

    fn read(&mut self, fid: u16, out: &mut [u8]) -> Option<usize> {
        if !self.ready {
            self.last_error = true;
            return None;
        }
        let Some(active) = &mut self.active else {
            self.last_error = true;
            return None;
        };
        let result = active.read(fid, out);
        self.last_error = active.last_error();
        result
    }

    fn write(&mut self, fid: u16, value: &[u8]) -> Result<()> {
        if !self.ready {
            return Err(Error::MemoryFatal);
        }
        if rsk_fs::STORE_INTERNAL_FIDS.contains(&fid) {
            return Err(Error::Blocked);
        }
        self.active
            .as_mut()
            .ok_or(Error::MemoryFatal)?
            .write(fid, value)
    }

    fn remove(&mut self, fid: u16) -> Result<()> {
        if !self.ready {
            return Err(Error::MemoryFatal);
        }
        if rsk_fs::STORE_INTERNAL_FIDS.contains(&fid) {
            return Err(Error::Blocked);
        }
        self.active.as_mut().ok_or(Error::MemoryFatal)?.remove(fid)
    }

    fn size(&mut self, fid: u16) -> Option<usize> {
        self.read(fid, &mut [])
    }
    fn last_error(&self) -> bool {
        self.last_error
    }
    fn for_each_key(&mut self, visit: &mut dyn FnMut(u16)) -> bool {
        if !self.ready {
            self.last_error = true;
            return false;
        }
        let Some(active) = &mut self.active else {
            self.last_error = true;
            return false;
        };
        let complete = active.for_each_key(visit);
        self.last_error = !complete;
        complete
    }
    fn compact(&mut self) -> Result<()> {
        if !self.ready {
            return Err(Error::MemoryFatal);
        }
        self.active.as_mut().ok_or(Error::MemoryFatal)?.compact()
    }
}

#[cfg(test)]
#[path = "managed_tests.rs"]
mod tests;
