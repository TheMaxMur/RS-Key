// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use core::ops::Range;

use embedded_storage_async::nor_flash::{MultiwriteNorFlash, NorFlash};
use rsk_fs::Storage;
use rsk_sdk::error::{Error, Result};
use sequential_storage::cache::CacheImpl;
use sequential_storage::map::{MapConfig, MapStorage};

use super::{CounterBank, Counters, Directory, Identity, Journal, KeySource, Main};
use super::{Partition, RawBank, RootArm};
use crate::verified_flash::VerifiedFlash;

const MAIN_BANK_BYTES: u32 = 44 * 1024;
const COUNTER_BANK_BYTES: u32 = 20 * 1024;
pub const AUTHORITY_BYTES: u32 = 2 * MAIN_BANK_BYTES + 2 * COUNTER_BANK_BYTES;

/// The existing counter window holds two main authorities and two inline counter banks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    pub main: [Range<u32>; 2],
    pub counter: [Range<u32>; 2],
}

impl Layout {
    pub fn new(counter_range: Range<u32>) -> Result<Self> {
        if counter_range.end.checked_sub(counter_range.start) != Some(AUTHORITY_BYTES) {
            return Err(Error::MemoryFatal);
        }
        let first = counter_range.start;
        let second = first
            .checked_add(MAIN_BANK_BYTES)
            .ok_or(Error::MemoryFatal)?;
        let third = second
            .checked_add(MAIN_BANK_BYTES)
            .ok_or(Error::MemoryFatal)?;
        let fourth = third
            .checked_add(COUNTER_BANK_BYTES)
            .ok_or(Error::MemoryFatal)?;
        Ok(Self {
            main: [first..second, second..third],
            counter: [third..fourth, fourth..counter_range.end],
        })
    }
}

/// Storage decisions are made from authenticated authority, including confirmed absence.
pub struct Authenticated<F: NorFlash + MultiwriteNorFlash + Clone, C: CacheImpl<u16>> {
    pub(super) main: Main<F, C>,
    counters: Counters<F>,
    pub(super) source: KeySource,
    pub(super) main_arm: RootArm,
    pub(super) counter_arm: RootArm,
    last_error: bool,
    flash: F,
    main_range: Range<u32>,
    counter_range: Range<u32>,
}

impl<F: NorFlash + MultiwriteNorFlash + Clone, C: CacheImpl<u16>> Authenticated<F, C> {
    #[inline(always)]
    pub fn new(
        flash: F,
        main_range: Range<u32>,
        counter_range: Range<u32>,
        cache: C,
        source: KeySource,
        epoch: [u8; super::EPOCH_BYTES],
        arm: RootArm,
    ) -> Result<Self> {
        Self::new_arms(
            flash,
            main_range,
            counter_range,
            cache,
            source,
            epoch,
            arm,
            arm,
            None,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Each partition can independently finish an interrupted root migration"
    )]
    #[inline(always)]
    pub(super) fn new_arms(
        flash: F,
        main_range: Range<u32>,
        counter_range: Range<u32>,
        cache: C,
        source: KeySource,
        epoch: [u8; super::EPOCH_BYTES],
        main_arm: RootArm,
        counter_arm: RootArm,
        digest: Option<super::BankDigest<F>>,
    ) -> Result<Self> {
        if main_range.start >= main_range.end || main_range.end > counter_range.start {
            return Err(Error::MemoryFatal);
        }
        let layout = Layout::new(counter_range.clone())?;
        let [main_zero, main_one] = layout.main;
        let [counter_zero, counter_one] = layout.counter;
        let mut main_journals = [
            Journal::new(RawBank::new(flash.clone(), main_zero)?, Partition::Main),
            Journal::new(RawBank::new(flash.clone(), main_one)?, Partition::Main),
        ];
        if let Some(digest) = digest {
            for journal in &mut main_journals {
                journal.set_digest(digest);
            }
        }
        let counter_banks = [
            CounterBank::new(RawBank::new(flash.clone(), counter_zero)?),
            CounterBank::new(RawBank::new(flash.clone(), counter_one)?),
        ];
        let counter_identity = Identity {
            partition: Partition::Counter,
            epoch,
        };
        let config = MapConfig::try_new(main_range.clone()).map_err(|_| Error::MemoryFatal)?;
        Ok(Self {
            main: Main::new(
                MapStorage::new(VerifiedFlash::new(flash.clone()), config, cache),
                main_journals,
                epoch,
                main_arm,
            ),
            counters: Counters::new(counter_banks, counter_identity, counter_arm)?,
            source,
            main_arm,
            counter_arm,
            last_error: false,
            flash,
            main_range,
            counter_range,
        })
    }

    /// Only explicit initialization of a wholly blank medium may mint empty authority.
    pub fn initialize_blank(&mut self) -> Result<()> {
        let mut main = RawBank::new(self.flash.clone(), self.main_range.clone())?;
        let mut counter = RawBank::new(self.flash.clone(), self.counter_range.clone())?;
        if !main.read_erased(0)? || !counter.read_erased(0)? {
            return Err(Error::MemoryFatal);
        }
        let mut key = self.source.key(self.main_arm)?;
        let result = self
            .main
            .initialize(key.expose(), 0, &Directory::new())
            .and_then(|()| {
                self.counters
                    .initialize(key.expose(), &Directory::new(), 0, |_, _| {
                        Err(Error::MemoryFatal)
                    })
            });
        key.wipe();
        result
    }

    pub(super) fn initialize_import(
        &mut self,
        counters: &Directory<{ super::MAX_COUNTER_ENTRIES }>,
        load: impl FnMut(super::Entry, &mut [u8]) -> Result<()>,
    ) -> Result<()> {
        let mut key = self.source.key(self.main_arm)?;
        let result = self
            .main
            .publish_import(key.expose())
            .and_then(|()| self.counters.initialize(key.expose(), counters, 0, load));
        key.wipe();
        result
    }

    pub(super) fn configure(
        &mut self,
        epoch: [u8; super::EPOCH_BYTES],
        main_arm: RootArm,
        counter_arm: RootArm,
    ) {
        self.main.configure(epoch, main_arm);
        self.counters.configure(epoch, counter_arm);
        self.main_arm = main_arm;
        self.counter_arm = counter_arm;
    }

    pub(super) fn repair_activation(&mut self) -> Result<()> {
        let mut key = self.source.key(self.main_arm)?;
        let result = self.main.repair_activation(key.expose());
        key.wipe();
        result
    }

    pub fn close_pre_otp(&mut self) -> Result<()> {
        if self.source.current_arm()? != RootArm::Otp {
            return Ok(());
        }
        let mut new = self.source.key(RootArm::Otp)?;
        let result = (|| {
            if self.main_arm == RootArm::PreOtp {
                let mut old = self.source.key(RootArm::PreOtp)?;
                let result = self.main.rekey(old.expose(), new.expose(), RootArm::Otp);
                old.wipe();
                result?;
                self.main_arm = RootArm::Otp;
            }
            if self.counter_arm == RootArm::PreOtp {
                let mut old = self.source.key(RootArm::PreOtp)?;
                let result = self
                    .counters
                    .rekey(old.expose(), new.expose(), RootArm::Otp);
                old.wipe();
                result?;
                self.counter_arm = RootArm::Otp;
            }
            Ok(())
        })();
        new.wipe();
        result
    }

    pub(super) fn checkpoint_history(&mut self) -> Result<()> {
        let mut key = self.source.key(self.main_arm)?;
        let result = self.main.checkpoint_history(key.expose());
        key.wipe();
        result
    }

    pub fn root_closed(&self) -> bool {
        self.main_arm == RootArm::Otp && self.counter_arm == RootArm::Otp
    }

    fn arm(&self, fid: u16) -> RootArm {
        if crate::is_counter_fid(fid) {
            self.counter_arm
        } else {
            self.main_arm
        }
    }

    fn read_checked(&mut self, fid: u16, out: &mut [u8]) -> Result<Option<usize>> {
        let mut key = self.source.key(self.arm(fid))?;
        let result = if crate::is_counter_fid(fid) {
            self.counters.read(key.expose(), fid, out)
        } else {
            self.main.read(key.expose(), fid, out)
        };
        key.wipe();
        result
    }
}

impl<F: NorFlash + MultiwriteNorFlash + Clone, C: CacheImpl<u16>> Storage for Authenticated<F, C> {
    const MAX_VALUE: usize = rsk_fs::MAX_VALUE_BYTES;

    fn read(&mut self, fid: u16, out: &mut [u8]) -> Option<usize> {
        if rsk_fs::STORE_INTERNAL_FIDS.contains(&fid) {
            self.last_error = false;
            return None;
        }
        let result = self.read_checked(fid, out);
        self.last_error = result.is_err();
        result.ok().flatten()
    }

    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        if rsk_fs::STORE_INTERNAL_FIDS.contains(&fid) {
            return Err(Error::Blocked);
        }
        let mut key = self.source.key(self.arm(fid))?;
        let result = if crate::is_counter_fid(fid) {
            self.counters.write(key.expose(), fid, Some(data))
        } else {
            self.main.write(key.expose(), fid, Some(data))
        };
        key.wipe();
        result
    }

    fn remove(&mut self, fid: u16) -> Result<()> {
        if rsk_fs::STORE_INTERNAL_FIDS.contains(&fid) {
            return Err(Error::Blocked);
        }
        let mut key = self.source.key(self.arm(fid))?;
        let result = if crate::is_counter_fid(fid) {
            self.counters.write(key.expose(), fid, None)
        } else {
            self.main.write(key.expose(), fid, None)
        };
        key.wipe();
        result
    }

    fn size(&mut self, fid: u16) -> Option<usize> {
        self.read(fid, &mut [])
    }

    fn last_error(&self) -> bool {
        self.last_error
    }

    fn for_each_key(&mut self, visit: &mut dyn FnMut(u16)) -> bool {
        let Ok(mut key) = self.source.key(self.main_arm) else {
            self.last_error = true;
            return false;
        };
        let main = self.main.for_each_key(key.expose(), |fid| {
            if !rsk_fs::STORE_INTERNAL_FIDS.contains(&fid) {
                visit(fid);
            }
        });
        key.wipe();
        let Ok(mut key) = self.source.key(self.counter_arm) else {
            self.last_error = true;
            return false;
        };
        let mut buffer = [];
        let mut counters = Ok(());
        for counter in &rsk_fs::counter::COUNTER_FIDS {
            match self.counters.read(key.expose(), counter.get(), &mut buffer) {
                Ok(Some(_)) => visit(counter.get()),
                Ok(None) => {}
                Err(error) => {
                    counters = Err(error);
                    break;
                }
            }
        }
        key.wipe();
        self.last_error = main.is_err() || counters.is_err();
        !self.last_error
    }

    fn compact(&mut self) -> Result<()> {
        let mut key = self.source.key(self.main_arm)?;
        let result = self.main.compact(key.expose());
        key.wipe();
        result
    }
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;
