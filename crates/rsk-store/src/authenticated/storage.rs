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
    pub const fn new(counter_range: Range<u32>) -> Result<Self> {
        match counter_range.end.checked_sub(counter_range.start) {
            Some(AUTHORITY_BYTES) => {}
            _ => return Err(Error::MemoryFatal),
        }
        // The checked full span bounds every intermediate bank boundary.
        let first = counter_range.start;
        let second = first + MAIN_BANK_BYTES;
        let third = second + MAIN_BANK_BYTES;
        let fourth = third + COUNTER_BANK_BYTES;
        Ok(Self {
            main: [first..second, second..third],
            counter: [third..fourth, fourth..counter_range.end],
        })
    }
}

/// Validated physical bounds for constructing an unbound store in static memory.
pub struct StoreLayout<F: NorFlash + MultiwriteNorFlash> {
    pub(super) main_range: Range<u32>,
    pub(super) counter_range: Range<u32>,
    main: [Range<u32>; 2],
    counter: [Range<u32>; 2],
    map: MapConfig<VerifiedFlash<F>>,
}

impl<F: NorFlash + MultiwriteNorFlash> StoreLayout<F> {
    pub const fn new(
        main_range: Range<u32>,
        counter_range: Range<u32>,
        capacity: usize,
    ) -> Result<Self> {
        if main_range.start >= main_range.end
            || main_range.end > counter_range.start
            || !RawBank::<F>::valid_range(&main_range, capacity)
            || !RawBank::<F>::valid_range(&counter_range, capacity)
        {
            return Err(Error::MemoryFatal);
        }
        let layout = match Layout::new(counter_range.start..counter_range.end) {
            Ok(layout) => layout,
            Err(error) => return Err(error),
        };
        let [main_zero, main_one] = &layout.main;
        let [counter_zero, counter_one] = &layout.counter;
        if !RawBank::<F>::valid_range(main_zero, capacity)
            || !RawBank::<F>::valid_range(main_one, capacity)
            || !RawBank::<F>::valid_range(counter_zero, capacity)
            || !RawBank::<F>::valid_range(counter_one, capacity)
        {
            return Err(Error::MemoryFatal);
        }
        let map = match MapConfig::try_new(main_range.start..main_range.end) {
            Ok(map) => map,
            Err(_) => return Err(Error::MemoryFatal),
        };
        Ok(Self {
            main_range,
            counter_range,
            main: layout.main,
            counter: layout.counter,
            map,
        })
    }
}

/// Storage decisions are made from authenticated authority, including confirmed absence.
pub struct Authenticated<F: NorFlash + MultiwriteNorFlash + Clone, C: CacheImpl<u16>> {
    pub(super) main: Main<F, C>,
    pub(super) counters: Counters<F>,
    pub(super) source: KeySource,
    pub(super) main_arm: RootArm,
    pub(super) counter_arm: RootArm,
    last_error: bool,
    flash: F,
    main_range: Range<u32>,
    counter_range: Range<u32>,
}

impl<F: NorFlash + MultiwriteNorFlash + Clone, C: CacheImpl<u16>> Authenticated<F, C> {
    pub(super) const fn new_unbound(
        flash: F,
        layout: StoreLayout<F>,
        cache: C,
        digest: Option<super::BankDigest<F>>,
        erased: Option<super::BankErased<F>>,
    ) -> Self
    where
        F: Copy,
    {
        let StoreLayout {
            main_range,
            counter_range,
            main,
            counter,
            map,
        } = layout;
        let [main_zero, main_one] = main;
        let [counter_zero, counter_one] = counter;
        let mut zero = RawBank::from_range(flash, main_zero);
        let mut one = RawBank::from_range(flash, main_one);
        zero.digest = digest;
        one.digest = digest;
        let mut counter_zero = RawBank::from_range(flash, counter_zero);
        let mut counter_one = RawBank::from_range(flash, counter_one);
        counter_zero.digest = digest;
        counter_one.digest = digest;
        counter_zero.erased = erased;
        counter_one.erased = erased;
        Self {
            main: Main::new(
                MapStorage::new(VerifiedFlash::new(flash), map, cache),
                [
                    Journal::new(zero, Partition::Main),
                    Journal::new(one, Partition::Main),
                ],
                [0; super::EPOCH_BYTES],
                RootArm::PreOtp,
            ),
            counters: Counters::from_banks(
                [
                    CounterBank::new(counter_zero),
                    CounterBank::new(counter_one),
                ],
                Identity {
                    partition: Partition::Counter,
                    epoch: [0; super::EPOCH_BYTES],
                },
                RootArm::PreOtp,
            ),
            source: KeySource::unavailable(),
            main_arm: RootArm::PreOtp,
            counter_arm: RootArm::PreOtp,
            last_error: false,
            flash,
            main_range,
            counter_range,
        }
    }

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
        erased: Option<super::BankErased<F>>,
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
        let mut counter_banks = [
            CounterBank::new(RawBank::new(flash.clone(), counter_zero)?),
            CounterBank::new(RawBank::new(flash.clone(), counter_one)?),
        ];
        if let Some(digest) = digest {
            for bank in &mut counter_banks {
                bank.set_digest(digest);
            }
        }
        if let Some(erased) = erased {
            for bank in &mut counter_banks {
                bank.set_erased(erased);
            }
        }
        let counter_identity = Identity {
            partition: Partition::Counter,
            epoch,
        };
        let config = MapConfig::try_new(main_range.clone()).map_err(|_| Error::MemoryFatal)?;
        // Finish fallible construction before building Main's large inline buffers.
        let counters = Counters::new(counter_banks, counter_identity, counter_arm)?;
        Ok(Self {
            main: Main::new(
                MapStorage::new(VerifiedFlash::new(flash.clone()), config, cache),
                main_journals,
                epoch,
                main_arm,
            ),
            counters,
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
        if super::bound_counter::public_pin(fid).is_some() {
            return self.read_public_pin(fid, out);
        }
        if super::bound_counter::Slot::pin(fid).is_some() {
            return self.read_pin(fid, out);
        }
        if crate::is_counter_fid(fid) {
            self.counters
                .read_with_source(self.source, self.counter_arm, fid, out)
        } else {
            self.main
                .read_with_source(self.source, self.main_arm, fid, out)
        }
    }
}

impl<F: NorFlash + MultiwriteNorFlash + Clone, C: CacheImpl<u16>> Storage for Authenticated<F, C> {
    const MAX_VALUE: usize = rsk_fs::MAX_VALUE_BYTES;

    fn read(&mut self, fid: u16, out: &mut [u8]) -> Option<usize> {
        if rsk_fs::STORE_INTERNAL_FIDS.contains(&fid)
            || super::bound_counter::bucket_index(fid).is_some()
        {
            self.last_error = false;
            return None;
        }
        let result = self.read_checked(fid, out);
        self.last_error = result.is_err();
        result.ok().flatten()
    }

    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        if rsk_fs::STORE_INTERNAL_FIDS.contains(&fid)
            || super::bound_counter::bucket_index(fid).is_some()
        {
            return Err(Error::Blocked);
        }
        if super::bound_counter::public_pin(fid).is_some() {
            return self.write_public_pin(fid, Some(data));
        }
        if super::bound_counter::Slot::pin(fid).is_some() && self.write_pin(fid, data)? {
            return Ok(());
        }
        if crate::is_counter_fid(fid) {
            return self
                .counters
                .write_with_source(self.source, self.counter_arm, fid, Some(data));
        }
        let mut key = self.source.key(self.arm(fid))?;
        let result = self.main.write(key.expose(), fid, Some(data));
        key.wipe();
        result
    }

    fn remove(&mut self, fid: u16) -> Result<()> {
        if rsk_fs::STORE_INTERNAL_FIDS.contains(&fid)
            || super::bound_counter::bucket_index(fid).is_some()
        {
            return Err(Error::Blocked);
        }
        if super::bound_counter::public_pin(fid).is_some() {
            // A durable tombstone prevents fallback even if legacy removal is interrupted.
            self.write_public_pin(fid, None)?;
        }
        if crate::is_counter_fid(fid) {
            return self
                .counters
                .write_with_source(self.source, self.counter_arm, fid, None);
        }
        let mut key = self.source.key(self.arm(fid))?;
        let result = self.main.write(key.expose(), fid, None);
        key.wipe();
        result
    }

    fn size(&mut self, fid: u16) -> Option<usize> {
        self.read(fid, &mut [])
    }

    fn read_bound_counter(&mut self, fid: u16, out: &mut [u8]) -> Result<Option<usize>> {
        self.read_oath_counter(fid, out)
    }

    fn write_bound_counter(&mut self, fid: u16, sealed: &[u8]) -> Result<bool> {
        self.write_oath_counter(fid, sealed)
    }

    fn last_error(&self) -> bool {
        self.last_error
    }

    fn for_each_key(&mut self, visit: &mut dyn FnMut(u16)) -> bool {
        use super::bound_counter::{PUBLIC_PINS, PublicPinState};
        let Ok(mut key) = self.source.key(self.main_arm) else {
            self.last_error = true;
            return false;
        };
        let mut legacy_pins = [false; PUBLIC_PINS.len()];
        let main = self.main.for_each_key(key.expose(), |fid| {
            if let Some(index) = PUBLIC_PINS.iter().position(|&owner| owner == fid) {
                if let Some(present) = legacy_pins.get_mut(index) {
                    *present = true;
                }
            } else if !rsk_fs::STORE_INTERNAL_FIDS.contains(&fid) {
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
        if main.is_ok() && counters.is_ok() {
            for (fid, legacy) in PUBLIC_PINS.into_iter().zip(legacy_pins) {
                match self.read_published_pin(fid, &mut []) {
                    Ok(PublicPinState::Present(_)) => visit(fid),
                    Ok(PublicPinState::Legacy) if legacy => visit(fid),
                    Ok(PublicPinState::Legacy | PublicPinState::Absent) => {}
                    Err(error) => {
                        counters = Err(error);
                        break;
                    }
                }
            }
        }
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
