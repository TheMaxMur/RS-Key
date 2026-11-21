// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::authenticated::StoreLayout;
use embedded_storage_async::nor_flash::{ErrorType, ReadNorFlash};

#[derive(Clone, Copy)]
struct CopyFlash<'a>(&'a FaultFlash);

impl ErrorType for CopyFlash<'_> {
    type Error = <FaultFlash as ErrorType>::Error;
}

impl ReadNorFlash for CopyFlash<'_> {
    const READ_SIZE: usize = FaultFlash::READ_SIZE;

    async fn read(
        &mut self,
        offset: u32,
        bytes: &mut [u8],
    ) -> core::result::Result<(), Self::Error> {
        self.0.clone().read(offset, bytes).await
    }

    fn capacity(&self) -> usize {
        self.0.capacity()
    }
}

impl NorFlash for CopyFlash<'_> {
    const WRITE_SIZE: usize = FaultFlash::WRITE_SIZE;
    const ERASE_SIZE: usize = FaultFlash::ERASE_SIZE;

    async fn erase(&mut self, from: u32, to: u32) -> core::result::Result<(), Self::Error> {
        self.0.clone().erase(from, to).await
    }

    async fn write(&mut self, offset: u32, bytes: &[u8]) -> core::result::Result<(), Self::Error> {
        self.0.clone().write(offset, bytes).await
    }
}

impl MultiwriteNorFlash for CopyFlash<'_> {}

fn unbound(flash: &FaultFlash) -> Managed<CopyFlash<'_>, MainCache> {
    let counter = MAIN.end..MAIN.end + 128 * 1024;
    flash
        .inner
        .bytes
        .borrow_mut()
        .resize(counter.end as usize, 0xFF);
    let layout = StoreLayout::new(MAIN, counter, flash.capacity()).unwrap();
    Managed::new_unbound(CopyFlash(flash), layout, cache(), None, None)
}

#[test]
fn an_unbound_store_refuses_all_admission_without_flash_io() {
    let flash = FaultFlash::new();
    let mut store = unbound(&flash);
    flash.arm(&[]);
    let before = flash.image();
    let mut out = [0xA5; 36];
    assert_eq!(store.mount(), Err(Error::MemoryFatal));
    assert_eq!(store.boot([0x5A; 16]), Err(Error::MemoryFatal));
    assert_eq!(
        store.administer(StorageAction::Initialize, [0x5A; 16]),
        Err(Error::MemoryFatal)
    );
    assert_eq!(
        store.administer(StorageAction::ImportLegacy, [0x5A; 16]),
        Err(Error::MemoryFatal)
    );
    assert_eq!(store.state(), StorageState::Recovery);
    assert!(!store.root_closed());
    assert_eq!(store.read(0xBA00, &mut out), None);
    assert!(store.last_error());
    assert_eq!(store.size(0xBA00), None);
    assert!(store.last_error());
    assert_eq!(store.write(0xBA00, b"owner"), Err(Error::MemoryFatal));
    assert_eq!(store.remove(0xBA00), Err(Error::MemoryFatal));
    assert_eq!(store.compact(), Err(Error::MemoryFatal));
    assert_eq!(
        store.read_bound_counter(0xBA00, &mut out),
        Err(Error::MemoryFatal)
    );
    assert_eq!(
        store.write_bound_counter(0xBA00, &[0x42; 36]),
        Err(Error::MemoryFatal)
    );
    assert!(!store.for_each_key(&mut |_| panic!("unbound directory escaped")));
    assert_eq!(out, [0xA5; 36]);
    assert!(flash.events().is_empty());
    assert_eq!(flash.image(), before);
}

#[test]
fn binding_rechecks_the_physical_capacity_before_boot_io() {
    let flash = FaultFlash::new();
    let mut store = unbound(&flash);
    flash
        .inner
        .bytes
        .borrow_mut()
        .truncate(MAIN.end as usize + 4096);
    flash.arm(&[]);
    assert_eq!(store.bind_source(source()), Err(Error::MemoryFatal));
    assert_eq!(store.boot([0x5A; 16]), Err(Error::MemoryFatal));
    assert!(flash.events().is_empty());
    assert_eq!(store.state(), StorageState::Recovery);
}

#[test]
fn a_bound_store_keeps_its_source_and_counter_authority() {
    fn exercise<S: Storage>(mut store: S, flash: &FaultFlash) -> S {
        store.boot([0x5A; 16]).unwrap();
        assert_eq!(store.state(), StorageState::Ready);
        store.write(0xBA00, b"owner").unwrap();
        assert!(store.exists(0xBA00));
        assert_eq!(store.size(0xBA00), Some(5));
        assert_eq!(store.write_bound_counter(0xBA00, &[0x42; 36]), Ok(true));
        let mut out = [0; 36];
        assert_eq!(store.read_bound_counter(0xBA00, &mut out), Ok(Some(36)));
        assert_eq!(out, [0x42; 36]);
        let mut found = Vec::new();
        assert!(store.for_each_key(&mut |fid| found.push(fid)));
        assert!(found.contains(&0xBA00));
        store.mount().unwrap();
        assert_eq!(store.read(0xBA00, &mut out), Some(5));
        assert_eq!(&out[..5], b"owner");
        flash.arm(&[Rule {
            io: Io::Read,
            skip: 0,
            effect: Effect::Refuse,
            latched: true,
        }]);
        assert_eq!(store.read(0xBA00, &mut out), None);
        assert!(store.last_error(), "storage hid a read fault as absence");
        store
    }

    let flash = FaultFlash::new();
    let mut store = unbound(&flash);
    store.bind_source(source()).unwrap();
    assert_eq!(
        store.bind_source(KeySource::new([0; 32], |_| RootRead::Unreadable, true)),
        Err(Error::Blocked)
    );
    let mut store = exercise(store, &flash);
    assert_eq!(store.bind_source(source()), Err(Error::Blocked));
}

#[test]
fn static_store_layout_refuses_overlap_misalignment_short_authority_and_capacity_overrun() {
    let counter = MAIN.end..MAIN.end + 128 * 1024;
    let capacity = counter.end as usize;
    for (main, authority, bytes) in [
        (0..0, counter.clone(), capacity),
        (1..MAIN.end, counter.clone(), capacity),
        (0..MAIN.end + 1, counter.clone(), capacity),
        (MAIN, MAIN.end - 4096..counter.end - 4096, capacity),
        (MAIN, MAIN.end..counter.end - 4096, capacity),
        (MAIN, counter.clone(), capacity - 1),
        (MAIN, u32::MAX - 1024..u32::MAX, capacity),
    ] {
        assert!(StoreLayout::<CopyFlash<'_>>::new(main, authority, bytes).is_err());
    }
    assert!(StoreLayout::<CopyFlash<'_>>::new(MAIN, counter, capacity).is_ok());
}
