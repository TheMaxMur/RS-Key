// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg_attr(not(test), no_main)]

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use embassy_futures::block_on;
use embedded_storage_async::nor_flash::{ErrorType, MultiwriteNorFlash, NorFlash, ReadNorFlash};
#[cfg(not(test))]
use libfuzzer_sys::fuzz_target;
use rsk_fs::Storage;
use rsk_store::authenticated::{Authenticated, KeySource, RootArm, RootRead};
use sequential_storage::cache::{Cache, Uncached};
use sequential_storage::mock_flash::{MockFlashBase, MockFlashError, Operation, WriteCountCheck};

const MAIN: core::ops::Range<u32> = 0..8 * 4096;
const COUNTER: core::ops::Range<u32> = MAIN.end..40 * 4096;
const OWNER: u16 = 0xB000;
const NEIGHBOR: u16 = 0xB001;
type Flash = MockFlashBase<40, 4, 1024>;
type Store = Authenticated<Medium, Cache<Uncached, Uncached, Uncached, u16>>;

#[derive(Clone)]
struct Medium {
    flash: Rc<RefCell<Flash>>,
    dead: Rc<Cell<bool>>,
}

impl ErrorType for Medium {
    type Error = MockFlashError;
}
impl ReadNorFlash for Medium {
    const READ_SIZE: usize = Flash::READ_SIZE;
    async fn read(&mut self, address: u32, out: &mut [u8]) -> Result<(), Self::Error> {
        block_on(self.flash.borrow_mut().read(address, out))
    }
    fn capacity(&self) -> usize {
        self.flash.borrow().capacity()
    }
}
impl NorFlash for Medium {
    const WRITE_SIZE: usize = Flash::WRITE_SIZE;
    const ERASE_SIZE: usize = Flash::ERASE_SIZE;
    async fn write(&mut self, address: u32, value: &[u8]) -> Result<(), Self::Error> {
        if self.dead.get() {
            return Err(MockFlashError::EarlyShutoff(address, Operation::Write));
        }
        let result = block_on(self.flash.borrow_mut().write(address, value));
        if result.is_err() {
            self.dead.set(true);
        }
        result
    }
    async fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        if self.dead.get() {
            return Err(MockFlashError::EarlyShutoff(from, Operation::Erase));
        }
        let result = block_on(self.flash.borrow_mut().erase(from, to));
        if result.is_err() {
            self.dead.set(true);
        }
        result
    }
}
impl MultiwriteNorFlash for Medium {}

fn blank(_: &mut [u8; 32]) -> RootRead {
    RootRead::Blank
}
fn mount(medium: &Medium) -> Store {
    Store::new(
        medium.clone(),
        MAIN,
        COUNTER,
        Cache::new_uncached(),
        KeySource::new([0x43; 32], blank, false),
        [0x4B; 16],
        RootArm::PreOtp,
    )
    .unwrap()
}
fn value(store: &mut Store, fid: u16) -> Result<Option<Vec<u8>>, rsk_sdk::error::Error> {
    let mut out = [0; rsk_fs::MAX_VALUE_BYTES];
    let result = store.read(fid, &mut out);
    if store.last_error() {
        return Err(rsk_sdk::error::Error::MemoryFatal);
    }
    Ok(result.map(|length| out[..length].to_vec()))
}
fn arm(medium: &Medium, budget: Option<u32>) {
    medium.dead.set(false);
    medium.flash.borrow_mut().bytes_until_shutoff = budget;
}
fn budget(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from(u16::from_le_bytes([
        data.get(offset).copied().unwrap_or(0xFF),
        data.get(offset + 1).copied().unwrap_or(0xFF),
    ])))
}

pub fn run(data: &[u8]) {
    let medium = Medium {
        flash: Rc::new(RefCell::new(Flash::new(WriteCountCheck::Twice, None, true))),
        dead: Rc::new(Cell::new(false)),
    };
    let mut store = mount(&medium);
    store.initialize_blank().unwrap();
    let fid = if data.get(4).copied().unwrap_or(0) & 1 == 0 {
        OWNER
    } else {
        rsk_fs::counter::COUNTER_FIDS[0].get()
    };
    let length = if data.get(4).copied().unwrap_or(0) & 2 == 0 {
        64
    } else {
        rsk_fs::MAX_VALUE_BYTES
    };
    let old = vec![0x35; length];
    let new = vec![data.get(5).copied().unwrap_or(0xA7); length];
    let warm = usize::from(data.get(6).copied().unwrap_or(0) % 192);
    for index in 0..warm {
        store
            .write(fid, &vec![u8::try_from(index).unwrap(); length])
            .unwrap();
    }
    store.write(fid, &old).unwrap();
    store.write(NEIGHBOR, b"acknowledged neighbor").unwrap();
    let delete = data.get(4).copied().unwrap_or(0) & 4 != 0;
    arm(&medium, budget(data, 0));
    let result = if delete {
        store.remove(fid)
    } else {
        store.write(fid, &new)
    };
    arm(&medium, budget(data, 2));
    let _interrupted_recovery = value(&mut mount(&medium), fid);
    arm(&medium, None);
    let mut recovered = mount(&medium);
    let current = value(&mut recovered, fid).unwrap();
    let desired = if delete { None } else { Some(new.as_slice()) };
    assert!(current.as_deref() == Some(old.as_slice()) || current.as_deref() == desired);
    if result.is_ok() {
        assert_eq!(current.as_deref(), desired);
    }
    assert_eq!(
        value(&mut recovered, NEIGHBOR).unwrap().as_deref(),
        Some(&b"acknowledged neighbor"[..])
    );

    if data.get(4).copied().unwrap_or(0) & 8 != 0 {
        // Damage after activation keeps the acknowledged oracle; never adopt damaged bytes.
        let (needle, expected) = match current.as_deref() {
            Some(value) => (value.to_vec(), current.clone()),
            None => (
                b"acknowledged neighbor".to_vec(),
                Some(b"acknowledged neighbor".to_vec()),
            ),
        };
        let target = if current.is_some() { fid } else { NEIGHBOR };
        let offsets: Vec<_> = medium
            .flash
            .borrow()
            .as_bytes()
            .windows(needle.len())
            .enumerate()
            .filter_map(|(index, bytes)| (bytes == needle).then_some(index))
            .collect();
        assert!(!offsets.is_empty());
        for offset in offsets {
            medium.flash.borrow_mut().as_bytes_mut()[offset] ^= 0x80;
        }
        let observation = value(&mut mount(&medium), target);
        assert!(observation.is_err() || observation == Ok(expected));
    }
}

#[cfg(not(test))]
fuzz_target!(|data: &[u8]| run(data));
