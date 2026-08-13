// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! A flash that stops accepting writes once its budget runs out — the software
//! half of `tools/emu --power-cut`, so a torn state can be produced by driving
//! the REAL command rather than by hand-assembling what it might have left
//! behind. Reads keep working, which is what a card does after a failed write.
//!
//! Its own module because two test files need it and a `#[path]` child cannot
//! see a sibling's **private** items.

use rsk_fs::storage::ram::RamStorage;

pub(crate) struct DyingStorage {
    inner: RamStorage,
    budget: std::rc::Rc<std::cell::Cell<usize>>,
}

impl DyingStorage {
    pub(crate) fn new() -> (Self, std::rc::Rc<std::cell::Cell<usize>>) {
        let budget = std::rc::Rc::new(std::cell::Cell::new(usize::MAX));
        (
            Self {
                inner: RamStorage::new(),
                budget: budget.clone(),
            },
            budget,
        )
    }

    fn spend(&mut self) -> rsk_sdk::error::Result<()> {
        match self.budget.get() {
            0 => Err(rsk_sdk::error::Error::MemoryFatal),
            n => {
                self.budget.set(n - 1);
                Ok(())
            }
        }
    }
}

impl rsk_fs::Storage for DyingStorage {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        self.spend()?;
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        self.spend()?;
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
}
