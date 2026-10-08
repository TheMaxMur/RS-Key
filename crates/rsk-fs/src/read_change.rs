// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! A one-read change between an occupied-slot snapshot and its consumer.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use crate::storage::ram::RamStorage;
use crate::{Result, Storage};

struct Change {
    fid: u16,
    skip: usize,
    value: Option<std::vec::Vec<u8>>,
}

pub struct ChangingRead {
    inner: RamStorage,
    change: Rc<RefCell<Option<Change>>>,
    served: Rc<Cell<bool>>,
}

pub struct ReadControl {
    change: Rc<RefCell<Option<Change>>>,
    served: Rc<Cell<bool>>,
}

impl ChangingRead {
    pub fn new() -> (Self, ReadControl) {
        let change = Rc::new(RefCell::new(None));
        let served = Rc::new(Cell::new(false));
        (
            Self {
                inner: RamStorage::new(),
                change: change.clone(),
                served: served.clone(),
            },
            ReadControl { change, served },
        )
    }

    pub fn value(&mut self, fid: u16, out: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, out)
    }
}

impl ReadControl {
    pub fn replace_on_read(&self, fid: u16, skip: usize, value: Option<&[u8]>) {
        *self.change.borrow_mut() = Some(Change {
            fid,
            skip,
            value: value.map(<[u8]>::to_vec),
        });
        self.served.set(false);
    }

    pub fn served(&self) -> bool {
        self.served.get()
    }
}

impl Storage for ChangingRead {
    fn read(&mut self, fid: u16, out: &mut [u8]) -> Option<usize> {
        let mut change = self.change.borrow_mut();
        if let Some(next) = change.as_mut()
            && next.fid == fid
        {
            if next.skip == 0 {
                let next = change.take()?;
                self.served.set(true);
                let value = next.value?;
                let n = value.len().min(out.len());
                out[..n].copy_from_slice(&value[..n]);
                return Some(value.len());
            }
            next.skip -= 1;
        }
        self.inner.read(fid, out)
    }

    fn write(&mut self, fid: u16, value: &[u8]) -> Result<()> {
        self.inner.write(fid, value)
    }

    fn remove(&mut self, fid: u16) -> Result<()> {
        self.inner.remove(fid)
    }

    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }

    fn for_each_key(&mut self, visit: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(visit)
    }
}
