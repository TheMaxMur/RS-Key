// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The power-cut sweep an applet suite runs over one command, beside the fault media
//! it drives ([`crate::storage::faults`]). Its own file, because the bcd gate excuses
//! a cfg-gated file and not a cfg-gated region of a shipped one.

use crate::Fs;
use crate::storage::Storage;
use crate::storage::faults::{Cut, CutMedium};
use rsk_sdk::error::{Error, Result};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

/// Run a command once per cut point: the medium serves k mutations and refuses
/// the rest, the store is remounted over what survived, and `oracle` reads it.
/// SQLite's anomaly loop at the command level, for the applet suites.
///
/// `provision` builds the starting state on a fresh medium, uncut. `command` runs
/// the command and answers whether it completed — an applet that swallows a write
/// failure (the audit journal does) can answer `true` over a lost write, so a
/// sweep of one of those needs its own notion. `oracle` sees the remounted store,
/// the budget, whether it completed, and the medium, whose `ops()` is the order
/// that landed. k grows until the command completes, since no larger budget can
/// change what it does.
pub fn sweep(
    provision: impl Fn() -> (Fs<Cut>, CutMedium),
    command: impl Fn(&mut Fs<Cut>) -> bool,
    mut oracle: impl FnMut(&mut Fs<Cut>, u32, bool, &CutMedium),
) {
    let mut torn = false;
    for budget in 0..SWEEP_MAX {
        let (mut fs, medium) = provision();
        // The fixture's own writes are not the command's; the log starts here.
        medium.clear_ops();
        medium.arm(budget);
        let completed = command(&mut fs);
        torn |= !completed;
        // Power back on: the same medium, a healthy budget, no cache carried over.
        medium.arm(u32::MAX);
        let mut fs = Fs::new(fs.into_storage());
        fs.scan();
        oracle(&mut fs, budget, completed, &medium);
        if completed {
            assert!(
                torn,
                "vacuous: budget {budget} completed and none before it was cut"
            );
            return;
        }
    }
    panic!("no budget under {SWEEP_MAX} let the command finish");
}

/// The ceiling [`sweep`] stops at. A command that writes more than this many
/// records is doing something the sweep's per-budget replay cannot afford anyway.
const SWEEP_MAX: u32 = 64;

/// A RAM medium that serves a budget of mutations and refuses every one after
/// it, as [`Cut`] does, and whose contents [`sweep_recovery`] carries from its
/// first cut into each run of its second.
pub struct Snap {
    map: Rc<RefCell<BTreeMap<u16, Vec<u8>>>>,
    budget: Rc<Cell<u32>>,
    refused: Rc<Cell<bool>>,
}

impl Snap {
    fn over(map: BTreeMap<u16, Vec<u8>>) -> (Fs<Snap>, SnapMedium) {
        let medium = SnapMedium {
            map: Rc::new(RefCell::new(map)),
            budget: Rc::new(Cell::new(u32::MAX)),
            refused: Rc::new(Cell::new(false)),
        };
        let mut fs = Fs::new(Snap {
            map: medium.map.clone(),
            budget: medium.budget.clone(),
            refused: medium.refused.clone(),
        });
        fs.scan();
        (fs, medium)
    }

    fn serve(&self) -> Result<()> {
        match self.budget.get() {
            0 => {
                self.refused.set(true);
                Err(Error::MemoryFatal)
            }
            left => {
                self.budget.set(left - 1);
                Ok(())
            }
        }
    }
}

impl Storage for Snap {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        let map = self.map.borrow();
        let v = map.get(&fid)?;
        let n = v.len().min(buf.len());
        buf[..n].copy_from_slice(&v[..n]);
        Some(v.len())
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        self.serve()?;
        self.map.borrow_mut().insert(fid, data.to_vec());
        Ok(())
    }
    fn remove(&mut self, fid: u16) -> Result<()> {
        self.serve()?;
        self.map.borrow_mut().remove(&fid);
        Ok(())
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.map.borrow().get(&fid).map(Vec::len)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        for &k in self.map.borrow().keys() {
            f(k);
        }
        true
    }
}

/// The other end of a [`Snap`].
struct SnapMedium {
    map: Rc<RefCell<BTreeMap<u16, Vec<u8>>>>,
    budget: Rc<Cell<u32>>,
    refused: Rc<Cell<bool>>,
}

impl SnapMedium {
    /// Serve `budget` more mutations; `None` restores a healthy medium. Answers
    /// whether the run before this call was cut.
    fn arm(&self, budget: Option<u32>) -> bool {
        self.budget.set(budget.unwrap_or(u32::MAX));
        self.refused.replace(false)
    }
}

/// SQLite's compound failure: a command cut at every point, then the recovery the
/// next boot or command runs cut at every point of ITS own, then that recovery
/// once more on a healthy medium, and `oracle` reads the store. A recovery that
/// repairs one torn write must survive being torn itself.
///
/// `provision` builds the starting state, uncut. `recover` is what finishes an
/// interrupted command — a boot pass, or the command that reaches the repair — and
/// runs over a remounted store each time, as it would after a reset. `oracle` gets
/// both cut points. A cut is a mutation the medium refused, so an applet that
/// swallows a refused write is judged by where it stopped and not by its answer.
pub fn sweep_recovery<C>(
    provision: impl Fn(&mut Fs<Snap>) -> C,
    command: impl Fn(&mut Fs<Snap>, &mut C),
    recover: impl Fn(&mut Fs<Snap>),
    mut oracle: impl FnMut(&mut Fs<Snap>, u32, u32),
) {
    let mut torn = false;
    let mut repaired = false;
    for first in 0..SWEEP_MAX {
        let (mut fs, medium) = Snap::over(BTreeMap::new());
        let mut cx = provision(&mut fs);
        medium.arm(Some(first));
        command(&mut fs, &mut cx);
        let cut = medium.arm(None);
        let after = medium.map.borrow().clone();
        let mut recovered = false;
        for second in 0..SWEEP_MAX {
            let (mut fs, medium) = Snap::over(after.clone());
            medium.arm(Some(second));
            recover(&mut fs);
            let recovery_cut = medium.arm(None);
            repaired |= recovery_cut;
            let (mut fs, _) = Snap::over(medium.map.borrow().clone());
            recover(&mut fs);
            oracle(&mut fs, first, second);
            if !recovery_cut {
                recovered = true;
                break;
            }
        }
        assert!(
            recovered,
            "no recovery budget under {SWEEP_MAX} let recovery finish"
        );
        if !cut {
            assert!(
                torn && repaired,
                "vacuous: no cut left a store whose recovery wrote anything"
            );
            return;
        }
        torn = true;
    }
    panic!("no budget under {SWEEP_MAX} let the command finish");
}

#[cfg(test)]
#[path = "cut_tests.rs"]
mod tests;
