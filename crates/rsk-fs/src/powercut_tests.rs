// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The power-cut oracle, driven over a RAM medium that can lose power between
//! two `Storage` calls.
//!
//! This is the payoff of lifting the model out of the fuzz target: the
//! properties used to be reachable only by `cargo fuzz`, in a detached nightly
//! workspace whose corpus is git-ignored, and they are `cargo test` now. The
//! medium is RAM rather than a mock NOR chip on purpose — what these tests
//! assert is [`Fs`]'s contract, and what `Fs` can lose is decided by the *order*
//! of its backend calls, which a per-call cut probes exactly. Byte-granular
//! flash tearing stays in `fuzz/fuzz_targets/power_cut.rs`, over this same model.
//!
//! Three of the tests are **controls**: a medium that breaks a property on
//! purpose, so the oracle is shown able to fail. An oracle nobody has watched go
//! red asserts nothing.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use rsk_sdk::error::{Error, Result};

use super::*;
use crate::{Fs, Storage};

const A: u16 = 0xB000;
const B: u16 = 0xB001;
const C: u16 = 0xB002;
const FIDS: [u16; 3] = [A, B, C];
/// `fs.rs`'s private `META_MAX`, which the model takes as a parameter.
const META_MAX: usize = 1024;

/// What the cut does to the mutation it lands on.
#[derive(Clone, Copy, PartialEq)]
enum Tear {
    /// The mutation does not land: the medium keeps what it held.
    Before,
    /// The mutation lands, and then the power goes.
    After,
    /// The mutation lands as filler — neither the old value nor the new one. A
    /// control: no store may do this, and the oracle has to say so.
    Garbage,
}

/// A RAM medium that survives a reboot and can lose power between two calls.
#[derive(Clone)]
struct Medium {
    /// What survives the power cycle.
    kept: Rc<RefCell<HashMap<u16, Vec<u8>>>>,
    /// Mutations left before the lights go out. `None` is mains power.
    budget: Rc<Cell<Option<u32>>>,
    dead: Rc<Cell<bool>>,
    tear: Tear,
    /// A control: this key's value evaporates on every boot, which is the
    /// durability failure the oracle exists to catch.
    forget: Rc<Cell<Option<u16>>>,
    /// How many cuts have actually fired. A sweep over budgets that never cut
    /// the power is a sweep that proves nothing, and it looks exactly like one
    /// that did.
    cuts: Rc<Cell<u32>>,
}

impl Medium {
    /// Spend one mutation of the budget, or refuse because the power is gone.
    fn power(&mut self) -> Result<()> {
        if self.dead.get() {
            return Err(Error::MemoryFatal);
        }
        match self.budget.get() {
            None => Ok(()),
            Some(0) => {
                self.cut();
                Err(Error::MemoryFatal)
            }
            Some(left) => {
                self.budget.set(Some(left - 1));
                Ok(())
            }
        }
    }

    /// Whether this is the mutation the budget runs out on.
    fn last(&self) -> bool {
        self.budget.get() == Some(0)
    }

    /// Fire the cut and disarm the budget, so the reboot loop terminates.
    fn cut(&mut self) {
        self.dead.set(true);
        self.budget.set(None);
        self.cuts.set(self.cuts.get() + 1);
    }

    /// The mutation has landed; decide whether the power survives it.
    fn landed(&mut self) -> Result<()> {
        if self.last() && matches!(self.tear, Tear::After | Tear::Garbage) {
            self.cut();
            return Err(Error::MemoryFatal);
        }
        Ok(())
    }
}

impl Storage for Medium {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        let kept = self.kept.borrow();
        let value = kept.get(&fid)?;
        let n = value.len().min(buf.len());
        buf[..n].copy_from_slice(&value[..n]);
        Some(value.len())
    }

    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        self.power()?;
        let landing = if self.last() && self.tear == Tear::Garbage {
            vec![0xA5; data.len().max(1)]
        } else {
            data.to_vec()
        };
        self.kept.borrow_mut().insert(fid, landing);
        self.landed()
    }

    fn remove(&mut self, fid: u16) -> Result<()> {
        self.power()?;
        self.kept.borrow_mut().remove(&fid);
        self.landed()
    }

    fn size(&mut self, fid: u16) -> Option<usize> {
        self.kept.borrow().get(&fid).map(Vec::len)
    }

    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        let keys: Vec<u16> = self.kept.borrow().keys().copied().collect();
        for key in keys {
            f(key);
        }
        true
    }
}

/// A device whose medium survives the reboot and whose power can be cut after a
/// chosen number of mutations.
struct RamDevice {
    medium: Medium,
}

impl RamDevice {
    fn new(tear: Tear) -> Self {
        Self {
            medium: Medium {
                kept: Rc::new(RefCell::new(HashMap::new())),
                budget: Rc::new(Cell::new(None)),
                dead: Rc::new(Cell::new(false)),
                tear,
                forget: Rc::new(Cell::new(None)),
                cuts: Rc::new(Cell::new(0)),
            },
        }
    }

    /// Cut the power around the mutation `n` further mutations from now.
    fn arm(&mut self, n: u32) {
        self.medium.budget.set(Some(n));
    }

    /// The first mount, before anything has been driven.
    fn mount(&self) -> Fs<Medium> {
        let mut fs = Fs::new(self.medium.clone());
        fs.scan();
        fs
    }
}

impl Device for RamDevice {
    type Storage = Medium;

    fn boot(&mut self) -> Fs<Medium> {
        if let Some(fid) = self.medium.forget.get() {
            self.medium.kept.borrow_mut().remove(&fid);
        }
        Fs::new(self.medium.clone())
    }

    fn dead(&self) -> bool {
        self.medium.dead.get()
    }

    fn revive(&mut self) {
        self.medium.dead.set(false);
    }
}

/// The script every sweep replays: two files with metadata, a delete, a rewrite
/// and two clean reboots, so both of `Fs`'s write orders and both halves of
/// `EF_META`'s lifecycle are crossed.
fn script() -> Vec<Op> {
    vec![
        Op::Put(A, vec![1, 2, 3]),
        Op::MetaAdd(A, vec![0xAA; 8]),
        Op::Put(B, vec![4; 40]),
        Op::MetaAdd(B, vec![0xBB; 8]),
        Op::Read(A, 3),
        Op::MetaFind(B),
        Op::Delete(A),
        Op::Put(C, vec![7; 12]),
        Op::Reboot,
        Op::MetaDelete(B),
        Op::Put(B, vec![9; 5]),
        Op::Read(B, 2),
        Op::Reboot,
    ]
}

/// Replay [`script`] with the power cut around mutation `budget`. Returns how
/// many cuts fired, so a sweep can prove it cut the power at all.
fn replay(tear: Tear, budget: Option<u32>) -> u32 {
    let mut dev = RamDevice::new(tear);
    let mut fs = dev.mount();
    let mut model = PowerCutModel::new(&FIDS, META_MAX);
    if let Some(n) = budget {
        dev.arm(n);
    }
    for op in script() {
        model.step(&mut dev, &mut fs, op);
    }
    // One more clean boot: whatever the cut left has to survive another mount.
    model.reboot(&mut dev, &mut fs);
    dev.medium.cuts.get()
}

#[test]
fn a_run_with_the_mains_on_holds_the_model() {
    assert_eq!(replay(Tear::Before, None), 0);
}

/// Budgets past the script's mutation count never fire, so the sweep's own
/// yield is asserted: measured 9 and 10 cuts across 40 budgets, and a change
/// that stops the medium cutting would otherwise leave a sweep of clean runs
/// looking exactly like a sweep of survived ones.
const CUTS_FLOOR: u32 = 9;

#[test]
fn a_cut_before_any_one_mutation_is_survivable() {
    let fired: u32 = (0..40)
        .map(|budget| replay(Tear::Before, Some(budget)))
        .sum();
    assert!(
        fired >= CUTS_FLOOR,
        "only {fired} cuts fired: the sweep proved nothing"
    );
}

#[test]
fn a_cut_after_any_one_mutation_is_survivable() {
    let fired: u32 = (0..40)
        .map(|budget| replay(Tear::After, Some(budget)))
        .sum();
    assert!(
        fired >= CUTS_FLOOR,
        "only {fired} cuts fired: the sweep proved nothing"
    );
}

#[test]
fn a_cut_never_leaves_metadata_behind_a_file_that_is_gone() {
    // `Fs::delete` drops the metadata FIRST, so no cut inside it can produce
    // value-gone-but-meta-alive. The sweeps above cross every cut point in the
    // script; this pins the one the ordering exists for, on a file that has
    // metadata, from both sides of the landing.
    for tear in [Tear::Before, Tear::After] {
        for budget in 0..6 {
            let mut dev = RamDevice::new(tear);
            let mut fs = dev.mount();
            let mut model = PowerCutModel::new(&FIDS, META_MAX);
            for op in [Op::Put(A, vec![1, 2, 3]), Op::MetaAdd(A, vec![0xAA; 8])] {
                model.step(&mut dev, &mut fs, op);
            }
            dev.arm(budget);
            model.step(&mut dev, &mut fs, Op::Delete(A));
            model.reboot(&mut dev, &mut fs);
        }
    }
}

/// A file that has metadata and NO value, whose delete is cut.
///
/// Every other cut sweep here puts a value first, so this shape — the one
/// `Fs::delete`'s unconditional `let _ = self.meta_delete(fid)` exists for
/// (0x077C) — was crossed by nothing. It is the shape `RSKeyStore`'s
/// `BugDeleteMetaOnlyUnderPresent` models: gate that call on the present bit and
/// a meta-only file keeps its record for ever.
#[test]
fn a_cut_inside_the_delete_of_a_meta_only_file_loses_neither_half() {
    for tear in [Tear::Before, Tear::After] {
        for budget in 0..6 {
            let mut dev = RamDevice::new(tear);
            let mut fs = dev.mount();
            let mut model = PowerCutModel::new(&FIDS, META_MAX);
            model.step(&mut dev, &mut fs, Op::MetaAdd(A, vec![0xAA; 8]));
            dev.arm(budget);
            model.step(&mut dev, &mut fs, Op::Delete(A));
            model.reboot(&mut dev, &mut fs);
            // The record is gone once the delete settled, and the file it never
            // had did not appear.
            model.step(&mut dev, &mut fs, Op::MetaFind(A));
            model.step(&mut dev, &mut fs, Op::Read(A, 8));
        }
    }
}

// --- controls: the oracle has to be able to fail ------------------------------

#[test]
#[should_panic(expected = "committed file lost or changed")]
fn a_medium_that_forgets_a_committed_file_is_caught() {
    let mut dev = RamDevice::new(Tear::Before);
    let mut fs = dev.mount();
    let mut model = PowerCutModel::new(&FIDS, META_MAX);
    model.step(&mut dev, &mut fs, Op::Put(C, vec![7; 12]));
    dev.medium.forget.set(Some(C));
    model.reboot(&mut dev, &mut fs);
}

#[test]
#[should_panic(expected = "torn put")]
fn a_cut_that_lands_filler_is_caught() {
    let mut dev = RamDevice::new(Tear::Garbage);
    let mut fs = dev.mount();
    let mut model = PowerCutModel::new(&FIDS, META_MAX);
    model.step(&mut dev, &mut fs, Op::Put(A, vec![1, 2, 3]));
    dev.arm(1); // the next mutation lands as filler, then the power goes
    model.step(&mut dev, &mut fs, Op::Put(A, vec![4, 5, 6]));
}

#[test]
#[should_panic(expected = "torn delete")]
fn a_delete_that_loses_the_value_but_keeps_the_metadata_is_caught() {
    // The forbidden intermediate, built by hand: the delete is cut before the
    // metadata goes, and the boot that follows drops the value while `EF_META`
    // still names it.
    let mut dev = RamDevice::new(Tear::Before);
    let mut fs = dev.mount();
    let mut model = PowerCutModel::new(&FIDS, META_MAX);
    for op in [Op::Put(A, vec![1, 2, 3]), Op::MetaAdd(A, vec![0xAA; 8])] {
        model.step(&mut dev, &mut fs, op);
    }
    dev.medium.forget.set(Some(A));
    dev.arm(0);
    model.step(&mut dev, &mut fs, Op::Delete(A));
}
