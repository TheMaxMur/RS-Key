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

#[test]
fn deletion_oracle_accepts_ordered_intermediates_and_refuses_changed_metadata() {
    let value = Some(&b"value"[..]);
    let policy = Some(&b"policy"[..]);
    assert!(delete_landed(value, policy, value, policy));
    assert!(delete_landed(value, policy, value, None));
    assert!(delete_landed(value, policy, None, None));
    assert!(!delete_landed(value, policy, None, policy));
    assert!(!delete_landed(
        value,
        policy,
        value,
        Some(b"another policy")
    ));
    assert!(!delete_landed(value, policy, Some(b"another value"), None));
}

#[test]
fn metadata_oracles_refuse_a_nonfitting_append_or_an_invented_value() {
    let old = Some(&b"old"[..]);
    let new = &b"new"[..];
    assert!(meta_add_landed(old, new, false, old));
    assert!(!meta_add_landed(old, new, false, Some(new)));
    assert!(meta_add_landed(old, new, true, Some(new)));
    assert!(!meta_add_landed(old, new, true, Some(b"third")));
    assert!(meta_delete_landed(old, old));
    assert!(meta_delete_landed(old, None));
    assert!(!meta_delete_landed(old, Some(b"third")));
}

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
    read_cut: Rc<Cell<Option<u16>>>,
    read_fault: Rc<Cell<Option<u16>>>,
    err: Rc<Cell<bool>>,
    walk_cut: Rc<Cell<Option<usize>>>,
    /// Number of upcoming key walks to truncate without cutting the power.
    walk_fault: Rc<Cell<u32>>,
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
        self.err.set(false);
        if self.read_fault.get() == Some(fid) {
            self.read_fault.set(None);
            self.err.set(true);
            return None;
        }
        if self.read_cut.get() == Some(fid) {
            self.read_cut.set(None);
            self.err.set(true);
            self.cut();
            return None;
        }
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
        self.err.set(false);
        self.kept.borrow().get(&fid).map(Vec::len)
    }

    fn last_error(&self) -> bool {
        self.err.get()
    }

    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        if self.walk_fault.get() > 0 {
            self.walk_fault.set(self.walk_fault.get() - 1);
            return false;
        }
        if let Some(skip) = self.walk_cut.get() {
            if skip == 0 {
                self.walk_cut.set(None);
                self.cut();
                return false;
            }
            self.walk_cut.set(Some(skip - 1));
        }
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
    boots: usize,
}

impl RamDevice {
    fn new(tear: Tear) -> Self {
        Self {
            boots: 0,
            medium: Medium {
                kept: Rc::new(RefCell::new(HashMap::new())),
                budget: Rc::new(Cell::new(None)),
                dead: Rc::new(Cell::new(false)),
                tear,
                forget: Rc::new(Cell::new(None)),
                cuts: Rc::new(Cell::new(0)),
                read_cut: Rc::new(Cell::new(None)),
                read_fault: Rc::new(Cell::new(None)),
                err: Rc::new(Cell::new(false)),
                walk_cut: Rc::new(Cell::new(None)),
                walk_fault: Rc::new(Cell::new(0)),
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
        self.boots += 1;
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

struct OneBoot(RamDevice);

impl Device for OneBoot {
    type Storage = Medium;

    fn boot(&mut self) -> Fs<Medium> {
        assert_eq!(self.0.boots, 0, "stable RAM recovery needs one boot");
        self.0.boot()
    }

    fn dead(&self) -> bool {
        self.0.dead()
    }

    fn revive(&mut self) {
        self.0.revive();
    }
}

#[test]
fn an_atomic_ram_put_cut_finishes_recovery_after_one_boot() {
    let mut dev = OneBoot(RamDevice::new(Tear::Before));
    let mut fs = dev.0.mount();
    let mut model = PowerCutModel::new(&FIDS, META_MAX);
    model.step(&mut dev, &mut fs, Op::Put(A, b"old".to_vec()));
    dev.0.arm(0);
    model.step(&mut dev, &mut fs, Op::Put(A, b"new".to_vec()));
    assert_eq!(dev.0.boots, 1);
    assert_eq!(model.live(), 1);
    assert!(!dev.dead());
    let mut out = [0; 3];
    assert_eq!(fs.read(A, &mut out), Some(3));
    assert_eq!(&out, b"old");
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

#[test]
fn adopting_an_existing_device_tracks_data_and_metadata_only_files() {
    let mut dev = RamDevice::new(Tear::Before);
    let mut fs = dev.mount();
    fs.put(A, b"old").unwrap();
    fs.meta_add(A, b"policy").unwrap();
    fs.meta_add(B, b"metadata only").unwrap();
    let mut model = PowerCutModel::new(&FIDS, META_MAX);
    model.adopt(&mut dev, &mut fs);
    assert_eq!(model.live(), 1);
    model.reboot(&mut dev, &mut fs);
    model.step(&mut dev, &mut fs, Op::Delete(B));
    assert_eq!(model.live(), 1);
    model.step(&mut dev, &mut fs, Op::Put(C, b"new".to_vec()));
    assert_eq!(model.live(), 2);
    model.step(&mut dev, &mut fs, Op::Delete(A));
    assert_eq!(model.live(), 1);
    model.reboot(&mut dev, &mut fs);
}

#[test]
fn adopting_after_a_power_cut_recovers_before_driving_the_model() {
    let mut dev = RamDevice::new(Tear::Before);
    let mut fs = dev.mount();
    fs.put(A, b"old").unwrap();
    dev.medium.dead.set(true);
    let mut model = PowerCutModel::new(&FIDS, META_MAX);
    model.adopt(&mut dev, &mut fs);
    assert!(!dev.dead());
    assert_eq!(model.live(), 1);
    model.step(&mut dev, &mut fs, Op::Read(A, 3));
    model.reboot(&mut dev, &mut fs);
}

#[test]
fn a_fourth_valid_metadata_entry_that_exceeds_the_store_is_refused() {
    let fourth = C + 1;
    let fids = [A, B, C, fourth];
    let mut dev = RamDevice::new(Tear::Before);
    let mut fs = dev.mount();
    let mut model = PowerCutModel::new(&fids, META_MAX);
    for fid in fids {
        model.step(&mut dev, &mut fs, Op::Put(fid, b"value".to_vec()));
    }
    for fid in fids {
        model.step(
            &mut dev,
            &mut fs,
            Op::MetaAdd(fid, vec![0xa5; u8::MAX as usize]),
        );
    }
    let mut out = [0; u8::MAX as usize];
    assert_eq!(fs.meta_add(fourth, &out), Err(Error::NoMemory));
    assert_eq!(fs.meta_find(fourth, &mut out), None);
    for fid in [A, B, C] {
        assert_eq!(fs.meta_find(fid, &mut out), Some(out.len()));
    }
    model.reboot(&mut dev, &mut fs);
}

#[test]
fn the_power_cut_model_recovers_when_reads_or_mount_walks_lose_power() {
    for cut in 0..5 {
        let mut dev = RamDevice::new(Tear::Before);
        let mut fs = dev.mount();
        let mut model = PowerCutModel::new(&FIDS, META_MAX);
        model.step(&mut dev, &mut fs, Op::Put(A, b"value".to_vec()));
        model.step(&mut dev, &mut fs, Op::MetaAdd(A, b"policy".to_vec()));
        match cut {
            0 => dev.medium.read_cut.set(Some(A)),
            1 => dev.medium.read_cut.set(Some(crate::EF_META)),
            2 | 3 => dev.medium.walk_cut.set(Some(cut - 2)),
            _ => dev.medium.read_cut.set(Some(A)),
        }
        match cut {
            0 => model.step(&mut dev, &mut fs, Op::Read(A, 5)),
            1 => model.step(&mut dev, &mut fs, Op::MetaFind(A)),
            _ => model.reboot(&mut dev, &mut fs),
        }
        assert_eq!(dev.medium.cuts.get(), 1);
        assert_eq!(dev.boots, if cut < 2 { 1 } else { 2 });
        assert!(!dev.dead());
        let mut value = [0; 5];
        assert_eq!(fs.read(A, &mut value), Some(value.len()));
        assert_eq!(&value, b"value");
        let mut record = [0; 6];
        assert_eq!(fs.meta_find(A, &mut record), Some(record.len()));
        assert_eq!(&record, b"policy");
    }
}

/// A failed read with the power still on is not evidence of absence. The old
/// oracle asked `Fs::read`, which collapses a backend fault into `None`, and
/// then accepted that `None` for a key the model knew was absent. The fuzz
/// target's torn records can produce exactly this read error after a reboot,
/// so the model must use the fallible probe and refuse the collapse.
#[test]
#[should_panic(expected = "read failed without a power cut")]
fn a_read_failure_is_not_an_absent_file() {
    let mut dev = RamDevice::new(Tear::Before);
    let mut fs = Fs::new(dev.medium.clone());
    // A truncated boot walk leaves the cache undecided, the one place a read is
    // allowed to reach the backend for an absent key.
    dev.medium.walk_fault.set(1);
    fs.scan();
    let mut model = PowerCutModel::new(&FIDS, META_MAX);
    dev.medium.read_fault.set(Some(C));
    model.step(&mut dev, &mut fs, Op::Read(C, 4));
}

/// A key walk that stops early with the power on is not evidence that its
/// un-yielded keys are absent. The old sweep ignored `for_each_key`'s
/// completeness flag, so a truncated walk could hide a committed key.
#[test]
#[should_panic(expected = "key walk truncated without a power cut")]
fn a_truncated_key_walk_is_not_an_absent_key() {
    let mut dev = RamDevice::new(Tear::Before);
    let mut fs = dev.mount();
    let mut model = PowerCutModel::new(&FIDS, META_MAX);
    model.step(&mut dev, &mut fs, Op::Put(A, b"value".to_vec()));
    // The recovery's scan consumes the first walk; the sweep's walk is the one
    // that must not be read as an absent key.
    dev.medium.walk_fault.set(2);
    model.reboot(&mut dev, &mut fs);
}

/// A recovery that never settles must need a second boot, and a second boot with
/// no second cut is not a recovery. This bounds the loop without weakening a
/// legitimate multi-cut history: `OneBoot` refuses the retry.
#[test]
fn a_recovery_that_does_not_settle_cannot_loop_on_healthy_power() {
    let mut dev = OneBoot(RamDevice::new(Tear::Before));
    let mut fs = dev.0.mount();
    let mut model = PowerCutModel::new(&FIDS, META_MAX);
    model.step(&mut dev, &mut fs, Op::Put(A, b"old".to_vec()));
    dev.0.arm(0);
    model.step(&mut dev, &mut fs, Op::Put(A, b"new".to_vec()));
}

/// The same rule without a hidden key: the model is empty, so a complete walk
/// would legitimately see nothing. The empty result still cannot be read from a
/// truncated walk; this isolates the completeness guard from the key-set check.
#[test]
#[should_panic(expected = "key walk truncated without a power cut")]
fn a_truncated_empty_key_walk_is_not_an_absent_key() {
    let mut dev = RamDevice::new(Tear::Before);
    let mut fs = Fs::new(dev.medium.clone());
    let mut model = PowerCutModel::new(&FIDS, META_MAX);
    dev.medium.walk_fault.set(2);
    model.reboot(&mut dev, &mut fs);
}

/// Adopting over a read fault with the power on must not turn that fault into
/// a partial model. This is the `adopt` half of the same rule the read path
/// checks: an error is not an absence, and a dead device needs a reboot rather
/// than a model built from whatever answered before the fault.
#[test]
#[should_panic(expected = "read failed without a power cut")]
fn adopting_a_value_read_failure_is_not_absence() {
    let mut dev = RamDevice::new(Tear::Before);
    let mut fs = Fs::new(dev.medium.clone());
    // A truncated boot walk leaves the FID undecided, so the read reaches the
    // medium instead of a cache that says "absent".
    dev.medium.walk_fault.set(1);
    fs.scan();
    let mut model = PowerCutModel::new(&FIDS, META_MAX);
    dev.medium.read_fault.set(Some(C));
    model.adopt(&mut dev, &mut fs);
}

#[test]
fn adopting_a_value_read_failure_after_a_power_cut_recovers() {
    let mut dev = RamDevice::new(Tear::Before);
    let mut fs = Fs::new(dev.medium.clone());
    dev.medium.walk_fault.set(1);
    fs.scan();
    let mut model = PowerCutModel::new(&FIDS, META_MAX);
    dev.medium.dead.set(true);
    dev.medium.read_fault.set(Some(A));
    model.adopt(&mut dev, &mut fs);
    assert!(!dev.dead());
}

#[test]
#[should_panic(expected = "read failed without a power cut")]
fn adopting_a_metadata_read_failure_is_not_absence() {
    let mut dev = RamDevice::new(Tear::Before);
    let mut fs = Fs::new(dev.medium.clone());
    dev.medium.walk_fault.set(1);
    fs.scan();
    let mut model = PowerCutModel::new(&FIDS, META_MAX);
    dev.medium.read_fault.set(Some(crate::EF_META));
    model.adopt(&mut dev, &mut fs);
}

#[test]
fn adopting_a_metadata_read_failure_after_a_power_cut_recovers() {
    let mut dev = RamDevice::new(Tear::Before);
    let mut fs = Fs::new(dev.medium.clone());
    dev.medium.walk_fault.set(1);
    fs.scan();
    let mut model = PowerCutModel::new(&FIDS, META_MAX);
    dev.medium.dead.set(true);
    dev.medium.read_fault.set(Some(crate::EF_META));
    model.adopt(&mut dev, &mut fs);
    assert!(!dev.dead());
}

/// A cut inside the command and a second cut inside its recovery. The first
/// must not hide the second: the recovery's read or mount walk fails, the loop
/// reboots, and the settled state is still the old value with the neighbour
/// intact. Both cuts are counted, so a fixture that only injected one cannot
/// pass as the combination.
#[test]
fn a_second_cut_inside_recovery_does_not_hide_the_first() {
    for refuse_walk in [false, true] {
        let mut dev = RamDevice::new(Tear::Before);
        let mut fs = dev.mount();
        let mut model = PowerCutModel::new(&FIDS, META_MAX);
        model.step(&mut dev, &mut fs, Op::Put(A, b"old".to_vec()));
        model.step(&mut dev, &mut fs, Op::Put(B, b"neighbour".to_vec()));
        dev.arm(0); // the command's write is cut
        if refuse_walk {
            dev.medium.walk_cut.set(Some(0)); // the recovery mount walk is cut
        } else {
            dev.medium.read_cut.set(Some(A)); // the recovery settle read is cut
        }
        model.step(&mut dev, &mut fs, Op::Put(A, b"new".to_vec()));
        assert_eq!(
            dev.medium.cuts.get(),
            2,
            "both the command cut and the recovery cut must fire (walk={refuse_walk})"
        );
        assert!(!dev.dead());
        let mut a = [0; 3];
        assert_eq!(fs.read(A, &mut a), Some(3));
        assert_eq!(&a, b"old");
        let mut b = [0; 9];
        assert_eq!(fs.read(B, &mut b), Some(9));
        assert_eq!(&b, b"neighbour");
    }
}

#[test]
fn explicit_reads_refuse_unmodelled_length_and_content_changes() {
    for metadata in [false, true] {
        for changed in [b"longer".as_slice(), b"lost".as_slice()] {
            let mut dev = RamDevice::new(Tear::Before);
            let mut fs = dev.mount();
            let mut model = PowerCutModel::new(&FIDS, META_MAX);
            let initial = if metadata {
                Op::MetaAdd(A, b"kept".to_vec())
            } else {
                Op::Put(A, b"kept".to_vec())
            };
            model.step(&mut dev, &mut fs, initial);
            if metadata {
                fs.meta_add(A, changed).unwrap();
            } else {
                fs.put(A, changed).unwrap();
            }
            let op = if metadata {
                Op::MetaFind(A)
            } else {
                Op::Read(A, 16)
            };
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                model.step(&mut dev, &mut fs, op)
            }))
            .expect_err("model accepted an unacknowledged replacement");
            let text = panic.downcast_ref::<String>().unwrap();
            assert!(
                text.starts_with("assertion `left == right` failed\n"),
                "{text}"
            );
            if changed.len() != 4 {
                assert!(text.contains("left: 6\n right: 4"), "{text}");
            } else {
                assert!(text.contains("left: [108, 111, 115, 116]"), "{text}");
                assert!(text.contains("right: [107, 101, 112, 116]"), "{text}");
            }
        }
    }
}

#[test]
#[should_panic(expected = "committed meta lost or changed")]
fn recovery_refuses_unacknowledged_metadata_with_the_value_intact() {
    let mut dev = RamDevice::new(Tear::Before);
    let mut fs = dev.mount();
    let mut model = PowerCutModel::new(&FIDS, META_MAX);
    model.step(&mut dev, &mut fs, Op::Put(A, b"value".to_vec()));
    model.step(&mut dev, &mut fs, Op::MetaAdd(A, b"policy".to_vec()));
    fs.meta_add(A, b"forged").unwrap();
    model.reboot(&mut dev, &mut fs);
}
