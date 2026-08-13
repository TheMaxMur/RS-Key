// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The driver half of the power-cut oracle: a shadow of what the device should
//! hold, and the reboot loop that judges what it does.
//!
//! Behind the same `test-util` feature as `RamStorage`, because it needs a heap
//! and a `HashMap`. Nothing that reaches a firmware image enables it — every
//! crate that does is a `[dev-dependencies]` entry, so feature unification cannot
//! drag it in.

use std::collections::{BTreeSet, HashMap};

use super::{delete_landed, meta_add_landed, meta_delete_landed, put_landed};
use crate::{EF_META, Fs, Storage};

/// `EF_META`'s record header: `[fid: u16 BE][len: u16 BE]`, which the model has
/// to know to predict whether the rebuilt blob will fit. The blob's ceiling comes
/// from the caller instead, because `fs.rs` keeps it private and widening it
/// would be a change to a file the firmware compiles — for a testing convenience.
const META_REC_HDR: usize = 4;

/// The observation buffer. Everything the oracle drives is far under this, and a
/// read is checked against the length `Fs` reports, so a longer value surfaces as
/// a length mismatch rather than a silently short comparison.
const READ_MAX: usize = 256;

/// A whole device the model can cut the power to and boot again.
///
/// Implemented by the fuzz target over `rsk_store::SeqStorage` and a mock NOR
/// chip, and by this crate's tests over a RAM medium. The model never builds a
/// store itself: what a reboot costs — which caches are lost, which bytes
/// survive — is the medium's business, and getting that wrong is exactly the
/// failure the oracle exists to find.
pub trait Device {
    /// The backend a boot produces.
    type Storage: Storage;

    /// Rebuild the whole stack over the same medium, with the RAM a power cycle
    /// would have lost. Called with the power already restored.
    fn boot(&mut self) -> Fs<Self::Storage>;

    /// Whether the power has cut since it was last restored. Once true, every
    /// further write must fail without touching the medium — a dead device
    /// cannot keep writing, and [`Fs::delete`] swallows its `meta_delete` error
    /// and would otherwise carry on.
    fn dead(&self) -> bool;

    /// Restore the power, without touching what is on the medium.
    fn revive(&mut self);
}

/// What the cut interrupted — the only operation a reboot may be ambiguous
/// about. Wasefire calls this half `Complete`.
#[derive(Debug)]
enum Pending {
    Put(u16, Vec<u8>),
    Delete(u16),
    /// The flag is whether the rebuilt `EF_META` blob would have fit, so a cut
    /// `meta_add` that could never have succeeded may not look as if it did.
    MetaAdd(u16, Vec<u8>, bool),
    MetaDelete(u16),
}

/// One driven operation. The fuzz target decodes these out of its input; the
/// crate's tests write them out.
#[derive(Debug, Clone)]
pub enum Op {
    Put(u16, Vec<u8>),
    /// Read into a buffer of this capacity — a short buffer must still report
    /// the value's full length.
    Read(u16, usize),
    Delete(u16),
    MetaAdd(u16, Vec<u8>),
    MetaFind(u16),
    MetaDelete(u16),
    /// A clean reboot: the same remount and full model check, nothing pending.
    Reboot,
}

/// The shadow of what the device should hold, and the judge of what it does.
pub struct PowerCutModel {
    /// FID -> committed value.
    val: HashMap<u16, Vec<u8>>,
    /// FID -> committed metadata record.
    meta: HashMap<u16, Vec<u8>>,
    /// Every FID the sweep asks about, present or not. An absent one must read
    /// back absent, which is half of what durability means.
    fids: Vec<u16>,
    /// What `EF_META` holds in total (`fs.rs`'s private `META_MAX`).
    meta_max: usize,
}

impl PowerCutModel {
    /// A model of an empty device that will only ever be asked about `fids`, whose
    /// metadata store holds `meta_max` bytes in total.
    pub fn new(fids: &[u16], meta_max: usize) -> Self {
        Self {
            val: HashMap::new(),
            meta: HashMap::new(),
            fids: fids.to_vec(),
            meta_max,
        }
    }

    /// Take whatever the device already holds as the committed truth.
    ///
    /// For a run that starts over a medium the store did not write — a prefix of
    /// entropy, say. The store's answers on an invalid storage are its own
    /// business, but from the first stable mount on it must still be
    /// self-consistent and power-cut-safe, and that is what this keeps checkable.
    pub fn adopt<D: Device>(&mut self, dev: &mut D, fs: &mut Fs<D::Storage>) {
        self.val.clear();
        self.meta.clear();
        for fid in self.fids.clone() {
            if let Some(value) = self.read_value(fs, fid) {
                self.val.insert(fid, value);
            }
            if let Some(record) = self.read_meta(fs, fid) {
                self.meta.insert(fid, record);
            }
        }
        // A read that faulted mid-sweep leaves a model of a device that is not
        // there; boot again and take the picture over.
        if dev.dead() {
            self.recover(dev, fs, None);
        }
    }

    /// Drive one operation, and — if the power cut during it — reboot and judge.
    pub fn step<D: Device>(&mut self, dev: &mut D, fs: &mut Fs<D::Storage>, op: Op) {
        let pending = match op {
            Op::Reboot => {
                self.reboot(dev, fs);
                return;
            }
            Op::Put(fid, value) => self.put(dev, fs, fid, value),
            Op::Read(fid, cap) => {
                self.read(dev, fs, fid, cap);
                None
            }
            Op::Delete(fid) => self.delete(dev, fs, fid),
            Op::MetaAdd(fid, value) => self.meta_add(dev, fs, fid, value),
            Op::MetaFind(fid) => {
                self.meta_find(dev, fs, fid);
                None
            }
            Op::MetaDelete(fid) => self.meta_delete(dev, fs, fid),
        };
        if dev.dead() {
            self.recover(dev, fs, pending);
        }
    }

    /// Reboot with nothing outstanding: the whole model check, no ambiguity.
    pub fn reboot<D: Device>(&mut self, dev: &mut D, fs: &mut Fs<D::Storage>) {
        self.recover(dev, fs, None);
    }

    /// How many files the model believes are live — what a stats replay reports.
    pub fn live(&self) -> usize {
        self.val.len()
    }

    fn put<D: Device>(
        &mut self,
        dev: &mut D,
        fs: &mut Fs<D::Storage>,
        fid: u16,
        value: Vec<u8>,
    ) -> Option<Pending> {
        let done = fs.put(fid, &value);
        if dev.dead() {
            return Some(Pending::Put(fid, value));
        }
        done.unwrap();
        self.val.insert(fid, value);
        None
    }

    fn read<D: Device>(&mut self, dev: &mut D, fs: &mut Fs<D::Storage>, fid: u16, cap: usize) {
        let cap = cap.min(READ_MAX);
        let mut buf = [0u8; READ_MAX];
        let got = fs.read(fid, &mut buf[..cap]);
        if dev.dead() {
            return;
        }
        match self.val.get(&fid) {
            Some(want) => {
                let n = got.expect("present file must read");
                assert_eq!(n, want.len());
                let seen = n.min(cap);
                assert_eq!(&buf[..seen], &want[..seen]);
            }
            None => assert!(got.is_none()),
        }
    }

    fn delete<D: Device>(
        &mut self,
        dev: &mut D,
        fs: &mut Fs<D::Storage>,
        fid: u16,
    ) -> Option<Pending> {
        let done = fs.delete(fid);
        if dev.dead() {
            return Some(Pending::Delete(fid));
        }
        done.unwrap();
        self.val.remove(&fid);
        self.meta.remove(&fid);
        None
    }

    fn meta_add<D: Device>(
        &mut self,
        dev: &mut D,
        fs: &mut Fs<D::Storage>,
        fid: u16,
        value: Vec<u8>,
    ) -> Option<Pending> {
        let fits = self.rebuilt_meta_len(fid, value.len()) <= self.meta_max;
        let done = fs.meta_add(fid, &value);
        if dev.dead() {
            return Some(Pending::MetaAdd(fid, value, fits));
        }
        if fits {
            done.unwrap();
            self.meta.insert(fid, value);
        } else {
            assert!(done.is_err(), "an oversized meta_add must be refused");
        }
        None
    }

    fn meta_find<D: Device>(&mut self, dev: &mut D, fs: &mut Fs<D::Storage>, fid: u16) {
        let mut out = [0u8; READ_MAX];
        let got = fs.meta_find(fid, &mut out);
        if dev.dead() {
            return;
        }
        match self.meta.get(&fid) {
            Some(want) => {
                let n = got.expect("present meta must be found");
                assert_eq!(n, want.len());
                let seen = n.min(out.len());
                assert_eq!(&out[..seen], &want[..seen]);
            }
            None => assert!(got.is_none()),
        }
    }

    fn meta_delete<D: Device>(
        &mut self,
        dev: &mut D,
        fs: &mut Fs<D::Storage>,
        fid: u16,
    ) -> Option<Pending> {
        let done = fs.meta_delete(fid);
        if dev.dead() {
            return Some(Pending::MetaDelete(fid));
        }
        done.unwrap();
        self.meta.remove(&fid);
        None
    }

    /// What `EF_META` would hold once `fid` carries `len` bytes.
    fn rebuilt_meta_len(&self, fid: u16, len: usize) -> usize {
        self.meta
            .iter()
            .filter(|(other, _)| **other != fid)
            .map(|(_, record)| META_REC_HDR + record.len())
            .sum::<usize>()
            + META_REC_HDR
            + len
    }

    /// Boot until a mount plus a full model check completes without another cut,
    /// resolving `pending` against the first stable observation.
    ///
    /// It terminates because the injected budget disarms itself when it fires:
    /// each lap either survives or spends a budget that is not rearmed.
    fn recover<D: Device>(
        &mut self,
        dev: &mut D,
        fs: &mut Fs<D::Storage>,
        mut pending: Option<Pending>,
    ) {
        loop {
            dev.revive();
            *fs = dev.boot();
            fs.scan();
            if dev.dead() {
                continue; // the cut landed inside the mount or its repair
            }
            if !self.settle(dev, fs, &pending) {
                continue; // a repair write inside the resolving reads was cut
            }
            pending = None; // resolved against stable flash — committed now
            if self.sweep(dev, fs) {
                return;
            }
        }
    }

    /// Resolve the interrupted operation against what the medium actually holds.
    /// `false` means the power went again before the answer was stable.
    fn settle<D: Device>(
        &mut self,
        dev: &mut D,
        fs: &mut Fs<D::Storage>,
        pending: &Option<Pending>,
    ) -> bool {
        match pending {
            None => return true,
            Some(Pending::Put(fid, new)) => {
                let got = self.read_value(fs, *fid);
                let old = self.val.get(fid).cloned();
                assert!(
                    put_landed(old.as_deref(), new, got.as_deref()),
                    "torn put: neither the old value nor the new one"
                );
                self.commit_value(*fid, got);
            }
            Some(Pending::Delete(fid)) => {
                let got_value = self.read_value(fs, *fid);
                let got_meta = self.read_meta(fs, *fid);
                let old_value = self.val.get(fid).cloned();
                let old_meta = self.meta.get(fid).cloned();
                assert!(
                    delete_landed(
                        old_value.as_deref(),
                        old_meta.as_deref(),
                        got_value.as_deref(),
                        got_meta.as_deref(),
                    ),
                    "torn delete: a state the write order forbids"
                );
                self.commit_value(*fid, got_value);
                self.commit_meta(*fid, got_meta);
            }
            Some(Pending::MetaAdd(fid, new, fits)) => {
                let got = self.read_meta(fs, *fid);
                let old = self.meta.get(fid).cloned();
                assert!(
                    meta_add_landed(old.as_deref(), new, *fits, got.as_deref()),
                    "torn meta_add: neither the old record nor the new one"
                );
                self.commit_meta(*fid, got);
            }
            Some(Pending::MetaDelete(fid)) => {
                let got = self.read_meta(fs, *fid);
                let old = self.meta.get(fid).cloned();
                assert!(
                    meta_delete_landed(old.as_deref(), got.as_deref()),
                    "torn meta_delete: garbage"
                );
                self.commit_meta(*fid, got);
            }
        }
        !dev.dead()
    }

    /// Every committed file and record reads back exactly, and the live key set
    /// is the model's. `false` means the power went during the sweep.
    fn sweep<D: Device>(&mut self, dev: &mut D, fs: &mut Fs<D::Storage>) -> bool {
        for fid in self.fids.clone() {
            let got = self.read_value(fs, fid);
            let got_meta = self.read_meta(fs, fid);
            if dev.dead() {
                return false;
            }
            assert_eq!(
                got,
                self.val.get(&fid).cloned(),
                "committed file lost or changed"
            );
            assert_eq!(
                got_meta,
                self.meta.get(&fid).cloned(),
                "committed meta lost or changed"
            );
        }
        let mut live = BTreeSet::new();
        fs.for_each_key(&mut |key| {
            live.insert(key);
        });
        if dev.dead() {
            return false;
        }
        let want: BTreeSet<u16> = self.val.keys().copied().collect();
        assert!(
            live.is_superset(&want),
            "committed key missing after the cut"
        );
        // `EF_META` may linger physically after the delete of the last record was
        // cut, so it is the one key allowed to be there without being modelled.
        assert!(
            live.difference(&want).all(|&key| key == EF_META),
            "unexpected key after the cut"
        );
        if !self.meta.is_empty() {
            assert!(
                live.contains(&EF_META),
                "metadata with no EF_META to hold it"
            );
        }
        true
    }

    fn read_value<S: Storage>(&self, fs: &mut Fs<S>, fid: u16) -> Option<Vec<u8>> {
        let mut buf = [0u8; READ_MAX];
        fs.read(fid, &mut buf)
            .map(|n| buf[..n.min(READ_MAX)].to_vec())
    }

    fn read_meta<S: Storage>(&self, fs: &mut Fs<S>, fid: u16) -> Option<Vec<u8>> {
        let mut buf = [0u8; READ_MAX];
        fs.meta_find(fid, &mut buf)
            .map(|n| buf[..n.min(READ_MAX)].to_vec())
    }

    fn commit_value(&mut self, fid: u16, got: Option<Vec<u8>>) {
        match got {
            Some(value) => self.val.insert(fid, value),
            None => self.val.remove(&fid),
        };
    }

    fn commit_meta(&mut self, fid: u16, got: Option<Vec<u8>>) {
        match got {
            Some(record) => self.meta.insert(fid, record),
            None => self.meta.remove(&fid),
        };
    }
}
