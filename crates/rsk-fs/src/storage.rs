// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The FID → bytes persistence backend. On device this is `sequential-storage`
//! over embassy-rp flash (implemented in `firmware`); tests use `RamStorage`.

use rsk_sdk::error::{Error, Result};

/// Only ready authority may answer application reads and confirmed absence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageState {
    Ready,
    Recovery,
}

/// Attended storage administration; an epoch is freshly drawn by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageAction {
    Initialize,
    ImportLegacy,
}

/// A persistent map from 16-bit file id to a byte value.
pub trait Storage {
    /// Recover an already constructed backend before exposing its contents.
    fn mount(&mut self) -> Result<()> {
        Ok(())
    }
    /// Boot may initialize blank media or migrate legacy records with a fresh epoch.
    fn boot(&mut self, _epoch: [u8; 16]) -> Result<()> {
        self.mount()
    }
    fn state(&self) -> StorageState {
        StorageState::Ready
    }
    fn root_closed(&self) -> bool {
        true
    }
    fn administer(&mut self, _action: StorageAction, _epoch: [u8; 16]) -> Result<()> {
        Err(Error::Blocked)
    }
    /// Largest value this backend can store for one FID. A log-structured backend
    /// serialises key+value through one scratch buffer, so the real ceiling is
    /// smaller than the buffer and was previously an unstated property of it —
    /// callers that picked their own cap could exceed it (audit run-32). Defaults
    /// to the device backend's, so a host test hits the same rejection.
    const MAX_VALUE: usize = crate::MAX_VALUE_BYTES;
    /// Copy the value for `fid` into `buf` (truncated to `buf.len()`), returning
    /// the value's full length, or `None` if `fid` is absent.
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize>;
    /// Store (or replace) the value for `fid`.
    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()>;
    /// Remove `fid` if present.
    fn remove(&mut self, fid: u16) -> Result<()>;
    /// Read a sealed counter bound to the current incarnation of `fid`.
    /// Backends without a separate counter journal leave the value in its owner.
    fn read_bound_counter(&mut self, _fid: u16, _out: &mut [u8]) -> Result<Option<usize>> {
        Ok(None)
    }
    /// Publish a sealed counter before releasing its response. `false` requests
    /// the caller's ordinary whole-record write; errors must never fall back.
    fn write_bound_counter(&mut self, _fid: u16, _sealed: &[u8]) -> Result<bool> {
        Ok(false)
    }
    /// Length of the value for `fid`, or `None`.
    fn size(&mut self, fid: u16) -> Option<usize>;
    /// Whether `fid` has a stored value.
    fn exists(&mut self, fid: u16) -> bool {
        self.size(fid).is_some()
    }
    /// Whether the most recent [`read`](Self::read) / [`size`](Self::size) FAILED,
    /// rather than finding the key absent.
    ///
    /// Both return `None` for either outcome, and [`Fs`](crate::Fs) memoises the
    /// answer as a *decided* fact — so without this a transient backend fault
    /// becomes a permanent "file absent" for the rest of the boot, and every gate
    /// that reads `has_data` opens: `clientpin::set_pin` is guarded by
    /// `if has_data(EF_PIN)` alone, so a poisoned absence lets an unauthenticated
    /// host install its own PIN over the owner's (audit run-36).
    ///
    /// Defaults to `false` — a backend that cannot fail (the test RAM map) never
    /// needs to say so, and an implementor that forgets is no worse than before.
    fn last_error(&self) -> bool {
        false
    }
    /// Invoke `f` once per stored key (used to rebuild the dynamic-file set and to
    /// probe credential slots without a per-slot `read` of every absent FID).
    /// Returns `true` iff the enumeration ran to completion — every live key was
    /// yielded. A `false` return means the walk was truncated (a flash read fault),
    /// so the caller MUST NOT treat an un-yielded FID as absent (see
    /// [`crate::Fs::scan`]).
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool;
    /// Physically reclaim superseded records so that *overwritten* and *deleted*
    /// payloads are erased from the medium, not merely unlinked.
    ///
    /// A log-structured backend ([`crate::Storage`] over `sequential-storage`)
    /// only appends: an overwrite leaves the prior value in the log and a delete
    /// flips a header flag, so the old bytes survive a raw flash dump until the
    /// page is naturally reclaimed. That is fine for the device-root seal in the
    /// steady state, but it means a record re-sealed under a *stronger* root (the
    /// pre-OTP → OTP seed migration) leaves a copy sealed under the *weaker*
    /// chip-serial-only root readable until compaction. This drives that
    /// compaction on demand. Default: no-op (backends, like the test RAM map,
    /// that overwrite in place and keep no remnants).
    fn compact(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(any(test, feature = "test-util"))]
pub mod ram {
    use super::*;
    use std::collections::HashMap;

    /// In-memory `Storage` for host tests. `Clone` lets fuzz targets snapshot
    /// an initialized image instead of re-deriving it per exec.
    #[derive(Default, Clone)]
    pub struct RamStorage {
        map: HashMap<u16, Vec<u8>>,
    }

    impl RamStorage {
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl Storage for RamStorage {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            let v = self.map.get(&fid)?;
            let n = v.len().min(buf.len());
            buf[..n].copy_from_slice(&v[..n]);
            Some(v.len())
        }
        fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
            self.map.insert(fid, data.to_vec());
            Ok(())
        }
        fn remove(&mut self, fid: u16) -> Result<()> {
            self.map.remove(&fid);
            Ok(())
        }
        fn size(&mut self, fid: u16) -> Option<usize> {
            self.map.get(&fid).map(|v| v.len())
        }
        fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
            for &k in self.map.keys() {
                f(k);
            }
            true // the RAM map iterates in memory; it cannot fault mid-walk
        }
    }
}

/// Backends that fail on purpose, shared by the applet crates' tests. One flash
/// fault shape per type, narrow enough that the setup and the observation cannot
/// be what fails.
#[cfg(any(test, feature = "test-util"))]
pub mod faults {
    use super::ram::RamStorage;
    use super::*;
    use crate::EF_META;
    use rsk_sdk::error::Error;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    /// A RAM medium whose EF_META reads fail on demand while every other value
    /// still reads. Deleting anything then leaves "a record may stand over what I
    /// erased" undecidable — and EF_META is ONE blob shared by every applet, so
    /// that answer arrives at fids which carry no record of their own. It is the
    /// fault all four applet reset sweeps must carry to the end of their range
    /// instead of stopping on it.
    pub struct MetaStuck {
        inner: Rc<RefCell<RamStorage>>,
        stuck: Rc<Cell<bool>>,
        err: bool,
    }

    /// The other end of a [`MetaStuck`]: arms the fault, and reads the medium
    /// past `Fs`'s present cache — which a delete marks absent whether or not the
    /// backend `remove` ran, so a cache-level check would pass over a wipe that
    /// never happened.
    pub struct Medium {
        inner: Rc<RefCell<RamStorage>>,
        stuck: Rc<Cell<bool>>,
    }

    impl MetaStuck {
        pub fn new() -> (Self, Medium) {
            let inner = Rc::new(RefCell::new(RamStorage::new()));
            let stuck = Rc::new(Cell::new(false));
            (
                Self {
                    inner: inner.clone(),
                    stuck: stuck.clone(),
                    err: false,
                },
                Medium { inner, stuck },
            )
        }
    }

    impl Medium {
        /// Start (`true`) or stop refusing EF_META.
        pub fn stick(&self, on: bool) {
            self.stuck.set(on);
        }
        /// Whether `fid` still has a value ON THE MEDIUM.
        pub fn live(&self, fid: u16) -> bool {
            self.inner.borrow_mut().exists(fid)
        }
    }

    impl Storage for MetaStuck {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            if fid == EF_META && self.stuck.get() {
                self.err = true;
                return None;
            }
            self.err = false;
            self.inner.borrow_mut().read(fid, buf)
        }
        fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
            self.inner.borrow_mut().write(fid, data)
        }
        fn remove(&mut self, fid: u16) -> Result<()> {
            self.inner.borrow_mut().remove(fid)
        }
        fn size(&mut self, fid: u16) -> Option<usize> {
            if fid == EF_META && self.stuck.get() {
                self.err = true;
                return None;
            }
            self.err = false;
            self.inner.borrow_mut().size(fid)
        }
        fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
            self.inner.borrow_mut().for_each_key(f)
        }
        /// The whole point: a FAILED read must not be memoised as absence.
        fn last_error(&self) -> bool {
            self.err
        }
    }

    /// A RAM medium whose `read`/`size` of ONE chosen fid fail while every other
    /// value still reads: the single faulted probe, aimed at the record a caller is
    /// about to make a decision about.
    ///
    /// [`Storage::read`] answers `None` for that and for an absent key alike, and an
    /// absent record is how this firmware spells *not provisioned* — so this is the
    /// medium that separates "no PIN configured" from "I could not look". It reports
    /// through [`Storage::last_error`] exactly as the device's `SeqStorage` does.
    pub struct ProbeStuck {
        inner: Rc<RefCell<RamStorage>>,
        stuck: Rc<Cell<Option<u16>>>,
        once: Rc<Cell<bool>>,
        /// Reads of the stuck fid to let through before the fault lands. A guard
        /// shadowed by an EARLIER probe of the same record is otherwise
        /// unfalsifiable: the first one catches every fault and the later one
        /// never runs.
        skip: Rc<Cell<u32>>,
        refused: Rc<Cell<Option<u16>>>,
        truncate: Rc<Cell<bool>>,
        err: bool,
    }

    /// The other end of a [`ProbeStuck`]: arms the fault, and reads the medium past
    /// `Fs`'s present cache — the only place a re-seed that really landed can be
    /// told from one the cache merely reports.
    pub struct ProbeMedium {
        inner: Rc<RefCell<RamStorage>>,
        stuck: Rc<Cell<Option<u16>>>,
        once: Rc<Cell<bool>>,
        skip: Rc<Cell<u32>>,
        refused: Rc<Cell<Option<u16>>>,
        truncate: Rc<Cell<bool>>,
    }

    impl ProbeStuck {
        pub fn new() -> (Self, ProbeMedium) {
            let inner = Rc::new(RefCell::new(RamStorage::new()));
            let stuck = Rc::new(Cell::new(None));
            let once = Rc::new(Cell::new(false));
            let skip = Rc::new(Cell::new(0));
            let refused = Rc::new(Cell::new(None));
            let truncate = Rc::new(Cell::new(false));
            (
                Self {
                    inner: inner.clone(),
                    stuck: stuck.clone(),
                    once: once.clone(),
                    skip: skip.clone(),
                    refused: refused.clone(),
                    truncate: truncate.clone(),
                    err: false,
                },
                ProbeMedium {
                    inner,
                    stuck,
                    once,
                    skip,
                    refused,
                    truncate,
                },
            )
        }
    }

    impl ProbeMedium {
        /// Fail every read of `fid` (`None` clears the fault).
        pub fn stick(&self, fid: Option<u16>) {
            self.stuck.set(fid);
            self.once.set(false);
            self.skip.set(0);
        }
        /// Fail the NEXT read of `fid` and then recover. A persistent fault is
        /// caught by whichever guard reads the record first, so it cannot falsify
        /// the ones further down the same command — the transient one can.
        pub fn stick_once(&self, fid: u16) {
            self.stick_after(fid, 0);
        }
        /// Let `skip` reads of `fid` through, fail the one after, then recover.
        /// [`stick_once`](Self::stick_once) is `skip = 0`. This is what reaches a
        /// guard standing BEHIND another probe of the same record — the shadowed
        /// ones a whole-suite run leaves unfalsifiable.
        pub fn stick_after(&self, fid: u16, skip: u32) {
            self.stuck.set(Some(fid));
            self.once.set(true);
            self.skip.set(skip);
        }
        /// Refuse `remove` for `fid` (`None` clears it), so a test can drive a
        /// failed delete and a faulted read-back probe on ONE medium — which is
        /// what the guards that check their own delete are made of.
        pub fn refuse_remove(&self, fid: Option<u16>) {
            self.refused.set(fid);
        }
        /// Cut every `for_each_key` walk short before it yields anything, as
        /// [`TruncatedWalk`] does permanently. Switchable, because the state that
        /// matters is what the cache still believes AFTER the medium recovers.
        pub fn truncate_walk(&self, on: bool) {
            self.truncate.set(on);
        }
        /// The bytes stored for `fid` ON THE MEDIUM, fault or no fault.
        pub fn value(&self, fid: u16) -> Option<Vec<u8>> {
            let mut buf = [0u8; crate::MAX_VALUE_BYTES];
            let n = self.inner.borrow_mut().read(fid, &mut buf)?;
            Some(buf[..n.min(buf.len())].to_vec())
        }
    }

    impl ProbeStuck {
        /// Whether this probe of `fid` is the one that faults, consuming a skip
        /// credit or the one-shot arming as it decides.
        fn faults(&self, fid: u16) -> bool {
            if self.stuck.get() != Some(fid) {
                return false;
            }
            if self.skip.get() > 0 {
                self.skip.set(self.skip.get() - 1);
                return false;
            }
            if self.once.get() {
                self.stuck.set(None);
            }
            true
        }
    }

    impl Storage for ProbeStuck {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            if self.faults(fid) {
                self.err = true;
                return None;
            }
            self.err = false;
            self.inner.borrow_mut().read(fid, buf)
        }
        fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
            self.inner.borrow_mut().write(fid, data)
        }
        fn remove(&mut self, fid: u16) -> Result<()> {
            if self.refused.get() == Some(fid) {
                return Err(Error::MemoryFatal);
            }
            self.inner.borrow_mut().remove(fid)
        }
        fn size(&mut self, fid: u16) -> Option<usize> {
            if self.faults(fid) {
                self.err = true;
                return None;
            }
            self.err = false;
            self.inner.borrow_mut().size(fid)
        }
        fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
            if self.truncate.get() {
                return false;
            }
            self.inner.borrow_mut().for_each_key(f)
        }
        fn last_error(&self) -> bool {
            self.err
        }
    }

    /// A RAM medium whose `remove` refuses one chosen fid while every other value
    /// still deletes — the other half of a [`MetaStuck`], and the one a sweep must
    /// stop on. [`crate::Fs::force_delete_halves`] removes UNCONDITIONALLY, so the
    /// refusal reaches a delete loop even at a fid that was never live.
    pub struct RemoveStuck {
        inner: Rc<RefCell<RamStorage>>,
        refused: Rc<Cell<Option<u16>>>,
        once: Rc<Cell<bool>>,
        attempts: Rc<Cell<u32>>,
    }

    /// The other end of a [`RemoveStuck`]: arms the fault, and reads the medium
    /// past `Fs`'s present cache, which a delete marks absent whether or not the
    /// backend `remove` ran.
    pub struct RemoveMedium {
        inner: Rc<RefCell<RamStorage>>,
        refused: Rc<Cell<Option<u16>>>,
        once: Rc<Cell<bool>>,
        attempts: Rc<Cell<u32>>,
    }

    impl RemoveStuck {
        pub fn new() -> (Self, RemoveMedium) {
            let inner = Rc::new(RefCell::new(RamStorage::new()));
            let refused = Rc::new(Cell::new(None));
            let once = Rc::new(Cell::new(false));
            let attempts = Rc::new(Cell::new(0));
            (
                Self {
                    inner: inner.clone(),
                    refused: refused.clone(),
                    once: once.clone(),
                    attempts: attempts.clone(),
                },
                RemoveMedium {
                    inner,
                    refused,
                    once,
                    attempts,
                },
            )
        }
    }

    impl RemoveMedium {
        /// Refuse `remove` for `fid` (`None` clears the fault).
        pub fn refuse(&self, fid: Option<u16>) {
            self.refused.set(fid);
            self.once.set(false);
        }
        /// Refuse the NEXT `remove` of `fid` and then recover — the remove twin of
        /// [`ProbeMedium::stick_once`]. A persistent refusal is caught by whichever
        /// caller asks first, so it cannot tell a RETRY further down the same
        /// command from a caller that never retried: both leave the record live.
        /// The single-shot one can.
        pub fn refuse_once(&self, fid: u16) {
            self.refused.set(Some(fid));
            self.once.set(true);
        }
        /// Whether `fid` still has a value ON THE MEDIUM.
        pub fn live(&self, fid: u16) -> bool {
            self.inner.borrow_mut().exists(fid)
        }
        /// Removals the medium was asked for. The refusal alone cannot tell a sweep
        /// that STOPPED on it from one that swallowed it: the second spins on the
        /// re-yielded fid into the delete budget, which answers the SAME error. The
        /// COUNT separates them — one batch against a whole budget.
        pub fn attempts(&self) -> u32 {
            self.attempts.get()
        }
    }

    impl Storage for RemoveStuck {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            self.inner.borrow_mut().read(fid, buf)
        }
        fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
            self.inner.borrow_mut().write(fid, data)
        }
        fn remove(&mut self, fid: u16) -> Result<()> {
            self.attempts.set(self.attempts.get() + 1);
            if self.refused.get() == Some(fid) {
                if self.once.get() {
                    self.refused.set(None);
                }
                return Err(Error::MemoryFatal);
            }
            self.inner.borrow_mut().remove(fid)
        }
        fn size(&mut self, fid: u16) -> Option<usize> {
            self.inner.borrow_mut().size(fid)
        }
        fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
            self.inner.borrow_mut().for_each_key(f)
        }
    }

    /// A RAM medium whose `for_each_key` faults before it yields anything, so the
    /// walk answers `false` over records that are still live. An un-yielded fid is
    /// not an absent one: the four applet sweeps must fail rather than read the
    /// empty batch as "the range is clear", which is a wipe reporting success over
    /// key material it never looked at.
    ///
    /// It was PIV's local `TruncatedWalk` for a release, and PIV was the only applet
    /// whose truncation guard anything could falsify — forcing the `complete` arm
    /// true left FIDO, OATH and OpenPGP at 615 / 118 / 197 passing.
    #[derive(Default)]
    pub struct TruncatedWalk(RamStorage);

    impl TruncatedWalk {
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl Storage for TruncatedWalk {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            self.0.read(fid, buf)
        }
        fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
            self.0.write(fid, data)
        }
        fn remove(&mut self, fid: u16) -> Result<()> {
            self.0.remove(fid)
        }
        fn size(&mut self, fid: u16) -> Option<usize> {
            self.0.size(fid)
        }
        fn for_each_key(&mut self, _f: &mut dyn FnMut(u16)) -> bool {
            false
        }
    }

    /// A RAM medium whose `remove` ANSWERS `Ok` and leaves the record standing, so
    /// `for_each_key` keeps yielding what the sweep just deleted. This is the fault
    /// the four applet wipes' delete budget exists for, and the one a REFUSED
    /// removal cannot produce: [`RemoveStuck`] errors, which stops a sweep at its
    /// `?` before the budget is ever consulted.
    ///
    /// The records really die once `ceiling` removals have been served, and that is
    /// what makes the budget's failure READABLE rather than a timeout: a sweep whose
    /// backstop has stopped guarding converges there and reports success over a
    /// range it never cleared, instead of spinning until the suite is killed.
    pub struct Undead {
        inner: RamStorage,
        served: Rc<Cell<u32>>,
        ceiling: u32,
    }

    /// The other end of an [`Undead`]: how much of its budget the sweep spent.
    pub struct UndeadCount {
        served: Rc<Cell<u32>>,
    }

    impl Undead {
        pub fn new(ceiling: u32) -> (Self, UndeadCount) {
            let served = Rc::new(Cell::new(0));
            (
                Self {
                    inner: RamStorage::new(),
                    served: served.clone(),
                    ceiling,
                },
                UndeadCount { served },
            )
        }
    }

    impl UndeadCount {
        /// Removals the medium was asked for.
        pub fn removals(&self) -> u32 {
            self.served.get()
        }
    }

    impl Storage for Undead {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            self.inner.read(fid, buf)
        }
        fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
            self.inner.write(fid, data)
        }
        fn remove(&mut self, fid: u16) -> Result<()> {
            self.served.set(self.served.get() + 1);
            if self.served.get() > self.ceiling {
                return self.inner.remove(fid);
            }
            Ok(())
        }
        fn size(&mut self, fid: u16) -> Option<usize> {
            self.inner.size(fid)
        }
        fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
            self.inner.for_each_key(f)
        }
    }
    /// A RAM medium whose `write` and `remove` REPORT `Ok` and apply nothing for
    /// one chosen fid, while every read and every other mutation still works — the
    /// backend that says it programmed (or tombstoned) the record and did not.
    ///
    /// [`Undead`] is the remove-only twin a wipe's delete budget is written
    /// against; this is the one a command that writes a record and then reads it
    /// back must catch. The two are different faults: a refusal ([`RemoveStuck`],
    /// a failed `write`) answers `Err` and the command's `?` stops, while this
    /// answers `Ok` — so only the command's own read-back can tell it apart from a
    /// write that landed.
    ///
    /// A delete is a mutation too (on a log-structured backend it appends a
    /// tombstone), so the drop covers `remove` as well: [`crate::request_rescrub`]
    /// re-reads the marker it removed, and a medium that swallows the tombstone
    /// leaves it live.
    pub struct Silent {
        inner: Rc<RefCell<RamStorage>>,
        dropped: Rc<Cell<Option<u16>>>,
        once: Rc<Cell<bool>>,
        attempts: Rc<Cell<u32>>,
        read_fault: Rc<Cell<Option<u16>>>,
        read_once: Rc<Cell<bool>>,
        read_faults: Rc<Cell<u32>>,
        read_err: Rc<Cell<bool>>,
    }

    /// The other end of a [`Silent`]: arms the drop, counts it, and reads the
    /// medium past [`crate::Fs`]'s present cache — which a `put` marks present
    /// whether or not the backend applied it, so a cache-level check would pass
    /// over a write that never landed (the fault [`RemoveMedium::live`] and
    /// [`Medium::live`] exist for on the remove side).
    pub struct SilentMedium {
        inner: Rc<RefCell<RamStorage>>,
        dropped: Rc<Cell<Option<u16>>>,
        once: Rc<Cell<bool>>,
        attempts: Rc<Cell<u32>>,
        read_fault: Rc<Cell<Option<u16>>>,
        read_once: Rc<Cell<bool>>,
        read_faults: Rc<Cell<u32>>,
    }

    impl Silent {
        pub fn new() -> (Self, SilentMedium) {
            let inner = Rc::new(RefCell::new(RamStorage::new()));
            let dropped = Rc::new(Cell::new(None));
            let once = Rc::new(Cell::new(false));
            let attempts = Rc::new(Cell::new(0));
            let read_fault = Rc::new(Cell::new(None));
            let read_once = Rc::new(Cell::new(false));
            let read_faults = Rc::new(Cell::new(0));
            let read_err = Rc::new(Cell::new(false));
            (
                Self {
                    inner: inner.clone(),
                    dropped: dropped.clone(),
                    once: once.clone(),
                    attempts: attempts.clone(),
                    read_fault: read_fault.clone(),
                    read_once: read_once.clone(),
                    read_faults: read_faults.clone(),
                    read_err,
                },
                SilentMedium {
                    inner,
                    dropped,
                    once,
                    attempts,
                    read_fault,
                    read_once,
                    read_faults,
                },
            )
        }

        /// Swallow this mutation iff the drop is armed for `fid`, spending a
        /// one-shot arming as it does.
        fn swallow(&self, fid: u16) -> bool {
            if self.dropped.get() != Some(fid) {
                return false;
            }
            if self.once.get() {
                self.dropped.set(None);
            }
            self.attempts.set(self.attempts.get() + 1);
            true
        }

        /// Refuse this read iff the read fault is armed for `fid`, spending a
        /// one-shot arming. The store must surface the failure through
        /// `last_error`: a `None` alone is "absent", which is the very collapse
        /// this correlated story exists to separate from a lost record.
        fn faulty_read(&self, fid: u16) -> bool {
            if self.read_fault.get() != Some(fid) {
                self.read_err.set(false);
                return false;
            }
            if self.read_once.get() {
                self.read_fault.set(None);
            }
            self.read_faults.set(self.read_faults.get() + 1);
            self.read_err.set(true);
            true
        }
    }

    impl SilentMedium {
        /// Silently lose every `write`/`remove` of `fid` (`None` clears the drop).
        pub fn arm(&self, fid: Option<u16>) {
            self.dropped.set(fid);
            self.once.set(false);
        }
        /// Silently lose the NEXT mutation of `fid`, then recover — the one-shot
        /// twin of [`RemoveMedium::refuse_once`]. A persistent drop is caught by
        /// whichever write the command makes first, so it cannot tell a retry
        /// further down the command from a command that never retried: both leave
        /// the record unwritten. The single-shot one can.
        pub fn arm_once(&self, fid: u16) {
            self.dropped.set(Some(fid));
            self.once.set(true);
        }
        /// Mutations the armed drop swallowed. The drop alone cannot tell a command
        /// that stopped on its read-back from one that never wrote at all: this
        /// COUNT says the medium was actually asked.
        pub fn attempts(&self) -> u32 {
            self.attempts.get()
        }
        /// Whether `fid` has a value ON THE MEDIUM.
        pub fn live(&self, fid: u16) -> bool {
            self.inner.borrow_mut().exists(fid)
        }
        /// The bytes stored for `fid` ON THE MEDIUM, drop or no drop.
        pub fn value(&self, fid: u16) -> Option<Vec<u8>> {
            let mut buf = [0u8; crate::MAX_VALUE_BYTES];
            let n = self.inner.borrow_mut().read(fid, &mut buf)?;
            Some(buf[..n.min(buf.len())].to_vec())
        }
        /// Fail every `read`/`size` of `fid` (`None` clears the fault). With the
        /// drop armed for the same fid this is the correlated story: the program
        /// lied and the read-back cannot answer either, so a test can prove both
        /// halves fired instead of one masking the other.
        pub fn fault_read(&self, fid: Option<u16>) {
            self.read_fault.set(fid);
            self.read_once.set(false);
        }
        /// Fail only the NEXT `read`/`size` of `fid`, then recover.
        pub fn fault_read_once(&self, fid: u16) {
            self.read_fault.set(Some(fid));
            self.read_once.set(true);
        }
        /// Reads the armed fault refused. A command that never reached its
        /// read-back leaves this at zero, which is how a test tells the
        /// combination from a fixture that only injected the write fault.
        pub fn read_faults(&self) -> u32 {
            self.read_faults.get()
        }
    }

    impl Storage for Silent {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            if self.faulty_read(fid) {
                return None;
            }
            self.inner.borrow_mut().read(fid, buf)
        }
        fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
            if self.swallow(fid) {
                return Ok(()); // reported applied, never applied
            }
            self.inner.borrow_mut().write(fid, data)
        }
        fn remove(&mut self, fid: u16) -> Result<()> {
            if self.swallow(fid) {
                return Ok(());
            }
            self.inner.borrow_mut().remove(fid)
        }
        fn size(&mut self, fid: u16) -> Option<usize> {
            if self.faulty_read(fid) {
                return None;
            }
            self.inner.borrow_mut().size(fid)
        }
        fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
            self.inner.borrow_mut().for_each_key(f)
        }
        /// The last `read`/`size` refused by the fault. Without this, `None`
        /// would be indistinguishable from absence and the command would treat a
        /// failure as an absent record — the collapse the read-back exists for.
        fn last_error(&self) -> bool {
            self.read_err.get()
        }
    }

    /// The bytes `inner` holds for `fid`, read straight through the backend so a
    /// caller sees the torn slot and not a cache the writes kept fresh.
    fn held(inner: &Rc<RefCell<RamStorage>>, fid: u16) -> Option<Vec<u8>> {
        let mut buf = [0u8; crate::MAX_VALUE_BYTES];
        let n = inner.borrow_mut().read(fid, &mut buf)?;
        Some(buf[..n.min(buf.len())].to_vec())
    }

    /// A RAM medium whose `write` lands only a PREFIX of its bytes and reports
    /// `Ok`, so a read of that fid answers the TORN value: the new prefix over
    /// whatever the slot held (`new[..k] ++ old[k..]`), or a plain prefix where it
    /// held nothing. An interrupted slot program is ONE physical event, so the
    /// write that lies and the read that exposes it are correlated rather than a
    /// drop glued to a separate read fault. The torn value is a THIRD one — neither
    /// the record the write replaced nor the one it claimed to store, and where the
    /// slot was empty its LENGTH lies too; [`Silent`]'s dropped write answers the
    /// OLD value, which is a state the caller already knew.
    pub struct Torn {
        inner: Rc<RefCell<RamStorage>>,
        armed: Rc<Cell<Option<(u16, usize)>>>,
        once: Rc<Cell<bool>>,
        attempts: Rc<Cell<u32>>,
    }

    /// The other end of a [`Torn`]: arms the tear at a byte offset, counts the
    /// writes it reached, and reads the medium past [`crate::Fs`]'s present cache —
    /// a `put` marks the fid present whether or not the program committed, so a
    /// cache-level check passes over a torn slot and only the medium shows it.
    pub struct TornMedium {
        inner: Rc<RefCell<RamStorage>>,
        armed: Rc<Cell<Option<(u16, usize)>>>,
        once: Rc<Cell<bool>>,
        attempts: Rc<Cell<u32>>,
    }

    impl Torn {
        pub fn new() -> (Self, TornMedium) {
            let inner = Rc::new(RefCell::new(RamStorage::new()));
            let armed = Rc::new(Cell::new(None));
            let once = Rc::new(Cell::new(false));
            let attempts = Rc::new(Cell::new(0));
            (
                Self {
                    inner: inner.clone(),
                    armed: armed.clone(),
                    once: once.clone(),
                    attempts: attempts.clone(),
                },
                TornMedium {
                    inner,
                    armed,
                    once,
                    attempts,
                },
            )
        }

        /// The prefix length this write tears at, spending a one-shot arming, or
        /// `None` for a write the tear does not reach.
        fn tear_at(&self, fid: u16) -> Option<usize> {
            let (armed, prefix) = self.armed.get()?;
            if armed != fid {
                return None;
            }
            if self.once.get() {
                self.armed.set(None);
            }
            self.attempts.set(self.attempts.get() + 1);
            Some(prefix)
        }

        /// Program a prefix of `data` over the slot and leave the rest of the old
        /// value standing, as a part-way slot program does.
        fn tear(&self, fid: u16, data: &[u8], prefix: usize) {
            let prefix = prefix.min(data.len());
            let mut torn = data[..prefix].to_vec();
            if let Some(old) = held(&self.inner, fid)
                && old.len() > prefix
            {
                torn.extend_from_slice(&old[prefix..]);
            }
            let _ = self.inner.borrow_mut().write(fid, &torn);
        }
    }

    impl TornMedium {
        /// Tear every `write` of `fid` after `prefix` bytes, leaving the rest of
        /// the slot. A `remove` has no payload to tear and forwards unchanged.
        pub fn arm(&self, fid: u16, prefix: usize) {
            self.armed.set(Some((fid, prefix)));
            self.once.set(false);
        }
        /// Tear the NEXT `write` of `fid`, then recover — the one-shot twin of
        /// [`RemoveMedium::refuse_once`]. A persistent tear is caught only by
        /// whichever write the command makes first, so it cannot tell a command
        /// that retried its write from one that stopped at the torn read-back.
        pub fn arm_once(&self, fid: u16, prefix: usize) {
            self.armed.set(Some((fid, prefix)));
            self.once.set(true);
        }
        /// Restore a healthy medium.
        pub fn disarm(&self) {
            self.armed.set(None);
            self.once.set(false);
        }
        /// Writes the armed tear reached. The torn VALUE alone cannot tell a
        /// command that re-read the medium from one that never wrote at all: this
        /// COUNT says the medium was actually asked.
        pub fn attempts(&self) -> u32 {
            self.attempts.get()
        }
        /// Whether `fid` has a value ON THE MEDIUM, torn or not.
        pub fn live(&self, fid: u16) -> bool {
            self.inner.borrow_mut().exists(fid)
        }
        /// The bytes stored for `fid` ON THE MEDIUM, torn or not.
        pub fn value(&self, fid: u16) -> Option<Vec<u8>> {
            held(&self.inner, fid)
        }
    }

    impl Storage for Torn {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            self.inner.borrow_mut().read(fid, buf)
        }
        fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
            if let Some(prefix) = self.tear_at(fid) {
                self.tear(fid, data, prefix);
                return Ok(()); // reported committed, half-programmed
            }
            self.inner.borrow_mut().write(fid, data)
        }
        fn remove(&mut self, fid: u16) -> Result<()> {
            self.inner.borrow_mut().remove(fid)
        }
        fn size(&mut self, fid: u16) -> Option<usize> {
            self.inner.borrow_mut().size(fid)
        }
        fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
            self.inner.borrow_mut().for_each_key(f)
        }
    }

    /// One mutation a [`Cut`] medium served, in the order it served it.
    #[derive(Clone, PartialEq, Eq)]
    pub enum Op {
        Write(u16, Vec<u8>),
        Remove(u16),
    }

    impl core::fmt::Debug for Op {
        // Values run to hundreds of bytes; a failing order is read off the fids.
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Op::Write(fid, v) => write!(f, "Write({fid:#06x}, {}B)", v.len()),
                Op::Remove(fid) => write!(f, "Remove({fid:#06x})"),
            }
        }
    }

    /// A RAM medium that serves a budget of mutations and then refuses every one
    /// after it, keeping the ordered log of those that landed.
    ///
    /// This is the shape of a reset landing between two flash appends: the first
    /// lands, nothing after it ever does. It is the only fault here that can tell
    /// the two orderings of a lazy re-key and its `crate::request_rescrub` apart —
    /// a backend that refuses one chosen fid refuses it under either order, so the
    /// end state it produces is the same one twice.
    pub struct Cut {
        inner: Rc<RefCell<RamStorage>>,
        budget: Rc<Cell<u32>>,
        log: Rc<RefCell<Vec<Op>>>,
        refused: Rc<Cell<bool>>,
    }

    /// The other end of a [`Cut`]: arms the cut, and reads the log and the medium
    /// past `crate::Fs`'s present cache — the only place a write that really landed
    /// can be told from one the cache merely reports.
    pub struct CutMedium {
        inner: Rc<RefCell<RamStorage>>,
        budget: Rc<Cell<u32>>,
        log: Rc<RefCell<Vec<Op>>>,
        refused: Rc<Cell<bool>>,
    }

    impl Cut {
        /// A healthy medium: unlimited budget, empty log. [`CutMedium::arm`] cuts it.
        pub fn new() -> (Self, CutMedium) {
            let inner = Rc::new(RefCell::new(RamStorage::new()));
            let budget = Rc::new(Cell::new(u32::MAX));
            let log = Rc::new(RefCell::new(Vec::new()));
            let refused = Rc::new(Cell::new(false));
            (
                Self {
                    inner: inner.clone(),
                    budget: budget.clone(),
                    log: log.clone(),
                    refused: refused.clone(),
                },
                CutMedium {
                    inner,
                    budget,
                    log,
                    refused,
                },
            )
        }

        /// Spend a mutation from the budget; `false` once the reset has landed.
        fn serve(&self) -> bool {
            let left = self.budget.get();
            if left == 0 {
                self.refused.set(true);
                return false;
            }
            self.budget.set(left - 1);
            true
        }
    }

    impl CutMedium {
        /// Serve `budget` more mutations and refuse every one after — the reset.
        /// `u32::MAX` restores a healthy medium.
        pub fn arm(&self, budget: u32) {
            self.budget.set(budget);
            self.refused.set(false);
        }
        /// Whether a mutation actually reached the armed cut.
        pub fn was_cut(&self) -> bool {
            self.refused.get()
        }
        /// Independent media over the same durable records, without shared caches.
        pub fn fork(&self) -> (Cut, Self) {
            let (storage, medium) = Cut::new();
            *storage.inner.borrow_mut() = self.inner.borrow().clone();
            *medium.log.borrow_mut() = self.log.borrow().clone();
            (storage, medium)
        }
        /// The mutations that LANDED, in order.
        pub fn ops(&self) -> Vec<Op> {
            self.log.borrow().clone()
        }
        /// Drop the log, so a fixture's own writes do not sit in front of the ones
        /// the command under test makes.
        pub fn clear_ops(&self) {
            self.log.borrow_mut().clear();
        }
        /// The bytes stored for `fid` ON THE MEDIUM, cut or no cut.
        pub fn value(&self, fid: u16) -> Option<Vec<u8>> {
            let mut buf = [0u8; crate::MAX_VALUE_BYTES];
            let n = self.inner.borrow_mut().read(fid, &mut buf)?;
            Some(buf[..n.min(buf.len())].to_vec())
        }
        /// The whole of a lazy re-key's ordering, read off the log: the
        /// `crate::request_rescrub` reached the medium BEFORE the append that
        /// superseded `fid`. A reset in that window can then only take the write —
        /// an idempotent lap over a record still in force — and never leave
        /// [`crate::EF_HARDENED`] standing over the copy the write displaced.
        ///
        /// `still_weak` names the writes of `fid` that are NOT that supersession: a
        /// verify spends its retry counter by rewriting the record, and that append
        /// re-keys nothing. Pass `|_| false` where the window writes `fid` once.
        ///
        /// Both halves must be in the log. An order nothing performed is held
        /// vacuously, and an absent marker is this store's DEFAULT state, so the two
        /// panics are the assertion and not decoration. Call
        /// [`clear_ops`](Self::clear_ops) first when an earlier command in the same
        /// fixture already re-armed.
        #[track_caller]
        pub fn assert_re_armed_before(
            &self,
            fid: u16,
            still_weak: impl Fn(&[u8]) -> bool,
            what: &str,
        ) {
            let ops = self.ops();
            let rekey = ops
                .iter()
                .position(|op| match op {
                    Op::Write(f, v) => *f == fid && !still_weak(v),
                    // A tombstone appends like a re-seal, so a delete supersedes too.
                    Op::Remove(f) => *f == fid,
                })
                .unwrap_or_else(|| {
                    panic!(
                        "{what}: nothing superseded {fid:#06x}, so the order is unobserved rather than held — {ops:?}"
                    )
                });
            let rearm = ops
                .iter()
                .position(|op| matches!(op, Op::Remove(f) if *f == crate::EF_HARDENED))
                .unwrap_or_else(|| {
                    panic!("{what}: nothing re-armed the at-rest lap at all — {ops:?}")
                });
            assert!(
                rearm < rekey,
                "{what}: {fid:#06x} was superseded BEFORE the lap was re-armed, so a reset between the two appends leaves the marker standing over the copy it superseded and no later boot ever scrubs it — {ops:?}"
            );
        }
    }

    impl Storage for Cut {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            self.inner.borrow_mut().read(fid, buf)
        }
        fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
            if !self.serve() {
                return Err(Error::MemoryFatal);
            }
            self.log.borrow_mut().push(Op::Write(fid, data.to_vec()));
            self.inner.borrow_mut().write(fid, data)
        }
        fn remove(&mut self, fid: u16) -> Result<()> {
            if !self.serve() {
                return Err(Error::MemoryFatal);
            }
            self.log.borrow_mut().push(Op::Remove(fid));
            self.inner.borrow_mut().remove(fid)
        }
        fn size(&mut self, fid: u16) -> Option<usize> {
            self.inner.borrow_mut().size(fid)
        }
        fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
            self.inner.borrow_mut().for_each_key(f)
        }
    }
}
