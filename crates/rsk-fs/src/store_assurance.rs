// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Verification-only projection of `RSKeyStore`'s cache variables onto the real
//! `Fs`, excluded from production builds.
//!
//! The model has seven variables. Four are persistent — `val`, `meta`, `dead`
//! and the blob's own `metaAbsent` — and the power-cut oracle already decides
//! those: `powercut.rs`'s four `*_landed` predicates are what the module was
//! lifted from, and `powercut_kani.rs` and the `power_cut` fuzz target exercise
//! them over a real medium. The remaining pair, `present` and `decided`, had no
//! link to the code at all. This is that half: the model's per-action cache
//! clauses, checked against the primitives `Fs` actually calls, over a symbolic
//! FID and a symbolic *other* FID.
//!
//! The second FID is the content. `[present EXCEPT ![f] = TRUE]` says one
//! element moves and every other stands; the code says
//! `present[fid >> 3] |= 1 << (fid & 7)`, and a mismatched shift aliases two
//! FIDs onto one bit — a `mark_absent` on one file then reading as a decided
//! absence for another, which is `NoFalseAbsent`'s disaster reached through
//! arithmetic rather than through a fault.

use super::Fs;
use crate::storage::Storage;
use rsk_sdk::error::Result;

/// The model's `present`/`decided` pair for one FID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheView {
    pub present: bool,
    pub decided: bool,
}

impl CacheView {
    /// `RSKeyStore!Init` and `Reboot`: nothing cached, nothing decided.
    pub const CLEAR: Self = Self {
        present: false,
        decided: false,
    };
    /// The pair `Put` leaves behind (`mark_present`).
    pub const LIVE: Self = Self {
        present: true,
        decided: true,
    };
    /// The pair a confirmed absence leaves behind (`mark_absent`).
    pub const ABSENT: Self = Self {
        present: false,
        decided: true,
    };
}

/// A backend that stores nothing and can be told to have failed. `Fs` reaches the
/// cache through `Storage::last_error()` alone on the paths this projection
/// observes, so a medium would only add state for CBMC to unwind.
pub struct FaultBackend {
    pub faulted: bool,
}

impl Storage for FaultBackend {
    fn read(&mut self, _fid: u16, _buf: &mut [u8]) -> Option<usize> {
        None
    }
    fn write(&mut self, _fid: u16, _data: &[u8]) -> Result<()> {
        Ok(())
    }
    fn remove(&mut self, _fid: u16) -> Result<()> {
        Ok(())
    }
    fn size(&mut self, _fid: u16) -> Option<usize> {
        None
    }
    fn last_error(&self) -> bool {
        self.faulted
    }
    fn for_each_key(&mut self, _f: &mut dyn FnMut(u16)) -> bool {
        true
    }
}

/// FIDs the shrunk `cfg(kani)` map addresses. Derived, so the harnesses' domain
/// follows the shrink instead of restating it.
#[cfg(kani)]
pub const FID_LIMIT: u16 = (super::FID_PRESENT_BYTES * 8) as u16;

/// A store whose caches are clear, i.e. `RSKeyStore!Init` after `Fs::new`.
pub fn fresh(faulted: bool) -> Fs<FaultBackend> {
    Fs::new(FaultBackend { faulted })
}

impl<S: Storage> Fs<S> {
    /// The model's cache pair for `fid`, read from the real bitmaps.
    pub fn cache_view(&self, fid: u16) -> CacheView {
        CacheView {
            present: self.present_bit(fid),
            decided: self.decided_bit(fid),
        }
    }

    /// `Put`'s cache clause (`fs.rs:376-396` → `mark_present`).
    pub fn step_put(&mut self, fid: u16) {
        self.mark_present(fid);
    }

    /// `Delete`'s cache clause (`fs.rs:426-433` → `mark_absent`).
    pub fn step_delete(&mut self, fid: u16) {
        self.mark_absent(fid);
    }

    /// `Confirm(f)`'s cache clause: the backend answered, so cache what it said —
    /// unless it faulted, in which case nothing is cached at all.
    pub fn step_confirm(&mut self, fid: u16, live: bool) {
        self.record_unless_faulted(fid, live);
    }

    /// The reader `NoFalseAbsent` is stated over (`fs.rs:113-115`).
    pub fn reads_absent(&self, fid: u16) -> bool {
        self.known_absent(fid)
    }
}
