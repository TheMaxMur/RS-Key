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

    /// `Put`'s cache clause (`fs.rs:391-411` → `mark_present`).
    pub fn step_put(&mut self, fid: u16) {
        self.mark_present(fid);
    }

    /// `Delete`'s cache clause (`fs.rs:451-460` → `mark_absent`).
    pub fn step_delete(&mut self, fid: u16) {
        self.mark_absent(fid);
    }

    /// `Confirm(f)`'s cache clause: the backend answered, so cache what it said —
    /// unless it faulted, in which case nothing is cached at all.
    pub fn step_confirm(&mut self, fid: u16, live: bool) {
        self.record_unless_faulted(fid, live);
    }

    /// The reader `NoFalseAbsent` is stated over (`fs.rs:128-130`).
    pub fn reads_absent(&self, fid: u16) -> bool {
        self.known_absent(fid)
    }
}

// ---------------------------------------------------------------------------
// The persistent half: `val`, `meta` and the blob's own `metaAbsent`.
// ---------------------------------------------------------------------------

/// The FIDs the persistent projection carries, and there are THREE on purpose.
/// `NoRecordLostToMetaWrite` is about the records a rewrite DROPS rather than the
/// one it writes, so a subject plus one neighbour cannot state it: with two, the
/// neighbour is the only thing that can be lost, and "the write kept everything
/// else" is indistinguishable from "the write kept the one file we looked at".
pub const VIEW_FIDS: [u16; 3] = [0x0301, 0x0302, 0x0455];

/// The VALUES are not load-bearing — measured, seven different triples (adjacent,
/// one map byte, far apart, around EF_META) give an identical verdict on the
/// shipped tree and on every mutant. The one thing that is: none may BE a record
/// the store keeps for itself, or a `Put` would be writing the metadata blob and
/// no recorder would notice.
const _: () = assert!(
    VIEW_FIDS[0] != crate::EF_META
        && VIEW_FIDS[1] != crate::EF_META
        && VIEW_FIDS[2] != crate::EF_META
        && VIEW_FIDS[0] != crate::EF_SCRUB_FILLER
        && VIEW_FIDS[1] != crate::EF_SCRUB_FILLER
        && VIEW_FIDS[2] != crate::EF_SCRUB_FILLER
);

/// `RSKeyStore`'s PERSISTENT half over the whole projected population at once,
/// read through the primitives a reader uses: `meta_find` for `meta[f]`,
/// `has_data` for `val[f] # NoVal`, and EF_META's own present cache for
/// `metaAbsent`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreView {
    /// Whether EF_META holds a record for each of [`VIEW_FIDS`].
    pub meta: [bool; VIEW_FIDS.len()],
    /// Whether each of [`VIEW_FIDS`] has a value. `has_data`, so a zero-length
    /// value reads FALSE here while `present_bit` calls it present — the model's
    /// `val[f] # NoVal` is the latter. The alphabet writes one non-empty value,
    /// which is the only thing keeping the two spellings from diverging.
    pub val: [bool; VIEW_FIDS.len()],
    /// The model's `metaAbsent`: EF_META reads confirmed-absent.
    pub meta_absent: bool,
}

impl<S: Storage> Fs<S> {
    /// [`StoreView`] for this store: `meta` and `val` from the MEDIUM,
    /// `metaAbsent` from the CACHE — which is the model's own split, and the
    /// only split under which `NoFalseMetaAbsent` can be stated at all.
    ///
    /// `meta_find` short-circuits on `known_absent(EF_META)`, so a projection
    /// read straight through this store cannot see the record a false-absent
    /// cache is hiding — the violation would erase its own evidence. Clearing the
    /// two bitmaps for the read and putting them back is what makes the
    /// observation honest; re-parsing the blob here instead would be a second
    /// copy of the rules, which is how the first attempt at this bridge came to
    /// be a copy compared to itself.
    ///
    /// Named `read`, not `view`: over a medium that is FAULTING, the observation
    /// is the thing that fails, and `meta_find` then answers `None` for a record
    /// that is still there. Measured — the first version of the faulting sweep
    /// reported `NoRecordLostToMetaWrite` on the shipped tree for exactly that.
    /// A caller that arms a fault must disarm it before reading.
    ///
    /// What it does NOT restore is the backend's error latch: the reads it makes
    /// leave `Storage::last_error()` reporting on THEM. Harmless only because
    /// every consumer in `Fs` reads the latch immediately after its own call —
    /// an invariant nothing states, so it is stated here.
    pub fn read_store_view(&mut self) -> StoreView {
        let cached = (self.present, self.decided);
        let absent = self.known_absent(crate::EF_META);
        self.present.fill(0);
        self.decided.fill(0);
        let mut view = StoreView {
            meta: [false; VIEW_FIDS.len()],
            val: [false; VIEW_FIDS.len()],
            meta_absent: absent,
        };
        for (i, &fid) in VIEW_FIDS.iter().enumerate() {
            view.meta[i] = self.meta_find(fid, &mut [0u8; 8]).is_some();
            view.val[i] = self.has_data(fid);
        }
        (self.present, self.decided) = cached;
        view
    }
}

// THE THREE STEP RECORDERS, and why they have to be steps.
//
// `store_refinement_kani.rs`'s cache clauses are STATE predicates: the model says
// `present' = [present EXCEPT ![f] = TRUE]` and the projection reads the bit
// back. None of the three below can be written that way, which is why the first
// attempt at this bridge was refuted — each came out as the same boolean function
// as its `powercut.rs` twin, a copy compared to itself.
//
// Each takes the pair the model's `viol'` is written over and answers whether the
// step VIOLATED it, so the name reads the way a counterexample does.
//
// A FOURTH step clause has no projection here, deliberately. `NoSilentOrphan` —
// SEC-STORE-006 — forbids not a state but an ANSWER: the record may stand over a
// value a faulted delete removed, provided the caller was told. So the sweep
// pairs `delete_orphaned_metadata` below with what `Fs::delete` returned, and a
// projection over `StoreView` alone could not see the half that decides it.

/// `RSKeyStore!NoOrphanedMetadata` at a `Delete(f)` step — SEC-STORE-001.
///
/// A STATE predicate cannot say this: a meta-only file legally has a record and
/// no value, so the same state is a violation after a delete and the ordinary
/// shape of a `MetaAdd`. The action it is read at is half the claim.
pub fn delete_orphaned_metadata(after: &StoreView, subject: usize) -> bool {
    after.meta[subject] && !after.val[subject]
}

/// `RSKeyStore!NoRecordLostToMetaWrite` at a `MetaAdd(f)` step — SEC-STORE-003.
///
/// Cross-FID: the subject's own record is what the write adds, so only a
/// bystander's can be lost. Treating a faulted EF_META read as an empty blob is
/// how one write drops every other record.
pub fn meta_add_lost_a_record(before: &StoreView, after: &StoreView, subject: usize) -> bool {
    (0..VIEW_FIDS.len()).any(|i| i != subject && before.meta[i] && !after.meta[i])
}

/// `RSKeyStore!NoFalseMetaAbsent` at a `MetaDelete(f)` step — SEC-STORE-004.
///
/// The blob may read absent only once the last record has gone. Caching a FAILED
/// read as absence loses nothing here and everything on the NEXT write.
pub fn meta_delete_false_absent(after: &StoreView) -> bool {
    after.meta_absent && after.meta.iter().any(|&held| held)
}
