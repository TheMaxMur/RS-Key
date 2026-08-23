// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `RSKeyStore`'s PERSISTENT clauses, driven over a real medium.
//!
//! The cache half is `store_refinement_kani.rs`: six one-step obligations at a
//! symbolic FID, over a backend that stores nothing. The persistent half cannot
//! be written that way, for two measured reasons.
//!
//! **It cannot be a per-FID state projection.** That was tried and refuted:
//! spelling the model's persistent clauses as Rust predicates and holding them
//! against `powercut.rs` gives 0 disagreements over the whole domain, because
//! each comes out as the same boolean function as its `*_landed` twin — a copy
//! compared to itself. Two of the three are STEP recorders and the third is
//! CROSS-FID; neither shape has a per-FID face.
//!
//! **And it cannot be a Kani harness in this build.** Every metadata path opens
//! with `known_absent(EF_META)`, `EF_META` is `0xE010`, and the `cfg(kani)`
//! present map is three bytes (`fs.rs:29`) — so the index is 7170 of 3. Measured
//! on a harness that does nothing but `meta_add`: `1 of 164 failed … index out
//! of bounds … fs.rs:118, decided_bit`, in 0.11 s. The shrink that made the
//! cache half provable is what puts this half out of CBMC's reach here.
//!
//! So: exhaustive enumeration on the host, over the REAL `Fs`, a REAL medium and
//! three FIDs, with the recorders read after every step. Bounded in the same
//! sense a Kani harness is — a length, not a corpus — and the registry keeps
//! these three `MODELLED-ONLY`, because `assurance_gate` reads `BOUNDED` off a
//! Kani harness name and there cannot be one.

use super::store_assurance::{
    StoreView, VIEW_FIDS, delete_orphaned_metadata, meta_add_lost_a_record,
    meta_delete_false_absent,
};
use super::{Fs, Storage};
use crate::storage::ram::RamStorage;
use rsk_sdk::error::Result;

/// One persistent step, named after the model action it drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Put(usize),
    Delete(usize),
    MetaAdd(usize),
    MetaDelete(usize),
    /// Not in [`ALPHABET`] — a marker in a printed trail, so a counterexample
    /// from the reboot sweep names the sequence that actually ran.
    Reboot,
}

const ALPHABET: [Step; 12] = [
    Step::Put(0),
    Step::Put(1),
    Step::Put(2),
    Step::Delete(0),
    Step::Delete(1),
    Step::Delete(2),
    Step::MetaAdd(0),
    Step::MetaAdd(1),
    Step::MetaAdd(2),
    Step::MetaDelete(0),
    Step::MetaDelete(1),
    Step::MetaDelete(2),
];

/// Drive one step and read the recorder the model records at THAT action.
///
/// `arm` turns the medium's fault budget on for the STEP and off for the two
/// observations. Reading a view through a dead medium answers `None` for a record
/// that is still on it, and every refused write then looks like a lost record —
/// measured, and it is the reason this parameter exists rather than a comment.
fn drive<S: Storage>(
    fs: &mut Fs<S>,
    step: Step,
    trail: &[Step],
    arm: &mut dyn FnMut(bool),
    live: &mut [usize; 4],
) {
    arm(false);
    let before: StoreView = fs.read_store_view();
    // A fault is armed only for the two actions the model gives one. `MetaAdd`
    // and `MetaDelete` each carry a faulted disjunct (their `*DropsOnFault`
    // mutants are its bug arm); `Delete` carries none — `dead` there is a power
    // CUT, not a medium error — so a faulted delete is a transition the model
    // does not have, and reading `NoOrphanedMetadata` at one would be judging a
    // step nothing states. That gap is now the model's alone: `Fs::delete`
    // (`fs.rs:451`) reports the failed drop instead of swallowing it, so the
    // state a faulted delete leaves — value gone, record standing — is one the
    // caller is told about. Giving `Delete` that disjunct, and arming it here,
    // is the open half recorded in docs/store-refinement.md.
    arm(matches!(step, Step::MetaAdd(_) | Step::MetaDelete(_)));
    match step {
        Step::Put(i) => {
            let _ = fs.put(VIEW_FIDS[i], b"v");
        }
        Step::Delete(i) => {
            let _ = fs.delete(VIEW_FIDS[i]);
            arm(false);
            let after = fs.read_store_view();
            live[0] += usize::from(before.meta[i]);
            // And a delete of a file that HAD a value, which is the only thing
            // `Step::Put` is in the alphabet for: without it `val` is constant
            // FALSE and the recorder's second conjunct is never exercised in the
            // direction that SUPPRESSES it. Measured — with `put` inert the three
            // clauses stayed green on every other counter.
            live[3] += usize::from(before.val[i]);
            assert!(
                !delete_orphaned_metadata(&after, i),
                "NoOrphanedMetadata: {trail:?} then {step:?} left a record over a gone value"
            );
        }
        Step::MetaAdd(i) => {
            let _ = fs.meta_add(VIEW_FIDS[i], b"m");
            arm(false);
            let after = fs.read_store_view();
            live[1] += usize::from((0..VIEW_FIDS.len()).any(|j| j != i && before.meta[j]));
            assert!(
                !meta_add_lost_a_record(&before, &after, i),
                "NoRecordLostToMetaWrite: {trail:?} then {step:?} dropped a bystander's record"
            );
        }
        Step::Reboot => unreachable!("a marker for a printed trail, never driven"),
        Step::MetaDelete(i) => {
            let _ = fs.meta_delete(VIEW_FIDS[i]);
            arm(false);
            let after = fs.read_store_view();
            live[2] += usize::from((0..VIEW_FIDS.len()).any(|j| j != i && before.meta[j]));
            assert!(
                !meta_delete_false_absent(&after),
                "NoFalseMetaAbsent: {trail:?} then {step:?} cached absence over a live record"
            );
        }
    }
}

/// Walk one sequence, reading the recorders after every step.
fn walk<S: Storage>(
    fs: &mut Fs<S>,
    code: u32,
    len: u32,
    arm: &mut dyn FnMut(bool),
    live: &mut [usize; 4],
) -> std::vec::Vec<Step> {
    let n = ALPHABET.len() as u32;
    let mut trail = std::vec::Vec::new();
    let mut rest = code;
    for _ in 0..len {
        let step = ALPHABET[(rest % n) as usize];
        rest /= n;
        drive(fs, step, &trail, arm, live);
        trail.push(step);
    }
    trail
}

const RECORDERS: [&str; 4] = [
    "NoOrphanedMetadata",
    "NoRecordLostToMetaWrite",
    "NoFalseMetaAbsent",
    "NoOrphanedMetadata over a file that had a value",
];

/// Every recorder must have been READ from a state it could have refused in.
///
/// Without this the sweeps pass while driving nothing: `drive` ignores every
/// `Result`, so making `put` and `meta_add` return `Err` left ~26 000 steps green
/// — a store that never changes never violates anything. This is `kani::cover!`
/// for a host sweep, and it is what would have caught the faulting medium
/// blinding `NoRecordLostToMetaWrite` without needing a mutant to say so.
#[track_caller]
fn assert_every_recorder_was_live(live: [usize; 4]) {
    for (count, name) in live.iter().zip(RECORDERS) {
        assert!(
            *count > 0,
            "{name} was never read from a state it could refuse"
        );
    }
}

/// The RAM sweeps' `arm`: nothing to turn on or off.
fn never(_: bool) {}

/// Every sequence of three steps over the twelve, against a fresh store.
///
/// Exhaustive rather than sampled: 12³ = 1728 orderings, 5184 steps, and a
/// recorder is read after each of the 3888 that have one. TWO is the length at
/// which each recorder's precondition first becomes reachable — measured, every
/// mutant that this sweep kills is already RED at LEN = 2, with
/// `[MetaAdd(0)] then Delete(0)` and `[MetaAdd(1)] then MetaAdd(0)`. Three is
/// chosen so one sequence can reach a precondition, exercise it and close over
/// it; it costs 12× the orderings and buys no new witness.
#[test]
fn every_three_step_sequence_keeps_the_persistent_clauses() {
    const LEN: u32 = 3;
    let mut live = [0usize; 4];
    for code in 0..(ALPHABET.len() as u32).pow(LEN) {
        let mut fs = Fs::new(RamStorage::new());
        walk(&mut fs, code, LEN, &mut never, &mut live);
    }
    assert_every_recorder_was_live(live);
}

/// The same walk over a store the caller never scanned, which is the state a
/// reboot leaves: EF_META is UNKNOWN rather than confirmed, and `meta_add`'s
/// `known_absent` short-circuit does not fire. That is the door the 0x077C
/// databug came through, and a fresh `Fs::new` per sequence would never open it.
#[test]
fn every_three_step_sequence_survives_an_unscanned_reboot_between_them() {
    const LEN: u32 = 3;
    let mut live = [0usize; 4];
    for code in 0..(ALPHABET.len() as u32).pow(LEN) {
        let mut fs = Fs::new(RamStorage::new());
        let mut trail = walk(&mut fs, code, LEN, &mut never, &mut live);
        // Same medium, caches gone — `Fs::new` without `scan`.
        let mut rebooted = Fs::new(fs.into_storage());
        trail.push(Step::Reboot);
        for step in ALPHABET {
            // The trail GROWS. It used to be the PRE-reboot prefix handed to all
            // twelve, so a counterexample named a sequence that never ran and
            // could not be replayed from its own message.
            drive(&mut rebooted, step, &trail, &mut never, &mut live);
            trail.push(step);
        }
    }
    assert_every_recorder_was_live(live);
}

/// A medium whose reads fail while the budget is armed, so the walk meets
/// EF_META's FAULT path — the one `RamStorage` cannot produce and the one both
/// remaining recorders are about. A fault is not an absence, and the whole of
/// `NoFalseMetaAbsent` is that the cache must not confuse them.
///
/// The budget is shared with the driver rather than counted down blindly,
/// because the OBSERVATIONS must not be what fails: see `drive`.
struct FaultAfter {
    inner: RamStorage,
    armed: std::rc::Rc<std::cell::Cell<bool>>,
    err: bool,
}

impl FaultAfter {
    fn faulting(&mut self) -> bool {
        if self.armed.get() {
            self.err = true;
            return true;
        }
        self.err = false;
        false
    }
}

impl Storage for FaultAfter {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        if self.faulting() {
            return None;
        }
        self.inner.read(fid, buf)
    }
    // READS ONLY, which is what the docstring above always said. The first
    // version faulted the writes too and that made the whole of
    // `NoRecordLostToMetaWrite` unreachable: its loss needs the EF_META read to
    // fail AND the rewrite to LAND, so with the write failing as well
    // `meta_add_reserve`'s `?` propagated and the blob was never touched — the
    // sweep stayed GREEN under `BugMetaAddDropsOnFault`, its own co-mutant. A
    // read that fails while an append succeeds is also the realistic shape for a
    // log-structured backend: a CRC failure on one item, a fresh page for the next.
    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        self.err = false;
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> Result<()> {
        self.err = false;
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        if self.faulting() {
            return None;
        }
        self.inner.size(fid)
    }
    fn last_error(&self) -> bool {
        self.err
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
}

/// The same walk with the medium failing for the duration of every step, so both
/// remaining recorders meet the state they are about: a `meta_add` that cannot
/// read the blob it is rewriting, and a `meta_delete` that cannot read the blob
/// it is dropping from.
///
/// Two steps, not three: a bystander's record is planted before the walk starts,
/// so two is already the shape both clauses need — one operation over the fault
/// that must not lose it, and one more to try to lose it afterwards.
#[test]
fn every_two_step_sequence_over_a_failing_medium_keeps_them_too() {
    const LEN: u32 = 2;
    let mut live = [0usize; 4];
    let armed = std::rc::Rc::new(std::cell::Cell::new(false));
    for code in 0..(ALPHABET.len() as u32).pow(LEN) {
        let mut seed = Fs::new(RamStorage::new());
        // A record for a bystander, so there is something for a rewrite to lose.
        seed.meta_add(VIEW_FIDS[2], b"keep").unwrap();
        let medium = FaultAfter {
            inner: seed.into_storage(),
            armed: armed.clone(),
            err: false,
        };
        // No `scan`: EF_META is UNKNOWN, so the fault is met head-on.
        let mut fs = Fs::new(medium);
        let handle = armed.clone();
        walk(&mut fs, code, LEN, &mut move |on| handle.set(on), &mut live);
    }
    // The two the fault is armed for; `Delete` is never faulted here, so its
    // recorder is the RAM sweeps' to cover.
    assert!(live[1] > 0 && live[2] > 0, "{live:?}");
}

/// The recorders have to be able to FIRE, or the two sweeps above are a loop
/// over nothing. Each is driven from the state the model's `viol'` names,
/// assembled by hand rather than reached by the walk.
#[test]
fn each_recorder_answers_true_on_the_state_its_invariant_forbids() {
    let held = |meta: [bool; 3], val: [bool; 3], absent: bool| StoreView {
        meta,
        val,
        meta_absent: absent,
    };
    // A record over a gone value, at the delete of that file.
    assert!(delete_orphaned_metadata(
        &held([true, false, false], [false; 3], false),
        0
    ));
    assert!(!delete_orphaned_metadata(
        &held([true, false, false], [true, false, false], false),
        0
    ));
    // A bystander's record lost to someone else's write.
    let before = held([false, true, false], [false; 3], false);
    let after = held([true, false, false], [false; 3], false);
    assert!(meta_add_lost_a_record(&before, &after, 0));
    // ...and the subject's own record appearing is not a loss.
    assert!(!meta_add_lost_a_record(
        &before,
        &held([true, true, false], [false; 3], false),
        0
    ));
    // The blob read absent while a record stands.
    assert!(meta_delete_false_absent(&held(
        [false, true, false],
        [false; 3],
        true
    )));
    assert!(!meta_delete_false_absent(&held(
        [false; 3], [false; 3], true
    )));
}
