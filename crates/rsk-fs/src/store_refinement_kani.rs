// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `RSKeyStore`'s cache clauses, checked against the primitives `Fs` calls.
//!
//! Every harness carries a *second* symbolic FID, because the model's clauses are
//! `[present EXCEPT ![f] = …]` — one element moves, every other stands — and the
//! code reaches its bit through `fid >> 3` and `1 << (fid & 7)`. A shift that
//! disagreed would alias two files onto one bit, and a `mark_absent` on one would
//! read as a decided absence for the other: `NoFalseAbsent`'s disaster reached
//! through arithmetic instead of through a fault.

use super::store_assurance::{CacheView, FID_LIMIT, fresh};

/// Two distinct FIDs, which is what `EXCEPT ![f]` quantifies over.
fn two_fids() -> (u16, u16) {
    let f: u16 = kani::any();
    let g: u16 = kani::any();
    kani::assume(f != g);
    kani::assume(f < FID_LIMIT && g < FID_LIMIT);
    (f, g)
}

/// `Put`: the written FID is decided live, and no other FID moves.
#[kani::proof]
fn put_decides_its_own_fid_and_moves_no_other() {
    let (f, g) = two_fids();
    let mut fs = fresh(false);
    fs.step_put(g);
    fs.step_put(f);
    assert!(fs.cache_view(f) == CacheView::LIVE);
    assert!(
        fs.cache_view(g) == CacheView::LIVE,
        "a put aliased another FID"
    );
    kani::cover!(f < g, "both orderings of the pair are reachable");
}

/// `Delete`: the removed FID is decided absent, and a neighbour that was live
/// stays live — the aliasing direction that matters, since the survivor is the
/// one a false absence would hide.
#[kani::proof]
fn no_false_absent_from_a_neighbours_delete() {
    let (f, g) = two_fids();
    let mut fs = fresh(false);
    fs.step_put(g);
    fs.step_delete(f);
    assert!(fs.cache_view(f) == CacheView::ABSENT);
    assert!(fs.reads_absent(f));
    assert!(
        fs.cache_view(g) == CacheView::LIVE,
        "a delete aliased another FID"
    );
    assert!(
        !fs.reads_absent(g),
        "a live neighbour read as a decided absence"
    );
}

/// `Confirm(f)` with `fault = FALSE`: the backend's answer is cached as decided.
#[kani::proof]
fn a_clean_confirm_caches_what_the_backend_said() {
    let (f, g) = two_fids();
    let live: bool = kani::any();
    let mut fs = fresh(false);
    fs.step_confirm(f, live);
    let want = if live {
        CacheView::LIVE
    } else {
        CacheView::ABSENT
    };
    assert!(fs.cache_view(f) == want);
    assert!(
        fs.cache_view(g) == CacheView::CLEAR,
        "a confirm aliased another FID"
    );
    kani::cover!(live, "the present answer is reachable");
    kani::cover!(!live, "the absent answer is reachable");
}

/// `Confirm(f)` with `fault = TRUE`: `record_unless_faulted` caches NOTHING, so
/// the pair is untouched. Caching it would set the decided bit over a live file,
/// which is audit run-36 — one transient error made permanent for the boot.
#[kani::proof]
fn no_false_absent_survives_a_faulted_confirm() {
    let (f, g) = two_fids();
    let live: bool = kani::any();
    let mut fs = fresh(true);
    fs.step_put(g);
    fs.step_confirm(f, live);
    assert!(
        fs.cache_view(f) == CacheView::CLEAR,
        "a fault was cached as a decision"
    );
    assert!(!fs.reads_absent(f));
    assert!(fs.cache_view(g) == CacheView::LIVE);
}

/// `Init` / `Reboot`: nothing is cached and nothing is decided, so every read
/// falls through to the backend rather than trusting a carried-over absence.
#[kani::proof]
fn a_fresh_store_decides_nothing() {
    let f: u16 = kani::any();
    kani::assume(f < FID_LIMIT);
    let fs = fresh(false);
    assert!(fs.cache_view(f) == CacheView::CLEAR);
    assert!(
        !fs.reads_absent(f),
        "an unprobed FID read as a decided absence"
    );
}

/// The reader `NoFalseAbsent` is stated over: a clear present bit is trusted only
/// once the authority bit confirms it.
#[kani::proof]
fn no_false_absent_reader_trusts_only_a_decided_bit() {
    let f: u16 = kani::any();
    kani::assume(f < FID_LIMIT);
    let put: bool = kani::any();
    let del: bool = kani::any();
    let mut fs = fresh(false);
    if put {
        fs.step_put(f);
    }
    if del {
        fs.step_delete(f);
    }
    let v = fs.cache_view(f);
    assert!(fs.reads_absent(f) == (v.decided && !v.present));
    kani::cover!(fs.reads_absent(f), "the decided-absent state is reachable");
    kani::cover!(v == CacheView::CLEAR, "the undecided state is reachable");
}
