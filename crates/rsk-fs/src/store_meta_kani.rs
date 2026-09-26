// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `RSKeyStore`'s two EF_META **fault sites**, over the same `FaultBackend` the
//! cache clauses use.
//!
//! `meta_add` and `meta_delete` each read the one shared blob, and
//! `Storage::read` answers `None` for "absent" and for "the read failed" alike.
//! Each therefore consults the error latch, and each has an arm where it must
//! refuse: rebuilding from an empty scratch drops every other applet's record
//! (`RSKeyStore!NoRecordLostToMetaWrite`, SEC-STORE-003), and caching the same
//! `None` as absence stands a false `metaAbsent` over live records
//! (`RSKeyStore!NoFalseMetaAbsent`, SEC-STORE-004, and `CacheHonest`'s premise).
//! Both directions of each are asserted **as separate clauses**, because a
//! refusal alone is satisfied by a `meta_add` that refuses everything — and
//! because the line is what names the direction: Kani 0.67 reports every
//! `assert!` message in this crate as "a placeholder message", so a clause per
//! direction is the only thing that tells a kill from its inverse.
//!
//! **The domain is named here, not borrowed from the persistent projection.**
//! These paths address EF_META in the present map, so EF_META has to be
//! addressable: under `cfg(kani)` `FID_PRESENT_BYTES = 3` (`fs.rs`) makes the map
//! three bytes — 24 bits — and `EF_META` is redefined to `0x0017` (`lib.rs`), bit
//! 23 of 24, the last bit of the last byte. `store_assurance::VIEW_FIDS` is
//! ≥ `0x0301` and does not land in that map at all; it belongs to the host sweep
//! (`store_steps_tests.rs`), and nothing here reads it.
//!
//! Three things stop being proved, and none of them is the arithmetic:
//!
//! * that EF_META indexes **within** the shipped map. Shipped, `fid >> 3` puts
//!   `0xE010` at BYTE 7170 of 8192, and that is the compile-time `assert!` in
//!   `fs.rs` — about the shipped width, so it holds where these no longer look;
//! * that EF_META is **disjoint** from every FID an applet writes. At `0xE010` it
//!   is outside every applet range; at `0x0017` it is inside the file space, so
//!   [`two_file_fids`] has to assume the collision away. That direction is an
//!   over-approximation the shrink INVENTS rather than one it hides: a `meta_add`
//!   whose subject is EF_META itself is a state the shipped store cannot reach;
//! * that `scan` registers every file it is handed. `fs.rs:287` skips
//!   `fid == EF_META`, so under the alias it refuses FID 23 — a FID this file's
//!   own domain draws from. Inert today, because no harness in the tree reaches
//!   `scan`, and the first one written over this domain is where it would bite.
//!
//! And what neither harness reaches, shrink or no shrink: the records. A
//! `FaultBackend` holds nothing, so `meta[f]` is not represented, and these prove
//! the guard at the fault site rather than "no record was lost". That clause is
//! the host sweep's, bounded by sequence length — which is why SEC-STORE-003 and
//! SEC-STORE-004 stay `MODELLED-ONLY` (`docs/store-refinement.md`).

use super::store_assurance::{CacheView, FID_LIMIT, fresh};
use super::{EF_META, Error};

/// A subject FID and a bystander, both distinct from EF_META.
///
/// The bystander is the same content as in `store_refinement_kani.rs`: EF_META's
/// bit is reached through `fid >> 3` and `1 << (fid & 7)`, and a shift that
/// disagreed would move a file's bit when the blob's moved. It is worth more here
/// than there, because bit 23 shares its byte with `0x0010..=0x0016`.
fn two_file_fids() -> (u16, u16) {
    let f: u16 = kani::any();
    let g: u16 = kani::any();
    kani::assume(f < FID_LIMIT && g < FID_LIMIT);
    kani::assume(f != g);
    kani::assume(f != EF_META && g != EF_META);
    (f, g)
}

/// `MetaAdd(f)` at its faulted disjunct: an EF_META read that FAILED is refused,
/// never rebuilt from an empty blob — `meta_add_reserve`'s guard, `fs.rs:808-810`.
///
/// The clean direction is not decoration: over a backend that genuinely holds no
/// blob, rebuilding from empty is the *correct* move, so a guard keyed on
/// `r.is_none()` alone would refuse the store its first record. Nothing else may
/// move either — the subject's own present bit is a value's, not a record's, and
/// the bystander is the aliasing direction.
///
/// The two `kani::cover!` are the vacuity guard, and they are about the ASSUMES,
/// not the arms: `faulted` is an unconstrained input, so an arm the code stopped
/// entering fails a clause rather than passing it — but three `kani::assume`s that
/// became contradictory would leave every clause SUCCESSFUL over nothing, and
/// Kani exits 0 on that. Kills `BugMetaAddDropsOnFault`
/// (`formal/comutants.toml`) on the first clause.
#[kani::proof]
fn a_faulted_meta_read_is_refused_rather_than_rebuilt_from_empty() {
    let (f, g) = two_file_fids();
    let faulted: bool = kani::any();
    kani::cover!(faulted, "the assume set leaves a faulted store");
    kani::cover!(!faulted, "the assume set leaves a clean one");
    let mut fs = fresh(faulted);
    let answered = fs.meta_add(f, &[0xA5]);
    assert!(
        !faulted || answered == Err(Error::MemoryFatal),
        "a failed EF_META read was rebuilt from an empty blob"
    );
    assert!(
        faulted || answered == Ok(()),
        "an EF_META that is genuinely absent was refused its first record"
    );
    assert!(
        !faulted || fs.cache_view(EF_META) == CacheView::CLEAR,
        "a refused meta_add still moved EF_META's cache"
    );
    assert!(
        faulted || fs.cache_view(EF_META) == CacheView::LIVE,
        "a landed meta_add left EF_META undecided"
    );
    assert!(
        fs.cache_view(f) == CacheView::CLEAR,
        "a meta_add moved the subject's own value cache"
    );
    assert!(
        fs.cache_view(g) == CacheView::CLEAR,
        "a meta_add aliased another FID"
    );
}

/// `MetaDelete(f)` at its faulted disjunct: an EF_META read that FAILED never
/// becomes a decided absence — `meta_delete`'s guard, `fs.rs:840`, and the one thing
/// that keeps `metaAbsent` honest while records stand.
///
/// The clean direction caches the absence, and must: that is what lets the next
/// `meta_add` skip the read, and it is only sound because a definitive `None` is
/// the sole arm that reaches it. The faulted arm is read through `reads_absent`,
/// the production reader, because there the claim is the WEAK one — nothing may
/// read absent — while `CacheView::CLEAR` beside it is the strong one; the clean
/// arm needs only `ABSENT`, which implies `reads_absent` outright.
///
/// The two `kani::cover!` are the vacuity guard, as above. Kills
/// `BugMetaDeleteDropsOnFault` (`formal/comutants.toml`) on the first clause.
#[kani::proof]
fn a_faulted_meta_read_is_never_cached_as_an_absent_blob() {
    let (f, g) = two_file_fids();
    let faulted: bool = kani::any();
    kani::cover!(faulted, "the assume set leaves a faulted store");
    kani::cover!(!faulted, "the assume set leaves a clean one");
    let mut fs = fresh(faulted);
    let answered = fs.meta_delete(f);
    assert!(
        !faulted || !fs.reads_absent(EF_META),
        "a failed EF_META read was cached as a confirmed absence"
    );
    assert!(
        !faulted || fs.cache_view(EF_META) == CacheView::CLEAR,
        "a failed EF_META read moved the blob's cache at all"
    );
    assert!(
        !faulted || answered == Err(Error::MemoryFatal),
        "a failed EF_META read was answered as nothing to drop"
    );
    assert!(
        faulted || answered == Ok(()),
        "an absent EF_META was reported as a medium failure"
    );
    assert!(
        faulted || fs.cache_view(EF_META) == CacheView::ABSENT,
        "a definitive absence was left undecided"
    );
    assert!(
        fs.cache_view(f) == CacheView::CLEAR,
        "a meta_delete moved the subject's own value cache"
    );
    assert!(
        fs.cache_view(g) == CacheView::CLEAR,
        "a meta_delete aliased another FID"
    );
}
