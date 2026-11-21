// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Stage 5A item 5: the `present`/`decided` bitmap arithmetic over the WHOLE
//! shipped `u16` FID domain, not three bytes of it.
//!
//! `store_refinement_kani.rs` proves the aliasing clauses over a symbolic pair
//! drawn from `0..FID_LIMIT`, and under `cfg(kani)` that limit is 24 — the
//! shrink `FID_PRESENT_BYTES = 3` produces. The roadmap's own rule for that
//! shrink is §7.2 item 5: say what stops being proved. What stops being proved is
//! everything above bit 23, which is 99.96 % of the map, and extrapolating three
//! bytes to 8192 is the error the stage names.
//!
//! The transfer is NOT another proof over a wider symbolic domain. It is a
//! compile-time theorem plus bounded representative classes, in that order:
//!
//! * `fs.rs`'s `const _: () = assert!(…)` pair states the two facts the
//!   arithmetic needs — no FID indexes past the map, and `fid ↦ (fid >> 3,
//!   fid & 7)` is INVERTIBLE, hence injective. Injectivity is the whole content
//!   of "no put aliases another FID": two FIDs sharing a bit is exactly two FIDs
//!   with the same `(byte, mask)`. The compile-time half is checked over every
//!   one of the 65 536 FIDs, which a symbolic proof at any width does not do.
//! * The classes below then exercise the real primitives at the SHIPPED width,
//!   which costs nothing to reach: `store_assurance.rs` is
//!   `#[cfg(any(kani, test))]` while `FID_PRESENT_BYTES = 3` is `cfg(kani)`, so
//!   under `cargo test` the same shims run over the full 8192-byte map.
//!
//! The guard that keeps this honest is [`the_sweep_runs_at_the_shipped_width`]:
//! a future shrink that reaches `cfg(test)` would silently turn every case below
//! into a statement about 24 bits again.

use super::store_assurance::{CacheView, fresh};
use super::*;

/// Every FID, and the classes a representative sample must contain: the two ends
/// of the domain, both ends of a map byte, the pair that differ only in the byte
/// index, the pair that differ only in the mask, the FIDs the shrunk proofs
/// address at all, and the two records the store keeps for itself.
fn representatives() -> std::vec::Vec<u16> {
    let mut out = std::vec![
        0,
        1,
        7,
        8,
        9,
        23,
        24,
        255,
        256,
        0x0301,
        0x0302,
        0x0455,
        EF_META,
        EF_SCRUB_FILLER,
        0x7FFF,
        0x8000,
        0xFFF7,
        0xFFF8,
        0xFFFE,
        0xFFFF,
    ];
    out.sort_unstable();
    out.dedup();
    out
}

#[test]
fn the_sweep_runs_at_the_shipped_width() {
    assert_eq!(
        FID_PRESENT_BYTES,
        (u16::MAX as usize + 1) / 8,
        "the cases below claim the whole u16 domain; a shrink that reaches \
         cfg(test) makes them a statement about a fraction of it"
    );
    // And the vacuity control the sweeps below need: three of them loop over
    // `representatives()`, so an empty list would pass every one of them over
    // nothing. Measured: with the list emptied, four cases stay green.
    let reps = representatives();
    assert!(
        reps.len() >= 20,
        "the representative classes were thinned: {reps:?}"
    );
    assert!(
        reps.contains(&0) && reps.contains(&u16::MAX),
        "both ends of the domain must be represented"
    );
}

#[test]
fn every_fid_in_the_domain_owns_a_distinct_bit() {
    // The runtime twin of the compile-time theorem, over the same 65 536 FIDs.
    // Kept because the const assert states INVERTIBILITY and this states the
    // consequence directly, in the shape the aliasing clauses are written in —
    // and because a const assert that stopped being compiled would take the
    // theorem with it silently.
    let mut seen = std::vec![false; FID_PRESENT_BYTES * 8];
    for fid in 0..=u16::MAX {
        let bit = (fid >> 3) as usize * 8 + (fid & 7) as usize;
        assert!(bit < seen.len(), "fid {fid:#06x} indexes past the map");
        assert!(
            !seen[bit],
            "fid {fid:#06x} shares a bit with an earlier FID"
        );
        seen[bit] = true;
    }
    assert!(
        seen.into_iter().all(|b| b),
        "the map has an unreachable bit"
    );
}

#[test]
fn a_put_over_the_whole_domain_moves_exactly_its_own_fid() {
    for fid in representatives() {
        let mut fs = fresh(false);
        fs.step_put(fid);
        assert_eq!(fs.cache_view(fid), CacheView::LIVE, "{fid:#06x}");
        let mut moved = 0usize;
        for other in 0..=u16::MAX {
            if fs.cache_view(other) != CacheView::CLEAR {
                moved += 1;
                assert_eq!(other, fid, "put on {fid:#06x} moved {other:#06x}");
            }
        }
        assert_eq!(moved, 1, "put on {fid:#06x} moved {moved} FIDs");
    }
}

#[test]
fn a_delete_never_makes_a_live_neighbour_read_absent() {
    // The direction that matters: a false absence hides a record that IS there.
    // Every representative against every other, which is the pairwise class the
    // shrunk harness draws its symbolic pair from — here over the real width.
    for &subject in &representatives() {
        for &neighbour in &representatives() {
            if neighbour == subject {
                continue;
            }
            let mut fs = fresh(false);
            fs.step_put(neighbour);
            fs.step_delete(subject);
            assert_eq!(fs.cache_view(subject), CacheView::ABSENT);
            assert!(fs.reads_absent(subject));
            assert_eq!(
                fs.cache_view(neighbour),
                CacheView::LIVE,
                "delete {subject:#06x} aliased {neighbour:#06x}"
            );
            assert!(
                !fs.reads_absent(neighbour),
                "a live {neighbour:#06x} read as a decided absence after \
                 deleting {subject:#06x}"
            );
        }
    }
}

#[test]
fn a_faulted_confirm_decides_nothing_anywhere_in_the_domain() {
    // `settle` must leave the FID UNDECIDED on a backend fault, or one transient
    // error becomes a permanent absence for the rest of the boot (audit run-36).
    // Over the full width, because the fault path indexes the same map.
    for fid in representatives() {
        let mut fs = fresh(true);
        fs.step_confirm(fid, false);
        assert_eq!(
            fs.cache_view(fid),
            CacheView::CLEAR,
            "a faulted probe of {fid:#06x} decided it"
        );
        assert!(!fs.reads_absent(fid));
    }
}

#[test]
fn the_shrunk_domain_is_a_prefix_of_the_shipped_one() {
    // What the `cfg(kani)` harnesses address, stated here rather than argued:
    // FIDs 0..23. Every one of them behaves under the shipped map exactly as the
    // shrunk proofs found it, so the proofs are about a sub-domain and not about
    // a different topology — which is the thing extrapolation cannot say.
    for fid in 0u16..24 {
        let mut fs = fresh(false);
        fs.step_put(fid);
        assert_eq!(fs.cache_view(fid), CacheView::LIVE);
        assert_eq!((fid >> 3) as usize, usize::from(fid) / 8);
        assert!((fid >> 3) < 3, "outside the shrunk map's three bytes");
    }
}
