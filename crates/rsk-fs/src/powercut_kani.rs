// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! What the power-cut rules say, proved over every observation rather than the
//! ones a fuzzer happened to produce.
//!
//! The predicates are the *only* thing the oracle judges a torn operation by, so
//! a rule that is too generous is an oracle that cannot fail — the same defect
//! as a test that cannot fail, one level up. The states are bounded to two
//! two-byte values because the rules compare whole values: nothing in them looks
//! at a length or an index, so a counterexample at two bytes exists at any width.
//!
//! The driver these rules serve needs a heap and is not here; `cargo kani` builds
//! `rsk-fs` `no_std`, and these are the half that survives that.
//!
//! `#[kani::unwind(3)]` bounds `memcmp`: comparing two `&[u8]` goes through the
//! builtin, whose loop CBMC does not fold to the constant length of a two-byte
//! slice — measured, it unwound past 3800 iterations and CBMC died with status
//! 15. Three is one past what a two-byte comparison needs.

use super::*;

/// A symbolic `Option<[u8; 2]>`, as the rules see it.
fn maybe(present: bool, value: &[u8; 2]) -> Option<&[u8]> {
    if present { Some(value) } else { None }
}

#[kani::proof]
#[kani::unwind(3)]
fn a_torn_put_is_the_old_value_or_the_new_one_and_nothing_else() {
    let old: [u8; 2] = kani::any();
    let new: [u8; 2] = kani::any();
    let got: [u8; 2] = kani::any();
    let had: bool = kani::any();
    let has: bool = kani::any();
    let old = maybe(had, &old);
    let got = maybe(has, &got);
    assert_eq!(
        put_landed(old, &new, got),
        got == old || got == Some(&new[..])
    );
    // The two outcomes the store is allowed to leave are always legal, so the
    // rule cannot be so strict that a correct store trips it.
    assert!(put_landed(old, &new, old));
    assert!(put_landed(old, &new, Some(&new)));
}

#[kani::proof]
#[kani::unwind(3)]
fn a_torn_delete_never_leaves_metadata_behind_a_missing_file() {
    let old_value: [u8; 2] = kani::any();
    let old_meta: [u8; 2] = kani::any();
    let got_meta: [u8; 2] = kani::any();
    let had_value: bool = kani::any();
    let had_meta: bool = kani::any();
    let has_meta: bool = kani::any();
    let old_value = maybe(had_value, &old_value);
    let old_meta = maybe(had_meta, &old_meta);
    let got_meta = maybe(has_meta, &got_meta);
    // Value gone while metadata survives is the state `Fs::delete`'s order
    // forbids — metadata describing a file that is not there.
    if old_value.is_some() && got_meta.is_some() {
        assert!(!delete_landed(old_value, old_meta, None, got_meta));
    }
    // The three states the order does allow.
    assert!(delete_landed(old_value, old_meta, old_value, old_meta));
    assert!(delete_landed(old_value, old_meta, old_value, None));
    assert!(delete_landed(old_value, old_meta, None, None));
}

#[kani::proof]
#[kani::unwind(3)]
fn a_torn_meta_add_that_could_not_fit_is_never_seen_as_written() {
    let old: [u8; 2] = kani::any();
    let new: [u8; 2] = kani::any();
    let had: bool = kani::any();
    let old = maybe(had, &old);
    // A record the ceiling would have refused may only be observed as the old
    // one, whatever the cut did to the medium.
    assert_eq!(
        meta_add_landed(old, &new, false, Some(&new)),
        old == Some(&new[..])
    );
    assert!(meta_add_landed(old, &new, true, Some(&new)));
    assert!(meta_add_landed(old, &new, false, old));
}

#[kani::proof]
#[kani::unwind(3)]
fn a_torn_meta_delete_is_the_old_record_or_none() {
    let old: [u8; 2] = kani::any();
    let got: [u8; 2] = kani::any();
    let had: bool = kani::any();
    let has: bool = kani::any();
    let old = maybe(had, &old);
    let got = maybe(has, &got);
    assert_eq!(meta_delete_landed(old, got), got == old || got.is_none());
    assert!(meta_delete_landed(old, old));
    assert!(meta_delete_landed(old, None));
}
