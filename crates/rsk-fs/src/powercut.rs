// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The power-cut oracle: what [`Fs`](crate::Fs) still promises when the lights
//! go out mid-write.
//!
//! It was 418 lines inside `fuzz/fuzz_targets/power_cut.rs`, so the only way to
//! ask any of these questions was to fuzz — not a unit test, not Kani, not the
//! emulator, and from nowhere in the root workspace, since `fuzz/` is a detached
//! nightly one whose corpus is git-ignored. The oracle was never the problem;
//! where it lived was. Shaped after Wasefire's `StoreModel`/`StoreDriver` split,
//! whose `StoreDriverOff` carries the last valid model *and* the invariant the
//! store must satisfy if the interrupted operation completes.
//!
//! Three properties, and they are `Fs`'s — which is why this is in `rsk-fs` and
//! not in `rsk-store`: nothing here mentions a page, a wear level or a log.
//!
//! * **Atomicity.** The interrupted operation either landed or did not — the old
//!   value or the new one, never a third thing.
//! * **Durability.** Every file committed before the cut reads back exactly. A
//!   spurious `None` here is the on-device "seed lost, regenerate" disaster.
//! * **Enumeration.** The live key set covers every committed key.
//!
//! This file is the *rules*: four predicates naming the states a cut may leave,
//! in terms `cargo kani` can reason about. The driver that runs them against a
//! real `Fs` needs a heap, so it sits beside them behind the `test-util` feature
//! that already gates `RamStorage`.

/// Whether `got` is a legal observation of a `put` of `new` over `old` that a
/// power cut interrupted: the old value or the new one, nothing else.
pub fn put_landed(old: Option<&[u8]>, new: &[u8], got: Option<&[u8]>) -> bool {
    got == old || got == Some(new)
}

/// Whether `got` is a legal observation of an interrupted `delete`.
///
/// [`Fs::delete`](crate::Fs::delete) drops the metadata **first**, so
/// value-gone-but-meta-alive is the one state the order forbids: a reader would
/// find metadata describing a file that is not there. The other way round —
/// metadata gone while the value survives — is the intended intermediate.
///
/// Refines `RSKeyStore!NoOrphanedMetadata` — SEC-STORE-001.
pub fn delete_landed(
    old_value: Option<&[u8]>,
    old_meta: Option<&[u8]>,
    got_value: Option<&[u8]>,
    got_meta: Option<&[u8]>,
) -> bool {
    let untouched = got_value == old_value && (got_meta == old_meta || got_meta.is_none());
    untouched || (got_value.is_none() && got_meta.is_none())
}

/// Whether `got` is a legal observation of an interrupted `meta_add`. `fits` is
/// whether the rebuilt `EF_META` blob would have been within its ceiling: one
/// that could never have been written may not be observed as written.
pub fn meta_add_landed(old: Option<&[u8]>, new: &[u8], fits: bool, got: Option<&[u8]>) -> bool {
    got == old || (fits && got == Some(new))
}

/// Whether `got` is a legal observation of an interrupted `meta_delete`.
pub fn meta_delete_landed(old: Option<&[u8]>, got: Option<&[u8]>) -> bool {
    got == old || got.is_none()
}

#[cfg(any(test, feature = "test-util"))]
#[path = "powercut_model.rs"]
mod model;
#[cfg(any(test, feature = "test-util"))]
pub use model::{Device, Op, PowerCutModel};

#[cfg(test)]
#[path = "powercut_tests.rs"]
mod tests;

#[cfg(kani)]
#[path = "powercut_kani.rs"]
mod proofs;
