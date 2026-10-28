// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Authenticated authority over the existing two payload maps.

#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

mod record;
pub use record::{Entry, Identity, Partition};

mod directory;
pub use directory::Directory;

mod authority;
mod read_proof;
mod read_tags;

mod keys;
pub use keys::{KeySource, RootArm, RootRead};

mod checkpoint;
pub use checkpoint::{CHECKPOINT_BYTES, Checkpoint};

mod transaction;
pub use transaction::{DELTA_BYTES, Delta, DeltaKind, Prepared, TransactionState};

mod append_proof;
mod bank;
pub use bank::{BankDigest, BankErased, RawBank, all_erased};

mod journal;
pub use journal::{Journal, JournalScan, JournalStatus};

mod counter_bank;
pub use counter_bank::{CounterBank, CounterLocation, CounterScan};

mod counters;
pub use counters::Counters;

pub(crate) mod bound_counter;
mod bound_storage;

mod main;
pub use main::Main;

mod storage;
pub use storage::{Authenticated, Layout};

mod import;
mod legacy;
mod managed;
pub use managed::Managed;

/// Directory format; payloads retain their existing page-sized representation.
pub const FORMAT: u8 = 2;
/// The metadata is outside the value, preserving the published value ceiling.
pub const ENTRY_BYTES: usize = 32;
/// A truncated HMAC-SHA256 tag, matching the existing 128-bit seal strength.
pub const TAG_BYTES: usize = 16;
/// A format epoch separates deliberate initialization from later transactions.
pub const EPOCH_BYTES: usize = 16;
/// EF_META does not consume a dynamic-file slot.
pub const MAX_MAIN_ENTRIES: usize = rsk_fs::MAX_DYNAMIC_FILES + 1 + 6;
/// Public counter records and private owner-bound counter buckets.
pub const MAX_COUNTER_ENTRIES: usize = rsk_fs::counter::COUNTER_FIDS.len() + bound_counter::BUCKETS;

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "Fixed test fixtures mutate every byte and fail immediately when setup is refused"
)]
#[path = "authenticated_tests.rs"]
mod tests;
