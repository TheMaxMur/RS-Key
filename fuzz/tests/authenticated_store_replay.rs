// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#[path = "../fuzz_targets/authenticated_store.rs"]
mod authenticated_store;

/// The 30-minute campaign crash `crash-157076ee…`: 260 bytes of the command
/// write, then one byte of the recovery discard. The medium must honour
/// `MultiwriteNorFlash`, so the next mount finishes that discard and keeps the
/// acknowledged old value and the neighbour.
///
/// Not under Miri: `run` is Miri-clean but its `initialize_blank` costs about
/// 54 minutes per seed, which the weekly shard must not pay eight times.
#[cfg(not(miri))]
#[test]
fn contract_cut_artifact_replays_to_acknowledged_state() {
    authenticated_store::run(&[0x04, 0x01, 0x01, 0x00, 0x00]);
}
