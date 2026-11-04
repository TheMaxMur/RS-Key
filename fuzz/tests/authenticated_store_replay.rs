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

#[cfg(not(miri))]
#[test]
fn bound_pin_and_hotp_cuts_cover_append_rollover_and_live_replay() {
    for kind in [16, 48] {
        for warm in [0, 80] {
            for cut in [0, 1, 255, 256, 257, 1023, 1024, 16384] {
                let [lo, hi] = u16::try_from(cut).unwrap().to_le_bytes();
                authenticated_store::run(&[lo, hi, 1, 0, kind, 0, warm]);
            }
        }
    }
}

/// The deterministic `V2H1` histories. They mirror `authenticated_store_sequences`
/// in `scripts/external_corpus.py`; each reaches one stateful transition in the
/// v2 store. Not under Miri: `initialize_blank`/`administer` costs minutes per seed.
#[cfg(not(miri))]
#[test]
fn v2_histories_replay_to_their_acknowledged_state() {
    for seed in V2_SEEDS {
        authenticated_store::run(seed);
    }
}

#[cfg(not(miri))]
const V2_SEEDS: &[&[u8]] = &[
    // 0: legacy image -> v2 import through boot, then cold mounts.
    b"V2H1\x00",
    // 1: legacy image -> v2 import through Fs::administer_storage.
    b"V2H1\x01",
    // 2: rescue IMPORTV2 contract, wrong P1/P2/payload and denied presence.
    b"V2H1\x02",
    // 3: rescue INITV2 on blank media.
    b"V2H1\x03",
    // 4: cut after the manifest is durable, then a recovery mount.
    b"V2H1\x04",
    // 5: corrupt manifest plus changed legacy value: refusal, no downgrade.
    b"V2H1\x05",
    // 6: activation witness loss and corruption are repaired, never re-init.
    b"V2H1\x06",
    // 7: pre-OTP -> OTP re-key, idempotent, pre-OTP authority revoked.
    b"V2H1\x07",
    // 8: two or three independent write faults during re-key plus a recovery cut.
    b"V2H1\x08\x00\x00",
    b"V2H1\x08\x00\xff",
    // 9: fill, compact, cold mount, superseded value not adopted.
    b"V2H1\x09",
    // 10: capacity exhaustion, remove/compaction, another value.
    b"V2H1\x0a",
    // 11: silent write plus refused read-back.
    b"V2H1\x0b",
    // 12: torn write.
    b"V2H1\x0c",
    // 13: refused read, write and erase.
    b"V2H1\x0d",
    // 14: command cut and recovery cut.
    b"V2H1\x0e",
    // 15: corruption during re-key, then during compaction.
    b"V2H1\x0f\x00",
    b"V2H1\x0f\x01",
];
