// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg(not(miri))]

#[path = "../fuzz_targets/fido_session.rs"]
mod fido_session;

#[path = "fixtures/fido_session.rs"]
mod fido_session_seeds;

/// Every named spend/revocation transition under the shipped `exercise`
/// function: the token route must stay a deterministic, non-panicking oracle on
/// healthy code.
#[test]
fn token_route_replays_every_named_transition() {
    // This test target sees only part of the shared fixture; keep the rest
    // referenced so `-D warnings` does not call it dead code. `miri.rs` is the
    // full consumer.
    let _ = fido_session_seeds::assertion_capacity(0);
    for seed in fido_session_seeds::TOKEN_SEEDS {
        fido_session::exercise(seed);
    }
}
