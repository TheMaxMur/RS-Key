// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the HMAC-DRBG: arbitrary seeds / reseeds / output lengths must terminate
//! without panicking, fully fill the request, and stay deterministic for a fixed
//! seed — the property the keygen / signing-nonce randomness relies on.

use libfuzzer_sys::fuzz_target;
use rsk_crypto::HmacDrbg;

fuzz_target!(|data: &[u8]| {
    // First byte picks an output length 0..=255; the rest is the seed.
    let (len, seed) = data
        .split_first()
        .map_or((0usize, data), |(n, s)| (*n as usize, s));

    // Determinism: two instances from the same seed yield the same stream.
    let mut a = HmacDrbg::new(seed);
    let mut b = HmacDrbg::new(seed);
    let mut out_a = [0u8; 256];
    let mut out_b = [0u8; 256];
    a.fill(&mut out_a[..len]);
    b.fill(&mut out_b[..len]);
    assert_eq!(out_a[..len], out_b[..len]);

    // A reseed must move the state and must not replay the stream. `b` is the
    // control — same seed, same draws, never reseeded — so a `reseed` that dropped
    // its entropy would leave the two post-reseed blocks equal.
    let mut pre = [0u8; 64];
    let mut ctrl = [0u8; 64];
    a.fill(&mut pre);
    b.fill(&mut ctrl);
    assert_eq!(pre, ctrl);

    a.reseed(seed);
    let mut post = [0u8; 64];
    a.fill(&mut post);
    b.fill(&mut ctrl);
    assert_ne!(pre, post);
    assert_ne!(post, ctrl);
});
