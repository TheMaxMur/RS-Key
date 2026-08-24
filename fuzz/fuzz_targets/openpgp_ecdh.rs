// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the PSO:DECIPHER ECDH path. Two attacker surfaces, neither reachable via
//! `openpgp_apdu` (which needs an EC DEC key provisioned first, so random bytes
//! never get past the RSA-by-default gate):
//!   1. `parse_ecdh_point` — the `A6 { 7F49 { 86 <point> } }` ASN.1 walk over the
//!      raw DECIPHER body.
//!   2. `PrivKey::ecdh` — P-256 key agreement against the attacker-chosen peer
//!      point (SEC1 decode + off-curve rejection).
//!
//! Neither may panic; the agreement may only return a status word.

use libfuzzer_sys::fuzz_target;
use rsk_ec::{Curve, PrivKey};
use rsk_openpgp::pso::parse_ecdh_point;

fuzz_target!(|data: &[u8]| {
    // Fixed valid scalars — we are fuzzing the parse + the peer-point decode, not
    // the private keys. P-256 = SEC1 Weierstrass; X25519 = the 0x40-prefixed
    // Montgomery point + the big-endian→little-endian scalar reversal.
    let p256 = PrivKey::from_scalar(Curve::P256, &[0x11; 32]).unwrap();
    let x25519 = PrivKey::from_scalar(Curve::X25519, &[0x22; 32]).unwrap();
    let mut out = [0u8; 64];

    // The wrapper walk must survive arbitrary bytes, and the extracted point
    // (still attacker-controlled) must agree-or-reject without panicking.
    if let Some(point) = parse_ecdh_point(data) {
        let _ = p256.ecdh(point, &mut out);
        let _ = x25519.ecdh(point, &mut out);
    }

    // Also feed the raw bytes straight in, so the point decoders see unwrapped
    // adversarial points (wrong length / off curve / identity / 0x40 handling).
    let _ = p256.ecdh(data, &mut out);
    let _ = x25519.ecdh(data, &mut out);
});
