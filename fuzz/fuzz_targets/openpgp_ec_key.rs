// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the EC IMPORT crypto path *after* the TLV parse (`openpgp_import` covers
//! the extended-header-list walk itself). On-device this is gated behind an EC
//! algorithm attribute written via PUT DATA, so `openpgp_apdu` cannot reach it
//! with random bytes — drive it directly here.
//!
//! Two surfaces: `curve_from_attr` (the OID matcher) on arbitrary bytes, and the
//! key reconstruction (`PrivKey::from_scalar` → `public_point`, where RustCrypto
//! validates the imported scalar). The curve is chosen by the first byte so the
//! reconstruction runs on every input rather than only when the OID happens to
//! match. Neither path may panic.

use libfuzzer_sys::fuzz_target;
use rsk_ec::{Curve, PrivKey};
use rsk_openpgp::keys::curve_from_attr;

const CURVES: [Curve; 5] = [
    Curve::P256,
    Curve::P384,
    Curve::P521,
    Curve::K256,
    Curve::Ed25519,
];

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // The OID matcher must survive arbitrary attribute bytes.
    let _ = curve_from_attr(data);

    // Reconstruct a key from an attacker scalar and derive the public point —
    // an out-of-range / zero / over-long scalar must be rejected, never panic.
    let curve = CURVES[data[0] as usize % CURVES.len()];
    if let Some(key) = PrivKey::from_scalar(curve, &data[1..]) {
        let mut pt = [0u8; 200];
        let _ = key.public_point(&mut pt);
    }
});
