// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the RSA signing input parser (`rsa_sign_em`): given attacker-controlled
//! data, `rsa_sign` either recognises a PKCS#1 DigestInfo, length-infers a bare
//! hash, or falls back to the raw private operation. The DigestInfo match + the
//! `prefix ‖ hash` buffer construction must never panic or overflow `em`. This is
//! the pure half of `rsa_sign` (no modexp), so it runs at full fuzzing speed; the
//! raw fallback and the actual signature are the modexp's, exercised by the
//! unit tests. On-device the path sits behind a provisioned RSA key, out of reach
//! of `openpgp_apdu`.

use libfuzzer_sys::fuzz_target;
use rsk_rsa::MAX_RSA_DIGESTINFO;
use rsk_rsa::pkcs1v15::rsa_sign_em;

fuzz_target!(|data: &[u8]| {
    let mut em = [0u8; MAX_RSA_DIGESTINFO];
    if let Some(n) = rsa_sign_em(data, &mut em) {
        // A recognised DigestInfo / bare hash never exceeds the EM buffer.
        assert!(n <= MAX_RSA_DIGESTINFO);
    }
});
