// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

// The harness only means anything if each selector actually executes the real
// hot path, not a near-free error/fallback. Pin that the fixed inputs drive the
// genuine primitive, and that `run` returns that primitive's checksum.

#[test]
fn ecdh_selector_runs_the_real_agreement() {
    // The peer point is the P-256 generator (a valid public key) and FIXED_SCALAR
    // is a valid nonzero secret key, so ecdh_raw MUST succeed — else run(0) would
    // time the `unwrap_or([0;32])` error path instead of a scalar multiply.
    let z = rsk_crypto::pinproto::ecdh_raw(&FIXED_SCALAR, &G_X, &G_Y)
        .expect("bench ECDH inputs must be valid so the real agreement is timed");
    assert_ne!(z, [0u8; 32]);
    assert_eq!(run(0), checksum(&z));
}

#[test]
fn sign_selector_produces_a_der_signature() {
    use p256::elliptic_curve::PrimeField;
    let d = Option::<p256::Scalar>::from(p256::Scalar::from_repr(p256::FieldBytes::from(
        FIXED_SCALAR,
    )))
    .unwrap();
    let mut out = [0u8; crate::ec::MAX_DER_SIG];
    let n = crate::ec::sign_p256_comb(&d, &FIXED_MSG, &mut out);
    assert!(
        n > 8 && n <= crate::ec::MAX_DER_SIG,
        "not a DER ECDSA sig: {n}"
    );
    assert_eq!(run(1), checksum(&out[..n]));
}

#[test]
fn ratchet_selector_matches_the_kdf() {
    let r = crate::keyderiv::ratchet(&FIXED_SEED, &FIXED_PATH);
    assert_eq!(run(2), checksum(&r));
}

#[test]
fn unknown_selectors_are_zero() {
    assert_eq!(run(3), 0);
    assert_eq!(run(255), 0);
}
