// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn checksum_folds_every_byte_into_its_little_endian_lane() {
    for (bytes, expected) in [
        (&[][..], 0),
        (&[0xA5][..], 0xA5),
        (&[0x11, 0x22, 0x44, 0x88][..], 0x8844_2211),
        (
            &[0x11, 0x22, 0x44, 0x88, 0x81, 0x18, 0x24, 0x42][..],
            0xCA60_3A90,
        ),
    ] {
        assert_eq!(
            checksum(bytes),
            expected,
            "the timing harness checksum must retain every folded lane"
        );
    }
}

// The harness only means anything if each selector actually executes the real
// hot path, not a near-free error/fallback. Pin that the fixed inputs drive the
// genuine primitive, and that `run` returns that primitive's checksum.

#[test]
fn ecdh_selector_runs_the_real_agreement() {
    // The peer point is the P-256 generator (a valid public key) and FIXED_SCALAR
    // is a valid nonzero secret key, so ecdh_raw MUST succeed — else run(0) would
    // time the error arm (checksum 0) instead of a scalar multiply.
    let z = rsk_crypto::pinproto::ecdh_raw(&FIXED_SCALAR, &G_X, &G_Y)
        .expect("bench ECDH inputs must be valid so the real agreement is timed");
    assert_ne!(*z.expose(), [0u8; 32]);
    assert_eq!(run(0), checksum(z.expose()));
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
    assert_eq!(run(2), checksum(r.expose()));
}

#[test]
fn unknown_selectors_are_zero() {
    assert_eq!(run(3), 0);
    assert_eq!(run(255), 0);
}
