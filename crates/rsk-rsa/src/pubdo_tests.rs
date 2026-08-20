// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::fixtures::{N_HEX, hex, test_key};

#[test]
fn import_recovers_modulus() {
    // from_p_q must reconstruct N = P·Q (the make_rsa_response modulus).
    let key = test_key();
    let mut out = [0u8; MAX_RSA_PUBDO];
    let n = make_rsa_response(&key, &mut out);
    assert_eq!(&out[..3], &[0x7f, 0x49, 0x82]); // outer DO
    assert_eq!(&out[5..7], &[0x81, 0x82]); // modulus tag + 2-byte length
    assert_eq!(u16::from_be_bytes([out[7], out[8]]), 256); // RSA-2048 modulus
    assert_eq!(&out[9..9 + 256], hex(N_HEX).as_slice());
    // Exponent 0x010001 follows the modulus.
    assert_eq!(out[9 + 256], 0x82);
    assert_eq!(out[9 + 256 + 1], 3);
    assert_eq!(&out[9 + 256 + 2..9 + 256 + 5], &[0x01, 0x00, 0x01]);
    assert_eq!(n, 270);
}

#[test]
fn make_rsa_pub_body_matches_make_rsa_response_inner() {
    // The PIV GET METADATA path builds the DO from N + e directly (no key
    // rebuild); it must be byte-identical to make_rsa_response's inner body — the
    // same bytes the old metadata path emitted, minus the 5-byte 7F49 wrapper.
    let key = test_key();
    let mut full_out = [0u8; MAX_RSA_PUBDO];
    let full = make_rsa_response(&key, &mut full_out);
    let mut body_out = [0u8; MAX_RSA_PUBDO];
    let body = make_rsa_pub_body(&key.n_be(), &key.e_be(), &mut body_out);
    assert_eq!(&body_out[..body], &full_out[5..full]);
}
