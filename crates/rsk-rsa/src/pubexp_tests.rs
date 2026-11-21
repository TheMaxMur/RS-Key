// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use num_bigint_dig::BigUint;

#[test]
fn public_exponent_matches_biguint() {
    for len in (32..=crate::MAX_RSA_BYTES).step_by(32) {
        for top in [0, 0x49, 0x80, 0xff] {
            let mut modulus = vec![0xb7; len];
            modulus[len - 1] = top;
            let n = BigUint::from_bytes_le(&modulus);
            for base in [
                BigUint::from(0u8),
                BigUint::from(1u8),
                BigUint::from_bytes_le(&vec![0x62; len]) % &n,
                &n - 1u8,
            ] {
                let want = base.modpow(&BigUint::from(RSA_E), &n);
                let mut input = base.to_bytes_le();
                input.resize(len, 0);
                let mut out = vec![0xa5; len];
                assert!(modexp_pub(&input, &modulus, &mut out));
                assert_eq!(
                    BigUint::from_bytes_le(&out),
                    want,
                    "{len} bytes, top {top:#x}"
                );
            }
        }
    }
}

#[test]
fn invalid_public_exponent_inputs_leave_output_untouched() {
    let base = [0; 32];
    let mut out = [0xa5; 32];
    let modulus = [0x81; 32];
    let mut tiny_modulus = [0; 32];
    tiny_modulus[..4].copy_from_slice(&RSA_E.to_le_bytes());
    for (base, modulus) in [
        (&base[..31], &modulus[..]),
        (&base[..], &[0x80; 32][..]),
        (&base[..], &tiny_modulus[..]),
        (&modulus[..], &modulus[..]),
        (&[0xff; 32][..], &modulus[..]),
    ] {
        assert!(!modexp_pub(base, modulus, &mut out));
        assert_eq!(out, [0xa5; 32]);
    }
    assert!(!modexp_pub(&base, &modulus, &mut out[..31]));
    assert_eq!(out, [0xa5; 32]);
    assert!(!modexp_pub(&[], &[], &mut []));
    assert!(!modexp_pub(&base[..31], &modulus[..31], &mut out[..31]));
    assert_eq!(out, [0xa5; 32]);
    const OVERSIZE: usize = crate::MAX_RSA_BYTES + 32;
    let mut oversize_out = [0xa5; OVERSIZE];
    assert!(!modexp_pub(
        &[0; OVERSIZE],
        &[1; OVERSIZE],
        &mut oversize_out
    ));
    assert_eq!(oversize_out, [0xa5; OVERSIZE]);
}

#[test]
fn public_exponent_accepts_a_padded_small_modulus() {
    let n = RSA_E + 2;
    let mut modulus = [0; 32];
    modulus[..4].copy_from_slice(&n.to_le_bytes());
    let mut base = [0; 32];
    base[0] = 2;
    let mut out = [0xa5; 32];
    assert!(modexp_pub(&base, &modulus, &mut out));
    let want = BigUint::from(2u8).modpow(&BigUint::from(RSA_E), &BigUint::from(n));
    assert_eq!(BigUint::from_bytes_le(&out), want);
}
