// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz OpenPGP RSA key reconstruction from imported MPIs
//! (`rsk_rsa::rsa_from_pqe`): the attacker-chosen `e`/`p`/`q` an authenticated
//! PW3 IMPORT feeds into `RsaKey::from_p_q`. Must never panic; and any key it
//! accepts must have modulus exactly `p * q` and the supplied exponent — a
//! differential against a plain big-integer multiply, so a wrapper that ever
//! mis-pairs the primes is caught.

use libfuzzer_sys::fuzz_target;
use num_bigint_dig::BigUint;
use rsk_rsa::rsa_from_pqe;

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    // e is a small (1..=8-byte) exponent; the remaining split point picks p, then q.
    let le = 1 + data[0] as usize % 8;
    let lp = data[1] as usize;
    let body = &data[2..];
    if body.len() < le {
        return;
    }
    let e = &body[..le];
    let after_e = &body[le..];
    let lp = lp.min(after_e.len());
    let p = &after_e[..lp];
    let q = &after_e[lp..];

    if let Some(key) = rsa_from_pqe(e, p, q) {
        let n = BigUint::from_bytes_be(p) * BigUint::from_bytes_be(q);
        assert_eq!(key.n_be(), n.to_bytes_be());
        assert_eq!(key.e_be(), BigUint::from_bytes_be(e).to_bytes_be());
    }
});
