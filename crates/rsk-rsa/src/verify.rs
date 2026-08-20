// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The verifier half of PKCS#1 v1.5 — the public operation a relying party
//! runs. Nothing on the card verifies an RSA signature, so this is behind
//! `test-util` and never reaches the firmware image; it exists because the two
//! card applets' tests have to ask "would a verifier accept what we just
//! signed?", and the `rsa` crate that used to answer left the tree with
//! RUSTSEC-2023-0071.
//!
//! It touches no private value, so it cannot pass by sharing a bug with the
//! signer. The frozen OpenSSL signatures in [`crate::vectors`] are the other
//! half of the check: this one says "well-formed", those say "byte-identical".

use num_bigint_dig::BigUint;

/// Whether `sig` is a valid RSASSA-PKCS1-v1_5 signature over `data` under the
/// public key `(n, e)`, both big-endian. `data` is the encoded DigestInfo (or a
/// bare hash), exactly what [`crate::pkcs1v15::rsa_sign_em`] would build —
/// matching the `rsa` crate's `Pkcs1v15Sign::new_unprefixed()`.
pub fn verify_pkcs1v15(n_be: &[u8], e_be: &[u8], data: &[u8], sig: &[u8]) -> bool {
    let n = BigUint::from_bytes_be(n_be);
    let e = BigUint::from_bytes_be(e_be);
    let k = n.bits().div_ceil(8);
    if sig.len() != k || data.len() + 11 > k {
        return false;
    }
    let s = BigUint::from_bytes_be(sig);
    if s >= n {
        return false;
    }
    // EM = 00 01 FF…FF 00 ‖ data (RFC 8017 §9.2), compared as an integer so the
    // leading zero byte `to_bytes_be` drops cannot make a wrong block pass.
    let mut want = alloc::vec![0xffu8; k];
    want[0] = 0x00;
    want[1] = 0x01;
    want[k - data.len() - 1] = 0x00;
    want[k - data.len()..].copy_from_slice(data);
    s.modpow(&e, &n) == BigUint::from_bytes_be(&want)
}
