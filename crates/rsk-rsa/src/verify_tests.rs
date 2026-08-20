// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::vectors::{N_HEX, N1024_HEX, SIGN_SHA256, hex};

/// The SHA-256 DigestInfo header, so a KAT digest becomes what gpg signs.
const DI_SHA256: &[u8] = crate::pkcs1v15::DI_SHA256;
const E: &[u8] = crate::RSA_PUB_EXP_BE;

fn signed(i: usize) -> (Vec<u8>, Vec<u8>) {
    let (digest, sig) = SIGN_SHA256[i];
    let mut di = DI_SHA256.to_vec();
    di.extend_from_slice(&hex(digest));
    (di, hex(sig))
}

#[test]
fn accepts_an_openssl_signature() {
    for i in 0..SIGN_SHA256.len() {
        let (di, sig) = signed(i);
        assert!(verify_pkcs1v15(&hex(N_HEX), E, &di, &sig), "signature {i}");
    }
}

/// Every way this can be handed something wrong. A verifier nothing can make say
/// `false` is a rubber stamp, and the tests that lean on it — the whole
/// generated-key half of both applets' RSA suites — would pass over any signer.
#[test]
fn refuses_everything_that_is_not_that_signature() {
    let (di, sig) = signed(0);
    let n = hex(N_HEX);

    // One flipped bit in the signature.
    let mut bad = sig.clone();
    bad[200] ^= 0x01;
    assert!(
        !verify_pkcs1v15(&n, E, &di, &bad),
        "a flipped bit must fail"
    );

    // One flipped bit in the signed data — the same signature, a different claim.
    let mut other = di.clone();
    let last = other.len() - 1;
    other[last] ^= 0x01;
    assert!(
        !verify_pkcs1v15(&n, E, &other, &sig),
        "wrong digest must fail"
    );

    // A signature made by a different key, under the wrong modulus, and under a
    // modulus of a different width.
    let (_, sig1) = signed(1);
    assert!(
        !verify_pkcs1v15(&n, E, &di, &sig1),
        "wrong message must fail"
    );
    assert!(
        !verify_pkcs1v15(&hex(N1024_HEX), E, &di, &sig),
        "wrong modulus must fail"
    );

    // A wrong public exponent: `sig^3` is not the EM either.
    assert!(
        !verify_pkcs1v15(&n, &[0x03], &di, &sig),
        "wrong e must fail"
    );

    // Lengths: a signature short of the modulus width, one past it, and an
    // empty one. RFC 8017 §8.2.2 step 1 rejects on length before any arithmetic.
    assert!(
        !verify_pkcs1v15(&n, E, &di, &sig[1..]),
        "short sig must fail"
    );
    let mut long = sig.clone();
    long.insert(0, 0x00);
    assert!(!verify_pkcs1v15(&n, E, &di, &long), "long sig must fail");
    assert!(!verify_pkcs1v15(&n, E, &di, &[]), "empty sig must fail");

    // `s ≥ n` at the right width — the modulus itself.
    assert!(!verify_pkcs1v15(&n, E, &di, &n), "s = n must fail");

    // Data too wide for the block it would have to sit in (`|PS| ≥ 8`).
    let wide = alloc::vec![0x42u8; n.len() - 10];
    assert!(
        !verify_pkcs1v15(&n, E, &wide, &sig),
        "over-wide data must fail"
    );
}

/// The bare-hash spelling and the DigestInfo spelling are different messages, so
/// a verifier that quietly ignored `data` would accept both.
#[test]
fn the_digestinfo_header_is_part_of_the_message() {
    let (digest, sig) = SIGN_SHA256[2];
    let (di, sig) = (
        {
            let mut v = DI_SHA256.to_vec();
            v.extend_from_slice(&hex(digest));
            v
        },
        hex(sig),
    );
    let n = hex(N_HEX);
    assert!(verify_pkcs1v15(&n, E, &di, &sig));
    assert!(
        !verify_pkcs1v15(&n, E, &hex(digest), &sig),
        "the bare hash is not what was signed"
    );
}
