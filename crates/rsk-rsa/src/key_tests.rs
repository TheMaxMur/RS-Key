// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::fixtures::{SeqRng, hex, test_key, test_key_640};
use crate::vectors::{ENCRYPT, N_HEX, P_HEX, Q_HEX, SIGN_SHA256};

fn big(v: u32) -> BigUint {
    BigUint::from(v)
}

fn e65537() -> BigUint {
    big(crate::RSA_E)
}

#[test]
fn public_exponent_refusals_are_not_masked_by_a_missing_inverse() {
    for (p, q, e) in [
        (big(11), big(13), big(1)),
        (big(11), big(13), BigUint::from(*PUB_EXP_RANGE.end() + 6)),
        (big(3), big(5), big(17)),
        (big(2), big(5), big(3)),
    ] {
        let lambda = (&p - big(1)).lcm(&(&q - big(1)));
        assert_eq!(e.gcd(&lambda), big(1));
        assert!(RsaKey::from_p_q(p, q, e).is_none());
    }
}

#[test]
fn private_operations_refuse_each_output_width_before_drawing_a_blind() {
    let oversized = RsaKey::from_p_q(
        (BigUint::from(1u8) << (MAX_RSA_BYTES * 8)) + big(1),
        big(17),
        big(3),
    )
    .unwrap();
    assert!(oversized.size() > MAX_RSA_BYTES);
    let mut rng = SeqRng(9);
    let mut out = [0xa5; MAX_RSA_BYTES];
    assert_eq!(
        crate::pkcs1v15::rsa_decrypt(&oversized, &[1], &mut rng, &mut out),
        Err(RsaError::BadWidth)
    );
    assert_eq!(out, [0xa5; MAX_RSA_BYTES]);
    assert_eq!(rng.0, 9);
    let ordinary = test_key();
    for (key, room) in [
        (&oversized, MAX_RSA_BYTES),
        (&ordinary, ordinary.size() - 1),
    ] {
        let mut rng = SeqRng(9);
        let mut out = vec![0xa5; room];
        assert_eq!(
            key.private_op(&[1], &mut rng, &mut out),
            Err(RsaError::BadWidth)
        );
        assert_eq!(out, vec![0xa5; room]);
        assert_eq!(rng.0, 9);
    }
}

fn p() -> BigUint {
    BigUint::from_bytes_be(&hex(P_HEX))
}

fn q() -> BigUint {
    BigUint::from_bytes_be(&hex(Q_HEX))
}

#[test]
fn assembles_the_openssl_key() {
    let k = test_key();
    assert_eq!(k.n_be(), hex(N_HEX));
    assert_eq!(k.e_be(), crate::RSA_PUB_EXP_BE);
    assert_eq!(k.size(), 256);
    assert_eq!(*k.p(), p());
    assert_eq!(*k.q(), q());
}

#[test]
fn crt_parameters_are_the_carmichael_ones() {
    // dP = d mod (p−1), dQ = d mod (q−1), qInv·q ≡ 1 (mod p) — the three values
    // the sealed blob caches, checked against the key's own d rather than
    // against a second copy of the same derivation.
    let k = test_key();
    let (dp, dq, qinv) = k.crt().unwrap();
    assert_eq!(*dp, &k.d % (p() - big(1)));
    assert_eq!(*dq, &k.d % (q() - big(1)));
    assert_eq!((qinv * q()) % p(), big(1));
    // And d is the Carmichael exponent, not Euler's: d < λ(n) = lcm(p−1, q−1).
    assert!(k.d < (p() - big(1)).lcm(&(q() - big(1))));
}

#[test]
fn refuses_a_key_that_is_not_one() {
    let (p, q) = (p(), q());
    // Degenerate primes — `p − 1` would underflow num-bigint's unsigned
    // subtraction, which panics rather than erroring (a device halt on import).
    assert!(RsaKey::from_p_q(big(0), q.clone(), e65537()).is_none());
    assert!(RsaKey::from_p_q(big(1), q.clone(), e65537()).is_none());
    assert!(RsaKey::from_p_q(p.clone(), big(0), e65537()).is_none());
    // p == q gives n = p², which no CRT layout describes.
    assert!(RsaKey::from_p_q(p.clone(), p.clone(), e65537()).is_none());
    // Exponent out of the accepted range, at both ends.
    assert!(RsaKey::from_p_q(p.clone(), q.clone(), big(1)).is_none());
    assert!(
        RsaKey::from_p_q(p.clone(), q.clone(), BigUint::from(PUB_EXP_RANGE.end() + 1)).is_none()
    );
    // Even exponent, and one that is not coprime to λ(n) so `d` does not exist.
    assert!(RsaKey::from_p_q(p.clone(), q.clone(), big(4)).is_none());
    assert!(RsaKey::from_p_q(big(11), big(23), big(5)).is_none()); // 5 | lcm(10, 22)
    // e ≥ n.
    assert!(RsaKey::from_p_q(big(11), big(23), e65537()).is_none());
}

/// Two composites sharing a factor pass every `validate` arm — `d·e ≡ 1` holds
/// modulo each of `p−1` and `q−1` by construction — yet have no `q⁻¹ mod p`. An
/// authenticated IMPORT is the only way to offer such a pair, and the `rsa`
/// crate accepted it too (its `precompute` error was discarded). What must hold
/// is that the key exists without CRT parameters and that sealing it refuses.
#[test]
fn primes_sharing_a_factor_yield_a_key_with_no_crt_form() {
    let k = RsaKey::from_p_q(big(303), big(309), e65537()).expect("validate accepts 3·101, 3·103");
    assert!(k.crt().is_none());
    let mut plain = [0u8; crate::MAX_CRT_PLAIN];
    assert_eq!(
        crate::crt::crt_plaintext(&k, &mut plain),
        Err(RsaError::Failed),
        "a key with no CRT form must fail loud at seal time"
    );
}

#[test]
fn private_op_reproduces_openssl_signatures() {
    // The software private op, over the same EM PSO:CDS builds, against
    // OpenSSL's frozen signatures. This is the CRT branch (the key has one).
    let k = test_key();
    for (i, (digest, want)) in SIGN_SHA256.iter().enumerate() {
        let hash = hex(digest);
        let mlen = k.size();
        let dlen = crate::fixtures::DI_SHA256.len() + hash.len();
        let mut em = [0xffu8; MAX_RSA_BYTES];
        em[0] = 0x00;
        em[1] = 0x01;
        em[mlen - dlen - 1] = 0x00;
        em[mlen - dlen..mlen - hash.len()].copy_from_slice(crate::fixtures::DI_SHA256);
        em[mlen - hash.len()..mlen].copy_from_slice(&hash);
        let mut out = [0u8; MAX_RSA_BYTES];
        let n = k
            .private_op(&em[..mlen], &mut SeqRng(5 + i as u64), &mut out)
            .unwrap();
        assert_eq!(&out[..n], hex(want).as_slice(), "signature {i}");
    }
}

#[test]
fn private_op_takes_the_non_crt_branch_to_the_same_answer() {
    // Garner's recombination and the plain `cᵈ mod n` are the two branches of
    // one operation; a key with no CRT form exercises the second, so a bug in
    // either shows up as the two disagreeing on the same input.
    let k = test_key();
    let (n, e, d) = (k.n.clone(), k.e.clone(), k.d.clone());
    let plain = RsaKey {
        n,
        e,
        d,
        p: p(),
        q: q(),
        crt: None,
    };
    let (digest, want) = SIGN_SHA256[1];
    let hash = hex(digest);
    let mlen = plain.size();
    let dlen = crate::fixtures::DI_SHA256.len() + hash.len();
    let mut em = [0xffu8; MAX_RSA_BYTES];
    em[0] = 0x00;
    em[1] = 0x01;
    em[mlen - dlen - 1] = 0x00;
    em[mlen - dlen..mlen - hash.len()].copy_from_slice(crate::fixtures::DI_SHA256);
    em[mlen - hash.len()..mlen].copy_from_slice(&hash);
    let mut out = [0u8; MAX_RSA_BYTES];
    let n = plain
        .private_op(&em[..mlen], &mut SeqRng(31), &mut out)
        .unwrap();
    assert_eq!(&out[..n], hex(want).as_slice());
}

#[test]
fn private_op_refuses_a_faulted_crt_intermediate() {
    // The software half of the same composition as `crt_tests.rs`'s: a `dP` off
    // by one leaves Garner's result congruent mod `q` only, and `mᵉ ≢ c` is the
    // one thing that stops it. The positive vectors above cannot fall for this.
    let mut k = test_key();
    let mlen = k.size();
    let mut em = [0xffu8; MAX_RSA_BYTES];
    em[0] = 0x00;
    em[1] = 0x01;
    let mut out = [0u8; MAX_RSA_BYTES];
    assert_eq!(
        k.private_op(&em[..mlen], &mut SeqRng(5), &mut out),
        Ok(mlen)
    );

    k.crt.as_mut().unwrap().dp += big(1);
    assert_eq!(
        k.private_op(&em[..mlen], &mut SeqRng(5), &mut out),
        Err(RsaError::Failed)
    );
}

#[test]
fn private_op_refuses_a_block_that_is_not_below_the_modulus() {
    // `cᵈ` is only defined for `c < n`; a wider block would decrypt `c mod n`
    // and then fail the fault check anyway, so it is refused up front —
    // `BadBlock`, the `WRONG_DATA` a short/oversized challenge already answers.
    let k = test_key();
    let mut out = [0u8; MAX_RSA_BYTES];
    let too_big = [0xffu8; 256];
    assert_eq!(
        k.private_op(&too_big, &mut SeqRng(7), &mut out),
        Err(RsaError::BadBlock)
    );
    // And an output buffer that cannot hold the modulus width is `BadWidth`.
    let mut narrow = [0u8; 255];
    assert_eq!(
        k.private_op(&[0x01u8], &mut SeqRng(7), &mut narrow),
        Err(RsaError::BadWidth)
    );
}

#[test]
fn private_op_round_trips_an_openssl_ciphertext() {
    // The other direction of the same operation, on a key too narrow for the asm
    // core — so this is the software arm PSO:DECIPHER falls back to.
    let k = test_key();
    for (i, (msg, ct)) in ENCRYPT.iter().enumerate() {
        let mut em = [0u8; MAX_RSA_BYTES];
        let n = k
            .private_op(&hex(ct), &mut SeqRng(11 + i as u64), &mut em)
            .unwrap();
        let mut out = [0u8; MAX_RSA_BYTES];
        let mn = crate::pkcs1v15::unpad_encrypt(&em[..n], &mut out).unwrap();
        assert_eq!(&out[..mn], hex(msg).as_slice(), "message {i}");
    }
}

#[test]
fn modulus_be_skips_the_key_rebuild() {
    // PIV GET METADATA takes this path instead of assembling a key; it owes the
    // same bytes, and must refuse rather than truncate into a short buffer.
    let mut out = [0u8; 256];
    let n = modulus_be(&hex(P_HEX), &hex(Q_HEX), &mut out).unwrap();
    assert_eq!(&out[..n], hex(N_HEX).as_slice());
    assert_eq!(&out[..n], test_key().n_be().as_slice());
    let mut narrow = [0u8; 255];
    assert_eq!(
        modulus_be(&hex(P_HEX), &hex(Q_HEX), &mut narrow),
        Err(RsaError::BadWidth)
    );
}

#[test]
fn size_is_the_modulus_width_not_the_prime_width() {
    // The 640-bit key's primes are 40 bytes; every buffer sized off `size()`
    // must be the 80-byte modulus, or a signature is written short.
    assert_eq!(test_key_640().size(), 80);
    assert_eq!(test_key_640().n_be().len(), 80);
}
