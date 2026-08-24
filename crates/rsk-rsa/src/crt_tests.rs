// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::fixtures::{
    P_HEX, Q_HEX, SeqRng, crt_of, hex, modulus, test_key, test_key_640, test_key_1024,
};
use crate::vectors::SIGN_SHA256;

// A 256-byte PKCS#1-shaped block guaranteed < n (leads 00 01), so the raw private
// op is well-defined and the fault check passes.
fn sample_block() -> [u8; 256] {
    let mut b = [0xffu8; 256];
    b[0] = 0x00;
    b[1] = 0x01;
    b[254] = 0x00;
    b[255] = 0x2a;
    b
}

#[test]
fn parse_rsa_blob_discriminates_layouts() {
    // These lengths are unambiguous (only one arm is in range), so content does
    // not matter: RSA-2048 half=128 (2-field 256, 5-field 640), RSA-4096 half=256.
    assert_eq!(parse_rsa_blob(&[0u8; 256]).unwrap(), (128, false));
    assert_eq!(parse_rsa_blob(&[0u8; 640]).unwrap(), (128, true));
    assert_eq!(parse_rsa_blob(&[0u8; 512]).unwrap(), (256, false));
    assert_eq!(parse_rsa_blob(&[0u8; 1280]).unwrap(), (256, true));
    // A non-standard even width (RSA-1600, half=100) reads as 2-field so it can
    // still DECIPHER on num-bigint; the asm sign path rejects it separately.
    assert_eq!(parse_rsa_blob(&[0u8; 200]).unwrap(), (100, false));
    // Out of range fails closed — as `BadBlob`, which the applets answer
    // `MEMORY_FAILURE` to. The variant is the wire surface: pin it, not `is_err`.
    assert_eq!(parse_rsa_blob(&[0u8; 0]), Err(RsaError::BadBlob));
    assert_eq!(parse_rsa_blob(&[0u8; 5 * 257]), Err(RsaError::BadBlob)); // half > CRT_FIELD
}

#[test]
fn crt_plaintext_is_five_fields_and_reloads() {
    let key = test_key();
    let mut plain = [0u8; MAX_CRT_PLAIN];
    let n = crt_plaintext(&key, &mut plain).unwrap();
    assert_eq!(n, 5 * 128); // P‖Q‖dP‖dQ‖qInv, half = 128
    // First two fields are the primes, big-endian, right-aligned.
    assert_eq!(&plain[..128], hex(P_HEX).as_slice());
    assert_eq!(&plain[128..256], hex(Q_HEX).as_slice());
    // The CRT form must parse back and carry cached params (is_crt = true).
    assert_eq!(parse_rsa_blob(&plain[..n]).unwrap(), (128, true));
    let crt = crt_from_plain(&plain[..n]).unwrap();
    assert_eq!(crt.modulus_len(), 256);
    assert_eq!(crt.p(), hex(P_HEX).as_slice());
    assert_eq!(crt.q(), hex(Q_HEX).as_slice());
}

#[test]
fn private_op_five_field_satisfies_bellcore() {
    // crt_plaintext (cached CRT) → private_op → sigᵉ ≡ c (mod n): the same
    // invariant the in-op Bellcore check enforces, verified independently here.
    let key = test_key();
    let mut plain = [0u8; MAX_CRT_PLAIN];
    let n = crt_plaintext(&key, &mut plain).unwrap();
    let crt = crt_from_plain(&plain[..n]).unwrap();
    let c = sample_block();
    let mut sig = [0u8; MAX_RSA_BYTES];
    let sn = private_op(&crt, &c, &mut SeqRng(1), &mut sig).unwrap();
    assert_eq!(sn, 256);
    let m = BigUint::from_bytes_be(&c);
    let s = BigUint::from_bytes_be(&sig[..sn]);
    assert_eq!(s.modpow(&rsa_e(), &modulus()), m);
}

#[test]
fn private_op_legacy_two_field_recomputes_and_matches() {
    // An old `P‖Q` blob (no cached dP/dQ/qInv) must recompute them and produce a
    // byte-identical signature to the 5-field path.
    let mut two = [0u8; 256];
    two[..128].copy_from_slice(&hex(P_HEX));
    two[128..].copy_from_slice(&hex(Q_HEX));
    assert_eq!(parse_rsa_blob(&two).unwrap(), (128, false));
    let crt_legacy = crt_from_plain(&two).unwrap();

    let key = test_key();
    let mut plain = [0u8; MAX_CRT_PLAIN];
    let n = crt_plaintext(&key, &mut plain).unwrap();
    let crt_cached = crt_from_plain(&plain[..n]).unwrap();

    let c = sample_block();
    let (mut a, mut b) = ([0u8; MAX_RSA_BYTES], [0u8; MAX_RSA_BYTES]);
    let an = private_op(&crt_legacy, &c, &mut SeqRng(9), &mut a).unwrap();
    let bn = private_op(&crt_cached, &c, &mut SeqRng(9), &mut b).unwrap();
    assert_eq!(&a[..an], &b[..bn]);
    // And it verifies under the public exponent.
    let s = BigUint::from_bytes_be(&a[..an]);
    assert_eq!(s.modpow(&rsa_e(), &modulus()), BigUint::from_bytes_be(&c));
}

#[test]
fn private_op_reproduces_an_openssl_signature() {
    // The asm CRT core, driven exactly as PSO:CDS drives it, against OpenSSL's
    // own PKCS#1 v1.5 signatures over the same key. Byte-for-byte, not
    // "verifies": a signer that is merely self-consistent passes the latter.
    let key = test_key();
    let mut plain = [0u8; MAX_CRT_PLAIN];
    let n = crt_plaintext(&key, &mut plain).unwrap();
    let crt = crt_from_plain(&plain[..n]).unwrap();

    for (i, (digest, want)) in SIGN_SHA256.iter().enumerate() {
        let hash = hex(digest);
        let dlen = crate::pkcs1v15::DI_SHA256.len() + hash.len();
        let mlen = 256;
        let mut em = [0xffu8; MAX_RSA_BYTES];
        em[0] = 0x00;
        em[1] = 0x01;
        em[mlen - dlen - 1] = 0x00;
        em[mlen - dlen..mlen - hash.len()].copy_from_slice(crate::pkcs1v15::DI_SHA256);
        em[mlen - hash.len()..mlen].copy_from_slice(&hash);

        let mut sig = [0u8; MAX_RSA_BYTES];
        let sn = private_op(&crt, &em[..mlen], &mut SeqRng(3 + i as u64), &mut sig).unwrap();
        assert_eq!(&sig[..sn], hex(want).as_slice(), "signature {i}");
    }
}

#[test]
fn private_op_refuses_a_block_of_the_wrong_width() {
    // Not the modulus width — `BadBlock`, which the applets answer `WRONG_DATA`
    // to. PIV's GENERAL AUTHENTICATE relies on that word for a short challenge.
    let key = test_key();
    let crt = crt_of(&key);
    let mut out = [0u8; MAX_RSA_BYTES];
    let short = [0u8; 255];
    assert_eq!(
        private_op(&crt, &short, &mut SeqRng(4), &mut out),
        Err(RsaError::BadBlock)
    );
}

#[test]
fn parse_disambiguates_320_byte_collision() {
    // n=320 reads as both 5·64 (RSA-1024 CRT) and 2·160 (RSA-2560 P‖Q). A genuine
    // 5-field blob is recognised via qInv·Q ≡ 1 mod P; a legacy P‖Q blob is not,
    // so an already-provisioned RSA-2560 key still loads as 2-field after upgrade.
    let k = test_key_1024();
    let mut five = [0u8; MAX_CRT_PLAIN];
    let fl = crt_plaintext(&k, &mut five).unwrap();
    assert_eq!(fl, 320);
    assert_eq!(parse_rsa_blob(&five[..fl]).unwrap(), (64, true));
    // A 320-byte P‖Q blob (varied bytes, top bit set so P ≥ 2) reads as 2-field.
    let mut two = [0u8; 320];
    for (i, b) in two.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    two[0] |= 0x80;
    assert_eq!(parse_rsa_blob(&two).unwrap(), (160, false));
}

#[test]
fn crt_plaintext_rejects_non_mult32_width() {
    // A non-32-multiple prime width (RSA-640 → 40-byte primes) has no asm CRT
    // path; sealing must fail loud, not seal a blob the loader would refuse.
    let k = test_key_640();
    let mut buf = [0u8; MAX_CRT_PLAIN];
    assert_eq!(crt_plaintext(&k, &mut buf), Err(RsaError::BadWidth));
}

#[test]
fn crt_from_plain_rejects_non_mult32_width() {
    // The loader half of the same rule, and the one PSO:CDS reports: a legacy
    // `P‖Q` blob of a width the asm cannot take answers `WRONG_LENGTH`.
    assert_eq!(crt_from_plain(&[0u8; 200]).err(), Some(RsaError::BadWidth));
}
