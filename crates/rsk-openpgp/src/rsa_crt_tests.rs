// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsa::RsaPublicKey;

// The same fixed RSA-2048 key as keys_rsa_tests (primes sans the DER sign byte),
// so the CRT layout is exercised against a known modulus.
const P_HEX: &str = "f05c23060effc422e4310c13b5aecda74744925c97c17d202aa9ed306941fa1e942e61c8d9c80961cf90459af36b9e7d529610f5165d60836de5aef2aeb47ea500c5a61bb96fd3bb4aca36d45464cce24ff0b67bb3ba382d9bdd95b7133eab86125800f10b0627fe1bd7689802d767dd9911eefb60d76e2ec860163f3077a5bd";
const Q_HEX: &str = "c6a96b4a9b7bdd654152f3302dd23bd7b18e62f999cf0d44d01c6ce18cfdfb1c29e523edebe5e6df8967f49afe38d6a9345bc6f4f966e0de2902bddc7caf5a4a1761d18b070cd4cda287388cbdf523c39e246c220af3292fee181b4bb1c3f533b74de89c586e6f9d47ae4bb7f8735d3f0b377a76a7ca6c81324833c2b78b737d";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

fn test_key() -> RsaPrivateKey {
    RsaPrivateKey::from_p_q(
        BigUint::from_bytes_be(&hex(P_HEX)),
        BigUint::from_bytes_be(&hex(Q_HEX)),
        rsa_e(),
    )
    .unwrap()
}

fn modulus() -> BigUint {
    BigUint::from_bytes_be(&hex(P_HEX)) * BigUint::from_bytes_be(&hex(Q_HEX))
}

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
    // Out of range fails closed.
    assert!(parse_rsa_blob(&[0u8; 0]).is_err());
    assert!(parse_rsa_blob(&[0u8; 5 * 257]).is_err()); // half > CRT_FIELD
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
fn sign_crt_five_field_satisfies_bellcore() {
    // crt_plaintext (cached CRT) → sign_crt → sigᵉ ≡ c (mod n): the same invariant
    // the in-op Bellcore check enforces, verified independently here.
    let key = test_key();
    let mut plain = [0u8; MAX_CRT_PLAIN];
    let n = crt_plaintext(&key, &mut plain).unwrap();
    let crt = crt_from_plain(&plain[..n]).unwrap();
    let c = sample_block();
    let mut sig = [0u8; MAX_RSA_BYTES];
    let sn = sign_crt(&crt, &c, &mut SeqRng(1), &mut sig).unwrap();
    assert_eq!(sn, 256);
    let m = BigUint::from_bytes_be(&c);
    let s = BigUint::from_bytes_be(&sig[..sn]);
    assert_eq!(s.modpow(&rsa_e(), &modulus()), m);
}

#[test]
fn sign_crt_legacy_two_field_recomputes_and_matches() {
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
    let an = sign_crt(&crt_legacy, &c, &mut SeqRng(9), &mut a).unwrap();
    let bn = sign_crt(&crt_cached, &c, &mut SeqRng(9), &mut b).unwrap();
    assert_eq!(&a[..an], &b[..bn]);
    // And it verifies under the public exponent.
    let s = BigUint::from_bytes_be(&a[..an]);
    assert_eq!(s.modpow(&rsa_e(), &modulus()), BigUint::from_bytes_be(&c));
}

#[test]
fn sign_crt_verifies_a_pkcs1_signature() {
    // End-to-end against the `rsa` crate's PKCS#1 v1.5 verifier: build a full EM
    // (00 01 FF..00 ‖ DigestInfo), sign the raw block, and verify.
    use rsa::Pkcs1v15Sign;
    let key = test_key();
    let mut plain = [0u8; MAX_CRT_PLAIN];
    let n = crt_plaintext(&key, &mut plain).unwrap();
    let crt = crt_from_plain(&plain[..n]).unwrap();

    // SHA-256 DigestInfo prefix + a fixed 32-byte hash.
    let di_sha256: &[u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    let hash = [0x42u8; 32];
    let dlen = di_sha256.len() + hash.len();
    let mlen = 256;
    let mut em = [0xffu8; MAX_RSA_BYTES];
    em[0] = 0x00;
    em[1] = 0x01;
    em[mlen - dlen - 1] = 0x00;
    em[mlen - dlen..mlen - hash.len()].copy_from_slice(di_sha256);
    em[mlen - hash.len()..mlen].copy_from_slice(&hash);

    let mut sig = [0u8; MAX_RSA_BYTES];
    let sn = sign_crt(&crt, &em[..mlen], &mut SeqRng(3), &mut sig).unwrap();

    let mut di = di_sha256.to_vec();
    di.extend_from_slice(&hash);
    RsaPublicKey::from(&key)
        .verify(Pkcs1v15Sign::new_unprefixed(), &di, &sig[..sn])
        .unwrap();
}
