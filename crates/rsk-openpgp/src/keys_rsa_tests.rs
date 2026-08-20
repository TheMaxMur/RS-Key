// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsa::{Pkcs1v15Sign, RsaPublicKey};

// A fixed RSA-2048 key (openssl genrsa), primes sans the DER sign byte.
const P_HEX: &str = "f05c23060effc422e4310c13b5aecda74744925c97c17d202aa9ed306941fa1e942e61c8d9c80961cf90459af36b9e7d529610f5165d60836de5aef2aeb47ea500c5a61bb96fd3bb4aca36d45464cce24ff0b67bb3ba382d9bdd95b7133eab86125800f10b0627fe1bd7689802d767dd9911eefb60d76e2ec860163f3077a5bd";
const Q_HEX: &str = "c6a96b4a9b7bdd654152f3302dd23bd7b18e62f999cf0d44d01c6ce18cfdfb1c29e523edebe5e6df8967f49afe38d6a9345bc6f4f966e0de2902bddc7caf5a4a1761d18b070cd4cda287388cbdf523c39e246c220af3292fee181b4bb1c3f533b74de89c586e6f9d47ae4bb7f8735d3f0b377a76a7ca6c81324833c2b78b737d";
const N_HEX: &str = "ba8654a65ddb75e8cf593ee635345ac0a64d43bd328849683979bf25928cf46489051bf991cdb56a464d83069048c651b049d0181bc08a1e34cb9130a86c67a6283e79100d6c32dce9ddf852ba94cbe1d2b3c89358096cd48a8c90fcb6089819258e44d92d25b0cc4ab2a9224e4489e2eec8abc13a19f520adec2710f8f8ac21b4cebe99a958fe38fe43b50c97375076c2ff5e98980af0c5a719a417ba8f657328ea95f50936d6f459af093bc864b222f89302e9e9972ff491608f7ef93b509c8a65bad0e51bcbf0d2e43d2c9956d762af1d26a01b776471e39a2338babb4f8a30199cf26dd8dbdccf59ef77912b1b700e59c3a7e327ffbb58b6584b827ed449";

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
    rsa_from_pqe(&[0x01, 0x00, 0x01], &hex(P_HEX), &hex(Q_HEX)).unwrap()
}

/// The CRT signing view the applet builds at seal time, so the sign tests drive
/// the same path production does.
fn crt_of(key: &RsaPrivateKey) -> crate::rsa_crt::RsaCrt {
    let mut plain = [0u8; crate::rsa_crt::MAX_CRT_PLAIN];
    let n = crate::rsa_crt::crt_plaintext(key, &mut plain).unwrap();
    crate::rsa_crt::crt_from_plain(&plain[..n]).unwrap()
}

#[test]
fn import_rejects_degenerate_primes() {
    // A zero-valued prime MPI must be rejected, not panic num-bigint's unsigned
    // subtraction inside from_p_q (a device-halt on import). The applet's
    // is_empty() guard misses a non-empty `00`, so rsa_from_pqe fails closed itself.
    let e = [0x01, 0x00, 0x01];
    assert!(rsa_from_pqe(&e, &[], &hex(Q_HEX)).is_none());
    assert!(rsa_from_pqe(&e, &hex(P_HEX), &[]).is_none());
    assert!(rsa_from_pqe(&e, &[0x00], &hex(Q_HEX)).is_none());
    assert!(rsa_from_pqe(&e, &hex(P_HEX), &[0x00]).is_none());
    assert!(rsa_from_pqe(&e, &[0x01], &hex(Q_HEX)).is_none()); // p = 1 rejected too
}

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
    let body = make_rsa_pub_body(
        &key.n().to_bytes_be(),
        &key.e().to_bytes_be(),
        &mut body_out,
    );
    assert_eq!(&body_out[..body], &full_out[5..full]);
}

#[test]
fn rsa_pub_exp_be_is_65537() {
    // The metadata path hardcodes RSA_PUB_EXP_BE; it must serialize the same 65537
    // exponent make_rsa_response emits from key.e().
    assert_eq!(
        RSA_PUB_EXP_BE,
        rsa::BigUint::from(RSA_E).to_bytes_be().as_slice()
    );
}

#[test]
fn sign_digestinfo_verifies() {
    let key = test_key();
    // A SHA-256 DigestInfo (what gpg sends for an RSA signature).
    let mut di = DI_SHA256.to_vec();
    di.extend_from_slice(&[0x42u8; 32]);
    let mut sig = [0u8; MAX_RSA_BYTES];
    let n = rsa_sign(&key, &di, &mut SeqRng(1), &mut sig).unwrap();
    assert_eq!(n, 256);
    RsaPublicKey::from(&key)
        .verify(Pkcs1v15Sign::new_unprefixed(), &di, &sig[..n])
        .unwrap();
}

#[test]
fn sign_bare_hash_infers_alg() {
    // A bare 32-byte hash is treated as SHA-256 (length inference), so it must
    // verify against the same DigestInfo signature.
    let key = test_key();
    let hash = [0x37u8; 32];
    let mut sig = [0u8; MAX_RSA_BYTES];
    let n = rsa_sign(&key, &hash, &mut SeqRng(2), &mut sig).unwrap();
    let mut di = DI_SHA256.to_vec();
    di.extend_from_slice(&hash);
    RsaPublicKey::from(&key)
        .verify(Pkcs1v15Sign::new_unprefixed(), &di, &sig[..n])
        .unwrap();
}

#[test]
fn sign_crt_digestinfo_verifies() {
    // The applet's asm CRT signer must produce the same verifiable PKCS#1 v1.5
    // signature as the `rsa`-crate path, over the CRT view built at seal time.
    let key = test_key();
    let mut di = DI_SHA256.to_vec();
    di.extend_from_slice(&[0x42u8; 32]);
    let mut asm = [0u8; MAX_RSA_BYTES];
    let n = rsa_sign_crt(&crt_of(&key), &di, &mut SeqRng(1), &mut asm).unwrap();
    assert_eq!(n, 256);
    RsaPublicKey::from(&key)
        .verify(Pkcs1v15Sign::new_unprefixed(), &di, &asm[..n])
        .unwrap();
    // PKCS#1 v1.5 is deterministic, so it is byte-identical to the crate signer.
    let mut crate_sig = [0u8; MAX_RSA_BYTES];
    let cn = rsa_sign(&key, &di, &mut SeqRng(2), &mut crate_sig).unwrap();
    assert_eq!(&asm[..n], &crate_sig[..cn]);
}

#[test]
fn parse_disambiguates_320_byte_collision() {
    // n=320 reads as both 5·64 (RSA-1024 CRT) and 2·160 (RSA-2560 P‖Q). A genuine
    // 5-field blob is recognised via qInv·Q ≡ 1 mod P; a legacy P‖Q blob is not,
    // so an already-provisioned RSA-2560 key still loads as 2-field after upgrade.
    let k = RsaPrivateKey::new(&mut RngAdapter(&mut SeqRng(5)), 1024).unwrap();
    let mut five = [0u8; crate::rsa_crt::MAX_CRT_PLAIN];
    let fl = crate::rsa_crt::crt_plaintext(&k, &mut five).unwrap();
    assert_eq!(fl, 320);
    assert_eq!(
        crate::rsa_crt::parse_rsa_blob(&five[..fl]).unwrap(),
        (64, true)
    );
    // A 320-byte P‖Q blob (varied bytes, top bit set so P ≥ 2) reads as 2-field.
    let mut two = [0u8; 320];
    for (i, b) in two.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    two[0] |= 0x80;
    assert_eq!(crate::rsa_crt::parse_rsa_blob(&two).unwrap(), (160, false));
}

#[test]
fn crt_plaintext_rejects_non_mult32_width() {
    // A non-32-multiple prime width (RSA-640 → 40-byte primes) has no asm CRT
    // path; sealing must fail loud, not seal a blob the loader would refuse.
    let k = RsaPrivateKey::new(&mut RngAdapter(&mut SeqRng(11)), 640).unwrap();
    let mut buf = [0u8; crate::rsa_crt::MAX_CRT_PLAIN];
    assert!(crate::rsa_crt::crt_plaintext(&k, &mut buf).is_err());
}

#[test]
fn decipher_roundtrip() {
    let key = test_key();
    let msg = b"a-32-byte-openpgp-session-key!!!";
    let ct = RsaPublicKey::from(&key)
        .encrypt(&mut RngAdapter(&mut SeqRng(7)), Pkcs1v15Encrypt, msg)
        .unwrap();
    // The DECIPHER command prepends the OpenPGP padding-indicator byte.
    let mut data = vec![0x00u8];
    data.extend_from_slice(&ct);
    let mut out = [0u8; MAX_RSA_BYTES];
    let n = rsa_decipher(&crt_of(&key), &mut SeqRng(8), &data, &mut out).unwrap();
    assert_eq!(&out[..n], msg);

    // The legacy fallback must return the same plaintext, or a key that took it
    // would silently decrypt to something else than the asm path.
    let mut slow = [0u8; MAX_RSA_BYTES];
    let sn = rsa_decipher_legacy(&key, &mut SeqRng(9), &data, &mut slow).unwrap();
    assert_eq!(&slow[..sn], &out[..n]);
}

#[test]
fn decipher_refuses_a_ciphertext_that_is_not_a_padded_block() {
    // `sign_crt`'s Bellcore check passes — this really is cᵈ — so the refusal has
    // to come from the unpad, which is the half being replaced here.
    let key = test_key();
    let crt = crt_of(&key);
    let mut data = vec![0x00u8];
    data.extend(core::iter::repeat_n(0x5Au8, crt.modulus_len()));
    let mut out = [0u8; MAX_RSA_BYTES];
    // Same status word the `rsa` crate's failure produced, so a host that keyed
    // off it before sees no change.
    let new = rsa_decipher(&crt, &mut SeqRng(12), &data, &mut out);
    let old = rsa_decipher_legacy(&key, &mut SeqRng(12), &data, &mut out);
    assert_eq!(new, Err(Sw::EXEC_ERROR));
    assert_eq!(new, old);
}

#[test]
fn decipher_refuses_a_short_command_field() {
    let key = test_key();
    let crt = crt_of(&key);
    let mut out = [0u8; MAX_RSA_BYTES];
    // One byte short of the indicator plus a full modulus-width cryptogram.
    let data = vec![0x00u8; crt.modulus_len()];
    assert_eq!(
        rsa_decipher(&crt, &mut SeqRng(13), &data, &mut out),
        Err(Sw::WRONG_DATA)
    );
}

#[test]
fn keygen_pool_assembles_in_either_order() {
    // The dual-core search feeds primes through `offer` in whatever order the
    // cores find them — both orders must assemble the same modulus.
    let p = BigUint::from_bytes_be(&hex(P_HEX));
    let q = BigUint::from_bytes_be(&hex(Q_HEX));
    for (first, second) in [(p.clone(), q.clone()), (q, p)] {
        let mut kg = RsaKeygen::new(2048);
        assert!(kg.usable());
        assert_eq!(kg.half_bytes(), 128);
        assert!(matches!(kg.offer(first), RsaStep::More));
        match kg.offer(second) {
            RsaStep::Done(k) => assert_eq!(k.n().to_bytes_be(), hex(N_HEX)),
            _ => panic!("two distinct primes must complete the key"),
        }
    }
}

#[test]
fn keygen_pool_le_transport() {
    // The inter-core transport: primes as little-endian bytes, scrubbed on use.
    let (mut p_le, mut q_le) = (hex(P_HEX), hex(Q_HEX));
    p_le.reverse();
    q_le.reverse();
    let mut kg = RsaKeygen::new(2048);
    assert!(matches!(kg.offer_le(&mut p_le), RsaStep::More));
    assert!(
        p_le.iter().all(|&b| b == 0),
        "transport buffer not scrubbed"
    );
    match kg.offer_le(&mut q_le) {
        RsaStep::Done(k) => assert_eq!(k.n().to_bytes_be(), hex(N_HEX)),
        _ => panic!("two distinct primes must complete the key"),
    }
}

#[test]
fn try_candidate_le_finds_exact_half() {
    // Smallest asm-eligible half (32 bytes = RSA-512) so the host search is
    // quick; a find must fill the half exactly, odd and with the top bits set.
    let mut rng = SeqRng(42);
    let mut sieve = IncrementalSieve::new();
    let mut out = [0u8; 32];
    let mut tries = 0;
    let len = loop {
        tries += 1;
        assert!(tries < 200_000, "prime search did not converge");
        if let Some(n) = RsaKeygen::try_candidate_le(&mut sieve, &mut rng, 32, &mut out) {
            break n;
        }
    };
    assert_eq!(len, 32);
    assert_eq!(out[31] & 0xC0, 0xC0);
    assert_eq!(out[0] & 1, 1);
}

#[test]
fn keygen_bpsw_split_matches_library() {
    // try_candidate's accept = strong-MR(asm) + strong-Lucas. Any prime it
    // produces must satisfy the library's own one-call Baillie-PSW — the
    // split changed backends, not the test.
    use num_bigint_dig::prime::probably_prime;
    let mut rng = SeqRng(7);
    let mut sieve = IncrementalSieve::new();
    let (mut found, mut tries) = (0, 0);
    while found < 2 {
        tries += 1;
        assert!(tries < 200_000, "prime search did not converge");
        if let Some(p) = RsaKeygen::try_candidate(&mut sieve, &mut rng, 32) {
            assert!(
                probably_prime(&p, 0),
                "split BPSW accepted what the library rejects"
            );
            found += 1;
        }
    }
}

#[test]
fn keygen_pool_le_rejects_wrong_size_prime() {
    // Belt-and-suspenders: a wrong-length byte-transport find (a stale prime from
    // a prior different-size job) must be dropped and scrubbed, leaving the pool
    // intact — feeding it would corrupt the modulus.
    let mut kg = RsaKeygen::new(2048); // half = 128 bytes
    assert_eq!(kg.half_bytes(), 128);
    let mut under = hex(P_HEX);
    under.truncate(64); // 64 < 128: an under-size stale prime
    assert!(matches!(kg.offer_le(&mut under), RsaStep::More));
    assert!(
        under.iter().all(|&b| b == 0),
        "rejected buffer not scrubbed"
    );
    // …and an over-size stale prime — pins the guard at `!=`, not `<`.
    let mut over = hex(P_HEX);
    over.extend_from_slice(&hex(Q_HEX)[..64]); // 192 > 128
    assert!(matches!(kg.offer_le(&mut over), RsaStep::More));
    assert!(over.iter().all(|&b| b == 0), "rejected buffer not scrubbed");
    // Pool untouched: a correct-size pair still assembles the exact modulus. (Were
    // either wrong prime pooled, this first offer would already return Done.)
    let (mut p_le, mut q_le) = (hex(P_HEX), hex(Q_HEX));
    p_le.reverse();
    q_le.reverse();
    assert!(matches!(kg.offer_le(&mut p_le), RsaStep::More));
    match kg.offer_le(&mut q_le) {
        RsaStep::Done(k) => assert_eq!(k.n().to_bytes_be(), hex(N_HEX)),
        _ => panic!("correct-size primes must complete the key after a reject"),
    }
}

#[test]
fn keygen_pool_rejects_duplicate_prime() {
    let p = BigUint::from_bytes_be(&hex(P_HEX));
    let mut kg = RsaKeygen::new(2048);
    assert!(matches!(kg.offer(p.clone()), RsaStep::More));
    // The same prime again must not assemble a broken p == q key…
    assert!(matches!(kg.offer(p), RsaStep::More));
    // …and the held prime survives: a distinct second one completes the key.
    let q = BigUint::from_bytes_be(&hex(Q_HEX));
    assert!(matches!(kg.offer(q), RsaStep::Done(_)));
}
