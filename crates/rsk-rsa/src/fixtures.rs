// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Test fixtures shared by this crate's sibling test modules: one fixed RSA-2048
//! key (`openssl genrsa`, primes sans the DER sign byte) and a deterministic RNG.
//! Shared rather than copied per module — the CRT, PKCS#1 and public-DO tests all
//! want to be talking about the *same* key, or a mismatch between them reads as a
//! bug in whichever one is looked at second.

use rsa::BigUint;

use crate::crt::{MAX_CRT_PLAIN, RsaCrt, crt_from_plain, crt_plaintext};
use crate::{Rng, RsaPrivateKey, keygen::rsa_from_pqe};

pub(crate) const P_HEX: &str = "f05c23060effc422e4310c13b5aecda74744925c97c17d202aa9ed306941fa1e942e61c8d9c80961cf90459af36b9e7d529610f5165d60836de5aef2aeb47ea500c5a61bb96fd3bb4aca36d45464cce24ff0b67bb3ba382d9bdd95b7133eab86125800f10b0627fe1bd7689802d767dd9911eefb60d76e2ec860163f3077a5bd";
pub(crate) const Q_HEX: &str = "c6a96b4a9b7bdd654152f3302dd23bd7b18e62f999cf0d44d01c6ce18cfdfb1c29e523edebe5e6df8967f49afe38d6a9345bc6f4f966e0de2902bddc7caf5a4a1761d18b070cd4cda287388cbdf523c39e246c220af3292fee181b4bb1c3f533b74de89c586e6f9d47ae4bb7f8735d3f0b377a76a7ca6c81324833c2b78b737d";
pub(crate) const N_HEX: &str = "ba8654a65ddb75e8cf593ee635345ac0a64d43bd328849683979bf25928cf46489051bf991cdb56a464d83069048c651b049d0181bc08a1e34cb9130a86c67a6283e79100d6c32dce9ddf852ba94cbe1d2b3c89358096cd48a8c90fcb6089819258e44d92d25b0cc4ab2a9224e4489e2eec8abc13a19f520adec2710f8f8ac21b4cebe99a958fe38fe43b50c97375076c2ff5e98980af0c5a719a417ba8f657328ea95f50936d6f459af093bc864b222f89302e9e9972ff491608f7ef93b509c8a65bad0e51bcbf0d2e43d2c9956d762af1d26a01b776471e39a2338babb4f8a30199cf26dd8dbdccf59ef77912b1b700e59c3a7e327ffbb58b6584b827ed449";

pub(crate) fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

pub(crate) struct SeqRng(pub(crate) u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

pub(crate) fn test_key() -> RsaPrivateKey {
    rsa_from_pqe(&[0x01, 0x00, 0x01], &hex(P_HEX), &hex(Q_HEX)).unwrap()
}

pub(crate) fn modulus() -> BigUint {
    BigUint::from_bytes_be(&hex(N_HEX))
}

/// The CRT signing view an applet builds at seal time, so the sign tests drive
/// the same path production does.
pub(crate) fn crt_of(key: &RsaPrivateKey) -> RsaCrt {
    let mut plain = [0u8; MAX_CRT_PLAIN];
    let n = crt_plaintext(key, &mut plain).unwrap();
    crt_from_plain(&plain[..n]).unwrap()
}
