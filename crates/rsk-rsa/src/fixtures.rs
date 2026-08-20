// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Test fixtures shared by this crate's sibling test modules: the three fixed
//! keys of [`crate::vectors`] and a deterministic RNG. Shared rather than copied
//! per module — the CRT, PKCS#1 and public-DO tests all want to be talking about
//! the *same* key, or a mismatch between them reads as a bug in whichever one is
//! looked at second.

use num_bigint_dig::BigUint;

use crate::crt::{MAX_CRT_PLAIN, RsaCrt, crt_from_plain, crt_plaintext};
use crate::{Rng, RsaKey, keygen::rsa_from_pqe};

pub(crate) use crate::vectors::{
    N_HEX, P_HEX, P640_HEX, P1024_HEX, Q_HEX, Q640_HEX, Q1024_HEX, hex,
};

const E_BE: &[u8] = crate::RSA_PUB_EXP_BE;

pub(crate) struct SeqRng(pub(crate) u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

/// The RSA-2048 key every sign / decipher known-answer vector is over.
pub(crate) fn test_key() -> RsaKey {
    rsa_from_pqe(E_BE, &hex(P_HEX), &hex(Q_HEX)).unwrap()
}

/// The RSA-1024 key: `half = 64`, the one width whose 5-field CRT blob is also a
/// readable `P‖Q` one (320 = 5·64 = 2·160).
pub(crate) fn test_key_1024() -> RsaKey {
    rsa_from_pqe(E_BE, &hex(P1024_HEX), &hex(Q1024_HEX)).unwrap()
}

/// The RSA-640 key: `half = 40`, which the asm CRT core refuses because it is
/// not a multiple of 32. Generation cannot produce one; only an import can.
pub(crate) fn test_key_640() -> RsaKey {
    rsa_from_pqe(E_BE, &hex(P640_HEX), &hex(Q640_HEX)).unwrap()
}

pub(crate) fn modulus() -> BigUint {
    BigUint::from_bytes_be(&hex(N_HEX))
}

/// The CRT signing view an applet builds at seal time, so the sign tests drive
/// the same path production does.
pub(crate) fn crt_of(key: &RsaKey) -> RsaCrt {
    let mut plain = [0u8; MAX_CRT_PLAIN];
    let n = crt_plaintext(key, &mut plain).unwrap();
    crt_from_plain(&plain[..n]).unwrap()
}
