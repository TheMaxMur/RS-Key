// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_rsa::crt::{crt_from_plain, crt_plaintext};
use rsk_rsa::rsa_from_pqe;
use rsk_rsa::vectors::{ENCRYPT, P_HEX, Q_HEX, hex};

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

fn test_key() -> RsaKey {
    rsa_from_pqe(&[0x01, 0x00, 0x01], &hex(P_HEX), &hex(Q_HEX)).unwrap()
}

/// The CRT signing view the applet builds at seal time, so the tests drive
/// the same path production does.
fn crt_of(key: &RsaKey) -> RsaCrt {
    let mut plain = [0u8; MAX_CRT_PLAIN];
    let n = crt_plaintext(key, &mut plain).unwrap();
    crt_from_plain(&plain[..n]).unwrap()
}

#[test]
fn rsa_sw_reproduces_every_status_word() {
    // The applet's whole share of the RSA wire surface is this table. `rsk-rsa`
    // names the target in each variant's doc; assert the four arms one by one, so
    // a swapped pair cannot pass by covering for each other.
    assert_eq!(
        rsa_sw(RsaError::BadWidth),
        Sw::WRONG_LENGTH,
        "a bad width must stay 6700"
    );
    assert_eq!(
        rsa_sw(RsaError::BadBlock),
        Sw::WRONG_DATA,
        "a bad input block must stay 6A80"
    );
    assert_eq!(
        rsa_sw(RsaError::BadBlob),
        Sw::MEMORY_FAILURE,
        "an unreadable stored blob must stay 6581"
    );
    assert_eq!(
        rsa_sw(RsaError::Failed),
        Sw::EXEC_ERROR,
        "a failed computation must stay 6400"
    );
}

#[test]
fn decipher_recovers_an_openssl_session_key() {
    // OpenSSL built the padded block (`rsk_rsa::vectors`), so what the applet is
    // asked to read back is what a real gpg peer would have sent.
    let key = test_key();
    let (msg, ct) = ENCRYPT[2];
    let (msg, ct) = (hex(msg), hex(ct));
    // The DECIPHER command prepends the OpenPGP padding-indicator byte.
    let mut data = vec![0x00u8];
    data.extend_from_slice(&ct);
    let mut out = [0u8; MAX_RSA_BYTES];
    let n = rsa_decipher(&crt_of(&key), &mut SeqRng(8), &data, &mut out).unwrap();
    assert_eq!(&out[..n], msg.as_slice());

    // The legacy fallback must return the same plaintext, or a key that took it
    // would silently decrypt to something else than the asm path.
    let mut slow = [0u8; MAX_RSA_BYTES];
    let sn = rsa_decipher_legacy(&key, &mut SeqRng(9), &data, &mut slow).unwrap();
    assert_eq!(&slow[..sn], &out[..n]);
}

#[test]
fn decipher_refuses_a_ciphertext_that_is_not_a_padded_block() {
    // The private op's Bellcore check passes — this really is cᵈ — so the refusal
    // has to come from the unpad, whose status word is deliberately not the one
    // its own error names.
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
