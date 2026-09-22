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
    // The private op's Bellcore check passes -- this really is c^d -- so the refusal
    // comes from the unpad. Both arms answer 6581, as a YubiKey 5.8.0 answers every
    // cryptogram it cannot decrypt.
    let key = test_key();
    let crt = crt_of(&key);
    let mut data = vec![0x00u8];
    data.extend(core::iter::repeat_n(0x5Au8, crt.modulus_len()));
    let mut out = [0u8; MAX_RSA_BYTES];
    let new = rsa_decipher(&crt, &mut SeqRng(12), &data, &mut out);
    let old = rsa_decipher_legacy(&key, &mut SeqRng(12), &data, &mut out);
    assert_eq!(new, Err(Sw::MEMORY_FAILURE));
    assert_eq!(new, old);
}

#[test]
fn decipher_answers_what_a_yubikey_answers_to_a_refused_cryptogram() {
    // Measured on a YubiKey 5.8.0 with an RSA-2048 DEC key, two rounds: 6581 to each
    // of these, and 6A80 only to a command with no data at all.
    let key = test_key();
    let crt = crt_of(&key);
    let n = key.n_be();
    let width = n.len();
    let mut n_less_one = n.clone();
    *n_less_one.last_mut().unwrap() -= 1; // n is odd
    let ct = hex(ENCRYPT[2].1);
    // A valid cryptogram plus n that still fits the width: c itself decrypts, so only
    // a range check -- the fault check against the unreduced input -- refuses it.
    let (msg1, c1) = (hex(ENCRYPT[1].0), hex(ENCRYPT[1].1));
    let mut out = [0u8; MAX_RSA_BYTES];
    let n1 = rsa_decipher(
        &crt,
        &mut SeqRng(18),
        &[vec![0x00], c1.clone()].concat(),
        &mut out,
    );
    assert_eq!(n1.map(|k| out[..k].to_vec()), Ok(msg1), "c alone decrypts");
    let cases: [(&str, Vec<u8>, Sw); 8] = [
        (
            "c = 0",
            [vec![0x00], vec![0; width]].concat(),
            Sw::MEMORY_FAILURE,
        ),
        (
            "c = n",
            [vec![0x00], n.clone()].concat(),
            Sw::MEMORY_FAILURE,
        ),
        (
            "c = n - 1",
            [vec![0x00], n_less_one].concat(),
            Sw::MEMORY_FAILURE,
        ),
        (
            "c + n, one width",
            [vec![0x00], add_be(&c1, &n)].concat(),
            Sw::MEMORY_FAILURE,
        ),
        (
            "00 00 prepended",
            [vec![0x00, 0x00, 0x00], ct.clone()].concat(),
            Sw::MEMORY_FAILURE,
        ),
        (
            "one byte short",
            [vec![0x00], ct[1..].to_vec()].concat(),
            Sw::MEMORY_FAILURE,
        ),
        ("the indicator alone", vec![0x00], Sw::MEMORY_FAILURE),
        ("no data at all", vec![], Sw::WRONG_DATA),
    ];
    for (what, data, sw) in cases {
        let asm = rsa_decipher(&crt, &mut SeqRng(16), &data, &mut out);
        assert_eq!(asm, Err(sw), "{what}: the asm CRT arm");
        let legacy = rsa_decipher_legacy(&key, &mut SeqRng(17), &data, &mut out);
        assert_eq!(legacy, Err(sw), "{what}: the legacy arm");
    }
}

/// `a + b`, big-endian at one width, for a sum that does not carry out of it.
fn add_be(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; a.len()];
    let mut carry = 0u16;
    for i in (0..a.len()).rev() {
        let s = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = s as u8;
        carry = s >> 8;
    }
    assert_eq!(carry, 0, "the sum must stay one modulus wide");
    out
}

#[test]
fn decipher_does_not_check_the_padding_indicator_either() {
    // A YubiKey 5.8.0 decrypts behind 00, 01 and FF alike (02 is RS-Key's AES PSO,
    // routed before this); a stricter check here would diverge with nothing red.
    let key = test_key();
    let crt = crt_of(&key);
    let (msg, ct) = (hex(ENCRYPT[2].0), hex(ENCRYPT[2].1));
    let mut out = [0u8; MAX_RSA_BYTES];
    for indicator in [0x00u8, 0x01, 0xFF] {
        let data = [vec![indicator], ct.clone()].concat();
        let n = rsa_decipher(&crt, &mut SeqRng(19), &data, &mut out);
        assert_eq!(
            n.map(|k| out[..k].to_vec()),
            Ok(msg.clone()),
            "{indicator:02X}: asm CRT"
        );
        let n = rsa_decipher_legacy(&key, &mut SeqRng(20), &data, &mut out);
        assert_eq!(
            n.map(|k| out[..k].to_vec()),
            Ok(msg.clone()),
            "{indicator:02X}: legacy"
        );
    }
}

#[test]
fn decipher_refuses_a_cryptogram_with_bytes_appended() {
    // Wycheproof's `appended bytes to ciphertext`: reading the first modulus-width
    // bytes after the indicator decrypted it and dropped the tail. A YubiKey 5.8.0
    // answers 6581, one byte appended or two.
    let key = test_key();
    let crt = crt_of(&key);
    let (_, ct) = ENCRYPT[2];
    let mut out = [0u8; MAX_RSA_BYTES];
    for tail in [&[0x00u8][..], &[0x00, 0x00]] {
        let mut data = vec![0x00u8];
        data.extend(hex(ct));
        data.extend_from_slice(tail);
        let n = tail.len();
        assert_eq!(
            rsa_decipher(&crt, &mut SeqRng(14), &data, &mut out),
            Err(Sw::MEMORY_FAILURE),
            "the asm CRT arm, {n} byte(s) appended"
        );
        assert_eq!(
            rsa_decipher_legacy(&key, &mut SeqRng(15), &data, &mut out),
            Err(Sw::MEMORY_FAILURE),
            "the legacy arm, {n} byte(s) appended"
        );
    }
}

/// Every Wycheproof decryption case through both DECIPHER arms, behind the padding
/// indicator a host sends: the asm CRT arm over the five-field blob a sealed key
/// holds, and the legacy one. A valid case gives its message back; an invalid one
/// is refused with 6581, the one answer a YubiKey 5.8.0 gives every such shape.
#[test]
fn wycheproof_decipher_reads_the_valid_and_refuses_the_rest() {
    use rsk_rsa::wycheproof::{Outcome, decrypt};
    let cases = decrypt();
    assert_eq!(cases.len(), 201, "Wycheproof RSA decryption cases");
    for case in &cases {
        let (bits, tc, comment) = (case.bits, case.tc_id, case.comment);
        let at = format!("RSA-{bits} tcId {tc} ({comment})");
        let blob: Vec<u8> = case.crt.iter().flat_map(|f| hex(f)).collect();
        let crt = crt_from_plain(&blob).unwrap_or_else(|e| panic!("{at}: CRT blob {e:?}"));
        let key = rsa_from_pqe(&[0x01, 0x00, 0x01], &hex(case.crt[0]), &hex(case.crt[1]))
            .unwrap_or_else(|| panic!("{at}: the key"));
        let data = [vec![0x00], hex(case.ct)].concat();
        let mut out = [0u8; MAX_RSA_BYTES];
        let asm = rsa_decipher(&crt, &mut SeqRng(21), &data, &mut out).map(|n| out[..n].to_vec());
        let legacy =
            rsa_decipher_legacy(&key, &mut SeqRng(22), &data, &mut out).map(|n| out[..n].to_vec());
        let want = match case.result {
            Outcome::Valid => Ok(hex(case.msg)),
            Outcome::Invalid => Err(Sw::MEMORY_FAILURE),
            Outcome::Acceptable => panic!("{at}: no decryption case is merely acceptable"),
        };
        assert_eq!(asm, want, "{at}: the asm CRT arm");
        assert_eq!(legacy, want, "{at}: the legacy arm");
    }
}
