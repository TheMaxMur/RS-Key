// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// `00 ‖ 02 ‖ PS(ps_len non-zero) ‖ 00 ‖ msg`.
fn em(ps_len: usize, msg: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(3 + ps_len + msg.len());
    v.extend_from_slice(&[0x00, 0x02]);
    v.extend(core::iter::repeat_n(0xA5u8, ps_len));
    v.push(0x00);
    v.extend_from_slice(msg);
    v
}

fn unpad(block: &[u8]) -> Result<Vec<u8>, Sw> {
    let mut out = [0u8; 512];
    unpad_encrypt(block, &mut out).map(|n| out[..n].to_vec())
}

#[test]
fn accepts_the_minimum_padding() {
    // RFC 8017 §7.2.2: PS is at least 8 octets. Exactly 8 is legal.
    let msg = b"session-key";
    assert_eq!(unpad(&em(8, msg)).unwrap(), msg);
}

#[test]
fn accepts_a_long_pad_and_an_empty_message() {
    assert_eq!(unpad(&em(200, b"k")).unwrap(), b"k");
    assert_eq!(unpad(&em(64, b"")).unwrap(), Vec::<u8>::new());
}

#[test]
fn rejects_a_seven_byte_pad() {
    // One octet under the floor — the block is otherwise well-formed, so this is
    // the length check firing rather than a structural one.
    assert!(unpad(&em(7, b"session-key")).is_err());
}

#[test]
fn rejects_each_structural_defect() {
    let good = em(16, b"session-key");

    let mut first = good.clone();
    first[0] = 0x01;
    assert!(unpad(&first).is_err(), "leading byte must be 0x00");

    let mut second = good.clone();
    second[1] = 0x01;
    assert!(unpad(&second).is_err(), "block type must be 0x02");

    let mut no_sep = good.clone();
    for b in no_sep.iter_mut().skip(2) {
        *b = 0xA5;
    }
    assert!(unpad(&no_sep).is_err(), "a separator must exist");

    assert!(unpad(&good[..10]).is_err(), "no valid form below 11 bytes");
}

#[test]
fn refuses_a_block_too_short_to_index() {
    // The length guard is also what keeps `em[0]`/`em[1]` from indexing off the
    // end. On device a panic is a reset, so deleting it must not stay green.
    for n in 0..11 {
        assert!(unpad(&vec![0u8; n]).is_err(), "{n} bytes");
    }
}

#[test]
fn the_first_zero_is_the_separator() {
    // A zero inside the message must not be mistaken for the separator — the
    // latch takes the first one and the rest of the block is message.
    let msg = [0x11u8, 0x00, 0x22];
    assert_eq!(unpad(&em(8, &msg)).unwrap(), msg);
}

#[test]
fn refuses_a_message_longer_than_the_caller_buffer() {
    let mut out = [0u8; 4];
    assert_eq!(
        unpad_encrypt(&em(8, b"much-longer-than-four"), &mut out),
        Err(Sw::WRONG_LENGTH)
    );
}

#[test]
fn agrees_with_the_rsa_crate_on_a_real_encryption() {
    // The reference implementation builds the EM; ours must read it back. This is
    // the differential that matters — a hand-rolled unpad is only worth having if
    // it accepts exactly what a conforming encrypter produces.
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    use rsa::{BigUint, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

    struct R(u64);
    impl rsa::rand_core::RngCore for R {
        fn next_u32(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            (self.0 >> 32) as u32
        }
        fn next_u64(&mut self) -> u64 {
            u64::from(self.next_u32()) << 32 | u64::from(self.next_u32())
        }
        fn fill_bytes(&mut self, d: &mut [u8]) {
            for b in d.iter_mut() {
                *b = self.next_u32() as u8;
            }
        }
        fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
            self.fill_bytes(d);
            Ok(())
        }
    }
    impl rsa::rand_core::CryptoRng for R {}

    let key = RsaPrivateKey::new(&mut R(3), 1024).unwrap();
    let k = key.size();
    for (i, msg) in [b"".as_slice(), b"x", b"a-32-byte-openpgp-session-key!!!"]
        .into_iter()
        .enumerate()
    {
        let ct = RsaPublicKey::from(&key)
            .encrypt(&mut R(17 + i as u64), Pkcs1v15Encrypt, msg)
            .unwrap();
        // Raw private op, so what reaches our unpad is the reference EM itself.
        let raw = BigUint::from_bytes_be(&ct)
            .modpow(key.d(), key.n())
            .to_bytes_be();
        let mut block = vec![0u8; k];
        block[k - raw.len()..].copy_from_slice(&raw);
        assert_eq!(unpad(&block).unwrap(), msg, "message {i}");
    }
}
