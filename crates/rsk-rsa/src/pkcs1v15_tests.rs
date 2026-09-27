// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::fixtures::{DI_SHA256, SeqRng, crt_of, test_key};
use crate::vectors::{ENCRYPT, SIGN_SHA256, hex};

/// `00 ‖ 02 ‖ PS(ps_len non-zero) ‖ 00 ‖ msg`.
fn em(ps_len: usize, msg: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(3 + ps_len + msg.len());
    v.extend_from_slice(&[0x00, 0x02]);
    v.extend(core::iter::repeat_n(0xA5u8, ps_len));
    v.push(0x00);
    v.extend_from_slice(msg);
    v
}

fn unpad(block: &[u8]) -> Result<Vec<u8>, RsaError> {
    let mut out = [0u8; MAX_RSA_BYTES];
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
    assert_eq!(unpad(&em(7, b"session-key")), Err(RsaError::BadBlock));
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
        Err(RsaError::BadWidth)
    );
}

#[test]
fn decrypts_an_openssl_ciphertext_on_both_arms() {
    // OpenSSL built the padded block; both DECIPHER arms must read it back. This
    // is the differential that matters — a hand-rolled unpad is only worth having
    // if it accepts exactly what a conforming encrypter produces.
    let key = test_key();
    let crt = crt_of(&key);
    let k = key.size();
    for (i, (msg, ct)) in ENCRYPT.iter().enumerate() {
        let (msg, ct) = (hex(msg), hex(ct));
        // The software arm, whole: private op then unpad.
        let mut soft = [0u8; MAX_RSA_BYTES];
        let sn = rsa_decrypt(&key, &ct, &mut SeqRng(17 + i as u64), &mut soft).unwrap();
        assert_eq!(&soft[..sn], msg.as_slice(), "software arm, message {i}");
        // The asm CRT arm the applet takes for a key of a width it can handle.
        let mut em = [0u8; MAX_RSA_BYTES];
        crate::crt::private_op(&crt, &ct, &mut SeqRng(23 + i as u64), &mut em[..k]).unwrap();
        assert_eq!(unpad(&em[..k]).unwrap(), msg, "asm arm, message {i}");
    }
}

#[test]
fn sign_crt_digestinfo_matches_openssl() {
    // The applets' asm CRT signer, over the CRT view built at seal time, must
    // produce OpenSSL's signature over the SHA-256 DigestInfo gpg sends.
    let key = test_key();
    let crt = crt_of(&key);
    for (i, (digest, want)) in SIGN_SHA256.iter().enumerate() {
        let mut di = DI_SHA256.to_vec();
        di.extend_from_slice(&hex(digest));
        let mut asm = [0u8; MAX_RSA_BYTES];
        let n = rsa_sign_crt(&crt, &di, &mut SeqRng(1 + i as u64), &mut asm).unwrap();
        assert_eq!(n, 256);
        assert_eq!(&asm[..n], hex(want).as_slice(), "signature {i}");
    }
}

#[test]
fn sign_crt_pads_up_to_k_minus_11_bytes_and_refuses_past_it() {
    // Type 1 needs `00 01`, eight bytes of padding and the `00` separator: 245 bytes
    // of data is the most a 2048-bit block carries, and 246 is `BadWidth`.
    let key = test_key();
    let crt = crt_of(&key);
    let mut out = [0u8; MAX_RSA_BYTES];
    let most = [0x11u8; 245];
    let n = rsa_sign_crt(&crt, &most, &mut SeqRng(6), &mut out).unwrap();
    let (n_be, e_be) = (key.n_be(), key.e_be());
    assert!(crate::verify::verify_pkcs1v15(
        &n_be,
        &e_be,
        &most,
        &out[..n]
    ));
    assert_eq!(
        rsa_sign_crt(&crt, &[0x11u8; 246], &mut SeqRng(7), &mut out),
        Err(RsaError::BadWidth)
    );
}
