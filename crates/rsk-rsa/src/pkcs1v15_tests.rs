// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::fixtures::{SeqRng, crt_of, test_key};
use rsa::RsaPublicKey;

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
fn agrees_with_the_rsa_crate_on_a_real_encryption() {
    // The reference implementation builds the EM; ours must read it back. This is
    // the differential that matters — a hand-rolled unpad is only worth having if
    // it accepts exactly what a conforming encrypter produces.
    use rsa::traits::PrivateKeyParts;
    use rsa::{BigUint, Pkcs1v15Encrypt};

    let key = RsaPrivateKey::new(&mut RngAdapter(&mut SeqRng(3)), 1024).unwrap();
    let k = key.size();
    for (i, msg) in [b"".as_slice(), b"x", b"a-32-byte-openpgp-session-key!!!"]
        .into_iter()
        .enumerate()
    {
        let ct = RsaPublicKey::from(&key)
            .encrypt(
                &mut RngAdapter(&mut SeqRng(17 + i as u64)),
                Pkcs1v15Encrypt,
                msg,
            )
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
    // The applets' asm CRT signer must produce the same verifiable PKCS#1 v1.5
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
fn sign_crt_refuses_a_raw_block_wider_than_the_modulus() {
    // Not a DigestInfo and not a length-inferable hash, so it takes the raw arm —
    // where anything past the modulus width is `BadBlock` (`WRONG_DATA`).
    let key = test_key();
    let mut out = [0u8; MAX_RSA_BYTES];
    let wide = [0x11u8; 257];
    assert_eq!(
        rsa_sign_crt(&crt_of(&key), &wide, &mut SeqRng(6), &mut out),
        Err(RsaError::BadBlock)
    );
}

/// The raw RSA fallback must be base-blinded yet still compute `m^d mod n`
/// exactly, independent of the blinding factor (CT-audit finding #1).
#[test]
fn rsa_raw_blinded_equals_unblinded() {
    use rsa::BigUint;
    use rsa::traits::PrivateKeyParts;
    let key = RsaPrivateKey::new(&mut RngAdapter(&mut SeqRng(7)), 512).unwrap();
    let ks = key.size();
    let data = [0x2au8; 40];
    let mut out = [0u8; MAX_RSA_BYTES];
    let n = rsa_raw(&key, &data, &mut out, &mut SeqRng(99)).unwrap();
    assert_eq!(n, ks);
    let got = BigUint::from_bytes_be(&out[..ks]);
    let want = BigUint::from_bytes_be(&data).modpow(key.d(), key.n());
    assert_eq!(got, want, "blinded raw RSA must equal m^d mod n");
    // The result must not depend on the random blinding factor.
    let mut out2 = [0u8; MAX_RSA_BYTES];
    rsa_raw(&key, &data, &mut out2, &mut SeqRng(424242)).unwrap();
    assert_eq!(out[..ks], out2[..ks], "blinding must cancel");
}
