// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn hex(bytes: &[u8]) -> std::string::String {
    use core::fmt::Write;
    let mut s = std::string::String::new();
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

#[test]
fn hmac_sha1_rfc2202_cases() {
    // RFC 2202 §3 case 1.
    let tag = hmac_sha1(&[0x0b; 20], b"Hi There");
    assert_eq!(hex(&tag), "b617318655057264e28bc0b6fb378c8ef146be00");
    // Case 2 — key shorter than the block size.
    let tag = hmac_sha1(b"Jefe", b"what do ya want for nothing?");
    assert_eq!(hex(&tag), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
}

#[test]
fn hmac_sha256_rfc4231_case1() {
    let key = [0x0b; 20];
    let tag = hmac_sha256(&key, b"Hi There");
    assert_eq!(
        hex(&tag),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}

#[test]
fn an_hmac_template_starts_each_frame_from_the_original_key() {
    for length in [0, 1, 32, 63, 64, 65, 129] {
        let key = std::vec![0x39; length];
        let template = HmacSha256::new(&key);
        for round in 0..3 {
            for size in [0, 1, 55, 56, 64, 68, 72, 128, 4096] {
                let message = std::vec![round; size];
                assert_eq!(template.tag(&message), hmac_sha256(&key, &message));
            }
        }
    }
}

#[test]
fn hkdf_sha256_rfc5869_case1() {
    let ikm = [0x0b; 22];
    let salt: [u8; 13] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let mut okm = [0u8; 42];
    hkdf_sha256(&salt, &ikm, &info, &mut okm).unwrap();
    assert_eq!(
        hex(&okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
         34007208d5b887185865"
    );
}

#[test]
fn hkdf_output_too_long_errors() {
    let mut okm = [0u8; 8161]; // > 255*32
    assert_eq!(
        hkdf_sha256(b"salt", b"ikm", b"info", &mut okm),
        Err(Error::BadLength)
    );
}

#[test]
fn hmac_sha512_rfc4231_case1() {
    let key = [0x0b; 20];
    let tag = hmac_sha512(&key, b"Hi There");
    assert_eq!(
        hex(&tag),
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
         daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
    );
}

// No RFC 5869 SHA-512 vectors exist, so check HKDF against its own definition:
// for L ≤ 64, OKM = HMAC(PRK, info‖0x01) where PRK = HMAC(salt, IKM).
#[test]
fn hkdf_sha512_matches_extract_then_expand() {
    let (salt, ikm, info) = (b"salt".as_slice(), b"input key material".as_slice(), b"ctx");
    let mut okm = [0u8; 64];
    hkdf_sha512(salt, ikm, info, &mut okm).unwrap();

    let prk = hmac_sha512(salt, ikm);
    let mut t1_input = std::vec::Vec::from(info.as_slice());
    t1_input.push(0x01);
    assert_eq!(okm, hmac_sha512(&prk, &t1_input));
}

#[test]
fn hkdf_sha512_salt_and_info_change_output() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    hkdf_sha512(b"salt-a", b"ikm", b"info", &mut a).unwrap();
    hkdf_sha512(b"salt-b", b"ikm", b"info", &mut b).unwrap();
    assert_ne!(a, b);
    hkdf_sha512(b"salt-a", b"ikm", b"info-2", &mut b).unwrap();
    assert_ne!(a, b);
}

#[test]
fn hkdf_sha512_output_too_long_errors() {
    let mut okm = [0u8; 16321]; // > 255*64
    assert_eq!(
        hkdf_sha512(b"salt", b"ikm", b"info", &mut okm),
        Err(Error::BadLength)
    );
}

#[test]
fn ct_eq_matches_slice_equality() {
    assert!(ct_eq(b"", b""));
    assert!(ct_eq(b"abc", b"abc"));
    assert!(!ct_eq(b"abc", b"abd")); // last byte differs
    assert!(!ct_eq(b"xbc", b"abc")); // first byte differs
    assert!(!ct_eq(b"abc", b"ab")); // length mismatch
}

#[test]
fn public_hmac_pads_match_independent_hmac_for_all_short_lengths() {
    let inner = [
        0x6d09e22e, 0x9f907107, 0x8bc4a120, 0xfa4f2121, 0x5aa096af, 0x45ea9241, 0xc498c7b0,
        0xce3ccb21,
    ];
    let outer = [
        0xe3b6250e, 0xcf4c54f2, 0xdec4e7fe, 0x6aecc3c3, 0x594e6fe9, 0x79de4b22, 0x72d45449,
        0x4c6daa0a,
    ];
    for length in (0..=512).chain([1023, 1024, 1025, 4096]) {
        let msg: std::vec::Vec<_> = (0..length).map(|i| (i * 73 + 19) as u8).collect();
        let mut reference = Hmac::<sha2::Sha256>::new_from_slice(b"NO-OTP").unwrap();
        reference.update(&msg);
        assert_eq!(
            hmac_sha256_public_pads(inner, outer, &msg).as_slice(),
            reference.finalize().into_bytes().as_slice(),
            "length={length}"
        );
    }
}
