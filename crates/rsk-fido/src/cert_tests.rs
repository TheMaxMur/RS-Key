// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use p256::Sec1Point;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

#[test]
fn cert_is_well_formed_and_self_signed() {
    let key = P256Key::from_scalar(&[0x33; 32]).unwrap();
    let serial = [0x7F; 16];
    let mut out = [0u8; 512];
    let n = build_attestation_cert(&key, &serial, &mut out).unwrap();
    let cert = &out[..n];

    // Outer SEQUENCE with a 2-byte length covering the rest.
    assert_eq!(cert[0], 0x30);
    assert_eq!(cert[1], 0x82);
    let content = ((cert[2] as usize) << 8) | cert[3] as usize;
    assert_eq!(content + 4, n);

    // TBS is the next TBS_LEN bytes; the signature covers it.
    let tbs = &cert[4..4 + TBS_LEN];
    assert_eq!(tbs[0], 0x30);

    // The signature BIT STRING is the tail; verify it under the embedded key.
    let sig_off = 4 + TBS_LEN + SIG_ALG.len();
    assert_eq!(cert[sig_off], 0x03); // BIT STRING
    let bit_len = cert[sig_off + 1] as usize;
    assert_eq!(cert[sig_off + 2], 0x00); // 0 unused bits
    let sig_der = &cert[sig_off + 3..sig_off + 2 + bit_len];

    let (x, y) = key.public_xy();
    let pt = Sec1Point::from_bytes(&crate::ec::sec1_uncompressed(x, y)).unwrap();
    let vk = VerifyingKey::from_sec1_point(&pt).unwrap();
    let sig = Signature::from_der(sig_der).unwrap();
    vk.verify(tbs, &sig).expect("cert is validly self-signed");

    // The subject public key is embedded uncompressed (0x04 ‖ x ‖ y), followed by
    // the extensions block.
    let ext_len = EXT_PREFIX.len() + AAGUID.len();
    let spki_key_off = 4 + TBS_LEN - ext_len - 65;
    assert_eq!(cert[spki_key_off], 0x04);
    assert_eq!(&cert[spki_key_off + 1..spki_key_off + 33], &x);
    assert_eq!(&cert[spki_key_off + 33..spki_key_off + 65], &y);
}

/// WebAuthn §8.2.1 — RP libraries reject a packed x5c leaf that misses any of
/// these, so the template carries them verbatim.
#[test]
fn cert_meets_packed_x5c_certificate_requirements() {
    let key = P256Key::from_scalar(&[0x44; 32]).unwrap();
    let mut out = [0u8; 512];
    let n = build_attestation_cert(&key, &[0x11; 16], &mut out).unwrap();
    let cert = &out[..n];

    let contains = |needle: &[u8]| cert.windows(needle.len()).any(|w| w == needle);
    // Subject-OU is the literal string, Subject-C is a two-character code, and
    // Subject-O / Subject-CN are non-empty.
    assert!(contains(b"Authenticator Attestation"));
    assert!(contains(&[
        0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, b'X', b'X'
    ])); // C=XX
    assert!(contains(b"RS-Key"));
    assert!(contains(b"RS-Key FIDO2"));
    // basicConstraints, critical, with cA absent (= false).
    assert!(contains(&[
        0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x02, 0x30, 0x00
    ]));
    // id-fido-gen-ce-aaguid carrying this build's AAGUID.
    assert!(contains(&[
        0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x1C, 0x01, 0x01, 0x04
    ]));
    assert_eq!(&cert[4 + TBS_LEN - 16..4 + TBS_LEN], &AAGUID);

    // A device provisioned before this template is detected and rebuilt.
    assert!(matches_template(cert));
    assert!(!matches_template(&cert[..4 + TBS_LEN - 20]));
    let mut stale = out;
    stale[4 + TBS_LEN - 1] ^= 0xFF; // AAGUID no longer this build's
    assert!(!matches_template(&stale[..n]));
}

#[test]
fn att_chain_pack_and_iterate() {
    // Two fake TLVs (framing is all that is validated).
    let c1 = [0x30, 0x03, 1, 2, 3];
    let c2 = [0x30, 0x81, 0x02, 9, 8]; // long-form length
    let mut chain = std::vec::Vec::new();
    chain.extend_from_slice(&c1);
    chain.extend_from_slice(&c2);
    let mut out = [0u8; 64];
    let n = att_chain_pack(&chain, &mut out).unwrap();
    assert_eq!(att_chain_count(&out[..n]), 2);
    assert_eq!(att_chain_cert(&out[..n], 0).unwrap(), &c1);
    assert_eq!(att_chain_cert(&out[..n], 1).unwrap(), &c2);
    assert!(att_chain_cert(&out[..n], 2).is_none());
    // Truncation and a non-SEQUENCE head are refused.
    assert!(att_chain_pack(&chain[..6], &mut out).is_none());
    assert!(att_chain_pack(&[0x31, 0x01, 0], &mut out).is_none());
}
