// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §6.1 `authenticatorMakeCredential` conformance assertions, driven
//! through the wire envelope (`process_cbor`): the attestation-object shape, the
//! authenticator-data layout, the packed self-attestation statement, and the
//! unsupported-algorithm rejection. A no-PIN request is user-presence-only, so
//! `AlwaysConfirm` satisfies it without arming a token.

use super::{Authr, Resp, assert_ok, field_at, int_map_keys};
use crate::consts::{
    AAGUID, ALG_EDDSA, ALG_ES256, CTAP_MAKE_CREDENTIAL, FLAG_AT, FLAG_UP, MAX_CRED_ID_LENGTH,
};
use crate::error::CtapError;
use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};
use rsk_crypto::sha256;

const RP_ID: &str = "example.com";

/// Every makeCredential ships packed basic attestation with the device x5c.
const ATT_FMT: &str = "packed";

/// A minimal single-algorithm makeCredential request over `RP_ID` (keys 1–4:
/// clientDataHash, rp, user, pubKeyCredParams).
fn mc_request(alg: i64) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().bytes(&[0xCD; 32]).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str(RP_ID)
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        e.str("name").unwrap().str("alice").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(alg).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// A makeCredential over `RP_ID` whose excludeList (key 5) names `cred_id`.
fn mc_request_exclude(cred_id: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(5).unwrap();
        e.u8(1).unwrap().bytes(&[0xCD; 32]).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str(RP_ID)
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        e.str("name").unwrap().str("alice").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(5).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.str("id").unwrap().bytes(cred_id).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

fn make_es256() -> Resp {
    Authr::fresh().send(CTAP_MAKE_CREDENTIAL, &mc_request(ALG_ES256))
}

#[test]
fn makecred_response_envelope() {
    let r = make_es256();
    assert_ok(&r);
    // Attestation object: exactly {1: fmt, 2: authData, 3: attStmt}, canonical.
    assert_eq!(int_map_keys(&r.body), vec![1u32, 2, 3]);
    let mut d = field_at(&r.body, 1).expect("fmt (0x01) present");
    assert_eq!(
        d.str().unwrap(),
        ATT_FMT,
        "attestation format must match the profile default"
    );
}

#[test]
fn makecred_authdata_structure() {
    let r = make_es256();
    let mut d = field_at(&r.body, 2).expect("authData (0x02) present");
    let ad = d.bytes().unwrap();
    // rpIdHash(32) | flags(1) | counter(4) | aaguid(16) | credLen(2) | credId | COSE key
    assert!(
        ad.len() >= 55,
        "authData too short for attested credential data"
    );
    assert_eq!(
        &ad[..32],
        &sha256(RP_ID.as_bytes())[..],
        "rpIdHash must be SHA-256(rpId)"
    );
    assert_eq!(
        ad[32] & (FLAG_AT | FLAG_UP),
        FLAG_AT | FLAG_UP,
        "AT (attested data) and UP (user present) flags must be set"
    );
    assert_eq!(
        &ad[37..53],
        &AAGUID[..],
        "attested aaguid must equal the model constant"
    );
    let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    assert!(cred_len > 0, "credential id must be non-empty");
    assert!(
        cred_len <= MAX_CRED_ID_LENGTH as usize,
        "credential id exceeds the advertised ceiling"
    );
    assert!(
        ad.len() >= 55 + cred_len,
        "authData truncated before the COSE public key"
    );
}

#[test]
fn makecred_attestation_statement() {
    let r = make_es256();
    // Basic attestation is {alg, sig, x5c}, signed by the device key.
    let (alg, sig, leaf) = super::packed_att_stmt(&r.body);
    assert_eq!(alg, ALG_ES256, "the device key is P-256");
    assert!(!sig.is_empty(), "attStmt signature must be present");
    assert_eq!(leaf[0], 0x30, "the x5c entry is a DER certificate");
}

/// GitHub issue #26: OpenSSH (via libfido2) rejected RS-Key's packed **EdDSA**
/// self-attestation on Windows. Self-attestation signs with the credential key, so
/// the statement inherits the credential's algorithm; basic attestation removes
/// that coupling. An Ed25519 credential must still carry an ES256 statement that
/// verifies under the x5c leaf — `fido_cred_verify`'s path, never
/// `fido_cred_verify_self`'s. Verify it the way an external verifier does: with the
/// key reconstructed from the emitted certificate, not from the signing key object.
#[test]
fn makecred_ed25519_attestation_is_es256_under_the_x5c_leaf() {
    let r = Authr::fresh().send(CTAP_MAKE_CREDENTIAL, &mc_request(ALG_EDDSA));
    assert_ok(&r);

    let ad = {
        let mut d = field_at(&r.body, 2).expect("authData (0x02) present");
        d.bytes().unwrap().to_vec()
    };
    // The credential itself is Ed25519: OKP {1:1, 3:-8, -1:6, -2:<32-byte x>}.
    let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let mut d = Decoder::new(&ad[55 + cred_len..]);
    assert_eq!(d.map().unwrap().unwrap(), 4);
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.u8().unwrap(), 1, "kty is OKP");
    assert_eq!(d.u8().unwrap(), 3);
    assert_eq!(d.i64().unwrap(), ALG_EDDSA, "credential alg is EdDSA");

    let (alg, sig, leaf) = super::packed_att_stmt(&r.body);
    assert_eq!(
        alg, ALG_ES256,
        "attestation stays ES256 for an EdDSA credential"
    );
    // Packed attestation signs authData ‖ clientDataHash; mc_request uses 0xCD*32.
    let (x, y) = super::att_leaf_pubkey(&leaf);
    let mut signed = ad;
    signed.extend_from_slice(&[0xCD; 32]);
    super::verify_p256(&x, &y, &signed, &sig);
}

#[test]
fn makecred_unsupported_algorithm_rejected() {
    // A request whose only pubKeyCredParams entry is an unsupported COSE id (RS256,
    // -257) must fail with CTAP2_ERR_UNSUPPORTED_ALGORITHM (CTAP 2.1 §6.1).
    let r = Authr::fresh().send(CTAP_MAKE_CREDENTIAL, &mc_request(-257));
    assert_eq!(r.status, CtapError::UnsupportedAlgorithm.as_u8());
    assert!(r.body.is_empty(), "an error response carries no CBOR body");
}

#[test]
fn makecred_exclude_list_rejects_existing() {
    let mut a = Authr::fresh();
    let r1 = a.send(CTAP_MAKE_CREDENTIAL, &mc_request(ALG_ES256));
    assert_ok(&r1);
    let cred_id = {
        let mut d = field_at(&r1.body, 2).expect("authData (0x02) present");
        let ad = d.bytes().unwrap();
        let cl = u16::from_be_bytes([ad[53], ad[54]]) as usize;
        ad[55..55 + cl].to_vec()
    };
    // Re-registering with that credential in excludeList → CREDENTIAL_EXCLUDED (§6.1).
    let r2 = a.send(CTAP_MAKE_CREDENTIAL, &mc_request_exclude(&cred_id));
    assert_eq!(r2.status, CtapError::CredentialExcluded.as_u8());
}

#[test]
fn makecred_attestation_signature_verifies() {
    let r = make_es256();
    let ad = {
        let mut d = field_at(&r.body, 2).expect("authData (0x02) present");
        d.bytes().unwrap().to_vec()
    };
    let (_, sig, leaf) = super::packed_att_stmt(&r.body);
    // Packed basic attestation signs authData ‖ clientDataHash with the device key,
    // so it verifies under the x5c leaf and *not* under the credential key.
    let mut signed = ad.clone();
    signed.extend_from_slice(&[0xCD; 32]);
    let (x, y) = super::att_leaf_pubkey(&leaf);
    super::verify_p256(&x, &y, &signed, &sig);
    let (cx, cy) = super::credential_pubkey(&ad);
    assert_ne!(
        (cx, cy),
        (x, y),
        "the attestation key must not be the credential key"
    );
}
