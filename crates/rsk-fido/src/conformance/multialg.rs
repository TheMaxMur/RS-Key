// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Multi-algorithm create+assert conformance, driven end-to-end through the wire
//! envelope (`process_cbor`). For each COSE algorithm the authenticator supports
//! by default (ES256/384/512, EdDSA) this registers a credential, then logs in
//! with it, and cryptographically verifies both signatures a conformance tool
//! checks: the packed self-attestation (CTAP 2.1 §6.1, over authData ‖ CDH) and
//! the assertion (§6.2). It also asserts the per-curve COSE public-key shape
//! (kty/crv/coordinate width). The sibling `ec_tests.rs`/`getassertion_tests.rs`
//! prove the curves at the module and command-fn level; this proves them across
//! the full dispatcher, the surface a host actually observes.

use super::{Authr, assert_ok, field_at, int_map_keys};
use crate::consts::{
    ALG_EDDSA, ALG_ES256, ALG_ES384, ALG_ES512, CTAP_GET_ASSERTION, CTAP_MAKE_CREDENTIAL,
    CURVE_ED25519, CURVE_P256, CURVE_P384, CURVE_P521, FLAG_AT, FLAG_UP,
};
use minicbor::Decoder;
use minicbor::Encoder;
use minicbor::encode::write::Cursor;
use rsk_crypto::sha256;

const RP_ID: &str = "example.com";
/// The fixed clientDataHash every request in this module carries.
const CDH: [u8; 32] = [0xCD; 32];

/// COSE key types (RFC 9053 §7): OKP for Ed25519, EC2 for the NIST curves.
const KTY_OKP: u8 = 1;
const KTY_EC2: u8 = 2;

/// One algorithm's wire fingerprint: the COSE id offered in pubKeyCredParams and
/// the credential public-key shape it must yield in attestedCredentialData.
struct AlgSpec {
    name: &'static str,
    alg: i64,
    kty: u8,
    crv: u8,
    /// EC2 field-element width; for OKP the compressed-point length.
    coord: usize,
}

const ES256: AlgSpec = AlgSpec {
    name: "ES256",
    alg: ALG_ES256,
    kty: KTY_EC2,
    crv: CURVE_P256,
    coord: 32,
};
const ES384: AlgSpec = AlgSpec {
    name: "ES384",
    alg: ALG_ES384,
    kty: KTY_EC2,
    crv: CURVE_P384,
    coord: 48,
};
const ES512: AlgSpec = AlgSpec {
    name: "ES512",
    alg: ALG_ES512,
    kty: KTY_EC2,
    crv: CURVE_P521,
    coord: 66,
};
const EDDSA: AlgSpec = AlgSpec {
    name: "EdDSA",
    alg: ALG_EDDSA,
    kty: KTY_OKP,
    crv: CURVE_ED25519,
    coord: 32,
};

/// A parsed credential public key, enough to verify a signature under it.
enum CoseKey {
    Ec2 { x: Vec<u8>, y: Vec<u8> },
    Okp { x: [u8; 32] },
}

/// A single-algorithm, non-discoverable makeCredential request over `RP_ID`
/// (keys 1–4: clientDataHash, rp, user, pubKeyCredParams).
fn mc_request(alg: i64) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
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

/// A getAssertion request over `RP_ID` whose allowList names `cred_id`
/// (keys 1–3: rpId, clientDataHash, allowList).
fn ga_request(cred_id: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(3).unwrap();
        e.u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.str("id").unwrap().bytes(cred_id).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// The authData byte string at key 2 of a makeCredential or getAssertion reply.
fn authdata(body: &[u8]) -> Vec<u8> {
    let mut d = field_at(body, 2).expect("authData (0x02) present");
    d.bytes().unwrap().to_vec()
}

/// The credential id carried inline in a makeCredential authData.
fn cred_id_of(ad: &[u8]) -> Vec<u8> {
    let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    ad[55..55 + cred_len].to_vec()
}

/// The `(alg, sig)` of a packed self-attestation statement (key 3), asserting the
/// canonical `{alg, sig}` shape (no x5c chain for self-attestation).
fn att_stmt(body: &[u8]) -> (i64, Vec<u8>) {
    let mut d = field_at(body, 3).expect("attStmt (0x03) present");
    assert_eq!(
        d.map().unwrap().unwrap(),
        2,
        "self-attestation attStmt is {{alg, sig}}"
    );
    assert_eq!(d.str().unwrap(), "alg");
    let alg = d.i64().unwrap();
    assert_eq!(d.str().unwrap(), "sig");
    (alg, d.bytes().unwrap().to_vec())
}

/// Assert the default-profile makeCredential shape: fmt "none" (field 1) with an
/// empty attStmt map (field 3).
fn assert_none_att_stmt(body: &[u8], name: &str) {
    let mut f = field_at(body, 1).expect("fmt (0x01) present");
    assert_eq!(f.str().unwrap(), "none", "{name}: default fmt is none");
    let mut s = field_at(body, 3).expect("attStmt (0x03) present");
    assert_eq!(
        s.map().unwrap().unwrap(),
        0,
        "{name}: default attStmt is empty"
    );
}

/// The assertion signature byte string at key 3 of a getAssertion reply.
fn assertion_sig(body: &[u8]) -> Vec<u8> {
    let mut d = field_at(body, 3).expect("signature (0x03) present");
    d.bytes().unwrap().to_vec()
}

/// Parse the credential COSE public key from the tail of a makeCredential
/// authData, asserting the algorithm's expected kty/crv/coordinate width.
fn cose_key(spec: &AlgSpec, ad: &[u8]) -> CoseKey {
    let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let mut d = Decoder::new(&ad[55 + cred_len..]);
    let entries = d.map().unwrap().expect("definite-length COSE key");
    assert_eq!(
        d.u8().unwrap(),
        1,
        "{}: first COSE key label is kty",
        spec.name
    );
    assert_eq!(d.u8().unwrap(), spec.kty, "{}: unexpected kty", spec.name);
    assert_eq!(
        d.u8().unwrap(),
        3,
        "{}: second COSE key label is alg",
        spec.name
    );
    assert_eq!(d.i64().unwrap(), spec.alg, "{}: COSE key alg", spec.name);
    assert_eq!(d.i8().unwrap(), -1, "{}: crv label", spec.name);
    assert_eq!(d.u8().unwrap(), spec.crv, "{}: unexpected curve", spec.name);
    assert_eq!(d.i8().unwrap(), -2, "{}: x label", spec.name);
    let x = d.bytes().unwrap().to_vec();
    assert_eq!(x.len(), spec.coord, "{}: x coordinate width", spec.name);
    if spec.kty == KTY_EC2 {
        assert_eq!(entries, 5, "{}: EC2 key is 5 entries", spec.name);
        assert_eq!(d.i8().unwrap(), -3, "{}: y label", spec.name);
        let y = d.bytes().unwrap().to_vec();
        assert_eq!(y.len(), spec.coord, "{}: y coordinate width", spec.name);
        CoseKey::Ec2 { x, y }
    } else {
        assert_eq!(entries, 4, "{}: OKP key is 4 entries", spec.name);
        CoseKey::Okp {
            x: x.try_into().expect("Ed25519 point is 32 bytes"),
        }
    }
}

/// Whether `sig` verifies over `msg` under `key` for `alg` — the cryptographic
/// check a conformance tool performs. EC signatures are DER; the RustCrypto
/// `Verifier` hashes with the curve's paired digest (SHA-256/384/512). EdDSA is a
/// raw 64-byte signature over the message.
fn verifies(alg: i64, key: &CoseKey, msg: &[u8], sig: &[u8]) -> bool {
    match (alg, key) {
        (ALG_ES256, CoseKey::Ec2 { x, y }) => {
            use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let pt = p256::Sec1Point::from_bytes(&crate::ec::sec1_uncompressed(x, y)).unwrap();
            let vk = VerifyingKey::from_sec1_point(&pt).unwrap();
            let Ok(s) = Signature::from_der(sig) else {
                return false;
            };
            vk.verify(msg, &s).is_ok()
        }
        (ALG_ES384, CoseKey::Ec2 { x, y }) => {
            use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let pt = p384::Sec1Point::from_bytes(&crate::ec::sec1_uncompressed(x, y)).unwrap();
            let vk = VerifyingKey::from_sec1_point(&pt).unwrap();
            let Ok(s) = Signature::from_der(sig) else {
                return false;
            };
            vk.verify(msg, &s).is_ok()
        }
        (ALG_ES512, CoseKey::Ec2 { x, y }) => {
            use p521::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let pt = p521::Sec1Point::from_bytes(&crate::ec::sec1_uncompressed(x, y)).unwrap();
            let vk = VerifyingKey::from_sec1_point(&pt).unwrap();
            let Ok(s) = Signature::from_der(sig) else {
                return false;
            };
            vk.verify(msg, &s).is_ok()
        }
        (ALG_EDDSA, CoseKey::Okp { x }) => {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let vk = VerifyingKey::from_bytes(x).unwrap();
            let Ok(s) = Signature::from_slice(sig) else {
                return false;
            };
            vk.verify(msg, &s).is_ok()
        }
        _ => panic!("algorithm / key-type mismatch"),
    }
}

/// Register a credential for `spec`, log in with it, and verify both signatures
/// under its credential key — the full multi-algorithm round-trip.
fn create_and_assert(spec: &AlgSpec) {
    let mut a = Authr::fresh();

    let mc = a.send(CTAP_MAKE_CREDENTIAL, &mc_request(spec.alg));
    assert_ok(&mc);
    assert_eq!(
        int_map_keys(&mc.body),
        vec![1u32, 2, 3],
        "{}: attObj is {{fmt, authData, attStmt}}",
        spec.name
    );
    let ad = authdata(&mc.body);
    let key = cose_key(spec, &ad);
    // Default ships fmt "none" with an empty attStmt; only the conformance
    // profile emits (and lets us verify) the packed self-attestation.
    if cfg!(feature = "fido-conformance") {
        let (att_alg, att_sig) = att_stmt(&mc.body);
        assert_eq!(
            att_alg, spec.alg,
            "{}: attStmt alg must match the credential key",
            spec.name
        );
        // Packed self-attestation signs authData ‖ clientDataHash with the new key.
        let mut att_signed = ad.clone();
        att_signed.extend_from_slice(&CDH);
        assert!(
            verifies(spec.alg, &key, &att_signed, &att_sig),
            "{}: packed self-attestation signature must verify",
            spec.name
        );
    } else {
        assert_none_att_stmt(&mc.body, spec.name);
    }

    let cred_id = cred_id_of(&ad);
    let ga = a.send(CTAP_GET_ASSERTION, &ga_request(&cred_id));
    assert_ok(&ga);
    let ga_ad = authdata(&ga.body);
    assert_eq!(
        &ga_ad[..32],
        &sha256(RP_ID.as_bytes())[..],
        "{}: assertion rpIdHash",
        spec.name
    );
    assert_eq!(ga_ad[32] & FLAG_UP, FLAG_UP, "{}: UP flag set", spec.name);
    assert_eq!(
        ga_ad[32] & FLAG_AT,
        0,
        "{}: assertion carries no attested credential data",
        spec.name
    );
    // The assertion signs authData ‖ clientDataHash with the same credential key.
    let mut ga_signed = ga_ad.clone();
    ga_signed.extend_from_slice(&CDH);
    assert!(
        verifies(spec.alg, &key, &ga_signed, &assertion_sig(&ga.body)),
        "{}: assertion signature must verify",
        spec.name
    );
}

#[test]
fn es256_create_and_assert() {
    create_and_assert(&ES256);
}

#[test]
fn es384_create_and_assert() {
    create_and_assert(&ES384);
}

#[test]
fn es512_create_and_assert() {
    create_and_assert(&ES512);
}

#[test]
fn eddsa_create_and_assert() {
    create_and_assert(&EDDSA);
}

#[test]
fn tampered_authdata_fails_for_every_algorithm() {
    // A verification harness that never rejects would let every positive test
    // pass vacuously. Flipping the UP bit in the signed authData must break the
    // self-attestation for each algorithm, proving the signature binds authData.
    // Only the conformance profile emits a self-attestation to tamper with; the
    // default profile has an empty attStmt, so assert that shape instead.
    for spec in [&ES256, &ES384, &ES512, &EDDSA] {
        let mut a = Authr::fresh();
        let mc = a.send(CTAP_MAKE_CREDENTIAL, &mc_request(spec.alg));
        assert_ok(&mc);
        let ad = authdata(&mc.body);
        let key = cose_key(spec, &ad);
        if cfg!(feature = "fido-conformance") {
            let (_, att_sig) = att_stmt(&mc.body);
            let mut tampered = ad.clone();
            tampered[32] ^= FLAG_UP;
            tampered.extend_from_slice(&CDH);
            assert!(
                !verifies(spec.alg, &key, &tampered, &att_sig),
                "{}: signature must not verify over mutated authData",
                spec.name
            );
        } else {
            assert_none_att_stmt(&mc.body, spec.name);
        }
    }
}
