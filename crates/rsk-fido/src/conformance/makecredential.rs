// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §6.1 `authenticatorMakeCredential` conformance assertions, driven
//! through the wire envelope (`process_cbor`): the attestation-object shape, the
//! authenticator-data layout, the packed attestation statement, algorithm choice,
//! and request validation (parameter and extension-input types). A no-PIN request
//! is user-presence-only, so `AlwaysConfirm` satisfies it without arming a token.

use super::{Authr, Resp, assert_ok, field_at, int_map_keys};
use crate::consts::{
    AAGUID, ALG_EDDSA, ALG_ES256, CTAP_CLIENT_PIN, CTAP_MAKE_CREDENTIAL, EF_EA_ENABLED, FLAG_AT,
    FLAG_ED, FLAG_UP, MAX_CRED_ID_LENGTH, PUBLIC_KEY_TYPE,
};
use crate::cose::cose_key_ecdh;
use crate::error::CtapError;
use crate::state::PERM_MC;
use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};
use rsk_crypto::pinproto::{self, PinProto, public_xy};
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

// ---- Request validation: the CTAP 2.3 conformance cases ----

/// The clientDataHash every request below carries, as [`mc_request`]'s does.
const CDH: [u8; 32] = [0xCD; 32];
/// Unassigned in the IANA COSE registry: unlike RS256, no backend added later can
/// make it supported.
const UNASSIGNED_ALG: i64 = -1000;
/// The one salt the hmac-secret-mc requests seal.
const SALT: [u8; 32] = [0xA5; 32];
/// clientPIN subCommand getKeyAgreement.
const GET_KEY_AGREEMENT: u64 = 0x02;

/// Writes one value, or a run of map entries, into a half-built request.
type Part<'a> = &'a dyn Fn(&mut Encoder<Cursor<&mut [u8]>>);

/// CBOR-encode a request body with `f`, which writes the map header too.
fn encode(f: impl Fn(&mut Encoder<Cursor<&mut [u8]>>)) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        f(&mut e);
        e.writer().position()
    };
    buf[..n].to_vec()
}

fn mc_cdh(e: &mut Encoder<Cursor<&mut [u8]>>) {
    e.u8(1).unwrap().bytes(&CDH).unwrap();
}

fn mc_rp(e: &mut Encoder<Cursor<&mut [u8]>>) {
    e.u8(2).unwrap().map(1).unwrap();
    e.str("id").unwrap().str(RP_ID).unwrap();
}

fn mc_user(e: &mut Encoder<Cursor<&mut [u8]>>) {
    e.u8(3).unwrap().map(2).unwrap();
    e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
    e.str("name").unwrap().str("alice").unwrap();
}

/// One well-formed pubKeyCredParams element offering `alg`.
fn params_element(e: &mut Encoder<Cursor<&mut [u8]>>, alg: i64) {
    e.map(2).unwrap();
    e.str("alg").unwrap().i64(alg).unwrap();
    e.str("type").unwrap().str(PUBLIC_KEY_TYPE).unwrap();
}

/// pubKeyCredParams (key 4) offering `algs`, in the platform's preference order.
fn mc_params(e: &mut Encoder<Cursor<&mut [u8]>>, algs: &[i64]) {
    e.u8(4).unwrap().array(algs.len() as u64).unwrap();
    for &alg in algs {
        params_element(e, alg);
    }
}

/// options (key 7) `{rk: true}`.
fn mc_rk(e: &mut Encoder<Cursor<&mut [u8]>>) {
    e.u8(7).unwrap().map(1).unwrap();
    e.str("rk").unwrap().bool(true).unwrap();
}

/// An ES256 makeCredential whose extensions (key 6) are the `count` entries `ext`
/// writes, discoverable when `rk`.
fn mc_with_extensions(count: u64, rk: bool, ext: Part) -> Vec<u8> {
    encode(|e| {
        e.map(if rk { 6 } else { 5 }).unwrap();
        mc_cdh(e);
        mc_rp(e);
        mc_user(e);
        mc_params(e, &[ALG_ES256]);
        e.u8(6).unwrap().map(count).unwrap();
        ext(e);
        if rk {
            mc_rk(e);
        }
    })
}

/// A refusal is exactly `err`'s status byte, with no CBOR body.
fn assert_refused(r: &Resp, err: CtapError, what: &str) {
    assert_eq!(
        r.status,
        err.as_u8(),
        "{what}: expected {err:?} (0x{:02x}), got status 0x{:02x}",
        err.as_u8(),
        r.status
    );
    assert!(
        r.body.is_empty(),
        "{what}: an error response carries no CBOR body"
    );
}

/// The authData (response key 2) of a registration.
fn auth_data(r: &Resp) -> Vec<u8> {
    let mut d = field_at(&r.body, 2).expect("authData (0x02) present");
    d.bytes().unwrap().to_vec()
}

/// Where the credential public key starts in a registration's authData.
fn cose_start(ad: &[u8]) -> usize {
    55 + u16::from_be_bytes([ad[53], ad[54]]) as usize
}

/// Where it ends — which is where an extension map, if any, starts.
fn cose_end(ad: &[u8]) -> usize {
    let mut d = Decoder::new(&ad[cose_start(ad)..]);
    d.skip().unwrap();
    cose_start(ad) + d.position()
}

/// The COSE `alg` (label 3) of the credential public key.
fn cose_alg(ad: &[u8]) -> i64 {
    let mut d = Decoder::new(&ad[cose_start(ad)..]);
    for _ in 0..d.map().unwrap().unwrap() {
        if d.i64().unwrap() == 3 {
            return d.i64().unwrap();
        }
        d.skip().unwrap();
    }
    panic!("the credential public key carries no alg");
}

/// A decoder at extension output `name` in a registration's authData, if present.
fn ext_output<'a>(ad: &'a [u8], name: &str) -> Option<Decoder<'a>> {
    let mut d = Decoder::new(&ad[cose_end(ad)..]);
    for _ in 0..d.map().ok()?? {
        if d.str().unwrap() == name {
            return Some(d);
        }
        d.skip().unwrap();
    }
    None
}

/// §6.1.2 step 3.1.3: an algorithm the authenticator does not support is passed
/// over, not refused, so the credential takes the first SUPPORTED element (FIDO
/// Authr-MakeCred-Req-4 P-1).
#[test]
fn makecred_passes_over_an_unsupported_alg_listed_first() {
    for (algs, chosen) in [
        ([UNASSIGNED_ALG, ALG_ES256, ALG_EDDSA], ALG_ES256),
        ([UNASSIGNED_ALG, ALG_EDDSA, ALG_ES256], ALG_EDDSA),
    ] {
        let r = Authr::fresh().send(
            CTAP_MAKE_CREDENTIAL,
            &encode(|e| {
                e.map(4).unwrap();
                mc_cdh(e);
                mc_rp(e);
                mc_user(e);
                mc_params(e, &algs);
            }),
        );
        assert_ok(&r);
        assert_eq!(
            cose_alg(&auth_data(&r)),
            chosen,
            "{algs:?} must register the first supported algorithm"
        );
    }
}

/// §6.1.2 step 3 "always iterates over every element of pubKeyCredParams to
/// validate them", so a malformed element AFTER the chosen one is still refused
/// (FIDO Authr-MakeCred-Req-4 F-1, F-3, F-4, F-5; F-2's shape rides along).
#[test]
fn makecred_validates_every_params_element_after_the_chosen_one() {
    let rows: [(&str, Part, CtapError); 5] = [
        (
            "a non-map element (F-1)",
            &|e| {
                e.bool(true).unwrap();
            },
            CtapError::CborUnexpectedType,
        ),
        (
            "an element without type",
            &|e| {
                e.map(1).unwrap();
                e.str("alg").unwrap().i64(ALG_ES256).unwrap();
            },
            CtapError::InvalidCbor,
        ),
        (
            "a non-text type (F-3)",
            &|e| {
                e.map(2).unwrap();
                e.str("alg").unwrap().i64(ALG_ES256).unwrap();
                e.str("type").unwrap().bool(false).unwrap();
            },
            CtapError::CborUnexpectedType,
        ),
        (
            "an element without alg (F-4)",
            &|e| {
                e.map(1).unwrap();
                e.str("type").unwrap().str(PUBLIC_KEY_TYPE).unwrap();
            },
            CtapError::InvalidCbor,
        ),
        (
            "a non-integer alg (F-5)",
            &|e| {
                e.map(2).unwrap();
                e.str("alg").unwrap().str("-7").unwrap();
                e.str("type").unwrap().str(PUBLIC_KEY_TYPE).unwrap();
            },
            CtapError::CborUnexpectedType,
        ),
    ];
    for (label, trailing, err) in rows {
        // Key 4 is the LAST key: a parser that stopped at the chosen element then
        // answers success, where a later key would misread the leftovers instead.
        let req = encode(|e| {
            e.map(4).unwrap();
            mc_cdh(e);
            mc_rp(e);
            mc_user(e);
            e.u8(4).unwrap().array(2).unwrap();
            params_element(e, ALG_ES256);
            trailing(e);
        });
        let r = Authr::fresh().send(CTAP_MAKE_CREDENTIAL, &req);
        assert_refused(&r, err, &format!("ES256 then {label}"));
    }
    // Control: a well-formed trailing element registers, and ES256 stays chosen.
    let r = Authr::fresh().send(
        CTAP_MAKE_CREDENTIAL,
        &encode(|e| {
            e.map(4).unwrap();
            mc_cdh(e);
            mc_rp(e);
            mc_user(e);
            mc_params(e, &[ALG_ES256, ALG_EDDSA]);
        }),
    );
    assert_ok(&r);
    assert_eq!(cose_alg(&auth_data(&r)), ALG_ES256);
}

/// §6.1 types clientDataHash (0x01) as a byte string: text of the right length, or
/// an integer, is a wrong-typed parameter, not bytes to take (FIDO
/// Authr-MakeCred-Req-1 F-2).
#[test]
fn makecred_client_data_hash_must_be_a_byte_string() {
    let rows: [(&str, Part); 2] = [
        ("a 32-character text string", &|e| {
            e.str("0123456789abcdef0123456789abcdef").unwrap();
        }),
        ("an integer", &|e| {
            e.u8(0xCD).unwrap();
        }),
    ];
    for (label, value) in rows {
        let req = encode(|e| {
            e.map(4).unwrap();
            e.u8(1).unwrap();
            value(e);
            mc_rp(e);
            mc_user(e);
            mc_params(e, &[ALG_ES256]);
        });
        let r = Authr::fresh().send(CTAP_MAKE_CREDENTIAL, &req);
        assert_refused(&r, CtapError::CborUnexpectedType, label);
    }
}

/// A user.displayName of another type than text is a wrong-typed member (§8),
/// judged here beside a valid byte-string user.id, so it is not the id that
/// answers (FIDO Authr-MakeCred-Req-3 F-3).
#[test]
fn makecred_user_display_name_must_be_text() {
    let request = |display_name: Part| {
        encode(|e| {
            e.map(4).unwrap();
            mc_cdh(e);
            mc_rp(e);
            e.u8(3).unwrap().map(3).unwrap();
            e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
            e.str("name").unwrap().str("alice").unwrap();
            e.str("displayName").unwrap();
            display_name(e);
            mc_params(e, &[ALG_ES256]);
        })
    };
    let rows: [(&str, Part); 2] = [
        ("an integer displayName", &|e| {
            e.u8(1).unwrap();
        }),
        ("a byte-string displayName", &|e| {
            e.bytes(b"Alice").unwrap();
        }),
    ];
    for (label, value) in rows {
        let r = Authr::fresh().send(CTAP_MAKE_CREDENTIAL, &request(value));
        assert_refused(&r, CtapError::CborUnexpectedType, label);
    }
    // Control: the same user with a text displayName registers.
    let r = Authr::fresh().send(
        CTAP_MAKE_CREDENTIAL,
        &request(&|e| {
            e.str("Alice").unwrap();
        }),
    );
    assert_ok(&r);
}

/// §6.1.2 step 14: an explicit `up: true` is the default spelled out — the touch
/// is still asked for (declined, OPERATION_DENIED), and the response sets UP
/// (FIDO Authr-MakeCred-Req-6 P-3).
#[test]
fn makecred_explicit_up_true_asks_for_the_touch_and_sets_up() {
    let req = encode(|e| {
        e.map(5).unwrap();
        mc_cdh(e);
        mc_rp(e);
        mc_user(e);
        mc_params(e, &[ALG_ES256]);
        e.u8(7).unwrap().map(1).unwrap();
        e.str("up").unwrap().bool(true).unwrap();
    });
    let r = Authr::fresh().send(CTAP_MAKE_CREDENTIAL, &req);
    assert_ok(&r);
    assert_eq!(
        auth_data(&r)[32] & FLAG_UP,
        FLAG_UP,
        "an explicit up:true must set UP in authData"
    );
    let declined = Authr::declining().send(CTAP_MAKE_CREDENTIAL, &req);
    assert_refused(&declined, CtapError::OperationDenied, "a declined touch");
}

/// §6.1.2 step 15.2 keeps the extension outputs a subset of the inputs, so with
/// none requested there is no extension map: ED clear and authData ending at the
/// credential public key, AT set (FIDO Authr-MakeCred-Resp-1 P-02).
#[test]
fn makecred_without_extensions_leaves_ed_clear() {
    for rk in [false, true] {
        let r = Authr::fresh().send(
            CTAP_MAKE_CREDENTIAL,
            &encode(|e| {
                e.map(if rk { 5 } else { 4 }).unwrap();
                mc_cdh(e);
                mc_rp(e);
                mc_user(e);
                mc_params(e, &[ALG_ES256]);
                if rk {
                    mc_rk(e);
                }
            }),
        );
        assert_ok(&r);
        let ad = auth_data(&r);
        assert_eq!(ad[32] & FLAG_AT, FLAG_AT, "AT must be set (rk={rk})");
        assert_eq!(
            ad[32] & FLAG_ED,
            0,
            "ED must be clear when no extension was requested (rk={rk})"
        );
        assert_eq!(
            cose_end(&ad),
            ad.len(),
            "nothing may follow the credential public key (rk={rk})"
        );
    }
}

/// §6.1 types enterpriseAttestation (0x0A) as an unsigned integer, so with EA
/// enabled a value of another type is refused as one, not judged as a level
/// (FIDO enteprise-attestation F-4).
#[test]
fn makecred_enterprise_attestation_must_be_an_unsigned_integer() {
    let request = |value: Part| {
        encode(|e| {
            e.map(5).unwrap();
            mc_cdh(e);
            mc_rp(e);
            mc_user(e);
            mc_params(e, &[ALG_ES256]);
            e.u8(10).unwrap();
            value(e);
        })
    };
    let enabled = || {
        let mut a = Authr::fresh();
        a.fs.put(EF_EA_ENABLED, &[1]).unwrap();
        a
    };
    let rows: [(&str, Part); 3] = [
        ("a text string", &|e| {
            e.str("2").unwrap();
        }),
        ("a byte string", &|e| {
            e.bytes(&[2]).unwrap();
        }),
        ("a boolean", &|e| {
            e.bool(true).unwrap();
        }),
    ];
    for (label, value) in rows {
        let r = enabled().send(CTAP_MAKE_CREDENTIAL, &request(value));
        assert_refused(&r, CtapError::CborUnexpectedType, label);
    }
    // Control: the same enabled authenticator registers a level-2 request.
    let r = enabled().send(
        CTAP_MAKE_CREDENTIAL,
        &request(&|e| {
            e.u8(2).unwrap();
        }),
    );
    assert_ok(&r);
}

/// A protocol's number on the wire.
fn wire(proto: PinProto) -> u64 {
    match proto {
        PinProto::One => 1,
        PinProto::Two => 2,
    }
}

/// `authenticate(token, msg)` under `proto` — `pin_auth` for either protocol.
fn pin_uv_auth_param(proto: PinProto, token: &[u8; 32], msg: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 32];
    let n = pinproto::authenticate(proto, token, msg, &mut out).unwrap();
    out[..n].to_vec()
}

/// A makeCredential whose one extension is `hmac-secret` with the value `value`
/// writes, sent under a fresh pinUvAuthToken authenticated with `proto`.
fn mc_hmac_secret(proto: PinProto, rk: bool, value: Part) -> Resp {
    let mut a = Authr::fresh();
    let token = a.arm_token(PERM_MC);
    let param = pin_uv_auth_param(proto, &token, &CDH);
    let req = encode(|e| {
        e.map(if rk { 8 } else { 7 }).unwrap();
        mc_cdh(e);
        mc_rp(e);
        mc_user(e);
        mc_params(e, &[ALG_ES256]);
        e.u8(6).unwrap().map(1).unwrap();
        e.str("hmac-secret").unwrap();
        value(e);
        if rk {
            mc_rk(e);
        }
        e.u8(8).unwrap().bytes(&param).unwrap();
        e.u8(9).unwrap().u64(wire(proto)).unwrap();
    });
    a.send(CTAP_MAKE_CREDENTIAL, &req)
}

/// §12.7: makeCredential's hmac-secret input is the boolean `true`; another type
/// is refused as one, under a token of either protocol and for either credential
/// kind (FIDO hmac-secret F-1, hmac-secret2 F-1).
#[test]
fn makecred_hmac_secret_input_must_be_a_boolean() {
    let rows: [(&str, Part); 2] = [
        ("a text string", &|e| {
            e.str("true").unwrap();
        }),
        ("an integer", &|e| {
            e.u8(1).unwrap();
        }),
    ];
    for proto in [PinProto::One, PinProto::Two] {
        for rk in [false, true] {
            for (label, value) in rows {
                let r = mc_hmac_secret(proto, rk, value);
                let what = format!("{label} ({proto:?}, rk={rk})");
                assert_refused(&r, CtapError::CborUnexpectedType, &what);
            }
            // Control: `true` under the same kind of token registers and is echoed.
            let r = mc_hmac_secret(proto, rk, &|e| {
                e.bool(true).unwrap();
            });
            assert_ok(&r);
            let echoed = ext_output(&auth_data(&r), "hmac-secret").map(|mut d| d.bool().unwrap());
            assert_eq!(echoed, Some(true), "{proto:?}, rk={rk}");
        }
    }
}

/// The `(x, y)` (labels -2 / -3) of a COSE EC2 public key.
fn cose_xy(mut d: Decoder<'_>) -> ([u8; 32], [u8; 32]) {
    let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
    for _ in 0..d.map().unwrap().unwrap() {
        match d.i64().unwrap() {
            -2 => x.copy_from_slice(d.bytes().unwrap()),
            -3 => y.copy_from_slice(d.bytes().unwrap()),
            _ => d.skip().unwrap(),
        }
    }
    (x, y)
}

/// The platform half of a clientPIN key agreement under `proto`: the point it
/// sends and the shared secret it seals the hmac-secret-mc salt with.
struct Platform {
    proto: PinProto,
    x: [u8; 32],
    y: [u8; 32],
    shared: Vec<u8>,
}

impl Platform {
    /// getKeyAgreement, then ECDH against it from a fixed platform scalar.
    fn agree(a: &mut Authr, proto: PinProto) -> Self {
        let r = a.send(
            CTAP_CLIENT_PIN,
            &encode(|e| {
                e.map(2).unwrap();
                e.u8(1).unwrap().u64(wire(proto)).unwrap();
                e.u8(2).unwrap().u64(GET_KEY_AGREEMENT).unwrap();
            }),
        );
        assert_ok(&r);
        let (ax, ay) = cose_xy(field_at(&r.body, 1).expect("keyAgreement (0x01) present"));
        let scalar = [0x21u8; 32];
        let (x, y) = public_xy(&scalar).unwrap();
        let mut shared = [0u8; 64];
        let n = pinproto::ecdh(proto, &scalar, &ax, &ay, &mut shared).unwrap();
        Platform {
            proto,
            x,
            y,
            shared: shared[..n].to_vec(),
        }
    }

    /// `(saltEnc, saltAuth)` for [`SALT`].
    fn seal(&self) -> (Vec<u8>, Vec<u8>) {
        let mut enc = [0u8; 48];
        let n = pinproto::encrypt(self.proto, &self.shared, &[0x55; 16], &SALT, &mut enc).unwrap();
        let mut auth = [0u8; 32];
        let m = pinproto::authenticate(self.proto, &self.shared, &enc[..n], &mut auth).unwrap();
        (enc[..n].to_vec(), auth[..m].to_vec())
    }
}

/// The members of an hmac-secret-mc input — hmac-secret's getAssertion input
/// (§12.8): `{1: keyAgreement, 2: saltEnc, 3: saltAuth, 4: pinUvAuthProtocol}`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Member {
    KeyAgreement,
    SaltEnc,
    SaltAuth,
    Protocol,
}

/// A makeCredential carrying [`SALT`] sealed for `p` as `hmac-secret-mc` — beside
/// `hmac-secret: true` when `flag`, and with `wrong` (if any) sent as a value of
/// the wrong type.
fn mc_hmac_mc(p: &Platform, rk: bool, flag: bool, wrong: Option<Member>) -> Vec<u8> {
    let (salt_enc, salt_auth) = p.seal();
    mc_with_extensions(1 + u64::from(flag), rk, &|e| {
        if flag {
            e.str("hmac-secret").unwrap().bool(true).unwrap();
        }
        e.str("hmac-secret-mc").unwrap().map(4).unwrap();
        e.u8(1).unwrap();
        if wrong == Some(Member::KeyAgreement) {
            e.str("not-a-key").unwrap();
        } else {
            cose_key_ecdh(e, &p.x, &p.y).unwrap();
        }
        e.u8(2).unwrap();
        if wrong == Some(Member::SaltEnc) {
            e.u8(7).unwrap();
        } else {
            e.bytes(&salt_enc).unwrap();
        }
        e.u8(3).unwrap();
        if wrong == Some(Member::SaltAuth) {
            e.bool(false).unwrap();
        } else {
            e.bytes(&salt_auth).unwrap();
        }
        e.u8(4).unwrap();
        if wrong == Some(Member::Protocol) {
            e.str("two").unwrap();
        } else {
            e.u64(wire(p.proto)).unwrap();
        }
    })
}

/// §12.8: "The authenticator MUST return CTAP2_ERR_MISSING_PARAMETER when they
/// receive this extension without the "hmac-secret" extension" — for either salt
/// protocol and credential kind (FIDO hmac-secret-mc F-1).
#[test]
fn makecred_hmac_secret_mc_without_hmac_secret_is_missing_parameter() {
    for proto in [PinProto::One, PinProto::Two] {
        for rk in [false, true] {
            let mut a = Authr::fresh();
            let p = Platform::agree(&mut a, proto);
            let what = format!("{proto:?}, rk={rk}");
            let alone = a.send(CTAP_MAKE_CREDENTIAL, &mc_hmac_mc(&p, rk, false, None));
            assert_refused(&alone, CtapError::MissingParameter, &what);
            // Control: the same input beside the flag registers, and is evaluated.
            let r = a.send(CTAP_MAKE_CREDENTIAL, &mc_hmac_mc(&p, rk, true, None));
            assert_ok(&r);
            assert!(
                ext_output(&auth_data(&r), "hmac-secret-mc").is_some(),
                "{what}: the hmac-secret-mc output is missing"
            );
        }
    }
}

/// §12.8 takes hmac-secret's getAssertion input — a COSE key, two byte strings, an
/// unsigned protocol — so each member sent as another type is refused as one,
/// beside otherwise well-formed members (FIDO hmac-secret-mc F-2).
#[test]
fn makecred_hmac_secret_mc_members_must_be_typed() {
    let rows = [
        (Member::KeyAgreement, "a text keyAgreement"),
        (Member::SaltEnc, "an integer saltEnc"),
        (Member::SaltAuth, "a boolean saltAuth"),
        (Member::Protocol, "a text pinUvAuthProtocol"),
    ];
    for proto in [PinProto::One, PinProto::Two] {
        let mut a = Authr::fresh();
        let p = Platform::agree(&mut a, proto);
        for (member, label) in rows {
            let r = a.send(
                CTAP_MAKE_CREDENTIAL,
                &mc_hmac_mc(&p, false, true, Some(member)),
            );
            assert_refused(
                &r,
                CtapError::CborUnexpectedType,
                &format!("{label} ({proto:?})"),
            );
        }
        // Control: every member well-typed registers.
        assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_hmac_mc(&p, false, true, None)));
    }
}

/// §12.3: "If the value of largeBlobKey is not true, return
/// CTAP2_ERR_INVALID_OPTION", for either credential kind (FIDO large-blob-key F-1).
/// A `largeblob-ext` build withdraws the extension (§12.4).
#[cfg(not(feature = "largeblob-ext"))]
#[test]
fn makecred_large_blob_key_false_is_invalid_option() {
    for rk in [true, false] {
        let req = mc_with_extensions(1, rk, &|e| {
            e.str("largeBlobKey").unwrap().bool(false).unwrap();
        });
        let r = Authr::fresh().send(CTAP_MAKE_CREDENTIAL, &req);
        assert_refused(
            &r,
            CtapError::InvalidOption,
            &format!("largeBlobKey:false, rk={rk}"),
        );
    }
    // Control: `true` on a discoverable credential registers.
    let req = mc_with_extensions(1, true, &|e| {
        e.str("largeBlobKey").unwrap().bool(true).unwrap();
    });
    assert_ok(&Authr::fresh().send(CTAP_MAKE_CREDENTIAL, &req));
}

/// §12.3 types the makeCredential input as `"largeBlobKey": boolean`, so another
/// type is refused as a wrong type rather than judged "not true" (FIDO
/// large-blob-key F-2). Withdrawn with the extension on a `largeblob-ext` build.
#[cfg(not(feature = "largeblob-ext"))]
#[test]
fn makecred_large_blob_key_must_be_a_boolean() {
    let rows: [(&str, Part); 2] = [
        ("a text string", &|e| {
            e.str("largeBlobKey").unwrap().str("true").unwrap();
        }),
        ("an integer", &|e| {
            e.str("largeBlobKey").unwrap().u8(1).unwrap();
        }),
    ];
    for (label, ext) in rows {
        let r = Authr::fresh().send(CTAP_MAKE_CREDENTIAL, &mc_with_extensions(1, true, ext));
        assert_refused(&r, CtapError::CborUnexpectedType, label);
    }
}
