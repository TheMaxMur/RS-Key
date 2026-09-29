// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Extension conformance (credBlob, hmac-secret, largeBlobKey, thirdPartyPayment),
//! driven through the wire envelope (`process_cbor`): what makeCredential and
//! getAssertion output for each, and the input types they refuse.

use super::{Authr, assert_ok, field_at};
use crate::consts::{
    ALG_ES256, CTAP_GET_ASSERTION, CTAP_MAKE_CREDENTIAL, FLAG_ED, PUBLIC_KEY_TYPE,
};
use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};

const RP_ID: &str = "ext.example";
const CDH: [u8; 32] = [0xCD; 32];
const USER_ID: &[u8] = &[3, 1, 4, 1];
const BLOB: [u8; 4] = [0xAB, 0xCD, 0xEF, 0x01];

/// A discoverable makeCredential over `RP_ID` whose extensions map (key 6) holds
/// `ext_count` entries written by `ext`.
fn mc_with_ext(ext_count: u64, ext: impl Fn(&mut Encoder<Cursor<&mut [u8]>>)) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(6).unwrap(); // keys 1,2,3,4,6,7
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
        e.str("id").unwrap().bytes(USER_ID).unwrap();
        e.str("name").unwrap().str("frank").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(6).unwrap().map(ext_count).unwrap();
        ext(&mut e);
        e.u8(7)
            .unwrap()
            .map(1)
            .unwrap()
            .str("rk")
            .unwrap()
            .bool(true)
            .unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// A getAssertion over `RP_ID` requesting the stored credBlob (extensions key 4).
fn ga_credblob() -> Vec<u8> {
    let mut buf = [0u8; 128];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(3).unwrap();
        e.u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(4)
            .unwrap()
            .map(1)
            .unwrap()
            .str("credBlob")
            .unwrap()
            .bool(true)
            .unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// Read a boolean extension output from a makeCredential authData (walking past
/// the attested credential data and the COSE public key to the extension map).
fn mc_ext_bool(body: &[u8], name: &str) -> Option<bool> {
    let mut d = field_at(body, 2).expect("authData (0x02) present");
    let ad = d.bytes().unwrap();
    let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let mut ext = Decoder::new(&ad[55 + cred_len..]);
    ext.skip().unwrap(); // the COSE public key
    let n = ext.map().ok()??;
    for _ in 0..n {
        if ext.str().unwrap() == name {
            return ext.bool().ok();
        }
        ext.skip().unwrap();
    }
    None
}

#[test]
fn credblob_makecredential_echoes_stored_flag() {
    // A short credBlob is stored → authData echoes credBlob: true.
    let r = Authr::fresh().send(
        CTAP_MAKE_CREDENTIAL,
        &mc_with_ext(1, |e| {
            e.str("credBlob").unwrap().bytes(&BLOB).unwrap();
        }),
    );
    assert_ok(&r);
    assert_eq!(mc_ext_bool(&r.body, "credBlob"), Some(true));
}

#[test]
fn hmac_secret_makecredential_echoes_true() {
    // hmac-secret is acknowledged in the makeCredential authData as a bool true.
    let r = Authr::fresh().send(
        CTAP_MAKE_CREDENTIAL,
        &mc_with_ext(1, |e| {
            e.str("hmac-secret").unwrap().bool(true).unwrap();
        }),
    );
    assert_ok(&r);
    assert_eq!(mc_ext_bool(&r.body, "hmac-secret"), Some(true));
}

#[test]
fn credblob_returned_by_getassertion() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(
        CTAP_MAKE_CREDENTIAL,
        &mc_with_ext(1, |e| {
            e.str("credBlob").unwrap().bytes(&BLOB).unwrap();
        }),
    ));
    let g = a.send(CTAP_GET_ASSERTION, &ga_credblob());
    assert_ok(&g);
    let mut d = field_at(&g.body, 2).expect("authData (0x02) present");
    let ad = d.bytes().unwrap();
    assert_eq!(
        ad[32] & FLAG_ED,
        FLAG_ED,
        "ED flag set (extension output present)"
    );
    // Assertion authData is rpIdHash(32) | flags(1) | counter(4) | extension map.
    let mut ext = Decoder::new(&ad[37..]);
    let n = ext.map().unwrap().unwrap();
    let mut got = None;
    for _ in 0..n {
        if ext.str().unwrap() == "credBlob" {
            got = Some(ext.bytes().unwrap().to_vec());
        } else {
            ext.skip().unwrap();
        }
    }
    assert_eq!(
        got.as_deref(),
        Some(&BLOB[..]),
        "getAssertion returns the stored credBlob"
    );
}

/// A makeCredential over `RP_ID` for user `uid`, discoverable when `rk`, whose
/// extensions map holds `ext_count` entries written by `ext` (no map when zero).
fn mc_ext_for(
    uid: &[u8],
    rk: bool,
    ext_count: u64,
    ext: impl Fn(&mut Encoder<Cursor<&mut [u8]>>),
) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4 + u64::from(ext_count > 0) + u64::from(rk)).unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str(RP_ID).unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(uid).unwrap();
        e.str("name").unwrap().str("frank").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str(PUBLIC_KEY_TYPE).unwrap();
        if ext_count > 0 {
            e.u8(6).unwrap().map(ext_count).unwrap();
            ext(&mut e);
        }
        if rk {
            e.u8(7).unwrap().map(1).unwrap();
            e.str("rk").unwrap().bool(true).unwrap();
        }
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// A getAssertion over `RP_ID` naming `id` in its allowList, whose extensions map
/// holds `ext_count` entries written by `ext`.
fn ga_ext_for(id: &[u8], ext_count: u64, ext: impl Fn(&mut Encoder<Cursor<&mut [u8]>>)) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(id).unwrap();
        e.str("type").unwrap().str(PUBLIC_KEY_TYPE).unwrap();
        e.u8(4).unwrap().map(ext_count).unwrap();
        ext(&mut e);
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// The credentialId out of a makeCredential's attested credential data.
fn cred_id(body: &[u8]) -> Vec<u8> {
    let mut d = field_at(body, 2).expect("authData (0x02) present");
    let ad = d.bytes().unwrap();
    let cl = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    ad[55..55 + cl].to_vec()
}

/// Every extension output name in a makeCredential authData. Read from the bytes
/// after the COSE key, not from the ED flag, so an output the flag fails to
/// announce is still seen.
fn mc_ext_names(body: &[u8]) -> Vec<String> {
    let mut d = field_at(body, 2).expect("authData (0x02) present");
    let ad = d.bytes().unwrap();
    let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let mut ext = Decoder::new(&ad[55 + cred_len..]);
    ext.skip().unwrap(); // the COSE public key
    if ext.position() == ext.input().len() {
        return Vec::new();
    }
    let n = ext.map().unwrap().expect("definite-length extension map");
    (0..n)
        .map(|_| {
            let name = ext.str().unwrap().to_string();
            ext.skip().unwrap();
            name
        })
        .collect()
}

/// The encoded value of extension output `name` in a getAssertion authData, or
/// `None` when there is no such output.
fn ga_ext_output(body: &[u8], name: &str) -> Option<Vec<u8>> {
    let mut d = field_at(body, 2).expect("authData (0x02) present");
    let ad = d.bytes().unwrap();
    // Assertion authData is rpIdHash(32) | flags(1) | counter(4) | extension map.
    let ext = &ad[37..];
    if ext.is_empty() {
        return None;
    }
    let mut d = Decoder::new(ext);
    let n = d.map().unwrap().expect("definite-length extension map");
    for _ in 0..n {
        let key = d.str().unwrap();
        let start = d.position();
        d.skip().unwrap();
        if key == name {
            return Some(ext[start..d.position()].to_vec());
        }
    }
    None
}

/// An extensions entry asking for the thirdPartyPayment flag.
fn ask_third_party_payment(e: &mut Encoder<Cursor<&mut [u8]>>) {
    e.str("thirdPartyPayment").unwrap().bool(true).unwrap();
}

/// FIDO thirdPartyPayment P-1 / P-2. CTAP 2.3 §12.9 keeps the flag with the
/// credential and reports it on getAssertion only: registration returns no
/// output for it, and an assertion asking reads `true` — discoverable or not.
#[test]
fn third_party_payment_is_reported_on_the_assertion_only() {
    for rk in [true, false] {
        let mut a = Authr::fresh();
        let mc = a.send(
            CTAP_MAKE_CREDENTIAL,
            &mc_ext_for(USER_ID, rk, 1, ask_third_party_payment),
        );
        assert_ok(&mc);
        assert!(
            !mc_ext_names(&mc.body)
                .iter()
                .any(|n| n == "thirdPartyPayment"),
            "rk={rk}: makeCredential has no thirdPartyPayment output"
        );

        let g = a.send(
            CTAP_GET_ASSERTION,
            &ga_ext_for(&cred_id(&mc.body), 1, ask_third_party_payment),
        );
        assert_ok(&g);
        let v = ga_ext_output(&g.body, "thirdPartyPayment").expect("thirdPartyPayment output");
        assert_eq!(
            Decoder::new(&v).bool().ok(),
            Some(true),
            "rk={rk}: a credential made with thirdPartyPayment reads true"
        );
    }
}

/// FIDO thirdPartyPayment F-1. A credential registered without the extension
/// still answers an assertion that asks: `false`, not a missing output.
#[test]
fn third_party_payment_reads_false_for_a_credential_made_without_it() {
    for rk in [false, true] {
        let mut a = Authr::fresh();
        let mc = a.send(CTAP_MAKE_CREDENTIAL, &mc_ext_for(USER_ID, rk, 0, |_| {}));
        assert_ok(&mc);
        let g = a.send(
            CTAP_GET_ASSERTION,
            &ga_ext_for(&cred_id(&mc.body), 1, ask_third_party_payment),
        );
        assert_ok(&g);
        let v = ga_ext_output(&g.body, "thirdPartyPayment")
            .expect("an output even for a credential made without the extension");
        assert_eq!(
            Decoder::new(&v).bool().ok(),
            Some(false),
            "rk={rk}: a credential made without thirdPartyPayment reads false"
        );
    }
}

/// FIDO credBlob P-3. CTAP 2.3 §12.2: an assertion asking for credBlob on a
/// credential that stored none gets an empty byte string — present and typed.
#[test]
fn credblob_reads_empty_for_a_credential_made_without_one() {
    let mut a = Authr::fresh();
    let mc = a.send(CTAP_MAKE_CREDENTIAL, &mc_ext_for(USER_ID, true, 0, |_| {}));
    assert_ok(&mc);
    let g = a.send(
        CTAP_GET_ASSERTION,
        &ga_ext_for(&cred_id(&mc.body), 1, |e| {
            e.str("credBlob").unwrap().bool(true).unwrap();
        }),
    );
    assert_ok(&g);
    let v = ga_ext_output(&g.body, "credBlob").expect("a credBlob output with nothing stored");
    let mut d = Decoder::new(&v);
    assert_eq!(
        d.datatype().unwrap(),
        minicbor::data::Type::Bytes,
        "credBlob is a byte string"
    );
    assert!(
        d.bytes().unwrap().is_empty(),
        "no stored blob reads as an empty one"
    );
}

/// FIDO largeBlobKey P-1. CTAP 2.3 §12.3 gives every credential its own 32-byte
/// key, and that key is all that tells their entries in the shared array apart:
/// two registrations under one RP must not get the same one.
#[cfg(not(feature = "largeblob-ext"))]
#[test]
fn each_credential_gets_its_own_large_blob_key() {
    let mut a = Authr::fresh();
    let mut keys = Vec::new();
    for uid in [[1u8], [2u8]] {
        let r = a.send(
            CTAP_MAKE_CREDENTIAL,
            &mc_ext_for(&uid, true, 1, |e| {
                e.str("largeBlobKey").unwrap().bool(true).unwrap();
            }),
        );
        assert_ok(&r);
        let mut d = field_at(&r.body, 0x05).expect("largeBlobKey (0x05) present");
        keys.push(d.bytes().unwrap().to_vec());
    }
    assert_eq!((keys[0].len(), keys[1].len()), (32, 32));
    assert_ne!(
        keys[0], keys[1],
        "two credentials must not share a largeBlobKey"
    );
}

/// FIDO largeBlobKey F-3. CTAP 2.3 §12.3's input is `true` or absent, so `false`
/// on a getAssertion is refused as an invalid option, not read as "no key".
#[cfg(not(feature = "largeblob-ext"))]
#[test]
fn large_blob_key_false_on_an_assertion_is_an_invalid_option() {
    use crate::error::CtapError;
    let mut a = Authr::fresh();
    let mc = a.send(
        CTAP_MAKE_CREDENTIAL,
        &mc_ext_for(USER_ID, true, 1, |e| {
            e.str("largeBlobKey").unwrap().bool(true).unwrap();
        }),
    );
    assert_ok(&mc);
    let r = a.send(
        CTAP_GET_ASSERTION,
        &ga_ext_for(&cred_id(&mc.body), 1, |e| {
            e.str("largeBlobKey").unwrap().bool(false).unwrap();
        }),
    );
    assert_eq!(
        r.status,
        CtapError::InvalidOption.as_u8(),
        "largeBlobKey: false on getAssertion must be INVALID_OPTION"
    );
    assert!(r.body.is_empty(), "a refused assertion returns nothing");
}

/// Writes one CBOR value: the wrong-typed extension input of a row below.
type WriteValue = fn(&mut Encoder<Cursor<&mut [u8]>>);

/// FIDO largeBlobKey F-4, plus thirdPartyPayment: the two advertised names the
/// getAssertion type table in getassertion_tests.rs leaves out. Both take a
/// boolean; any other type is CBOR_UNEXPECTED_TYPE, never a quietly dropped input.
#[test]
fn a_non_boolean_large_blob_key_or_third_party_payment_is_the_wrong_type() {
    use crate::error::CtapError;
    // A largeblob-ext build does not know `largeBlobKey` (§12.4 allows one design),
    // and an unknown name is ignored at any type.
    let names: &[&str] = if crate::consts::LARGE_BLOB_EXT {
        &["thirdPartyPayment"]
    } else {
        &["largeBlobKey", "thirdPartyPayment"]
    };
    let mut a = Authr::fresh();
    let mc = a.send(CTAP_MAKE_CREDENTIAL, &mc_ext_for(USER_ID, true, 0, |_| {}));
    assert_ok(&mc);
    let id = cred_id(&mc.body);
    for &name in names {
        // The same request with a boolean is served, so the type is what is refused.
        assert_ok(&a.send(
            CTAP_GET_ASSERTION,
            &ga_ext_for(&id, 1, |e| {
                e.str(name).unwrap().bool(true).unwrap();
            }),
        ));
        let wrong: [(&str, WriteValue); 5] = [
            ("an int", |e| {
                e.u8(1).unwrap();
            }),
            ("a text string", |e| {
                e.str("true").unwrap();
            }),
            ("a byte string", |e| {
                e.bytes(&[1]).unwrap();
            }),
            ("an array", |e| {
                e.array(0).unwrap();
            }),
            ("a map", |e| {
                e.map(0).unwrap();
            }),
        ];
        for (what, value) in wrong {
            let r = a.send(
                CTAP_GET_ASSERTION,
                &ga_ext_for(&id, 1, |e| {
                    e.str(name).unwrap();
                    value(e);
                }),
            );
            assert_eq!(
                r.status,
                CtapError::CborUnexpectedType.as_u8(),
                "`{name}` as {what} must be refused as the wrong type"
            );
        }
    }
}
