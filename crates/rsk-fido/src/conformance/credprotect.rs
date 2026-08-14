// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 credProtect (§12.1 + §6.2.2 privacy) conformance, driven through the
//! wire envelope (`process_cbor`): a level-3 (userVerificationRequired) extension
//! is echoed in the makeCredential authData, and a level-3 discoverable
//! credential is invisible to getAssertion without user verification — but
//! returned once a pinUvAuthToken supplies UV.

use super::{Authr, assert_ok, field_at, pin_auth};
use crate::consts::{
    ALG_ES256, CRED_PROT_UV_OPTIONAL, CRED_PROT_UV_OPTIONAL_WITH_LIST, CRED_PROT_UV_REQUIRED,
    CTAP_GET_ASSERTION, CTAP_MAKE_CREDENTIAL, FLAG_ED,
};
use crate::error::CtapError;
use crate::state::PERM_GA;
use minicbor::Encoder;
use minicbor::encode::write::Cursor;

const RP_ID: &str = "protect.example";
const USER_ID: &[u8] = &[7, 7, 7, 7];
const CDH: [u8; 32] = [0xCD; 32];

/// makeCredential with a `credProtect` extension (request key 6), optionally rk.
fn mc_credprotect(level: u64, rk: bool) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(if rk { 6 } else { 5 }).unwrap();
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
        e.str("name").unwrap().str("carol").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(6)
            .unwrap()
            .map(1)
            .unwrap()
            .str("credProtect")
            .unwrap()
            .u64(level)
            .unwrap();
        if rk {
            e.u8(7)
                .unwrap()
                .map(1)
                .unwrap()
                .str("rk")
                .unwrap()
                .bool(true)
                .unwrap();
        }
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// A getAssertion request over `RP_ID`, optionally carrying a pinUvAuthParam
/// (keys 6/7) to supply UV.
fn ga(uv: Option<&[u8]>) -> Vec<u8> {
    let mut buf = [0u8; 128];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(if uv.is_some() { 4 } else { 2 }).unwrap();
        e.u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        if let Some(param) = uv {
            e.u8(6).unwrap().bytes(param).unwrap();
            e.u8(7).unwrap().u64(2).unwrap();
        }
        e.writer().position()
    };
    buf[..n].to_vec()
}

#[test]
fn credprotect_echoed_in_authdata() {
    let r = Authr::fresh().send(
        CTAP_MAKE_CREDENTIAL,
        &mc_credprotect(CRED_PROT_UV_REQUIRED, false),
    );
    assert_ok(&r);
    let mut d = field_at(&r.body, 2).expect("authData (0x02) present");
    let ad = d.bytes().unwrap();
    assert_eq!(
        ad[32] & FLAG_ED,
        FLAG_ED,
        "ED flag must be set when extensions are present"
    );
    // Walk past the attested credential data (aaguid, credId, COSE key) to the
    // authData extension map and read back the credProtect level.
    let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let mut ext = minicbor::Decoder::new(&ad[55 + cred_len..]);
    ext.skip().unwrap(); // the COSE public key map
    let n = ext.map().unwrap().expect("authData extension map");
    let mut level = None;
    for _ in 0..n {
        if ext.str().unwrap() == "credProtect" {
            level = Some(ext.u64().unwrap());
        } else {
            ext.skip().unwrap();
        }
    }
    assert_eq!(
        level,
        Some(CRED_PROT_UV_REQUIRED),
        "credProtect level must echo the request"
    );
}

#[test]
fn credprotect3_hidden_without_uv() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(
        CTAP_MAKE_CREDENTIAL,
        &mc_credprotect(CRED_PROT_UV_REQUIRED, true),
    ));
    // A userVerificationRequired credential is invisible to a no-UV assertion
    // (CTAP 2.1 §6.2.2 / §12.1) → CTAP2_ERR_NO_CREDENTIALS.
    let r = a.send(CTAP_GET_ASSERTION, &ga(None));
    assert_eq!(r.status, CtapError::NoCredentials.as_u8());
}

#[test]
fn credprotect3_visible_with_uv() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(
        CTAP_MAKE_CREDENTIAL,
        &mc_credprotect(CRED_PROT_UV_REQUIRED, true),
    ));
    // Supply UV via a pinUvAuthToken → the same credential is now returned.
    let token = a.arm_token(PERM_GA);
    let param = pin_auth(&token, &CDH);
    let r = a.send(CTAP_GET_ASSERTION, &ga(Some(&param)));
    assert_ok(&r);
}

/// A getAssertion over `RP_ID` naming `id` in the allowList (no UV).
fn ga_allow(id: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 128];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(3).unwrap();
        e.u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.str("id").unwrap().bytes(id).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// The credential id from a makeCredential authData.
fn cred_id(body: &[u8]) -> Vec<u8> {
    let mut d = field_at(body, 2).expect("authData (0x02) present");
    let ad = d.bytes().unwrap();
    let cl = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    ad[55..55 + cl].to_vec()
}

#[test]
fn credprotect1_always_visible() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(
        CTAP_MAKE_CREDENTIAL,
        &mc_credprotect(CRED_PROT_UV_OPTIONAL, true),
    ));
    // Level 1 (userVerificationOptional) is returned to a no-UV discoverable assertion.
    assert_ok(&a.send(CTAP_GET_ASSERTION, &ga(None)));
}

#[test]
fn credprotect2_needs_list_or_uv() {
    let mut a = Authr::fresh();
    let r = a.send(
        CTAP_MAKE_CREDENTIAL,
        &mc_credprotect(CRED_PROT_UV_OPTIONAL_WITH_LIST, true),
    );
    assert_ok(&r);
    let id = cred_id(&r.body);
    // Level 2 is invisible to a no-UV discoverable assertion (§12.1)...
    assert_eq!(
        a.send(CTAP_GET_ASSERTION, &ga(None)).status,
        CtapError::NoCredentials.as_u8()
    );
    // ...but visible when named in the allowList.
    assert_ok(&a.send(CTAP_GET_ASSERTION, &ga_allow(&id)));
}

/// A credProtect=userVerificationRequired credential must NOT be usable over the U2F
/// authenticate path (U2F performs no user verification); a level-1 credential still
/// signs there. Guards the credProtect §12.1 invariant on the legacy transport.
#[test]
fn credprotect3_box_refused_on_u2f_but_level1_signs() {
    use crate::consts::{CTAP_AUTHENTICATE, U2F_AUTH_ENFORCE};
    use rsk_sdk::sw::Sw;

    // Extended-length U2F APDU: cla ins p1 00 00 Lc(2) data 00 00.
    fn ext(ins: u8, p1: u8, data: &[u8]) -> Vec<u8> {
        let mut v = std::vec![
            0x00,
            ins,
            p1,
            0x00,
            0x00,
            (data.len() >> 8) as u8,
            data.len() as u8
        ];
        v.extend_from_slice(data);
        v.extend_from_slice(&[0x00, 0x00]);
        v
    }
    // U2F_AUTHENTICATE body: challenge(32) ‖ application=sha256(rpId) ‖ khLen ‖ keyHandle.
    fn auth_body(app: &[u8; 32], id: &[u8]) -> Vec<u8> {
        let mut ad = std::vec![0xC4u8; 32];
        ad.extend_from_slice(app);
        ad.push(id.len() as u8);
        ad.extend_from_slice(id);
        ad
    }
    let app = rsk_crypto::sha256(RP_ID.as_bytes());

    // Level 3 (UV-required), non-resident: U2F must refuse the box (no UV on U2F).
    let mut a = Authr::fresh();
    let r = a.send(
        CTAP_MAKE_CREDENTIAL,
        &mc_credprotect(CRED_PROT_UV_REQUIRED, false),
    );
    assert_ok(&r);
    let id3 = cred_id(&r.body);
    let (sw, body) = a.send_u2f(&ext(
        CTAP_AUTHENTICATE,
        U2F_AUTH_ENFORCE,
        &auth_body(&app, &id3),
    ));
    assert_eq!(
        sw,
        Sw::WRONG_DATA,
        "credProtect=3 box must be refused over U2F"
    );
    assert!(body.is_empty());

    // Level 1 (UV-optional), non-resident: a valid CTAP2 box still signs over U2F.
    let mut a = Authr::fresh();
    let r = a.send(
        CTAP_MAKE_CREDENTIAL,
        &mc_credprotect(CRED_PROT_UV_OPTIONAL, false),
    );
    assert_ok(&r);
    let id1 = cred_id(&r.body);
    let (sw, body) = a.send_u2f(&ext(
        CTAP_AUTHENTICATE,
        U2F_AUTH_ENFORCE,
        &auth_body(&app, &id1),
    ));
    assert_eq!(sw, Sw::OK, "credProtect=1 box authenticates over U2F");
    assert!(!body.is_empty());
}
