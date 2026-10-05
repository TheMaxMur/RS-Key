// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §6.2 `authenticatorGetAssertion` conformance assertions, driven
//! through the wire envelope (`process_cbor`). Discoverable credentials are made
//! first and then asserted: user-presence-only where no PIN is set, and under a
//! pinUvAuthToken where the case is about user verification or its absence.

use super::{Authr, assert_ok, assert_ok_empty, field_at, int_map_keys, pin_auth};
use crate::consts::{
    ALG_ES256, CM_DELETE_CREDENTIAL, CTAP_CREDENTIAL_MGMT, CTAP_GET_ASSERTION,
    CTAP_GET_NEXT_ASSERTION, CTAP_MAKE_CREDENTIAL, FLAG_AT, FLAG_UP, FLAG_UV, PUBLIC_KEY_TYPE,
};
use crate::error::CtapError;
use crate::state::{PERM_CM, PERM_GA};
use minicbor::Encoder;
use minicbor::encode::write::Cursor;
use rsk_crypto::sha256;

const RP_ID: &str = "example.com";
const USER_ID: &[u8] = &[1, 2, 3, 4];

/// A discoverable (rk=true) ES256 makeCredential request over `RP_ID`.
fn mc_rk_request() -> Vec<u8> {
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
        e.str("id").unwrap().bytes(USER_ID).unwrap();
        e.str("name").unwrap().str("alice").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
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

/// A getAssertion request over `rp` with no allowList (discoverable lookup).
fn ga_request(rp: &str) -> Vec<u8> {
    let mut buf = [0u8; 128];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(2).unwrap();
        e.u8(1).unwrap().str(rp).unwrap();
        e.u8(2).unwrap().bytes(&[0xCD; 32]).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// A fresh authenticator carrying one discoverable ES256 credential for `RP_ID`.
fn authr_with_credential() -> Authr {
    let mut a = Authr::fresh();
    let r = a.send(CTAP_MAKE_CREDENTIAL, &mc_rk_request());
    assert_ok(&r); // precondition, not the assertion under test
    a
}

#[test]
fn getassertion_response_envelope() {
    let mut a = authr_with_credential();
    let r = a.send(CTAP_GET_ASSERTION, &ga_request(RP_ID));
    assert_ok(&r);
    // Single discoverable credential → {1: credential, 2: authData, 3: sig, 4: user}.
    assert_eq!(int_map_keys(&r.body), vec![1u32, 2, 3, 4]);
    let mut d = field_at(&r.body, 1).expect("credential (0x01) present");
    assert_eq!(
        d.map().unwrap().unwrap(),
        2,
        "credential descriptor is {{id, type}}"
    );
    assert_eq!(d.str().unwrap(), "id");
    assert!(!d.bytes().unwrap().is_empty(), "credential id present");
    assert_eq!(d.str().unwrap(), "type");
    assert_eq!(d.str().unwrap(), "public-key");
}

#[test]
fn getassertion_authdata_and_user() {
    let mut a = authr_with_credential();
    let r = a.send(CTAP_GET_ASSERTION, &ga_request(RP_ID));

    let mut d = field_at(&r.body, 2).expect("authData (0x02) present");
    let ad = d.bytes().unwrap();
    // Assertion authData is rpIdHash(32) | flags(1) | counter(4): no attested data.
    assert!(
        ad.len() >= 37,
        "assertion authData must carry rpIdHash + flags + counter"
    );
    assert_eq!(
        &ad[..32],
        &sha256(RP_ID.as_bytes())[..],
        "rpIdHash must be SHA-256(rpId)"
    );
    assert_eq!(ad[32] & FLAG_UP, FLAG_UP, "UP flag must be set");
    assert_eq!(
        ad[32] & FLAG_AT,
        0,
        "an assertion carries no attested credential data"
    );

    let mut s = field_at(&r.body, 3).expect("signature (0x03) present");
    assert!(
        !s.bytes().unwrap().is_empty(),
        "assertion signature must be present"
    );

    let mut u = field_at(&r.body, 4).expect("user (0x04) present");
    assert_eq!(
        u.map().unwrap().unwrap(),
        1,
        "user is id-only without UV (§6.2.2 privacy)"
    );
    assert_eq!(u.str().unwrap(), "id");
    assert_eq!(
        u.bytes().unwrap(),
        USER_ID,
        "user handle must round-trip the registered id"
    );
}

#[test]
fn getassertion_no_credentials() {
    // An assertion for an RP with no credentials → CTAP2_ERR_NO_CREDENTIALS (§6.2).
    let r = Authr::fresh().send(CTAP_GET_ASSERTION, &ga_request("absent.example"));
    assert_eq!(r.status, CtapError::NoCredentials.as_u8());
    assert!(r.body.is_empty(), "an error response carries no CBOR body");
}

/// A discoverable makeCredential over `RP_ID` with an explicit user id.
fn mc_rk_user(uid: &[u8]) -> Vec<u8> {
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
        e.str("id").unwrap().bytes(uid).unwrap();
        e.str("name").unwrap().str("user").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
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

/// The user id ("id") from an assertion's user field (key 4).
fn assertion_user_id(body: &[u8]) -> Vec<u8> {
    let mut d = field_at(body, 4).expect("user (0x04) present");
    assert!(d.map().unwrap().unwrap() >= 1);
    assert_eq!(d.str().unwrap(), "id");
    d.bytes().unwrap().to_vec()
}

#[test]
fn getnextassertion_walks_multiple_credentials() {
    let mut a = Authr::fresh();
    // Two discoverable credentials on the same RP (distinct user ids).
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk_user(&[0xA1])));
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk_user(&[0xB2])));

    // The first getAssertion reports the count and returns one credential.
    let g1 = a.send(CTAP_GET_ASSERTION, &ga_request(RP_ID));
    assert_ok(&g1);
    let mut d = field_at(&g1.body, 5).expect("numberOfCredentials (0x05) present");
    assert_eq!(d.u32().unwrap(), 2, "two credentials must be reported");
    let u1 = assertion_user_id(&g1.body);

    // getNextAssertion returns the other; a further call is exhausted.
    let g2 = a.send(CTAP_GET_NEXT_ASSERTION, &[]);
    assert_ok(&g2);
    let u2 = assertion_user_id(&g2.body);
    assert_ne!(u1, u2, "the two assertions cover distinct credentials");
    // getNextAssertion carries no numberOfCredentials.
    assert!(
        field_at(&g2.body, 5).is_none(),
        "only the first assertion counts"
    );

    let g3 = a.send(CTAP_GET_NEXT_ASSERTION, &[]);
    assert_eq!(
        g3.status,
        CtapError::NotAllowed.as_u8(),
        "walk is exhausted"
    );
}

#[test]
fn getassertion_signature_verifies() {
    let mut a = Authr::fresh();
    let mc = a.send(CTAP_MAKE_CREDENTIAL, &mc_rk_request());
    assert_ok(&mc);
    let (x, y) = {
        let mut d = field_at(&mc.body, 2).expect("authData (0x02) present");
        super::credential_pubkey(d.bytes().unwrap())
    };

    let g = a.send(CTAP_GET_ASSERTION, &ga_request(RP_ID));
    assert_ok(&g);
    let ad = {
        let mut d = field_at(&g.body, 2).expect("authData (0x02) present");
        d.bytes().unwrap().to_vec()
    };
    let sig = {
        let mut d = field_at(&g.body, 3).expect("signature (0x03) present");
        d.bytes().unwrap().to_vec()
    };
    // The assertion signs authData ‖ clientDataHash with the credential key.
    let mut signed = ad;
    signed.extend_from_slice(&[0xCD; 32]);
    super::verify_p256(&x, &y, &signed, &sig);
}

/// CBOR-encode a request body with `f`.
fn enc(f: impl Fn(&mut Encoder<Cursor<&mut [u8]>>)) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        f(&mut e);
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// Writes one CBOR value into a request under construction.
type Value = fn(&mut Encoder<Cursor<&mut [u8]>>);

/// A `{id, type: "public-key"}` credential descriptor.
fn descriptor(e: &mut Encoder<Cursor<&mut [u8]>>, id: &[u8]) {
    e.map(2).unwrap();
    e.str("id").unwrap().bytes(id).unwrap();
    e.str("type").unwrap().str(PUBLIC_KEY_TYPE).unwrap();
}

/// A discoverable makeCredential over `RP_ID` for one account, with a displayName
/// stored so that an assertion leaking it can be caught doing so.
fn mc_rk_account(uid: &[u8], name: &str, display: &str) -> Vec<u8> {
    enc(|e| {
        e.map(5).unwrap();
        e.u8(1).unwrap().bytes(&[0xCD; 32]).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str(RP_ID).unwrap();
        e.u8(3).unwrap().map(3).unwrap();
        e.str("id").unwrap().bytes(uid).unwrap();
        e.str("name").unwrap().str(name).unwrap();
        e.str("displayName").unwrap().str(display).unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str(PUBLIC_KEY_TYPE).unwrap();
        e.u8(7).unwrap().map(1).unwrap();
        e.str("rk").unwrap().bool(true).unwrap();
    })
}

/// The credential id and public key `(x, y)` a makeCredential response registered.
fn registered(resp: &[u8]) -> (Vec<u8>, ([u8; 32], [u8; 32])) {
    let mut d = field_at(resp, 2).expect("authData (0x02) present");
    let ad = d.bytes().unwrap();
    let len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    (ad[55..55 + len].to_vec(), super::credential_pubkey(ad))
}

/// A getAssertion over `RP_ID`, with `allow` as its allowList and a protocol-2
/// pinUvAuthParam under `token`, each only when given.
fn ga_with(allow: Option<&[&[u8]]>, token: Option<&[u8; 32]>) -> Vec<u8> {
    let cdh = [0xCD; 32];
    enc(|e| {
        let entries = 2 + u64::from(allow.is_some()) + 2 * u64::from(token.is_some());
        e.map(entries).unwrap();
        e.u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&cdh).unwrap();
        if let Some(ids) = allow {
            e.u8(3).unwrap().array(ids.len() as u64).unwrap();
            for id in ids {
                descriptor(e, id);
            }
        }
        if let Some(t) = token {
            e.u8(6).unwrap().bytes(&pin_auth(t, &cdh)).unwrap();
            e.u8(7).unwrap().u64(2).unwrap();
        }
    })
}

/// The credential id (0x01) an assertion was made with.
fn asserted_id(resp: &[u8]) -> Vec<u8> {
    let mut d = field_at(resp, 1).expect("credential (0x01) present");
    assert_eq!(d.map().unwrap().unwrap(), 2);
    assert_eq!(d.str().unwrap(), "id");
    d.bytes().unwrap().to_vec()
}

/// The flags byte of an assertion's authData.
fn asserted_flags(resp: &[u8]) -> u8 {
    let mut d = field_at(resp, 2).expect("authData (0x02) present");
    d.bytes().unwrap()[32]
}

/// Every member of an assertion's user entity (0x04) in wire order, each value as
/// bytes: `id` is a byte string, the rest are text.
fn user_entity(resp: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut d = field_at(resp, 4).expect("user (0x04) present");
    let n = d.map().unwrap().unwrap();
    let mut members = Vec::new();
    for _ in 0..n {
        let key = d.str().unwrap().to_string();
        let value = if key == "id" {
            d.bytes().unwrap().to_vec()
        } else {
            d.str().unwrap().as_bytes().to_vec()
        };
        members.push((key, value));
    }
    members
}

/// `members` in the shape [`user_entity`] returns.
fn entity(members: &[(&str, &[u8])]) -> Vec<(String, Vec<u8>)> {
    members
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_vec()))
        .collect()
}

/// Three accounts on `RP_ID` — user id, name, displayName — registered in order.
const ACCOUNTS: [(&[u8], &str, &str); 3] = [
    (&[0xA0, 0x01], "ann", "Ann Example"),
    (&[0xB0, 0x02], "ben", "Ben Example"),
    (&[0xC0, 0x03], "cat", "Cat Example"),
];

/// Register `accounts` in order and return their credential ids, index for index.
fn register(a: &mut Authr, accounts: &[(&[u8], &str, &str)]) -> Vec<Vec<u8>> {
    accounts
        .iter()
        .map(|(uid, name, display)| {
            let r = a.send(CTAP_MAKE_CREDENTIAL, &mc_rk_account(uid, name, display));
            assert_ok(&r);
            registered(&r.body).0
        })
        .collect()
}

/// Every leg of a discoverable walk over `RP_ID`: the getAssertion, which must
/// count `count` credentials, then the getNextAssertion legs, which must not.
fn walk(a: &mut Authr, token: Option<&[u8; 32]>, count: u32) -> Vec<Vec<u8>> {
    let first = a.send(CTAP_GET_ASSERTION, &ga_with(None, token));
    assert_ok(&first);
    let mut d = field_at(&first.body, 5).expect("numberOfCredentials (0x05) present");
    assert_eq!(
        d.u32().unwrap(),
        count,
        "every account of the RP is counted"
    );
    let mut legs = vec![first.body];
    for _ in 1..count {
        let r = a.send(CTAP_GET_NEXT_ASSERTION, &[]);
        assert_ok(&r);
        assert!(
            field_at(&r.body, 5).is_none(),
            "only the first leg carries numberOfCredentials"
        );
        legs.push(r.body);
    }
    legs
}

/// FIDO ResidentKey P-2. Without user verification every leg of a discoverable walk
/// names its account by user id alone and leaves UV clear: §6.2.2 step 12 and §6.3
/// withhold name and displayName unless the authenticator verified the user.
#[test]
fn a_walk_without_uv_names_each_account_by_its_id_alone() {
    let mut a = Authr::fresh();
    let ids = register(&mut a, &ACCOUNTS);
    let legs = walk(&mut a, None, 3);
    // §6.2.2 step 12: the most recently created credential comes first.
    for (leg, k) in legs.iter().zip([2, 1, 0]) {
        let (uid, _, _) = ACCOUNTS[k];
        assert_eq!(asserted_id(leg), ids[k], "the walk runs newest first");
        assert_eq!(
            user_entity(leg),
            entity(&[("id", uid)]),
            "an unverified leg names the user id alone"
        );
        assert_eq!(
            asserted_flags(leg) & (FLAG_UP | FLAG_UV),
            FLAG_UP,
            "presence was tested, the user was not verified"
        );
    }
}

/// FIDO ResidentKey P-3. With the user verified by a pinUvAuthToken (§6.2.2 step 6)
/// every leg sets UV and names its account in full, getNextAssertion legs included
/// (§6.3): user id, name and displayName exactly as registered.
#[test]
fn a_walk_with_uv_names_each_account_in_full() {
    let mut a = Authr::fresh();
    let accounts = &ACCOUNTS[..2];
    let ids = register(&mut a, accounts);
    let token = a.arm_token(PERM_GA);
    let legs = walk(&mut a, Some(&token), 2);
    for (leg, k) in legs.iter().zip([1, 0]) {
        let (uid, name, display) = accounts[k];
        assert_eq!(asserted_id(leg), ids[k], "the walk runs newest first");
        assert_eq!(
            user_entity(leg),
            entity(&[
                ("id", uid),
                ("name", name.as_bytes()),
                ("displayName", display.as_bytes()),
            ]),
            "a verified leg names the whole account"
        );
        assert_eq!(
            asserted_flags(leg) & (FLAG_UP | FLAG_UV),
            FLAG_UP | FLAG_UV,
            "presence was tested and the user verified"
        );
    }
}

/// FIDO ResidentKey P-6. A second discoverable registration for the same RP and
/// user id overwrites the first (§6.1.2 step 17) with a new id and key pair, and
/// the old id then resolves to nothing: NO_CREDENTIALS (§6.2.2 step 7).
#[test]
fn re_registering_an_account_retires_its_old_credential() {
    let mut a = Authr::fresh();
    let uid: &[u8] = &[0x5A, 0x5A];
    let r = a.send(CTAP_MAKE_CREDENTIAL, &mc_rk_account(uid, "old", "Old Name"));
    assert_ok(&r);
    let (old_id, old_key) = registered(&r.body);
    let r = a.send(CTAP_MAKE_CREDENTIAL, &mc_rk_account(uid, "new", "New Name"));
    assert_ok(&r);
    let (new_id, new_key) = registered(&r.body);
    assert_ne!(new_id, old_id, "the replacement is a new credential");
    assert_ne!(new_key, old_key, "made with a new key pair");

    let r = a.send(
        CTAP_GET_ASSERTION,
        &ga_with(Some(&[old_id.as_slice()]), None),
    );
    assert_eq!(
        r.status,
        CtapError::NoCredentials.as_u8(),
        "the overwritten credential must not assert"
    );

    let r = a.send(
        CTAP_GET_ASSERTION,
        &ga_with(Some(&[new_id.as_slice()]), None),
    );
    assert_ok(&r);
    assert_eq!(asserted_id(&r.body), new_id);
    let mut signed = field_at(&r.body, 2).unwrap().bytes().unwrap().to_vec();
    signed.extend_from_slice(&[0xCD; 32]);
    let sig = field_at(&r.body, 3).unwrap().bytes().unwrap().to_vec();
    super::verify_p256(&new_key.0, &new_key.1, &signed, &sig);

    // One account, one credential: discovery finds the replacement alone.
    let r = a.send(CTAP_GET_ASSERTION, &ga_with(None, None));
    assert_ok(&r);
    assert_eq!(asserted_id(&r.body), new_id);
    assert!(
        field_at(&r.body, 5).is_none(),
        "a lone credential carries no numberOfCredentials"
    );
}

/// deleteCredential for `id` under `token`; the MAC covers `0x06 ‖ subCommandParams`
/// (§6.8.5), and those params go on the wire exactly as MACed.
fn cm_delete(id: &[u8], token: &[u8; 32]) -> Vec<u8> {
    let params = enc(|e| {
        e.map(1).unwrap();
        e.u8(2).unwrap();
        descriptor(e, id);
    });
    let mut msg = vec![CM_DELETE_CREDENTIAL as u8];
    msg.extend_from_slice(&params);
    let head = enc(|e| {
        e.map(4).unwrap();
        e.u8(1).unwrap().u64(CM_DELETE_CREDENTIAL).unwrap();
        e.u8(2).unwrap();
    });
    let tail = enc(|e| {
        e.u8(3).unwrap().u64(2).unwrap();
        e.u8(4).unwrap().bytes(&pin_auth(token, &msg)).unwrap();
    });
    [head, params, tail].concat()
}

/// FIDO CredentialManagement-UpdateAndDelete P-2. A deleted credential is gone for
/// an allowList too (§6.8.5): its id misses the store and falls through to the
/// non-resident path, which must not bring it back — NO_CREDENTIALS.
#[test]
fn a_deleted_credential_does_not_assert_by_its_id() {
    let mut a = Authr::fresh();
    let r = a.send(
        CTAP_MAKE_CREDENTIAL,
        &mc_rk_account(&[0x0D], "dan", "Dan Example"),
    );
    assert_ok(&r);
    let (id, _) = registered(&r.body);
    let allow: &[&[u8]] = &[&id];

    // Control: while stored, the id resolves through the allowList.
    let token = a.arm_token(PERM_GA);
    let r = a.send(CTAP_GET_ASSERTION, &ga_with(Some(allow), Some(&token)));
    assert_ok(&r);
    assert_eq!(asserted_id(&r.body), id);

    let token = a.arm_token(PERM_CM);
    assert_ok_empty(&a.send(CTAP_CREDENTIAL_MGMT, &cm_delete(&id, &token)));

    let token = a.arm_token(PERM_GA);
    let r = a.send(CTAP_GET_ASSERTION, &ga_with(Some(allow), Some(&token)));
    assert_eq!(
        r.status,
        CtapError::NoCredentials.as_u8(),
        "a deleted credential must not assert"
    );
}

/// FIDO Authr-GetAssertion-Req-1 F-3. clientDataHash is Required (§6.2), so a
/// request going from rpId straight to allowList is MISSING_PARAMETER — seen as
/// key 3 arrives, not by the check after the map for a request that just stops.
#[test]
fn a_client_data_hash_skipped_for_the_allow_list_is_missing_parameter() {
    let req = enc(|e| {
        e.map(2).unwrap();
        e.u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(3).unwrap().array(1).unwrap();
        descriptor(e, &[0x42; 16]);
    });
    let r = Authr::fresh().send(CTAP_GET_ASSERTION, &req);
    assert_eq!(
        r.status,
        CtapError::MissingParameter.as_u8(),
        "clientDataHash is absent, not malformed: got 0x{:02x}",
        r.status
    );
}

/// `{1: rpId, 2: clientDataHash [, 3: allowList]}`, all well-formed except the
/// value of `key` (1, 2 or 3), which `bad` writes.
fn ga_one_bad(key: u8, bad: Value) -> Vec<u8> {
    enc(|e| {
        e.map(if key == 3 { 3 } else { 2 }).unwrap();
        e.u8(1).unwrap();
        if key == 1 {
            bad(e);
        } else {
            e.str(RP_ID).unwrap();
        }
        e.u8(2).unwrap();
        if key == 2 {
            bad(e);
        } else {
            e.bytes(&[0xCD; 32]).unwrap();
        }
        if key == 3 {
            e.u8(3).unwrap();
            bad(e);
        }
    })
}

/// FIDO Authr-GetAssertion-Req-1 F-2, F-4, F-5 and F-6. A request member of the
/// wrong CBOR type — rpId, clientDataHash, allowList, or an allowList member that
/// is not a map — is CTAP2_ERR_CBOR_UNEXPECTED_TYPE (§8), whatever the type.
#[test]
fn a_wrong_typed_request_member_is_cbor_unexpected_type() {
    let rows: [(&str, u8, Value); 11] = [
        ("rpId as a byte string", 1, |e| {
            e.bytes(RP_ID.as_bytes()).unwrap();
        }),
        ("rpId as an integer", 1, |e| {
            e.u8(7).unwrap();
        }),
        ("rpId as a map", 1, |e| {
            e.map(0).unwrap();
        }),
        ("clientDataHash as a text string", 2, |e| {
            e.str("digest").unwrap();
        }),
        ("clientDataHash as an integer", 2, |e| {
            e.u8(7).unwrap();
        }),
        ("clientDataHash as an array", 2, |e| {
            e.array(0).unwrap();
        }),
        ("allowList as a map", 3, |e| {
            e.map(0).unwrap();
        }),
        ("allowList as a byte string", 3, |e| {
            e.bytes(&[0x42; 16]).unwrap();
        }),
        ("allowList member as a byte string", 3, |e| {
            e.array(2).unwrap();
            descriptor(e, &[0x42; 16]);
            e.bytes(&[0x42; 16]).unwrap();
        }),
        ("allowList member as a text string", 3, |e| {
            e.array(2).unwrap();
            descriptor(e, &[0x42; 16]);
            e.str(PUBLIC_KEY_TYPE).unwrap();
        }),
        ("allowList member as an integer", 3, |e| {
            e.array(2).unwrap();
            descriptor(e, &[0x42; 16]);
            e.u8(7).unwrap();
        }),
    ];
    for (label, key, bad) in rows {
        let r = Authr::fresh().send(CTAP_GET_ASSERTION, &ga_one_bad(key, bad));
        assert_eq!(
            r.status,
            CtapError::CborUnexpectedType.as_u8(),
            "{label}: got 0x{:02x}",
            r.status
        );
    }
}

#[path = "assertion_failure_tests.rs"]
mod failures;
