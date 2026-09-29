// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §6.8 `authenticatorCredentialManagement` conformance, driven through
//! the wire envelope (`process_cbor`): getCredsMetadata's counts, the enumerations'
//! content under a persistent (pcmr) grant, and the permission checks. The MAC over
//! a parameter-less subcommand covers just its command byte (§6.8).

use super::{Authr, assert_ok, assert_ok_empty, field_at, int_map_keys, pin_auth};
use crate::consts::{
    ALG_ES256, CM_ENUMERATE_CREDS_BEGIN, CM_ENUMERATE_RPS_BEGIN, CM_ENUMERATE_RPS_NEXT,
    CM_GET_CREDS_METADATA, CP_GET_PIN_UV_TOKEN_USING_PIN, CRED_PROT_UV_OPTIONAL, CTAP_CLIENT_PIN,
    CTAP_CREDENTIAL_MGMT, CTAP_MAKE_CREDENTIAL, PUBLIC_KEY_TYPE,
};
use crate::cose::cose_key_ecdh;
use crate::error::CtapError;
use crate::state::{PERM_CM, PERM_GA, PERM_PCMR};
use crate::test_pins::PIN;
use minicbor::Encoder;
use minicbor::encode::write::Cursor;
use rsk_crypto::pinproto::{self, PinProto, public_xy};
use rsk_crypto::sha256;

/// A discoverable ES256 makeCredential request over `rp` with user id `uid`.
fn mc_rk(rp: &str, uid: &[u8]) -> Vec<u8> {
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
            .str(rp)
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(uid).unwrap();
        e.str("name").unwrap().str("dave").unwrap();
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

/// getCredsMetadata request: `{1: subCommand, [3: proto, 4: pinUvAuthParam]}`.
fn cm_metadata(param: Option<&[u8]>) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(if param.is_some() { 3 } else { 1 }).unwrap();
        e.u8(1).unwrap().u64(CM_GET_CREDS_METADATA).unwrap();
        if let Some(p) = param {
            e.u8(3).unwrap().u64(2).unwrap();
            e.u8(4).unwrap().bytes(p).unwrap();
        }
        e.writer().position()
    };
    buf[..n].to_vec()
}

#[test]
fn credmgmt_creds_metadata_counts() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk("a.example", &[1])));
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk("b.example", &[2])));

    let token = a.arm_token(PERM_CM);
    let param = pin_auth(&token, &[CM_GET_CREDS_METADATA as u8]);
    let r = a.send(CTAP_CREDENTIAL_MGMT, &cm_metadata(Some(&param)));
    assert_ok(&r);
    // { 1: existingResidentCredentials, 2: maxPossibleRemainingResidentCredentials }
    assert_eq!(int_map_keys(&r.body), vec![1u32, 2]);
    let mut d = field_at(&r.body, 1).expect("existing count (0x01)");
    assert_eq!(
        d.u16().unwrap(),
        2,
        "two resident credentials were registered"
    );
    let mut d = field_at(&r.body, 2).expect("remaining count (0x02)");
    assert!(d.u16().unwrap() >= 1, "remaining capacity must be reported");
}

#[test]
fn credmgmt_requires_pinuvauth() {
    // credMgmt with no pinUvAuthParam → CTAP2_ERR_PUAT_REQUIRED (§6.8).
    let r = Authr::fresh().send(CTAP_CREDENTIAL_MGMT, &cm_metadata(None));
    assert_eq!(r.status, CtapError::PuatRequired.as_u8());
}

#[test]
fn credmgmt_wrong_permission_rejected() {
    // A token missing the credMgmt permission → CTAP2_ERR_PIN_AUTH_INVALID (§6.8).
    let mut a = Authr::fresh();
    let token = a.arm_token(PERM_GA);
    let param = pin_auth(&token, &[CM_GET_CREDS_METADATA as u8]);
    let r = a.send(CTAP_CREDENTIAL_MGMT, &cm_metadata(Some(&param)));
    assert_eq!(r.status, CtapError::PinAuthInvalid.as_u8());
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

/// The platform half of clientPIN protocol two: a fixed ECDH key and the secret it
/// shares with the authenticator.
struct PinClient {
    x: [u8; 32],
    y: [u8; 32],
    shared: Vec<u8>,
}

impl PinClient {
    /// getKeyAgreement, then the platform's half of the ECDH.
    fn establish(a: &mut Authr) -> Self {
        let r = a.send(
            CTAP_CLIENT_PIN,
            &enc(|e| {
                e.map(2).unwrap();
                e.u8(1).unwrap().u64(2).unwrap();
                e.u8(2).unwrap().u64(2).unwrap();
            }),
        );
        assert_ok(&r);
        // {1: 2, 3: -25, -1: 1, -2: x, -3: y}
        let mut d = field_at(&r.body, 1).expect("keyAgreement (0x01) present");
        assert_eq!(d.map().unwrap().unwrap(), 5);
        for _ in 0..3 {
            d.i64().unwrap();
            d.i64().unwrap();
        }
        assert_eq!(d.i64().unwrap(), -2);
        let ax: [u8; 32] = d.bytes().unwrap().try_into().unwrap();
        assert_eq!(d.i64().unwrap(), -3);
        let ay: [u8; 32] = d.bytes().unwrap().try_into().unwrap();
        let s = [0x2B; 32];
        let (x, y) = public_xy(&s).unwrap();
        let mut shared = [0u8; 64];
        let n = pinproto::ecdh(PinProto::Two, &s, &ax, &ay, &mut shared).unwrap();
        PinClient {
            x,
            y,
            shared: shared[..n].to_vec(),
        }
    }

    fn encrypt(&self, pt: &[u8]) -> Vec<u8> {
        let mut out = [0u8; 96];
        let n = pinproto::encrypt(PinProto::Two, &self.shared, &[0x5A; 16], pt, &mut out).unwrap();
        out[..n].to_vec()
    }

    /// setPIN `{1: 2, 2: 3, 3: keyAgreement, 4: pinUvAuthParam, 5: newPinEnc}`.
    fn set_pin(&self, pin: &[u8]) -> Vec<u8> {
        let mut padded = [0u8; 64];
        padded[..pin.len()].copy_from_slice(pin);
        let npe = self.encrypt(&padded);
        let mut mac = [0u8; 32];
        let n = pinproto::authenticate(PinProto::Two, &self.shared, &npe, &mut mac).unwrap();
        enc(|e| {
            e.map(5).unwrap();
            e.u8(1).unwrap().u64(2).unwrap();
            e.u8(2).unwrap().u64(3).unwrap();
            e.u8(3).unwrap();
            cose_key_ecdh(e, &self.x, &self.y).unwrap();
            e.u8(4).unwrap().bytes(&mac[..n]).unwrap();
            e.u8(5).unwrap().bytes(&npe).unwrap();
        })
    }

    /// getPinUvAuthTokenUsingPinWithPermissions for `pcmr` alone and no rpId, as
    /// enumeration requires (§6.8.3): `{1: 2, 2: 9, 3: keyAgreement, 6, 9: pcmr}`.
    fn pcmr_token(&self, pin: &[u8]) -> Vec<u8> {
        let phe = self.encrypt(&sha256(pin)[..16]);
        enc(|e| {
            e.map(5).unwrap();
            e.u8(1).unwrap().u64(2).unwrap();
            e.u8(2).unwrap().u64(CP_GET_PIN_UV_TOKEN_USING_PIN).unwrap();
            e.u8(3).unwrap();
            cose_key_ecdh(e, &self.x, &self.y).unwrap();
            e.u8(6).unwrap().bytes(&phe).unwrap();
            e.u8(9).unwrap().u8(PERM_PCMR).unwrap();
        })
    }

    /// The token a getPinUvAuthToken response `{2: encrypted token}` carries.
    fn decrypt_token(&self, resp: &[u8]) -> [u8; 32] {
        let mut d = field_at(resp, 2).expect("pinUvAuthToken (0x02) present");
        let mut tok = [0u8; 32];
        let n =
            pinproto::decrypt(PinProto::Two, &self.shared, d.bytes().unwrap(), &mut tok).unwrap();
        assert_eq!(n, 32, "a pinUvAuthToken is 32 bytes");
        tok
    }
}

/// Set `PIN`, then take the `pcmr` grant as a platform does (§6.5.5.7.2): the
/// persistent pinUvAuthToken, decrypted out of the clientPIN response.
fn pcmr_grant(a: &mut Authr) -> [u8; 32] {
    let pc = PinClient::establish(a);
    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.set_pin(PIN)));
    let r = a.send(CTAP_CLIENT_PIN, &pc.pcmr_token(PIN));
    assert_ok(&r);
    pc.decrypt_token(&r.body)
}

/// A credentialManagement request `{1: sub, [2: params], 3: 2, 4: MAC}`, MACed with
/// `token` over `sub ‖ params` (§6.8); the params go on the wire exactly as MACed.
fn cm_signed(sub: u64, params: Option<&[u8]>, token: &[u8; 32]) -> Vec<u8> {
    let raw = params.unwrap_or_default();
    let mut msg = vec![sub as u8];
    msg.extend_from_slice(raw);
    let head = enc(|e| {
        e.map(3 + u64::from(params.is_some())).unwrap();
        e.u8(1).unwrap().u64(sub).unwrap();
        if params.is_some() {
            e.u8(2).unwrap();
        }
    });
    let tail = enc(|e| {
        e.u8(3).unwrap().u64(2).unwrap();
        e.u8(4).unwrap().bytes(&pin_auth(token, &msg)).unwrap();
    });
    [head, raw.to_vec(), tail].concat()
}

/// A walker continuation `{1: sub}`, which carries no parameters of its own (§6.8.3).
fn cm_next(sub: u64) -> Vec<u8> {
    enc(|e| {
        e.map(1).unwrap();
        e.u8(1).unwrap().u64(sub).unwrap();
    })
}

/// A discoverable makeCredential over `rp` for one account, displayName included.
fn mc_rk_account(rp: &str, uid: &[u8], name: &str, display: &str) -> Vec<u8> {
    enc(|e| {
        e.map(5).unwrap();
        e.u8(1).unwrap().bytes(&[0xCD; 32]).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str(rp).unwrap();
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

/// The rp.id and rpIDHash of an enumerateRPs leg, asserting the rp entity is `{id}`.
fn enumerated_rp(resp: &[u8]) -> (String, Vec<u8>) {
    let mut d = field_at(resp, 3).expect("rp (0x03) present");
    assert_eq!(d.map().unwrap().unwrap(), 1, "the rp entity is {{id}}");
    assert_eq!(d.str().unwrap(), "id");
    let id = d.str().unwrap().to_string();
    let mut h = field_at(resp, 4).expect("rpIDHash (0x04) present");
    (id, h.bytes().unwrap().to_vec())
}

/// Every member of an enumerated user entity (0x06) in wire order, each value as
/// bytes: `id` is a byte string, the rest are text.
fn enumerated_user(resp: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut d = field_at(resp, 6).expect("user (0x06) present");
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

/// The id of an enumerated credentialID (0x07), asserting a public-key descriptor.
fn enumerated_id(resp: &[u8]) -> Vec<u8> {
    let mut d = field_at(resp, 7).expect("credentialID (0x07) present");
    assert_eq!(d.map().unwrap().unwrap(), 2);
    assert_eq!(d.str().unwrap(), "id");
    let id = d.bytes().unwrap().to_vec();
    assert_eq!(d.str().unwrap(), "type");
    assert_eq!(d.str().unwrap(), "public-key");
    id
}

/// The point `(x, y)` of an enumerated publicKey (0x08), asserting the ES256
/// COSE_Key `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`.
fn enumerated_pubkey(resp: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut d = field_at(resp, 8).expect("publicKey (0x08) present");
    assert_eq!(d.map().unwrap().unwrap(), 5);
    assert_eq!((d.i64().unwrap(), d.i64().unwrap()), (1, 2), "kty: EC2");
    assert_eq!((d.i64().unwrap(), d.i64().unwrap()), (3, ALG_ES256), "alg");
    assert_eq!((d.i64().unwrap(), d.i64().unwrap()), (-1, 1), "crv: P-256");
    assert_eq!(d.i64().unwrap(), -2);
    let x: [u8; 32] = d.bytes().unwrap().try_into().unwrap();
    assert_eq!(d.i64().unwrap(), -3);
    let y: [u8; 32] = d.bytes().unwrap().try_into().unwrap();
    (x, y)
}

/// FIDO CredentialManagement-EnumerateRPs P-5 and P-6. The `pcmr` grant authorizes
/// enumerateRPsBegin and its getNextRP continuation (§6.8.3): each leg names one RP
/// by id and SHA-256(id), and only Begin carries totalRPs.
#[test]
fn a_persistent_grant_walks_the_rps_by_id_and_hash() {
    let mut a = Authr::fresh();
    let rps = ["one.example", "two.example"];
    for (i, rp) in rps.iter().enumerate() {
        assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk(rp, &[i as u8 + 1])));
    }
    let grant = pcmr_grant(&mut a);

    let begin = a.send(
        CTAP_CREDENTIAL_MGMT,
        &cm_signed(CM_ENUMERATE_RPS_BEGIN, None, &grant),
    );
    assert_ok(&begin);
    assert_eq!(
        int_map_keys(&begin.body),
        vec![3u32, 4, 5],
        "Begin is {{rp, rpIDHash, totalRPs}}"
    );
    let mut d = field_at(&begin.body, 5).expect("totalRPs (0x05) present");
    assert_eq!(d.u32().unwrap(), 2, "totalRPs counts both RPs");

    let next = a.send(CTAP_CREDENTIAL_MGMT, &cm_next(CM_ENUMERATE_RPS_NEXT));
    assert_ok(&next);
    assert_eq!(
        int_map_keys(&next.body),
        vec![3u32, 4],
        "getNextRP is {{rp, rpIDHash}}"
    );

    let mut named = Vec::new();
    for leg in [&begin.body, &next.body] {
        let (id, hash) = enumerated_rp(leg);
        assert_eq!(hash, sha256(id.as_bytes()), "rpIDHash is SHA-256(rp.id)");
        named.push(id);
    }
    named.sort();
    assert_eq!(named, rps, "the two legs name the two RPs, one each");
}

/// FIDO CredentialManagement-EnumerateCredentials P-3. Under the `pcmr` grant,
/// enumerateCredentialsBegin (§6.8.4) returns a credential as it was registered —
/// user entity, credential id, public key — and the RP's credential total.
#[test]
fn a_persistent_grant_enumerates_a_credential_as_registered() {
    let mut a = Authr::fresh();
    let accounts: [(&[u8], &str, &str); 2] = [
        (&[0x51], "eve", "Eve Example"),
        (&[0x52], "fay", "Fay Example"),
    ];
    let mut made = Vec::new();
    for (uid, name, display) in accounts {
        let r = a.send(
            CTAP_MAKE_CREDENTIAL,
            &mc_rk_account("one.example", uid, name, display),
        );
        assert_ok(&r);
        made.push(registered(&r.body));
    }
    // Another RP's credential, which this RP's total must not count.
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk("two.example", &[0x53])));
    let grant = pcmr_grant(&mut a);

    let params = enc(|e| {
        e.map(1).unwrap();
        e.u8(1).unwrap().bytes(&sha256(b"one.example")).unwrap();
    });
    let r = a.send(
        CTAP_CREDENTIAL_MGMT,
        &cm_signed(CM_ENUMERATE_CREDS_BEGIN, Some(&params), &grant),
    );
    assert_ok(&r);
    // user, credentialID, publicKey, totalCredentials, credProtect, thirdPartyPayment
    assert_eq!(int_map_keys(&r.body), vec![6u32, 7, 8, 9, 0x0A, 0x0C]);
    let id = enumerated_id(&r.body);
    let k = made
        .iter()
        .position(|(made_id, _)| *made_id == id)
        .expect("the enumerated id is one makeCredential returned");
    let (uid, name, display) = accounts[k];
    let user: Vec<(String, Vec<u8>)> = [
        ("id", uid),
        ("name", name.as_bytes()),
        ("displayName", display.as_bytes()),
    ]
    .iter()
    .map(|(key, value)| (key.to_string(), value.to_vec()))
    .collect();
    assert_eq!(
        enumerated_user(&r.body),
        user,
        "the user entity as registered"
    );
    assert_eq!(
        enumerated_pubkey(&r.body),
        made[k].1,
        "the public key the RP was given at registration"
    );
    let mut d = field_at(&r.body, 9).expect("totalCredentials (0x09) present");
    assert_eq!(
        d.u32().unwrap(),
        2,
        "this RP's two credentials, not the other's"
    );
    let mut d = field_at(&r.body, 0x0A).expect("credProtect (0x0A) present");
    assert_eq!(
        d.u64().unwrap(),
        CRED_PROT_UV_OPTIONAL,
        "registered without credProtect: userVerificationOptional"
    );
    let mut d = field_at(&r.body, 0x0C).expect("thirdPartyPayment (0x0C) present");
    assert!(!d.bool().unwrap(), "not registered for third-party payment");
}
