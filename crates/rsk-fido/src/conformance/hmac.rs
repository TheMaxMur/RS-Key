// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §12.5 hmac-secret *evaluate* conformance, driven through the wire
//! envelope (`process_cbor`): a credential is created with hmac-secret, then a
//! getAssertion carries `{keyAgreement, saltEnc, saltAuth}` and the encrypted
//! output decrypts (under the ECDH shared secret) to a 32-byte value that is
//! deterministic per (credential, salt). The platform runs the real
//! pinUvAuthProtocol-2 primitives.

use super::{Authr, assert_ok, field_at};
use crate::consts::{ALG_ES256, CTAP_CLIENT_PIN, CTAP_GET_ASSERTION, CTAP_MAKE_CREDENTIAL};
use crate::cose::cose_key_ecdh;
use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};
use rsk_crypto::pinproto::{self, PinProto, public_xy};

const RP_ID: &str = "hmac.example";
const CDH: [u8; 32] = [0xCD; 32];
const SALT: [u8; 32] = [0xA1; 32];

/// The platform half of the ECDH exchange (a fixed key + the shared secret).
struct Ecdh {
    x: [u8; 32],
    y: [u8; 32],
    shared: Vec<u8>,
}

impl Ecdh {
    fn establish(a: &mut Authr) -> Self {
        // getKeyAgreement: {1: proto=2, 2: subCommand=2}.
        let mut kbuf = [0u8; 16];
        let kn = {
            let mut e = Encoder::new(Cursor::new(&mut kbuf[..]));
            e.map(2).unwrap();
            e.u8(1).unwrap().u64(2).unwrap();
            e.u8(2).unwrap().u64(2).unwrap();
            e.writer().position()
        };
        let r = a.send(CTAP_CLIENT_PIN, &kbuf[..kn]);
        let (ax, ay) = authenticator_public(&r.body);
        let mut s = [0u8; 32];
        s[0] = 0x13;
        s[31] = 0x42;
        let (x, y) = public_xy(&s).unwrap();
        let mut shared = [0u8; 64];
        let slen = pinproto::ecdh(PinProto::Two, &s, &ax, &ay, &mut shared).unwrap();
        Ecdh {
            x,
            y,
            shared: shared[..slen].to_vec(),
        }
    }

    fn enc(&self, pt: &[u8]) -> Vec<u8> {
        let mut out = [0u8; 96];
        let n = pinproto::encrypt(PinProto::Two, &self.shared, &[0x55; 16], pt, &mut out).unwrap();
        out[..n].to_vec()
    }

    fn mac(&self, data: &[u8]) -> Vec<u8> {
        let mut out = [0u8; 32];
        let n = pinproto::authenticate(PinProto::Two, &self.shared, data, &mut out).unwrap();
        out[..n].to_vec()
    }

    fn decrypt(&self, ct: &[u8]) -> Vec<u8> {
        let mut out = [0u8; 96];
        let n = pinproto::decrypt(PinProto::Two, &self.shared, ct, &mut out).unwrap();
        out[..n].to_vec()
    }
}

/// The authenticator's key-agreement public key from getKeyAgreement.
fn authenticator_public(body: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut d = field_at(body, 1).expect("keyAgreement (0x01) present");
    assert_eq!(d.map().unwrap().unwrap(), 5);
    d.u8().unwrap();
    d.u8().unwrap(); // 1: kty
    d.u8().unwrap();
    d.i64().unwrap(); // 3: alg
    d.i8().unwrap();
    d.u8().unwrap(); // -1: crv
    d.i8().unwrap(); // -2: x label
    let mut x = [0u8; 32];
    x.copy_from_slice(d.bytes().unwrap());
    d.i8().unwrap(); // -3: y label
    let mut y = [0u8; 32];
    y.copy_from_slice(d.bytes().unwrap());
    (x, y)
}

/// A discoverable makeCredential over `RP_ID` requesting hmac-secret.
fn mc_hmac() -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(6).unwrap();
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
        e.str("id").unwrap().bytes(&[9, 9]).unwrap();
        e.str("name").unwrap().str("grace").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(6)
            .unwrap()
            .map(1)
            .unwrap()
            .str("hmac-secret")
            .unwrap()
            .bool(true)
            .unwrap();
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

/// A getAssertion over `RP_ID` evaluating hmac-secret for `salt`.
fn ga_hmac(ecdh: &Ecdh, salt: &[u8]) -> Vec<u8> {
    let salt_enc = ecdh.enc(salt);
    let salt_auth = ecdh.mac(&salt_enc);
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(3).unwrap();
        e.u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        // extensions: { hmac-secret: { 1: keyAgreement, 2: saltEnc, 3: saltAuth, 4: proto } }
        e.u8(4).unwrap().map(1).unwrap();
        e.str("hmac-secret").unwrap().map(4).unwrap();
        e.u8(1).unwrap();
        cose_key_ecdh(&mut e, &ecdh.x, &ecdh.y).unwrap();
        e.u8(2).unwrap().bytes(&salt_enc).unwrap();
        e.u8(3).unwrap().bytes(&salt_auth).unwrap();
        e.u8(4).unwrap().u64(2).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// [`ga_hmac`] plus `{5: {"up": false}}` — the silent pre-flight shape.
fn ga_hmac_up_false(ecdh: &Ecdh, salt: &[u8]) -> Vec<u8> {
    let salt_enc = ecdh.enc(salt);
    let salt_auth = ecdh.mac(&salt_enc);
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(4).unwrap().map(1).unwrap();
        e.str("hmac-secret").unwrap().map(4).unwrap();
        e.u8(1).unwrap();
        cose_key_ecdh(&mut e, &ecdh.x, &ecdh.y).unwrap();
        e.u8(2).unwrap().bytes(&salt_enc).unwrap();
        e.u8(3).unwrap().bytes(&salt_auth).unwrap();
        e.u8(4).unwrap().u64(2).unwrap();
        e.u8(5).unwrap().map(1).unwrap();
        e.str("up").unwrap().bool(false).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// The (still-encrypted) hmac-secret output from a getAssertion authData.
fn hmac_output(body: &[u8]) -> Vec<u8> {
    let mut d = field_at(body, 2).expect("authData (0x02) present");
    let ad = d.bytes().unwrap();
    // Assertion authData is rpIdHash(32) | flags(1) | counter(4) | extension map.
    let mut ext = Decoder::new(&ad[37..]);
    let n = ext.map().unwrap().unwrap();
    for _ in 0..n {
        if ext.str().unwrap() == "hmac-secret" {
            return ext.bytes().unwrap().to_vec();
        }
        ext.skip().unwrap();
    }
    panic!("hmac-secret output missing from the assertion");
}

#[test]
fn hmac_secret_evaluate_returns_output() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_hmac()));
    let ecdh = Ecdh::establish(&mut a);
    let g = a.send(CTAP_GET_ASSERTION, &ga_hmac(&ecdh, &SALT));
    assert_ok(&g);
    let out = ecdh.decrypt(&hmac_output(&g.body));
    assert_eq!(
        out.len(),
        32,
        "one salt yields a 32-byte hmac-secret output"
    );
}

#[test]
fn hmac_secret_is_deterministic_per_salt() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_hmac()));
    let ecdh = Ecdh::establish(&mut a);

    let out1 = ecdh.decrypt(&hmac_output(
        &a.send(CTAP_GET_ASSERTION, &ga_hmac(&ecdh, &SALT)).body,
    ));
    let out2 = ecdh.decrypt(&hmac_output(
        &a.send(CTAP_GET_ASSERTION, &ga_hmac(&ecdh, &SALT)).body,
    ));
    assert_eq!(out1, out2, "same salt → same hmac-secret output");

    let salt2 = [0xB2u8; 32];
    let other = ecdh.decrypt(&hmac_output(
        &a.send(CTAP_GET_ASSERTION, &ga_hmac(&ecdh, &salt2)).body,
    ));
    assert_ne!(out1, other, "a different salt yields a different output");
}

/// CTAP 2.1 §12.5: "If 'up' is set to false, authenticator returns
/// CTAP2_ERR_UNSUPPORTED_OPTION." The `up:false` probe skips the presence gate, so
/// serving the extension there hands out per-credential PRF material with no touch
/// and no PIN — and does so on the always-uv build too (audit run-32).
#[test]
fn hmac_secret_is_refused_on_an_up_false_probe() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_hmac()));
    let ecdh = Ecdh::establish(&mut a);
    // The same request minus the option still works, so this is the option's doing.
    assert_ok(&a.send(CTAP_GET_ASSERTION, &ga_hmac(&ecdh, &SALT)));
    let g = a.send(CTAP_GET_ASSERTION, &ga_hmac_up_false(&ecdh, &SALT));
    assert_eq!(
        g.status,
        crate::error::CtapError::UnsupportedOption as u8,
        "hmac-secret must be refused with 0x2b on an up:false request"
    );
    assert!(g.body.is_empty(), "a refused probe returns no assertion");
}
