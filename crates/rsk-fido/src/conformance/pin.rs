// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §6.5 clientPIN crypto-flow conformance, driven through the wire
//! envelope (`process_cbor`): key agreement (ECDH), setPIN, getPinToken (correct
//! PIN → a decryptable token; wrong PIN → PIN_INVALID + a retry decrement) and
//! changePIN. The platform side runs the real pinUvAuthProtocol primitives (protocol
//! 2 throughout, protocol 1 where a case needs it), so the exchange is verified end to end.

use super::{Authr, assert_ok, assert_ok_empty, field_at};
use crate::consts::{
    CP_GET_PIN_TOKEN, CP_GET_PIN_UV_TOKEN_USING_PIN, CTAP_CLIENT_PIN, MAX_PIN_RETRIES,
    PUBLIC_KEY_TYPE,
};
use crate::cose::cose_key_ecdh;
use crate::error::{CTAP2_OK, CtapError};
use crate::test_pins::{NEW_PIN, PIN, WRONG_PIN};
use minicbor::Encoder;
use minicbor::encode::write::Cursor;
use rsk_crypto::pinproto::{self, PinProto, public_xy};
use rsk_crypto::sha256;

/// A short two-key clientPIN request `{1: proto=2, 2: subCommand}`.
fn cp_short(sub: u64) -> Vec<u8> {
    let mut buf = [0u8; 16];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(2).unwrap();
        e.u8(1).unwrap().u64(2).unwrap();
        e.u8(2).unwrap().u64(sub).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// Read `options.clientPin` from a fresh getInfo.
fn client_pin_set(a: &mut Authr) -> bool {
    let r = a.get_info();
    let mut d = field_at(&r.body, 4).expect("options (0x04) present");
    let n = d.map().unwrap().unwrap();
    for _ in 0..n {
        let hit = d.str().unwrap() == "clientPin";
        let v = d.bool().unwrap();
        if hit {
            return v;
        }
    }
    false
}

/// getPINRetries (subCommand 1) → the current counter.
fn pin_retries(a: &mut Authr) -> u8 {
    let r = a.send(CTAP_CLIENT_PIN, &cp_short(1));
    let mut d = field_at(&r.body, 3).expect("retries (0x03) present");
    d.u8().unwrap()
}

/// The platform half of the PIN protocol: a fixed ECDH key + the shared secret.
struct PinClient {
    x: [u8; 32],
    y: [u8; 32],
    shared: Vec<u8>,
}

impl PinClient {
    /// Perform key agreement (getKeyAgreement) and derive the shared secret.
    fn establish(a: &mut Authr) -> Self {
        let r = a.send(CTAP_CLIENT_PIN, &cp_short(2));
        let (ax, ay) = authenticator_public(&r.body);
        let mut s = [0u8; 32];
        s[0] = 0x13;
        s[31] = 0x42;
        let (x, y) = public_xy(&s).unwrap();
        let mut shared = [0u8; 64];
        let slen = pinproto::ecdh(PinProto::Two, &s, &ax, &ay, &mut shared).unwrap();
        PinClient {
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

    /// setPIN request: `{1:2, 2:3, 3:keyAgreement, 4:pinUvAuthParam, 5:newPinEnc}`.
    fn set_pin(&self, pin: &[u8]) -> Vec<u8> {
        let mut padded = [0u8; 64];
        padded[..pin.len()].copy_from_slice(pin);
        let npe = self.enc(&padded);
        let puap = self.mac(&npe);
        let mut buf = [0u8; 256];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(5).unwrap();
            e.u8(1).unwrap().u64(2).unwrap();
            e.u8(2).unwrap().u64(3).unwrap();
            e.u8(3).unwrap();
            cose_key_ecdh(&mut e, &self.x, &self.y).unwrap();
            e.u8(4).unwrap().bytes(&puap).unwrap();
            e.u8(5).unwrap().bytes(&npe).unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    /// Legacy getPinToken request: `{1:2, 2:5, 3:keyAgreement, 6:pinHashEnc}`.
    fn get_token(&self, pin: &[u8]) -> Vec<u8> {
        let h = sha256(pin);
        let phe = self.enc(&h[..16]);
        let mut buf = [0u8; 256];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(4).unwrap();
            e.u8(1).unwrap().u64(2).unwrap();
            e.u8(2).unwrap().u64(5).unwrap();
            e.u8(3).unwrap();
            cose_key_ecdh(&mut e, &self.x, &self.y).unwrap();
            e.u8(6).unwrap().bytes(&phe).unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    /// getPinUvAuthTokenUsingPinWithPermissions (0x09) request:
    /// `{1:2, 2:9, 3:keyAgreement, 6:pinHashEnc, 9:permissions, 10:rpId}` — the path
    /// desktop Chrome takes (an rpId-bound, permission-scoped token).
    fn get_token_perms(&self, pin: &[u8], permissions: u8, rp: &str) -> Vec<u8> {
        let h = sha256(pin);
        let phe = self.enc(&h[..16]);
        let mut buf = [0u8; 256];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(6).unwrap();
            e.u8(1).unwrap().u64(2).unwrap();
            e.u8(2).unwrap().u64(9).unwrap();
            e.u8(3).unwrap();
            cose_key_ecdh(&mut e, &self.x, &self.y).unwrap();
            e.u8(6).unwrap().bytes(&phe).unwrap();
            e.u8(9).unwrap().u64(u64::from(permissions)).unwrap();
            e.u8(10).unwrap().str(rp).unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    /// changePIN request: `{1:2, 2:4, 3:keyAgreement, 4:puap, 5:newPinEnc, 6:pinHashEnc}`.
    fn change_pin(&self, old: &[u8], new: &[u8]) -> Vec<u8> {
        let mut padded = [0u8; 64];
        padded[..new.len()].copy_from_slice(new);
        let npe = self.enc(&padded);
        let oh = sha256(old);
        let phe = self.enc(&oh[..16]);
        let mut macd = npe.clone();
        macd.extend_from_slice(&phe);
        let puap = self.mac(&macd);
        let mut buf = [0u8; 256];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(6).unwrap();
            e.u8(1).unwrap().u64(2).unwrap();
            e.u8(2).unwrap().u64(4).unwrap();
            e.u8(3).unwrap();
            cose_key_ecdh(&mut e, &self.x, &self.y).unwrap();
            e.u8(4).unwrap().bytes(&puap).unwrap();
            e.u8(5).unwrap().bytes(&npe).unwrap();
            e.u8(6).unwrap().bytes(&phe).unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    /// Decrypt the pinUvAuthToken from a getPinToken response `{2: enc}`.
    fn decrypt_token(&self, body: &[u8]) -> [u8; 32] {
        let mut d = field_at(body, 2).expect("pinUvAuthToken (0x02) present");
        let enc = d.bytes().unwrap();
        let mut tok = [0u8; 32];
        let n = pinproto::decrypt(PinProto::Two, &self.shared, enc, &mut tok).unwrap();
        assert_eq!(n, 32, "a pinUvAuthToken is 32 bytes");
        tok
    }
}

/// The authenticator's key-agreement public key (x, y) from getKeyAgreement:
/// `{1: {1:2, 3:-25, -1:1, -2:x, -3:y}}`.
fn authenticator_public(body: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut d = field_at(body, 1).expect("keyAgreement (0x01) present");
    assert_eq!(d.map().unwrap().unwrap(), 5);
    d.u8().unwrap();
    d.u8().unwrap(); // 1: kty = 2
    d.u8().unwrap();
    d.i64().unwrap(); // 3: alg = -25
    d.i8().unwrap();
    d.u8().unwrap(); // -1: crv = 1
    d.i8().unwrap(); // -2: x label
    let mut x = [0u8; 32];
    x.copy_from_slice(d.bytes().unwrap());
    d.i8().unwrap(); // -3: y label
    let mut y = [0u8; 32];
    y.copy_from_slice(d.bytes().unwrap());
    (x, y)
}

/// A no-PIN makeCredential over `rp` (up-only, keys 1–4).
fn mc_nopin(rp: &str) -> Vec<u8> {
    use crate::consts::ALG_ES256;
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
            .str(rp)
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        e.str("name").unwrap().str("alice").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// A makeCredential over `rp` carrying a pinUvAuthParam (keys 1–4, [7 rk], 8, 9):
/// the MAC of the clientDataHash under `token` (protocol 2). Models what a browser
/// sends once a PIN is configured; `rk` requests a discoverable (passkey) credential.
fn mc_with_pin(rp: &str, token: &[u8; 32], rk: bool) -> Vec<u8> {
    use crate::consts::ALG_ES256;
    let cdh = [0xCEu8; 32];
    let puap = super::pin_auth(token, &cdh);
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(if rk { 7 } else { 6 }).unwrap();
        e.u8(1).unwrap().bytes(&cdh).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str(rp)
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[9, 9, 9, 9]).unwrap();
        e.str("name").unwrap().str("bob").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
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
        e.u8(8).unwrap().bytes(&puap).unwrap();
        e.u8(9).unwrap().u64(2).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// A no-PIN discoverable (rk=true) makeCredential over `rp` (keys 1–4, 7).
fn mc_nopin_rk(rp: &str) -> Vec<u8> {
    use crate::consts::ALG_ES256;
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
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
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

/// A makeCredential over `rp` carrying a ZERO-LENGTH pinUvAuthParam (key 8 empty,
/// key 9 protocol): the CTAP 2.1 §6.1.2 step-1 selection probe a platform sends to
/// get a device-selection touch and learn the PIN state.
fn mc_probe(rp: &str) -> Vec<u8> {
    use crate::consts::ALG_ES256;
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(6).unwrap();
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
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        e.str("name").unwrap().str("alice").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(8).unwrap().bytes(&[]).unwrap();
        e.u8(9).unwrap().u64(2).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// A getAssertion over `rp` carrying a ZERO-LENGTH pinUvAuthParam (key 6 empty,
/// key 7 protocol): the CTAP 2.1 §6.2.2 step-1 selection probe.
fn ga_probe(rp: &str) -> Vec<u8> {
    let mut buf = [0u8; 128];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().str(rp).unwrap();
        e.u8(2).unwrap().bytes(&[0xCD; 32]).unwrap();
        e.u8(6).unwrap().bytes(&[]).unwrap();
        e.u8(7).unwrap().u64(2).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// CTAP 2.1 §6.1.2 step 1 / §6.2.2 step 1: a zero-length pinUvAuthParam takes a
/// device-selection touch, then reports the PIN state via the returned error — and
/// with a PIN configured that MUST be CTAP2_ERR_PIN_INVALID (0x31), not
/// PIN_AUTH_INVALID. Platforms managing device selection (Chrome) advance from the
/// selection touch to PIN entry off exactly this code; the wrong code leaves the
/// ceremony stuck on the touch. This is the field report: after a PIN is set, a new
/// registration shows "press the button" and the press never advances.
#[test]
fn zero_length_pinuvauthparam_probe_reports_pin_invalid() {
    let mut a = Authr::fresh();
    let pc = PinClient::establish(&mut a);
    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.set_pin(PIN)));

    let r = a.send(
        crate::consts::CTAP_MAKE_CREDENTIAL,
        &mc_probe("example.com"),
    );
    assert_eq!(
        r.status,
        CtapError::PinInvalid.as_u8(),
        "makeCredential zero-length pinUvAuthParam with a PIN set must be PIN_INVALID (0x31), got 0x{:02x}",
        r.status
    );

    let r = a.send(crate::consts::CTAP_GET_ASSERTION, &ga_probe("example.com"));
    assert_eq!(
        r.status,
        CtapError::PinInvalid.as_u8(),
        "getAssertion zero-length pinUvAuthParam with a PIN set must be PIN_INVALID (0x31), got 0x{:02x}",
        r.status
    );
}

/// The no-PIN counterpart is already correct and must stay CTAP2_ERR_PIN_NOT_SET
/// (0x35) — the code Chrome reads as "no PIN, proceed user-presence-only", which is
/// why step 3 (register before setting a PIN) works.
#[test]
fn zero_length_pinuvauthparam_probe_no_pin_reports_pin_not_set() {
    let mut a = Authr::fresh();
    let r = a.send(
        crate::consts::CTAP_MAKE_CREDENTIAL,
        &mc_probe("example.com"),
    );
    assert_eq!(
        r.status,
        CtapError::PinNotSet.as_u8(),
        "no-PIN probe must be PIN_NOT_SET (0x35), got 0x{:02x}",
        r.status
    );
}

/// Field report: no-PIN device registers/logs in fine, user then sets a PIN, and a
/// subsequent registration ("create another account") hangs on the touch. Drive
/// the exact sequence: up-only makeCredential (register), setPIN, obtain a UV
/// token (browser), then makeCredential with that token — it must reach the
/// presence check and succeed (AlwaysConfirm stands in for the touch).
#[test]
fn makecred_after_setpin_still_registers() {
    use crate::consts::CTAP_MAKE_CREDENTIAL;
    let mut a = Authr::fresh();

    // Step 3: register on a no-PIN device (up-only).
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_nopin("example.com")));

    // Step 5: set a PIN.
    let pc = PinClient::establish(&mut a);
    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.set_pin(PIN)));

    // The browser obtains a UV token (legacy getPinToken → mc|ga permissions).
    let r = a.send(CTAP_CLIENT_PIN, &pc.get_token(PIN));
    assert_eq!(r.status, CTAP2_OK, "getPinToken with the correct PIN");
    let token = pc.decrypt_token(&r.body);

    // Step 6/7: create another account, now PIN-gated. Must succeed.
    let r = a.send(
        CTAP_MAKE_CREDENTIAL,
        &mc_with_pin("other.example", &token, false),
    );
    assert_eq!(
        r.status, CTAP2_OK,
        "makeCredential after setPIN must succeed, got status 0x{:02x}",
        r.status
    );
}

/// The realistic desktop-Chrome passkey path: discoverable (rk=true) credentials
/// throughout, and the PIN-gated registration uses an rpId-bound, mc-scoped token
/// from getPinUvAuthTokenUsingPinWithPermissions (0x09) — the exact shape Chrome
/// sends. Reproduces the field report end to end.
#[test]
fn makecred_passkey_after_setpin_perms_token() {
    use crate::consts::CTAP_MAKE_CREDENTIAL;
    use crate::state::PERM_MC;
    let mut a = Authr::fresh();

    // Step 3: register a passkey on a no-PIN device (up-only, discoverable).
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_nopin_rk("example.com")));

    // Step 5: set a PIN.
    let pc = PinClient::establish(&mut a);
    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.set_pin(PIN)));

    // Chrome obtains an rpId-bound, mc-scoped token for the NEW account's RP.
    let r = a.send(
        CTAP_CLIENT_PIN,
        &pc.get_token_perms(PIN, PERM_MC, "other.example"),
    );
    assert_eq!(
        r.status, CTAP2_OK,
        "getPinUvAuthTokenUsingPinWithPermissions"
    );
    let token = pc.decrypt_token(&r.body);

    // Step 6/7: create another passkey, PIN-gated, token bound to its RP. Must succeed.
    let r = a.send(
        CTAP_MAKE_CREDENTIAL,
        &mc_with_pin("other.example", &token, true),
    );
    assert_eq!(
        r.status, CTAP2_OK,
        "PIN-gated passkey registration must succeed, got status 0x{:02x}",
        r.status
    );
}

#[test]
fn clientpin_set_pin_enables_client_pin() {
    let mut a = Authr::fresh();
    assert!(!client_pin_set(&mut a), "clientPin starts unset");
    let pc = PinClient::establish(&mut a);
    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.set_pin(PIN)));
    assert!(
        client_pin_set(&mut a),
        "clientPin flips to true after setPIN"
    );
    assert_eq!(
        pin_retries(&mut a),
        MAX_PIN_RETRIES,
        "setPIN does not consume a retry"
    );
}

#[test]
fn clientpin_get_token_with_correct_pin() {
    let mut a = Authr::fresh();
    let pc = PinClient::establish(&mut a);
    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.set_pin(PIN)));
    let r = a.send(CTAP_CLIENT_PIN, &pc.get_token(PIN));
    assert_eq!(r.status, CTAP2_OK);
    let tok = pc.decrypt_token(&r.body);
    assert_ne!(tok, [0u8; 32], "a non-trivial pinUvAuthToken is returned");
}

#[test]
fn clientpin_wrong_pin_decrements_retries() {
    let mut a = Authr::fresh();
    let pc = PinClient::establish(&mut a);
    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.set_pin(PIN)));
    let before = pin_retries(&mut a);
    let r = a.send(CTAP_CLIENT_PIN, &pc.get_token(WRONG_PIN));
    assert_eq!(r.status, CtapError::PinInvalid.as_u8());
    assert_eq!(
        pin_retries(&mut a),
        before - 1,
        "a wrong PIN consumes exactly one retry"
    );
}

#[test]
fn clientpin_change_pin() {
    let mut a = Authr::fresh();
    let pc = PinClient::establish(&mut a);
    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.set_pin(PIN)));
    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.change_pin(PIN, NEW_PIN)));
    // The new PIN yields a token; the old PIN is rejected.
    assert_eq!(
        a.send(CTAP_CLIENT_PIN, &pc.get_token(NEW_PIN)).status,
        CTAP2_OK
    );
    assert_eq!(
        a.send(CTAP_CLIENT_PIN, &pc.get_token(PIN)).status,
        CtapError::PinInvalid.as_u8()
    );
}

/// The `pinUvAuthProtocol` value that names `proto` on the wire.
fn wire(proto: PinProto) -> u64 {
    match proto {
        PinProto::One => 1,
        PinProto::Two => 2,
    }
}

/// `{1: pinUvAuthProtocol, 2: subCommand}` under `proto` — [`cp_short`] for either
/// protocol.
fn cp_over(proto: PinProto, sub: u64) -> Vec<u8> {
    let mut buf = [0u8; 16];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(2).unwrap();
        e.u8(1).unwrap().u64(wire(proto)).unwrap();
        e.u8(2).unwrap().u64(sub).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// `authenticate(key, msg)` in `proto`'s dialect: protocol one keeps the first 16
/// bytes of the HMAC, protocol two all 32 (CTAP 2.3 §6.5.6, §6.5.7).
fn auth_param(proto: PinProto, key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 32];
    let n = pinproto::authenticate(proto, key, msg, &mut out).unwrap();
    out[..n].to_vec()
}

/// The platform half of either PIN/UV auth protocol. [`PinClient`] speaks only
/// protocol two; protocol one encrypts under a zero IV with no prefix and takes
/// SHA-256(Z) as its shared secret (CTAP 2.3 §6.5.6).
struct ProtoClient {
    proto: PinProto,
    x: [u8; 32],
    y: [u8; 32],
    shared: Vec<u8>,
}

impl ProtoClient {
    /// getKeyAgreement over `proto`, then this side of the ECDH.
    fn establish(a: &mut Authr, proto: PinProto) -> Self {
        let r = a.send(CTAP_CLIENT_PIN, &cp_over(proto, 2));
        assert_ok(&r);
        let (ax, ay) = authenticator_public(&r.body);
        let mut s = [0u8; 32];
        s[0] = 0x13;
        s[31] = 0x42;
        let (x, y) = public_xy(&s).unwrap();
        let mut shared = [0u8; 64];
        let slen = pinproto::ecdh(proto, &s, &ax, &ay, &mut shared).unwrap();
        ProtoClient {
            proto,
            x,
            y,
            shared: shared[..slen].to_vec(),
        }
    }

    fn enc(&self, pt: &[u8]) -> Vec<u8> {
        let mut out = [0u8; 96];
        let n = pinproto::encrypt(self.proto, &self.shared, &[0x55; 16], pt, &mut out).unwrap();
        out[..n].to_vec()
    }

    /// `{1: proto, 2: sub, 3: keyAgreement}` and `more` keys after them, which `rest`
    /// writes in ascending order.
    fn keyed(
        &self,
        sub: u64,
        more: u64,
        rest: impl FnOnce(&mut Encoder<Cursor<&mut [u8]>>),
    ) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(3 + more).unwrap();
            e.u8(1).unwrap().u64(wire(self.proto)).unwrap();
            e.u8(2).unwrap().u64(sub).unwrap();
            e.u8(3).unwrap();
            cose_key_ecdh(&mut e, &self.x, &self.y).unwrap();
            rest(&mut e);
            e.writer().position()
        };
        buf[..n].to_vec()
    }

    /// setPIN (0x03): `{4: pinUvAuthParam, 5: newPinEnc}`.
    fn set_pin(&self, pin: &[u8]) -> Vec<u8> {
        let mut padded = [0u8; 64];
        padded[..pin.len()].copy_from_slice(pin);
        let npe = self.enc(&padded);
        let puap = auth_param(self.proto, &self.shared, &npe);
        self.keyed(3, 2, |e| {
            e.u8(4).unwrap().bytes(&puap).unwrap();
            e.u8(5).unwrap().bytes(&npe).unwrap();
        })
    }

    /// changePIN (0x04): `{4: pinUvAuthParam, 5: newPinEnc, 6: pinHashEnc}`.
    fn change_pin(&self, old: &[u8], new: &[u8]) -> Vec<u8> {
        let mut padded = [0u8; 64];
        padded[..new.len()].copy_from_slice(new);
        let npe = self.enc(&padded);
        let phe = self.enc(&sha256(old)[..16]);
        let puap = auth_param(self.proto, &self.shared, &[&npe[..], &phe[..]].concat());
        self.keyed(4, 3, |e| {
            e.u8(4).unwrap().bytes(&puap).unwrap();
            e.u8(5).unwrap().bytes(&npe).unwrap();
            e.u8(6).unwrap().bytes(&phe).unwrap();
        })
    }

    /// Legacy getPinToken (0x05): `{6: pinHashEnc}`.
    fn get_token(&self, pin: &[u8]) -> Vec<u8> {
        let phe = self.enc(&sha256(pin)[..16]);
        self.keyed(CP_GET_PIN_TOKEN, 1, |e| {
            e.u8(6).unwrap().bytes(&phe).unwrap();
        })
    }

    /// getPinUvAuthTokenUsingPinWithPermissions (0x09) with no rpId, as §6.8.2 has a
    /// platform ask for `pcmr`: `{6: pinHashEnc, 9: permissions}`.
    fn get_token_perms(&self, pin: &[u8], permissions: u8) -> Vec<u8> {
        let phe = self.enc(&sha256(pin)[..16]);
        self.keyed(CP_GET_PIN_UV_TOKEN_USING_PIN, 2, |e| {
            e.u8(6).unwrap().bytes(&phe).unwrap();
            e.u8(9).unwrap().u8(permissions).unwrap();
        })
    }

    /// The pinUvAuthToken out of a token response `{2: enc}`.
    fn decrypt_token(&self, body: &[u8]) -> [u8; 32] {
        let mut d = field_at(body, 2).expect("pinUvAuthToken (0x02) present");
        let mut tok = [0u8; 32];
        let n = pinproto::decrypt(self.proto, &self.shared, d.bytes().unwrap(), &mut tok).unwrap();
        assert_eq!(n, 32, "a pinUvAuthToken is 32 bytes");
        tok
    }

    /// A PIN token over this protocol: legacy getPinToken (0x05) with the right PIN.
    fn pin_token(&self, a: &mut Authr, pin: &[u8]) -> [u8; 32] {
        let r = a.send(CTAP_CLIENT_PIN, &self.get_token(pin));
        assert_ok(&r);
        self.decrypt_token(&r.body)
    }
}

/// A non-discoverable makeCredential over `rp` carrying `puap` under `proto`
/// (keys 1–4, 8, 9).
fn mc_authorized(rp: &str, cdh: &[u8; 32], proto: PinProto, puap: &[u8]) -> Vec<u8> {
    use crate::consts::ALG_ES256;
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(6).unwrap();
        e.u8(1).unwrap().bytes(cdh).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str(rp)
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[7, 7, 7, 7]).unwrap();
        e.str("name").unwrap().str("carol").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str(PUBLIC_KEY_TYPE).unwrap();
        e.u8(8).unwrap().bytes(puap).unwrap();
        e.u8(9).unwrap().u64(wire(proto)).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// A getAssertion over `rp` for `cred_id`, carrying `puap` under `proto`
/// (keys 1–3, 6, 7).
fn ga_authorized(
    rp: &str,
    cdh: &[u8; 32],
    cred_id: &[u8],
    proto: PinProto,
    puap: &[u8],
) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(5).unwrap();
        e.u8(1).unwrap().str(rp).unwrap();
        e.u8(2).unwrap().bytes(cdh).unwrap();
        e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(cred_id).unwrap();
        e.str("type").unwrap().str(PUBLIC_KEY_TYPE).unwrap();
        e.u8(6).unwrap().bytes(puap).unwrap();
        e.u8(7).unwrap().u64(wire(proto)).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// authData (0x02) of a makeCredential or getAssertion response.
fn auth_data(body: &[u8]) -> &[u8] {
    field_at(body, 2)
        .expect("authData (0x02) present")
        .bytes()
        .unwrap()
}

/// The credentialId inside a makeCredential authData, after its 2-byte length at 53.
fn credential_id(ad: &[u8]) -> &[u8] {
    let len = usize::from(u16::from_be_bytes([ad[53], ad[54]]));
    &ad[55..55 + len]
}

/// setMinPINLength raising only forceChangePin, `{3: true}` (CTAP 2.3 §6.11.4); the
/// pinUvAuthParam covers `0xff×32 ‖ 0x0d ‖ 0x03 ‖ subCommandParams` under `proto`.
fn force_change_request(proto: PinProto, token: &[u8; 32]) -> Vec<u8> {
    use crate::consts::{CONFIG_SET_MIN_PIN, CTAP_CONFIG};
    let mut sub = [0u8; 8];
    let sn = {
        let mut e = Encoder::new(Cursor::new(&mut sub[..]));
        e.map(1).unwrap().u8(3).unwrap().bool(true).unwrap();
        e.writer().position()
    };
    let mut msg = [0u8; 64];
    let mn = crate::state::puat_subcommand_msg(
        &mut msg,
        CTAP_CONFIG,
        CONFIG_SET_MIN_PIN as u8,
        &sub[..sn],
    );
    let puap = auth_param(proto, token, &msg[..mn]);
    let mut buf = [0u8; 96];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().u64(CONFIG_SET_MIN_PIN).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .u8(3)
            .unwrap()
            .bool(true)
            .unwrap();
        e.u8(3).unwrap().u64(wire(proto)).unwrap();
        e.u8(4).unwrap().bytes(&puap).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// Raise forcePINChange as a platform does: an acfg token over `pc`'s protocol,
/// spent on setMinPINLength.
fn raise_force_pin_change(a: &mut Authr, pc: &ProtoClient, pin: &[u8]) {
    use crate::consts::CTAP_CONFIG;
    use crate::state::PERM_ACFG;
    let r = a.send(CTAP_CLIENT_PIN, &pc.get_token_perms(pin, PERM_ACFG));
    assert_ok(&r);
    let token = pc.decrypt_token(&r.body);
    assert_ok_empty(&a.send(CTAP_CONFIG, &force_change_request(pc.proto, &token)));
}

/// getInfo `forcePINChange` (0x0C); absent reads as false (CTAP 2.3 §6.4).
fn force_pin_change_advertised(a: &mut Authr) -> bool {
    let r = a.get_info();
    assert_ok(&r);
    field_at(&r.body, 0x0C).is_some_and(|mut d| d.bool().unwrap())
}

/// FIDO Authr-ClientPin1-NewPin P-4: a legacy getPinToken (0x05) token over PIN
/// protocol one authorizes makeCredential with its 16-byte pinUvAuthParam, and the
/// credential comes back user-verified (CTAP 2.3 §6.1.2 step 11.1).
#[test]
fn a_protocol_one_token_makes_a_user_verified_credential() {
    use crate::consts::{CTAP_MAKE_CREDENTIAL, FLAG_UV};
    let mut a = Authr::fresh();
    let pc = ProtoClient::establish(&mut a, PinProto::One);
    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.set_pin(PIN)));
    let token = pc.pin_token(&mut a, PIN);

    let cdh = [0xC1u8; 32];
    let puap = auth_param(PinProto::One, &token, &cdh);
    assert_eq!(puap.len(), 16, "fixture: protocol one's MAC is truncated");
    let r = a.send(
        CTAP_MAKE_CREDENTIAL,
        &mc_authorized("example.com", &cdh, PinProto::One, &puap),
    );
    assert_ok(&r);
    assert_eq!(
        auth_data(&r.body)[32] & FLAG_UV,
        FLAG_UV,
        "a verified protocol-one pinUvAuthParam must set UV"
    );
}

/// FIDO Authr-ClientPin1-NewPin P-5: the same for getAssertion (CTAP 2.3 §6.2.2 step
/// 6.1). The credential is made up-only before the PIN is set, so the assertion is the
/// one step here that rides protocol one.
#[test]
fn a_protocol_one_token_makes_a_user_verified_assertion() {
    use crate::consts::{CTAP_GET_ASSERTION, CTAP_MAKE_CREDENTIAL, FLAG_UV};
    let mut a = Authr::fresh();
    let r = a.send(CTAP_MAKE_CREDENTIAL, &mc_nopin("example.com"));
    assert_ok(&r);
    let cred_id = credential_id(auth_data(&r.body)).to_vec();
    let pc = ProtoClient::establish(&mut a, PinProto::One);
    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.set_pin(PIN)));
    let token = pc.pin_token(&mut a, PIN);

    let cdh = [0xC2u8; 32];
    let puap = auth_param(PinProto::One, &token, &cdh);
    let r = a.send(
        CTAP_GET_ASSERTION,
        &ga_authorized("example.com", &cdh, &cred_id, PinProto::One, &puap),
    );
    assert_ok(&r);
    assert_eq!(
        auth_data(&r.body)[32] & FLAG_UV,
        FLAG_UV,
        "a verified protocol-one pinUvAuthParam must set UV"
    );
}

/// FIDO Authr-ClientPin1-NewPin F-1: once setMinPINLength has raised forcePINChange,
/// getPinToken over protocol one turns even the right PIN away with PIN_INVALID
/// (CTAP 2.3 §6.5.5.7.1) — after the verify, which the retry budget shows.
#[test]
fn a_forced_pin_change_refuses_the_protocol_one_pin_token() {
    let mut a = Authr::fresh();
    let pc = ProtoClient::establish(&mut a, PinProto::One);
    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.set_pin(PIN)));
    raise_force_pin_change(&mut a, &pc, PIN);

    // A wrong PIN spends a retry and the right one restores the budget: a refusal
    // made before the verify would leave the budget untouched both times. A mismatch
    // regenerates the key-agreement key, so each attempt agrees afresh.
    for (pin, retries, what) in [
        (
            WRONG_PIN,
            MAX_PIN_RETRIES - 1,
            "a wrong PIN is verified, and spends a retry",
        ),
        (
            PIN,
            MAX_PIN_RETRIES,
            "the right PIN is verified, and restores the budget",
        ),
    ] {
        let pc = ProtoClient::establish(&mut a, PinProto::One);
        let r = a.send(CTAP_CLIENT_PIN, &pc.get_token(pin));
        assert_eq!(
            r.status,
            CtapError::PinInvalid.as_u8(),
            "getPinToken under a pending forced change must be PIN_INVALID (0x31), got 0x{:02x}",
            r.status
        );
        let r = a.send(CTAP_CLIENT_PIN, &cp_over(PinProto::One, 1));
        assert_ok(&r);
        let mut d = field_at(&r.body, 3).expect("pinRetries (0x03) present");
        assert_eq!(d.u8().unwrap(), retries, "{what}");
    }
}

/// changePIN sets getInfo's forcePINChange back to false (CTAP 2.3 §6.5.5.6), read on
/// the wire; the flag reading true before the change is the control.
fn change_pin_clears_get_info_force_pin_change(proto: PinProto) {
    let mut a = Authr::fresh();
    let pc = ProtoClient::establish(&mut a, proto);
    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.set_pin(PIN)));
    raise_force_pin_change(&mut a, &pc, PIN);
    assert!(
        force_pin_change_advertised(&mut a),
        "control: setMinPINLength(forceChangePin) raised getInfo 0x0C"
    );

    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.change_pin(PIN, NEW_PIN)));
    assert!(
        !force_pin_change_advertised(&mut a),
        "changePIN over {proto:?} left getInfo forcePINChange (0x0C) true"
    );
}

/// FIDO Authr-ClientPin1-NewPin P-6.
#[test]
fn change_pin_clears_get_info_force_pin_change_protocol_one() {
    change_pin_clears_get_info_force_pin_change(PinProto::One);
}

/// FIDO Authr-ClientPin2-NewPin P-3.
#[test]
fn change_pin_clears_get_info_force_pin_change_protocol_two() {
    change_pin_clears_get_info_force_pin_change(PinProto::Two);
}

/// FIDO Authr-ClientPin1-PinPolicy F-4: a PIN one code point past the maxPINLength
/// getInfo advertises (0x1D) is PIN_POLICY_VIOLATION over protocol one (CTAP 2.3 §6.4,
/// §6.5.5.5). Read from getInfo, so the refusal tracks what the device claims.
#[test]
fn a_protocol_one_pin_past_the_advertised_max_length_is_policy_violation() {
    let mut a = Authr::fresh();
    let r = a.get_info();
    assert_ok(&r);
    let mut d = field_at(&r.body, 0x1D).expect("maxPINLength (0x1D) present");
    let max = usize::from(d.u8().unwrap());
    let pc = ProtoClient::establish(&mut a, PinProto::One);

    let r = a.send(CTAP_CLIENT_PIN, &pc.set_pin(&vec![b'7'; max + 1]));
    assert_eq!(
        r.status,
        CtapError::PinPolicyViolation.as_u8(),
        "a PIN of maxPINLength + 1 = {} must be PIN_POLICY_VIOLATION (0x37), got 0x{:02x}",
        max + 1,
        r.status
    );
    assert!(!client_pin_set(&mut a), "the refused PIN was stored");
}

/// FIDO Authr-ClientPin2-NewPin P-4, in one session: changePIN calls
/// resetPersistentPinUvAuthToken (CTAP 2.3 §6.5.5.6), so the pcmr grant a platform
/// holds stops reading the credential directory at once, not at the next power cycle.
#[test]
fn change_pin_revokes_the_persistent_grant_within_the_session() {
    use crate::consts::{CM_ENUMERATE_RPS_BEGIN, CTAP_CREDENTIAL_MGMT, CTAP_MAKE_CREDENTIAL};
    use crate::state::PERM_PCMR;
    let mut a = Authr::fresh();
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_nopin_rk("example.com")));
    let pc = ProtoClient::establish(&mut a, PinProto::Two);
    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.set_pin(PIN)));
    let r = a.send(CTAP_CLIENT_PIN, &pc.get_token_perms(PIN, PERM_PCMR));
    assert_ok(&r);
    let grant = pc.decrypt_token(&r.body);

    // enumerateRPsBegin `{1: 0x02, 3: 2, 4: authenticate(grant, 0x02)}` (§6.8.3).
    let puap = auth_param(PinProto::Two, &grant, &[CM_ENUMERATE_RPS_BEGIN as u8]);
    let mut buf = [0u8; 64];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(3).unwrap();
        e.u8(1).unwrap().u64(CM_ENUMERATE_RPS_BEGIN).unwrap();
        e.u8(3).unwrap().u64(2).unwrap();
        e.u8(4).unwrap().bytes(&puap).unwrap();
        e.writer().position()
    };
    let enumerate = &buf[..n];
    assert_ok(&a.send(CTAP_CREDENTIAL_MGMT, enumerate)); // control: the grant reads

    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.change_pin(PIN, NEW_PIN)));
    let r = a.send(CTAP_CREDENTIAL_MGMT, enumerate);
    assert_eq!(
        r.status,
        CtapError::PinAuthInvalid.as_u8(),
        "the pcmr grant minted under the old PIN still read the directory, got 0x{:02x}",
        r.status
    );
}
