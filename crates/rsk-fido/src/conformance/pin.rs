// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §6.5 clientPIN crypto-flow conformance, driven through the wire
//! envelope (`process_cbor`): key agreement (ECDH), setPIN, getPinToken (correct
//! PIN → a decryptable token; wrong PIN → PIN_INVALID + a retry decrement) and
//! changePIN. The platform side runs the real pinUvAuthProtocol-2 primitives, so
//! the exchange is verified end to end.

use super::{Authr, assert_ok, assert_ok_empty, field_at};
use crate::consts::{CTAP_CLIENT_PIN, MAX_PIN_RETRIES};
use crate::cose::cose_key_ecdh;
use crate::error::{CTAP2_OK, CtapError};
use minicbor::Encoder;
use minicbor::encode::write::Cursor;
use rsk_crypto::pinproto::{self, PinProto, public_xy};
use rsk_crypto::sha256;

use crate::test_pins::{NEW_PIN, PIN, WRONG_PIN};

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
