// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §12.5 hmac-secret *evaluate* conformance, driven through the wire
//! envelope (`process_cbor`): a credential is created with hmac-secret, then a
//! getAssertion carries `{keyAgreement, saltEnc, saltAuth}` and the encrypted
//! output decrypts (under the ECDH shared secret) to a 32-byte value that is
//! deterministic per (credential, salt). The platform runs the real
//! pinUvAuthProtocol primitives: protocol 2, and protocol 1 where a case names it.

use super::{Authr, assert_ok, field_at, pin_auth};
use crate::consts::{
    ALG_ES256, CTAP_CLIENT_PIN, CTAP_GET_ASSERTION, CTAP_MAKE_CREDENTIAL, PUBLIC_KEY_TYPE,
};
use crate::cose::cose_key_ecdh;
use crate::error::CTAP2_OK;
use crate::state::{PERM_GA, PERM_MC};
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

/// [`ga_hmac_up_false`] with the extension value replaced by one carrying no
/// sub-fields — an empty map, or a value that is not a map at all.
fn ga_degenerate_up_false(empty_map: bool) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(4).unwrap().map(1).unwrap();
        e.str("hmac-secret").unwrap();
        if empty_map {
            e.map(0).unwrap();
        } else {
            e.bool(true).unwrap();
        }
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

/// The `up:false` probe skips the presence gate, so serving the extension there
/// hands out per-credential PRF material with no touch and no PIN — and does so on
/// the always-uv build too (audit run-32). The refusal is the invariant; its code
/// follows the reference device: §12.5 writes CTAP2_ERR_UNSUPPORTED_OPTION, a
/// YubiKey 5.8.0 answers CTAP2_ERR_UP_REQUIRED — measured in all three shapes
/// (allowList with a token, without one, and a discoverable walk), issue #109.
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
        crate::error::CtapError::UpRequired as u8,
        "hmac-secret must be refused with 0x3b on an up:false request"
    );
    assert!(g.body.is_empty(), "a refused probe returns no assertion");
}

/// The other half of that rule, and the line between them: an hmac-secret value
/// with no sub-fields in it is not a present extension, so it is not what the
/// refusal above is about. A YubiKey 5.8.0 answers `0x00` to the silent
/// pre-flight for both shapes — an empty map and a boolean — where a real
/// request in the same position is `UP_REQUIRED`. Ours used to answer
/// MISSING_PARAMETER to the first and INVALID_CBOR to the second, and a platform
/// that sends either got no assertion at all.
#[test]
fn a_degenerate_hmac_secret_is_not_a_present_extension() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_hmac()));
    for empty_map in [true, false] {
        let g = a.send(CTAP_GET_ASSERTION, &ga_degenerate_up_false(empty_map));
        assert_eq!(
            g.status, 0,
            "a value with no sub-fields must not refuse the ceremony (empty_map={empty_map})"
        );
        assert!(
            !g.body.is_empty(),
            "the assertion is served (empty_map={empty_map})"
        );
    }
}

/// A UV makeCredential evaluating hmac-secret at registration time
/// (`hmac-secret-mc`, CTAP 2.2 §12.8), the way a platform asking for PRF at
/// creation does.
fn mc_hmac_mc(ecdh: &Ecdh, token: &[u8; 32], salt: &[u8]) -> Vec<u8> {
    let salt_enc = ecdh.enc(salt);
    let salt_auth = ecdh.mac(&salt_enc);
    let auth = pin_auth(token, &CDH);
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(8).unwrap();
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
        // extensions: { hmac-secret: true, hmac-secret-mc: {1: kA, 2: saltEnc, 3: saltAuth, 4: proto} }
        e.u8(6).unwrap().map(2).unwrap();
        e.str("hmac-secret").unwrap().bool(true).unwrap();
        e.str("hmac-secret-mc").unwrap().map(4).unwrap();
        e.u8(1).unwrap();
        cose_key_ecdh(&mut e, &ecdh.x, &ecdh.y).unwrap();
        e.u8(2).unwrap().bytes(&salt_enc).unwrap();
        e.u8(3).unwrap().bytes(&salt_auth).unwrap();
        e.u8(4).unwrap().u64(2).unwrap();
        e.u8(7)
            .unwrap()
            .map(1)
            .unwrap()
            .str("rk")
            .unwrap()
            .bool(true)
            .unwrap();
        e.u8(8).unwrap().bytes(&auth).unwrap();
        e.u8(9).unwrap().u64(2).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// [`ga_hmac`] under a pinUvAuthToken, so the assertion asserts UV.
fn ga_hmac_uv(ecdh: &Ecdh, token: &[u8; 32], salt: &[u8]) -> Vec<u8> {
    let salt_enc = ecdh.enc(salt);
    let salt_auth = ecdh.mac(&salt_enc);
    let auth = pin_auth(token, &CDH);
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(5).unwrap();
        e.u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(4).unwrap().map(1).unwrap();
        e.str("hmac-secret").unwrap().map(4).unwrap();
        e.u8(1).unwrap();
        cose_key_ecdh(&mut e, &ecdh.x, &ecdh.y).unwrap();
        e.u8(2).unwrap().bytes(&salt_enc).unwrap();
        e.u8(3).unwrap().bytes(&salt_auth).unwrap();
        e.u8(4).unwrap().u64(2).unwrap();
        e.u8(6).unwrap().bytes(&auth).unwrap();
        e.u8(7).unwrap().u64(2).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// The `hmac-secret-mc` output from a makeCredential authData.
fn hmac_mc_output(body: &[u8]) -> Vec<u8> {
    let mut d = field_at(body, 2).expect("authData (0x02) present");
    let ad = d.bytes().unwrap();
    // rpIdHash(32) | flags(1) | counter(4) | aaguid(16) | credLen(2) | credId | COSE | ext
    let cred_len = ((ad[53] as usize) << 8) | ad[54] as usize;
    let mut after = Decoder::new(&ad[55 + cred_len..]);
    after.skip().unwrap(); // the COSE public key
    let mut ext = Decoder::new(&ad[55 + cred_len + after.position()..]);
    let n = ext.map().unwrap().unwrap();
    for _ in 0..n {
        if ext.str().unwrap() == "hmac-secret-mc" {
            return ext.bytes().unwrap().to_vec();
        }
        ext.skip().unwrap();
    }
    panic!("hmac-secret-mc output missing from the registration");
}

/// The whole point of PRF for a password manager, and the one thing no test
/// covered: the value a platform reads at REGISTRATION and the value it reads on
/// the follow-up assertion are the same secret. They travel two different code
/// paths — makeCredential's `key_input` is the box or the fresh resident id,
/// getAssertion's is whatever the lookup found — and §12.5 selects a different
/// half of `cred_random` by the response's UV bit, so both ceremonies must agree
/// on both. A Bitwarden-shaped vault key is exactly this pair (#109).
#[test]
fn hmac_secret_mc_and_the_follow_up_assertion_agree() {
    let mut a = Authr::fresh();
    let ecdh = Ecdh::establish(&mut a);
    let token = a.arm_token(PERM_MC | PERM_GA);

    let mc = a.send(CTAP_MAKE_CREDENTIAL, &mc_hmac_mc(&ecdh, &token, &SALT));
    assert_ok(&mc);
    let at_creation = ecdh.decrypt(&hmac_mc_output(&mc.body));
    assert_eq!(at_creation.len(), 32);

    // A fresh token for the second ceremony: registration collected user presence
    // and that retires the one it rode in on (GHSA-wqjm-653g-hgw3), which is also
    // what a platform does — the follow-up read is its own PIN prompt.
    let token = a.arm_token(PERM_MC | PERM_GA);
    let ga = a.send(CTAP_GET_ASSERTION, &ga_hmac_uv(&ecdh, &token, &SALT));
    assert_ok(&ga);
    let on_read = ecdh.decrypt(&hmac_output(&ga.body));
    assert_eq!(
        at_creation, on_read,
        "the PRF value read back on the assertion must be the one registration returned"
    );
}

/// The UV half is not the non-UV half — §12.5's `CredRandomWithUV` — so a
/// registration under a pinUvAuthToken and an assertion without one must NOT
/// hand the same secret out. The equality above would hold vacuously if both
/// ceremonies quietly picked the same half whatever the UV bit said.
#[test]
fn the_uv_half_is_not_the_one_an_unverified_assertion_gets() {
    let mut a = Authr::fresh();
    let ecdh = Ecdh::establish(&mut a);
    let token = a.arm_token(PERM_MC | PERM_GA);

    let mc = a.send(CTAP_MAKE_CREDENTIAL, &mc_hmac_mc(&ecdh, &token, &SALT));
    assert_ok(&mc);
    let with_uv = ecdh.decrypt(&hmac_mc_output(&mc.body));

    let ga = a.send(CTAP_GET_ASSERTION, &ga_hmac(&ecdh, &SALT));
    assert_ok(&ga);
    let without_uv = ecdh.decrypt(&hmac_output(&ga.body));
    assert_ne!(
        with_uv, without_uv,
        "a UV registration and an unverified assertion must not share a CredRandom"
    );
}

/// A second salt, for the two-salt form of CTAP 2.3 §12.7 (hmac-secret) and §12.8
/// (hmac-secret-mc).
const SALT2: [u8; 32] = [0xB2; 32];

/// [`Ecdh`] under either pinUvAuthProtocol: CTAP 2.3 §12.7 serves hmac-secret over
/// both, and protocol one differs in every step — the KDF, a zero IV, a 16-byte MAC.
struct ProtoEcdh {
    proto: PinProto,
    x: [u8; 32],
    y: [u8; 32],
    shared: Vec<u8>,
}

impl ProtoEcdh {
    fn establish(a: &mut Authr, proto: PinProto) -> Self {
        // getKeyAgreement: {1: proto, 2: subCommand=2}.
        let mut kbuf = [0u8; 16];
        let kn = {
            let mut e = Encoder::new(Cursor::new(&mut kbuf[..]));
            e.map(2).unwrap();
            e.u8(1).unwrap().u64(wire(proto)).unwrap();
            e.u8(2).unwrap().u64(2).unwrap();
            e.writer().position()
        };
        let r = a.send(CTAP_CLIENT_PIN, &kbuf[..kn]);
        assert_ok(&r);
        let (ax, ay) = authenticator_public(&r.body);
        let mut s = [0u8; 32];
        s[0] = 0x27;
        s[31] = 0x61;
        let (x, y) = public_xy(&s).unwrap();
        let mut shared = [0u8; 64];
        let slen = pinproto::ecdh(proto, &s, &ax, &ay, &mut shared).unwrap();
        ProtoEcdh {
            proto,
            x,
            y,
            shared: shared[..slen].to_vec(),
        }
    }

    /// `(saltEnc, saltAuth)` for `salts` (one salt, or two concatenated).
    fn seal(&self, salts: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut enc = [0u8; 96];
        let n = pinproto::encrypt(self.proto, &self.shared, &[0x5A; 16], salts, &mut enc).unwrap();
        let mut mac = [0u8; 32];
        let m = pinproto::authenticate(self.proto, &self.shared, &enc[..n], &mut mac).unwrap();
        (enc[..n].to_vec(), mac[..m].to_vec())
    }

    fn open(&self, ct: &[u8]) -> Vec<u8> {
        let mut out = [0u8; 96];
        let n = pinproto::decrypt(self.proto, &self.shared, ct, &mut out).unwrap();
        out[..n].to_vec()
    }
}

/// The `pinUvAuthProtocol` wire value naming `proto`.
fn wire(proto: PinProto) -> u64 {
    match proto {
        PinProto::One => 1,
        PinProto::Two => 2,
    }
}

/// [`pin_auth`] under either protocol (protocol one truncates the MAC to 16 bytes).
fn pin_auth_under(proto: PinProto, token: &[u8; 32], msg: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 32];
    let n = pinproto::authenticate(proto, token, msg, &mut out).unwrap();
    out[..n].to_vec()
}

/// A makeCredential over `RP_ID` for user `uid` with hmac-secret on. `mc` adds
/// `hmac-secret-mc` for those salts on that channel, `token` a pinUvAuthParam
/// under the given protocol (so the registration asserts UV), `rk` discoverability.
fn mc_prf(
    uid: &[u8],
    rk: bool,
    mc: Option<(&ProtoEcdh, &[u8])>,
    token: Option<(&[u8; 32], PinProto)>,
) -> Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(5 + u64::from(rk) + 2 * u64::from(token.is_some()))
            .unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str(RP_ID).unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(uid).unwrap();
        e.str("name").unwrap().str("grace").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str(PUBLIC_KEY_TYPE).unwrap();
        e.u8(6).unwrap().map(1 + u64::from(mc.is_some())).unwrap();
        e.str("hmac-secret").unwrap().bool(true).unwrap();
        if let Some((ch, salts)) = mc {
            let (salt_enc, salt_auth) = ch.seal(salts);
            e.str("hmac-secret-mc").unwrap().map(4).unwrap();
            e.u8(1).unwrap();
            cose_key_ecdh(&mut e, &ch.x, &ch.y).unwrap();
            e.u8(2).unwrap().bytes(&salt_enc).unwrap();
            e.u8(3).unwrap().bytes(&salt_auth).unwrap();
            e.u8(4).unwrap().u64(wire(ch.proto)).unwrap();
        }
        if rk {
            e.u8(7).unwrap().map(1).unwrap();
            e.str("rk").unwrap().bool(true).unwrap();
        }
        if let Some((t, proto)) = token {
            e.u8(8)
                .unwrap()
                .bytes(&pin_auth_under(proto, t, &CDH))
                .unwrap();
            e.u8(9).unwrap().u64(wire(proto)).unwrap();
        }
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// A getAssertion over `RP_ID` evaluating hmac-secret for `salts` on channel
/// `ch`: naming `allow` when given, sending key 4 (pinUvAuthProtocol) only when
/// `key4`, and under `token` (the channel's protocol) when given.
fn ga_prf(
    ch: &ProtoEcdh,
    salts: &[u8],
    allow: Option<&[u8]>,
    key4: bool,
    token: Option<&[u8; 32]>,
) -> Vec<u8> {
    let (salt_enc, salt_auth) = ch.seal(salts);
    let mut buf = [0u8; 768];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(3 + u64::from(allow.is_some()) + 2 * u64::from(token.is_some()))
            .unwrap();
        e.u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        if let Some(id) = allow {
            e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("id").unwrap().bytes(id).unwrap();
            e.str("type").unwrap().str(PUBLIC_KEY_TYPE).unwrap();
        }
        e.u8(4).unwrap().map(1).unwrap();
        e.str("hmac-secret")
            .unwrap()
            .map(3 + u64::from(key4))
            .unwrap();
        e.u8(1).unwrap();
        cose_key_ecdh(&mut e, &ch.x, &ch.y).unwrap();
        e.u8(2).unwrap().bytes(&salt_enc).unwrap();
        e.u8(3).unwrap().bytes(&salt_auth).unwrap();
        if key4 {
            e.u8(4).unwrap().u64(wire(ch.proto)).unwrap();
        }
        if let Some(t) = token {
            e.u8(6)
                .unwrap()
                .bytes(&pin_auth_under(ch.proto, t, &CDH))
                .unwrap();
            e.u8(7).unwrap().u64(wire(ch.proto)).unwrap();
        }
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// The flags byte of a makeCredential or getAssertion authData.
fn auth_flags(body: &[u8]) -> u8 {
    let mut d = field_at(body, 2).expect("authData (0x02) present");
    d.bytes().unwrap()[32]
}

/// The credentialId out of a makeCredential's attested credential data.
fn cred_id(body: &[u8]) -> Vec<u8> {
    let mut d = field_at(body, 2).expect("authData (0x02) present");
    let ad = d.bytes().unwrap();
    let cl = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    ad[55..55 + cl].to_vec()
}

/// The decrypted hmac-secret output for `salts` on credential `id`, verified when
/// `token` is given — after checking the response's UV bit agrees, since that
/// bit is what selects the CredRandom half.
fn prf(
    a: &mut Authr,
    ch: &ProtoEcdh,
    id: &[u8],
    salts: &[u8],
    token: Option<&[u8; 32]>,
) -> Vec<u8> {
    let g = a.send(
        CTAP_GET_ASSERTION,
        &ga_prf(ch, salts, Some(id), true, token),
    );
    assert_ok(&g);
    assert_eq!(
        auth_flags(&g.body) & crate::consts::FLAG_UV != 0,
        token.is_some(),
        "the assertion's UV bit must follow the pinUvAuthToken"
    );
    ch.open(&hmac_output(&g.body))
}

/// FIDO hmac-secret P-3 / hmac-secret2 P-3. CTAP 2.3 §12.7 evaluates under
/// CredRandomWithUV when the response's UV bit is set, so a verified assertion
/// gets a different pair for the same two salts — both slots, either protocol.
#[test]
fn uv_changes_both_outputs_under_either_protocol() {
    let salts = [SALT, SALT2].concat();
    for proto in [PinProto::One, PinProto::Two] {
        for rk in [true, false] {
            let mut a = Authr::fresh();
            let mc = a.send(CTAP_MAKE_CREDENTIAL, &mc_prf(&[9, 9], rk, None, None));
            assert_ok(&mc);
            let id = cred_id(&mc.body);
            let ch = ProtoEcdh::establish(&mut a, proto);

            let without_uv = prf(&mut a, &ch, &id, &salts, None);
            let token = a.arm_token(PERM_GA);
            let with_uv = prf(&mut a, &ch, &id, &salts, Some(&token));
            assert_eq!((without_uv.len(), with_uv.len()), (64, 64));
            assert_ne!(
                without_uv[..32],
                with_uv[..32],
                "{proto:?} rk={rk}: output1 must come from the UV half under UV"
            );
            assert_ne!(
                without_uv[32..],
                with_uv[32..],
                "{proto:?} rk={rk}: output2 must come from the UV half under UV"
            );
        }
    }
}

/// FIDO hmac-secret P-2 / hmac-secret2 P-2 on a non-resident credential, whose
/// CredRandom keys off the credential box: one salt's output is stable, keeps its
/// slot in a two-salt request, and belongs to that credential alone.
#[test]
fn a_non_resident_credential_serves_stable_salt_positioned_outputs() {
    for proto in [PinProto::One, PinProto::Two] {
        let mut a = Authr::fresh();
        let first = a.send(CTAP_MAKE_CREDENTIAL, &mc_prf(&[1], false, None, None));
        assert_ok(&first);
        let second = a.send(CTAP_MAKE_CREDENTIAL, &mc_prf(&[2], false, None, None));
        assert_ok(&second);
        let (id, other_id) = (cred_id(&first.body), cred_id(&second.body));
        let ch = ProtoEcdh::establish(&mut a, proto);

        let h1 = prf(&mut a, &ch, &id, &SALT, None);
        assert_eq!(h1.len(), 32, "{proto:?}: one salt, one 32-byte output");
        assert_eq!(
            prf(&mut a, &ch, &id, &SALT, None),
            h1,
            "{proto:?}: the same salt must give the same output"
        );
        let h2 = prf(&mut a, &ch, &id, &SALT2, None);
        // Reversed, so salt1 is SALT2: each output must follow its salt's slot.
        let pair = prf(&mut a, &ch, &id, &[SALT2, SALT].concat(), None);
        assert_eq!(pair[..32], h2[..], "{proto:?}: output1 is salt1's");
        assert_eq!(pair[32..], h1[..], "{proto:?}: output2 is salt2's");
        assert_ne!(
            prf(&mut a, &ch, &other_id, &SALT, None),
            h1,
            "{proto:?}: another credential must not share the output"
        );
    }
}

/// FIDO hmac-secret P-2's input shape. CTAP 2.3 §12.7 makes key 4
/// (pinUvAuthProtocol) optional and its absence protocol one, so the same sealed
/// salt must be served identically with the key left off and spelt out.
#[test]
fn an_omitted_protocol_key_means_protocol_one() {
    let mut a = Authr::fresh();
    let mc = a.send(CTAP_MAKE_CREDENTIAL, &mc_prf(&[9, 9], true, None, None));
    assert_ok(&mc);
    let id = cred_id(&mc.body);
    let ch = ProtoEcdh::establish(&mut a, PinProto::One);

    let spelt_out = prf(&mut a, &ch, &id, &SALT, None);
    let g = a.send(
        CTAP_GET_ASSERTION,
        &ga_prf(&ch, &SALT, Some(&id), false, None),
    );
    assert_eq!(
        g.status, CTAP2_OK,
        "an hmac-secret input without key 4 must be read as protocol one"
    );
    assert_eq!(ch.open(&hmac_output(&g.body)), spelt_out);
}

/// FIDO hmac-secret-mc P-1. A registration without UV — a non-discoverable
/// credential on a PIN-protected key (makeCredUvNotRqd) — evaluates both salts
/// under CredRandomWithoutUV: what an unverified assertion reads, not a verified one.
#[test]
fn an_unverified_registration_hands_out_the_unverified_pair() {
    let salts = [SALT, SALT2].concat();
    for proto in [PinProto::One, PinProto::Two] {
        let mut a = Authr::fresh();
        a.set_pin_file();
        let ch = ProtoEcdh::establish(&mut a, proto);
        let mc = a.send(
            CTAP_MAKE_CREDENTIAL,
            &mc_prf(&[9, 9], false, Some((&ch, &salts)), None),
        );
        assert_ok(&mc);
        assert_eq!(
            auth_flags(&mc.body) & crate::consts::FLAG_UV,
            0,
            "{proto:?}: a registration with no token must not assert UV"
        );
        let at_creation = ch.open(&hmac_mc_output(&mc.body));
        let id = cred_id(&mc.body);

        assert_eq!(
            at_creation,
            prf(&mut a, &ch, &id, &salts, None),
            "{proto:?}: an unverified registration must hand out the unverified pair"
        );
        let token = a.arm_token(PERM_GA);
        let with_uv = prf(&mut a, &ch, &id, &salts, Some(&token));
        assert_ne!(at_creation[..32], with_uv[..32], "{proto:?}: output1");
        assert_ne!(at_creation[32..], with_uv[32..], "{proto:?}: output2");
    }
}

/// FIDO hmac-secret-mc P-2 past `hmac_secret_mc_and_the_follow_up_assertion_agree`
/// (protocol two, discoverable): the registration's output is the assertion's under
/// protocol one too, and for a non-resident credential, keyed off its box.
#[test]
fn hmac_secret_mc_agrees_with_the_assertion_under_every_protocol_and_shape() {
    for proto in [PinProto::One, PinProto::Two] {
        for rk in [false, true] {
            let mut a = Authr::fresh();
            let ch = ProtoEcdh::establish(&mut a, proto);
            let token = a.arm_token(PERM_MC | PERM_GA);
            let mc = a.send(
                CTAP_MAKE_CREDENTIAL,
                &mc_prf(&[9, 9], rk, Some((&ch, &SALT)), Some((&token, proto))),
            );
            assert_ok(&mc);
            assert_eq!(
                auth_flags(&mc.body) & crate::consts::FLAG_UV,
                crate::consts::FLAG_UV,
                "{proto:?} rk={rk}: the registration must assert UV"
            );
            let at_creation = ch.open(&hmac_mc_output(&mc.body));
            assert_eq!(at_creation.len(), 32);

            let token = a.arm_token(PERM_GA);
            assert_eq!(
                prf(&mut a, &ch, &cred_id(&mc.body), &SALT, Some(&token)),
                at_creation,
                "{proto:?} rk={rk}: the assertion must read back what registration returned"
            );
        }
    }
}

/// FIDO hmac-secret-mc P-3. With two salts, a registration's output1 and output2
/// are salt1's and salt2's — each what a one-salt assertion returns for it — and a
/// second credential's pair shares neither half.
#[test]
fn hmac_secret_mc_keeps_salt_order_and_is_per_credential() {
    let salts = [SALT, SALT2].concat();
    for proto in [PinProto::One, PinProto::Two] {
        for rk in [false, true] {
            let mut a = Authr::fresh();
            let ch = ProtoEcdh::establish(&mut a, proto);
            let register = |a: &mut Authr, uid: &[u8]| {
                let token = a.arm_token(PERM_MC | PERM_GA);
                let mc = a.send(
                    CTAP_MAKE_CREDENTIAL,
                    &mc_prf(uid, rk, Some((&ch, &salts)), Some((&token, proto))),
                );
                assert_ok(&mc);
                (cred_id(&mc.body), ch.open(&hmac_mc_output(&mc.body)))
            };
            let (id, pair) = register(&mut a, &[1]);
            let (_, other) = register(&mut a, &[2]);
            assert_eq!(pair.len(), 64);

            let token = a.arm_token(PERM_GA);
            let h1 = prf(&mut a, &ch, &id, &SALT, Some(&token));
            let token = a.arm_token(PERM_GA);
            let h2 = prf(&mut a, &ch, &id, &SALT2, Some(&token));
            assert_eq!(pair[..32], h1[..], "{proto:?} rk={rk}: output1 is salt1's");
            assert_eq!(pair[32..], h2[..], "{proto:?} rk={rk}: output2 is salt2's");
            assert_ne!(other[..32], pair[..32], "{proto:?} rk={rk}: output1");
            assert_ne!(other[32..], pair[32..], "{proto:?} rk={rk}: output2");
        }
    }
}

/// FIDO hmac-secret-mc F-3 / F-4. hmac-secret-mc carries getAssertion's salt fields,
/// so a salt CTAP 2.3 §12.7 refuses — 16 bytes, or 48 (a short second salt) — gets
/// the assertion path's code: the wire-length gate, else INVALID_PARAMETER.
#[test]
fn hmac_secret_mc_refuses_a_short_salt_as_the_assertion_does() {
    use crate::error::CtapError;
    for proto in [PinProto::One, PinProto::Two] {
        for len in [16usize, 48] {
            // Only protocol one's 16-byte saltEnc misses every §12.7 wire length;
            // the rest pass the MAC and decrypt to a length §12.7 refuses.
            let want = if proto == PinProto::One && len == 16 {
                CtapError::InvalidLength
            } else {
                CtapError::InvalidParameter
            };
            let mut a = Authr::fresh();
            let known = a.send(CTAP_MAKE_CREDENTIAL, &mc_prf(&[7], false, None, None));
            assert_ok(&known);
            let ch = ProtoEcdh::establish(&mut a, proto);
            let salt = vec![0xC3u8; len];

            let mc = a.send(
                CTAP_MAKE_CREDENTIAL,
                &mc_prf(&[9, 9], false, Some((&ch, &salt)), None),
            );
            assert_eq!(
                mc.status,
                want.as_u8(),
                "{proto:?}: a {len}-byte salt at registration"
            );
            assert!(mc.body.is_empty(), "a refused registration returns nothing");
            let ga = a.send(
                CTAP_GET_ASSERTION,
                &ga_prf(&ch, &salt, Some(&cred_id(&known.body)), true, None),
            );
            assert_eq!(
                ga.status,
                want.as_u8(),
                "{proto:?}: a {len}-byte salt on the assertion path"
            );
        }
    }
}
