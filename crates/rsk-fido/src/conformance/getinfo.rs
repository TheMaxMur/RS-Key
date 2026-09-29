// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §6.4 `authenticatorGetInfo` conformance assertions, driven through
//! the wire envelope (`process_cbor`), including the encrypted identifier and store
//! state across a reset. The pilot the other command files fan out from.

use super::{Authr, assert_ok, assert_ok_empty, bool_map_canonical, field_at, int_map_keys};
use crate::FidoState;
use crate::consts::{
    AAGUID, ALG_EDDSA, ALG_ES256, ALG_ES256K, ALG_ES384, ALG_ES512, ALG_MLDSA44,
    CP_GET_PIN_UV_TOKEN_USING_PIN, CTAP_CLIENT_PIN, CTAP_MAKE_CREDENTIAL, CTAP_RESET,
    FIRMWARE_VERSION, MAX_CRED_ID_LENGTH, MAX_MSG_SIZE, PUBLIC_KEY_TYPE,
};
use crate::cose::cose_key_ecdh;
use crate::state::PERM_PCMR;
use crate::test_pins::PIN;
use minicbor::Encoder;
use minicbor::encode::write::Cursor;
use rsk_crypto::pinproto::{self, PinProto, public_xy};
use rsk_crypto::{Mode, aes_decrypt, hkdf_sha256, sha256};

/// The exact set of getInfo members this build advertises, in canonical order.
/// A new member must land here *and* in `metadata/rs-key.metadata.json` +
/// `docs/protocol.md` — this test is the tripwire.
/// 0x0B (maxSerializedLargeBlobArray) belongs to the `authenticatorLargeBlobs`
/// command, which a `largeblob-ext` build does not serve (CTAP 2.3 §12.4).
/// 0x19 and 0x1E are expected too: `ensure_seed` mints the persistent token they are
/// sealed under, so `Authr::fresh()` publishes both —
/// `the_sealed_members_are_published_before_any_token_is_issued` pins that.
const GETINFO_KEYS: [u32; 26] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x14, 0x15, 0x16, 0x18, 0x19, 0x1A, 0x1B, 0x1D, 0x1E, 0x1F,
];

#[test]
fn getinfo_envelope_and_canonical() {
    let r = Authr::fresh().get_info();
    assert_ok(&r);
    // Keys strictly ascending + no trailing bytes (checked inside int_map_keys),
    // and exactly the advertised member set.
    let keys = int_map_keys(&r.body);
    let expected: Vec<u32> = GETINFO_KEYS
        .iter()
        .copied()
        .filter(|k| *k != 0x0B || !crate::consts::LARGE_BLOB_EXT)
        .collect();
    assert_eq!(keys, expected, "getInfo top-level members changed");
}

#[test]
fn getinfo_versions_and_aaguid() {
    let r = Authr::fresh().get_info();

    let mut d = field_at(&r.body, 0x01).expect("versions (0x01) present");
    let n = d.array().unwrap().expect("versions is a definite array");
    assert!(n >= 1, "versions must be non-empty");
    let known = ["U2F_V2", "FIDO_2_0", "FIDO_2_1", "FIDO_2_1_PRE", "FIDO_2_3"];
    let mut vers = Vec::new();
    for _ in 0..n {
        vers.push(d.str().unwrap().to_string());
    }
    for v in &vers {
        assert!(known.contains(&v.as_str()), "unknown version string {v:?}");
    }
    // The CTAP2 baseline and the FIDO_2_1 surface must both be advertised.
    assert!(vers.iter().any(|v| v == "FIDO_2_0"));
    assert!(vers.iter().any(|v| v == "FIDO_2_1"));
    // CTAP 2.3 §6.4: "FIDO_2_2" was never defined and MUST NOT appear. `known`
    // above would already reject it; this names the rule at the point it applies.
    assert!(!vers.iter().any(|v| v == "FIDO_2_2"));

    let mut d = field_at(&r.body, 0x03).expect("aaguid (0x03) present");
    let aaguid = d.bytes().unwrap();
    assert_eq!(aaguid.len(), 16, "aaguid must be exactly 16 bytes");
    assert_eq!(aaguid, &AAGUID[..], "aaguid must equal the model constant");
}

#[test]
fn getinfo_options_dependencies() {
    let r = Authr::fresh().get_info();
    let mut d = field_at(&r.body, 0x04).expect("options (0x04) present");
    // Canonical text-key order + every value a boolean.
    let keys = bool_map_canonical(&mut d);
    let has = |name: &str| keys.iter().any(|k| k == name);

    for req in ["rk", "up", "clientPin", "pinUvAuthToken"] {
        assert!(has(req), "required option {req:?} missing");
    }
    // CTAP 2.1 §6.4 dependency rules.
    if has("pinUvAuthToken") {
        assert!(
            has("clientPin"),
            "pinUvAuthToken implies the clientPin option"
        );
    }
    assert!(
        field_at(&r.body, 0x06).is_some(),
        "clientPin support requires pinUvAuthProtocols (0x06)"
    );
    // No built-in UV on a screenless build → the uv option is omitted entirely.
    assert!(!has("uv"), "uv option must be absent without built-in UV");
}

#[test]
fn getinfo_algorithms_policy() {
    let r = Authr::fresh().get_info();
    let mut d = field_at(&r.body, 0x0A).expect("algorithms (0x0A) present");
    let n = d.array().unwrap().expect("algorithms is a definite array");
    assert!(n >= 1, "algorithms must be non-empty");
    let mut algs = Vec::new();
    for _ in 0..n {
        assert_eq!(
            d.map().unwrap().unwrap(),
            2,
            "each algorithm entry is a 2-key map"
        );
        assert_eq!(d.str().unwrap(), "alg");
        algs.push(d.i64().unwrap());
        assert_eq!(d.str().unwrap(), "type");
        assert_eq!(d.str().unwrap(), "public-key");
    }
    for a in [ALG_ES256, ALG_ES384, ALG_ES512] {
        assert!(algs.contains(&a), "NIST ECDSA curve {a} must be advertised");
    }
    // ES256K (-47) is never advertised (FIDO conformance MakeCred-Resp P-06).
    assert!(
        !algs.contains(&ALG_ES256K),
        "ES256K (-47) must never be advertised"
    );
    // EdDSA is advertised by default, suppressed only under the conformance profile.
    assert_eq!(
        algs.contains(&ALG_EDDSA),
        cfg!(not(feature = "fido-conformance")),
        "EdDSA (-8) advertisement must track the fido-conformance feature"
    );
    // ML-DSA-44 only when explicitly opted in.
    assert_eq!(
        algs.contains(&ALG_MLDSA44),
        cfg!(feature = "advertise-pqc"),
        "ML-DSA-44 (-48) advertisement must track the advertise-pqc feature"
    );
}

#[test]
fn getinfo_limits_and_formats() {
    let r = Authr::fresh().get_info();

    let mut d = field_at(&r.body, 0x05).expect("maxMsgSize (0x05) present");
    assert_eq!(d.u64().unwrap(), MAX_MSG_SIZE);

    let mut d = field_at(&r.body, 0x08).expect("maxCredentialIdLength (0x08) present");
    assert_eq!(
        d.u64().unwrap(),
        MAX_CRED_ID_LENGTH,
        "maxCredentialIdLength must equal the credential-box ceiling (metadata must match)"
    );

    let mut d = field_at(&r.body, 0x06).expect("pinUvAuthProtocols (0x06) present");
    let n = d.array().unwrap().unwrap();
    assert!(n >= 1, "pinUvAuthProtocols must be non-empty");
    for _ in 0..n {
        let p = d.u32().unwrap();
        assert!(p == 1 || p == 2, "unknown pinUvAuthProtocol {p}");
    }

    assert!(
        str_array(&r.body, 0x09).iter().any(|s| s == "usb"),
        "transports must include usb"
    );
    // transportsForReset is what a platform reads to decide whether a reset it can
    // reach exists at all; claiming a transport the applet does not answer on would
    // send it looking for one that is not there.
    assert_eq!(
        str_array(&r.body, 0x1A),
        str_array(&r.body, 0x09),
        "transportsForReset must match the transports the applet answers on"
    );
    // A URL for a policy the authenticator does not enforce points a reader at
    // nothing. The roster above already fires when 0x1C appears at all; this is
    // what still holds after someone adds it there deliberately.
    let mut d = field_at(&r.body, 0x1B).expect("pinComplexityPolicy (0x1B) present");
    if !d.bool().unwrap() {
        assert!(
            field_at(&r.body, 0x1C).is_none(),
            "pinComplexityPolicyURL must not describe a policy that is not enforced"
        );
    }
    assert!(
        str_array(&r.body, 0x16).iter().any(|s| s == "packed"),
        "attestationFormats must include packed"
    );

    let mut d = field_at(&r.body, 0x1F).expect("authenticatorConfigCommands (0x1F) present");
    let n = d.array().unwrap().unwrap();
    let mut cmds = Vec::new();
    for _ in 0..n {
        cmds.push(d.u32().unwrap());
    }
    assert_eq!(cmds, vec![0x01u32, 0x02, 0x03, 0xFF]);

    let mut d = field_at(&r.body, 0x0E).expect("firmwareVersion (0x0E) present");
    assert_eq!(d.u32().unwrap(), FIRMWARE_VERSION);
}

/// Collect a getInfo text-string array member into owned strings.
fn str_array(body: &[u8], key: u32) -> Vec<String> {
    let mut d = field_at(body, key).expect("array field present");
    let n = d.array().unwrap().expect("definite array");
    let mut out = Vec::new();
    for _ in 0..n {
        out.push(d.str().unwrap().to_string());
    }
    out
}

/// 0x19 and 0x1E are published from provisioning, not from the first `pcmr`
/// request. A platform cannot decrypt either without the token, so withholding
/// them bought no privacy — it only hid them from a conformance runner, which
/// reads getInfo before it is in a position to ask for anything. Both are
/// `iv ‖ AES-128-CBC(k, 16-byte block)`, and the IV is fresh per call: a fixed one
/// would turn either member into a stable cross-origin fingerprint served to
/// anyone who asks.
#[test]
fn the_sealed_members_are_published_before_any_token_is_issued() {
    let mut a = Authr::fresh();
    let first = a.get_info();
    assert_ok(&first);
    let second = a.get_info();
    for key in [0x19u32, 0x1E] {
        let mut d = field_at(&first.body, key).unwrap_or_else(|| panic!("{key:#04x} present"));
        let one = d.bytes().unwrap().to_vec();
        assert_eq!(one.len(), 32, "{key:#04x} is iv ‖ one AES block");
        let mut d2 = field_at(&second.body, key).unwrap_or_else(|| panic!("{key:#04x} present"));
        let two = d2.bytes().unwrap().to_vec();
        assert_ne!(one, two, "{key:#04x} must not repeat across calls");
        assert_ne!(one[..16], two[..16], "the IV is what must move");
    }
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

    /// getPinUvAuthTokenUsingPinWithPermissions for `pcmr` alone, with no rpId:
    /// `{1: 2, 2: 9, 3: keyAgreement, 6: pinHashEnc, 9: permissions}`.
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
/// persistent pinUvAuthToken the two sealed members are keyed with.
fn pcmr_grant(a: &mut Authr) -> [u8; 32] {
    let pc = PinClient::establish(a);
    assert_ok_empty(&a.send(CTAP_CLIENT_PIN, &pc.set_pin(PIN)));
    let r = a.send(CTAP_CLIENT_PIN, &pc.pcmr_token(PIN));
    assert_ok(&r);
    pc.decrypt_token(&r.body)
}

/// getInfo member `key`, which must be present, as bytes.
fn member(a: &mut Authr, key: u32) -> Vec<u8> {
    let r = a.get_info();
    let mut d = field_at(&r.body, key).unwrap_or_else(|| panic!("{key:#04x} present"));
    d.bytes().unwrap().to_vec()
}

/// Open a sealed member as §6.4 tells a platform to: `iv ‖ ct`, AES-128-CBC under
/// HKDF-SHA-256(salt = 32 zero bytes, IKM = the persistent token, info = `label`).
fn open_member(token: &[u8; 32], blob: &[u8], label: &[u8]) -> [u8; 16] {
    let mut key = [0u8; 16];
    hkdf_sha256(&[0u8; 32], token, label, &mut key).unwrap();
    let iv: [u8; 16] = blob[..16].try_into().unwrap();
    let mut block: [u8; 16] = blob[16..].try_into().unwrap();
    aes_decrypt(&key, &iv, Mode::Cbc, &mut block).unwrap();
    block
}

/// FIDO Authr-Generic-1 P-4. Under the `pcmr` grant 0x19 opens to one device
/// identifier call after call, and authenticatorReset generates a new one (§6.6),
/// which is what the grant taken after the reset opens it to.
#[test]
fn a_reset_gives_the_device_a_new_identifier() {
    let mut a = Authr::fresh();
    let before = pcmr_grant(&mut a);
    let id = open_member(&before, &member(&mut a, 0x19), b"encIdentifier");
    assert_eq!(
        open_member(&before, &member(&mut a, 0x19), b"encIdentifier"),
        id,
        "the identifier holds from one getInfo to the next"
    );
    replug(&mut a);
    assert_ok_empty(&a.send(CTAP_RESET, &[]));
    let after = pcmr_grant(&mut a);
    let new_id = open_member(&after, &member(&mut a, 0x19), b"encIdentifier");
    assert_eq!(
        open_member(&after, &member(&mut a, 0x19), b"encIdentifier"),
        new_id,
        "the grant taken after the reset opens 0x19 to one value"
    );
    assert_ne!(
        new_id, id,
        "authenticatorReset must generate a new device identifier"
    );
}

/// Power-cycle the authenticator: RAM state goes, flash stays, and the clock
/// restarts — §6.6 honours authenticatorReset only in the first 10 s after it.
fn replug(a: &mut Authr) {
    a.state = FidoState::new();
    a.clock = 0;
}

/// A discoverable makeCredential over `example.com`: a change to the credential store.
fn mc_rk() -> Vec<u8> {
    enc(|e| {
        e.map(5).unwrap();
        e.u8(1).unwrap().bytes(&[0xCD; 32]).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str("example.com").unwrap();
        e.u8(3).unwrap().map(1).unwrap();
        e.str("id").unwrap().bytes(&[7, 7]).unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str(PUBLIC_KEY_TYPE).unwrap();
        e.u8(7).unwrap().map(1).unwrap();
        e.str("rk").unwrap().bool(true).unwrap();
    })
}

/// FIDO Authr-Generic-1 P-5, as far as RS-Key meets it: §6.6 asks a reset for a fresh
/// random store state, but `cred_store_state` reads the wiped tag as the fresh-device
/// zero, so only a store that changed before the reset reads differently after it.
#[test]
fn a_store_changed_before_a_reset_reads_differently_after_it() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk()));
    let before = pcmr_grant(&mut a);
    let state = open_member(&before, &member(&mut a, 0x1E), b"encCredStoreState");
    assert_eq!(
        open_member(&before, &member(&mut a, 0x1E), b"encCredStoreState"),
        state,
        "the state holds from one getInfo to the next"
    );
    replug(&mut a);
    assert_ok_empty(&a.send(CTAP_RESET, &[]));
    let after = pcmr_grant(&mut a);
    let new_state = open_member(&after, &member(&mut a, 0x1E), b"encCredStoreState");
    assert_eq!(
        open_member(&after, &member(&mut a, 0x1E), b"encCredStoreState"),
        new_state,
        "the grant taken after the reset opens 0x1E to one value"
    );
    assert_ne!(
        new_state, state,
        "a changed store must not read the same after a reset"
    );
}
