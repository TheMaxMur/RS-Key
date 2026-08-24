// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §6.4 `authenticatorGetInfo` conformance assertions, driven through
//! the wire envelope (`process_cbor`). The pilot for the host-side conformance
//! layer; other commands fan out from the same harness.

use super::{Authr, assert_ok, bool_map_canonical, field_at, int_map_keys};
use crate::consts::{
    AAGUID, ALG_EDDSA, ALG_ES256, ALG_ES256K, ALG_ES384, ALG_ES512, ALG_MLDSA44, FIRMWARE_VERSION,
    MAX_CRED_ID_LENGTH, MAX_MSG_SIZE,
};

/// The exact set of getInfo members this build advertises, in canonical order.
/// A new member must land here *and* in `metadata/rs-key.metadata.json` +
/// `docs/protocol.md` — this test is the tripwire.
/// 0x0B (maxSerializedLargeBlobArray) belongs to the `authenticatorLargeBlobs`
/// command, which a `largeblob-ext` build does not serve (CTAP 2.3 §12.4).
/// 0x19 (encIdentifier) is listed but never expected here: it needs a persistent
/// pinUvAuthToken to key it, and `Authr::fresh()` has none. Its presence is proved
/// where a token exists — `tests::dispatch_get_info_carries_enc_identifier_once_a_token_exists`.
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
        // 0x19 and 0x1E are both keyed by the persistent pinUvAuthToken, which an
        // `Authr::fresh()` has never issued.
        .filter(|k| *k != 0x19 && *k != 0x1E)
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
