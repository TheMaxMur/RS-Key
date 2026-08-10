// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::consts::{ALG_ES256K, LARGE_BLOB_EXT};

/// Options in a screenless build. `largeBlobs` is one of them, and it goes away
/// with the command it describes on a `largeblob-ext` build (§12.4).
const N_OPTIONS: usize = 12 - LARGE_BLOB_EXT as usize;
use minicbor::Decoder;

/// Decode the advertised `algorithms` (0x0A) COSE ids from a getInfo response.
fn advertised_algs() -> std::vec::Vec<i64> {
    let mut out = [0u8; 1024];
    let n = get_info(false, 6, false, false, false, false, 256, &mut out).unwrap();
    let mut d = Decoder::new(&out[..n]);
    let entries = d.map().unwrap().unwrap();
    let mut algs = std::vec::Vec::new();
    for _ in 0..entries {
        let key = d.u32().unwrap();
        if key == 0x0A {
            let m = d.array().unwrap().unwrap();
            for _ in 0..m {
                assert_eq!(d.map().unwrap().unwrap(), 2);
                assert_eq!(d.str().unwrap(), "alg");
                algs.push(d.i64().unwrap());
                assert_eq!(d.str().unwrap(), "type");
                assert_eq!(d.str().unwrap(), "public-key");
            }
        } else {
            d.skip().unwrap();
        }
    }
    algs
}

/// Algorithm-advertisement policy (0x0A).
///
/// EdDSA (-8) is advertised by DEFAULT — the Windows WebAuthn API filters a
/// request's `pubKeyCredParams` by the advertised set, so an unadvertised -8
/// breaks `ssh-keygen -t ed25519-sk`. The `fido-conformance` feature suppresses
/// it (the conformance tool's shared `verifySignatureCOSE` cannot verify an
/// EdDSA self-attestation — MakeCred-Resp P-06). ES256K (-47) is never
/// advertised (same P-06 limitation). Both stay implemented: makeCredential
/// still negotiates them from a request's `pubKeyCredParams`.
#[test]
fn algorithms_advertisement_policy() {
    let algs = advertised_algs();
    // The NIST ECDSA curves are always advertised.
    assert!(algs.contains(&ALG_ES256));
    assert!(algs.contains(&ALG_ES384));
    assert!(algs.contains(&ALG_ES512));
    // ES256K is never advertised (FIDO conformance MakeCred-Resp P-06).
    assert!(
        !algs.contains(&ALG_ES256K),
        "ES256K (-47) must not be advertised"
    );
    // EdDSA is advertised by default, suppressed only under `fido-conformance`.
    if cfg!(feature = "fido-conformance") {
        assert!(
            !algs.contains(&ALG_EDDSA),
            "EdDSA (-8) must not be advertised in the conformance profile"
        );
    } else {
        assert!(
            algs.contains(&ALG_EDDSA),
            "EdDSA (-8) must be advertised by default (Windows WebAuthn / ed25519-sk)"
        );
    }
}

/// A golden transcript of the DEFAULT profile's getInfo. The `largeblob-ext`
/// build serves a different member set by design, checked by
/// `conformance::largeblobext::get_info_offers_the_extension_and_withdraws_the_pair`
/// rather than by threading conditionals through every line here.
#[test]
#[cfg(not(feature = "largeblob-ext"))]
fn get_info_fields() {
    let mut buf = [0u8; 512];
    let n = get_info(true, 4, false, false, false, false, 200, &mut buf).unwrap();
    let mut d = Decoder::new(&buf[..n]);

    let entries = d.map().unwrap().unwrap();
    assert_eq!(entries, 20);

    // 0x01 versions
    assert_eq!(d.u8().unwrap(), 0x01);
    let nv = d.array().unwrap().unwrap();
    // No FIDO_2_2 — CTAP 2.3 §6.4: the string was never defined and "MUST not be
    // present in versions member".
    assert_eq!(nv, 4);
    assert_eq!(d.str().unwrap(), "U2F_V2");
    assert_eq!(d.str().unwrap(), "FIDO_2_0");
    assert_eq!(d.str().unwrap(), "FIDO_2_1");
    assert_eq!(d.str().unwrap(), "FIDO_2_3");

    // 0x02 extensions
    assert_eq!(d.u8().unwrap(), 0x02);
    assert_eq!(d.array().unwrap().unwrap(), 7);
    assert_eq!(d.str().unwrap(), "credBlob");
    assert_eq!(d.str().unwrap(), "credProtect");
    assert_eq!(d.str().unwrap(), "hmac-secret");
    assert_eq!(d.str().unwrap(), "largeBlobKey");
    assert_eq!(d.str().unwrap(), "minPinLength");
    assert_eq!(d.str().unwrap(), "hmac-secret-mc");
    assert_eq!(d.str().unwrap(), "thirdPartyPayment");

    // 0x03 aaguid
    assert_eq!(d.u8().unwrap(), 0x03);
    assert_eq!(d.bytes().unwrap(), &AAGUID);

    // 0x04 options — ep, rk, up, alwaysUv, credMgmt, authnrCfg, clientPin (PIN
    // set → true), largeBlobs, perCredMgmtRO, pinUvAuthToken, setMinPINLength,
    // makeCredUvNotRqd (canonical: length then bytewise; "ep" first among 2-char
    // keys, "alwaysUv" first among 8-char keys, the 16-char key last).
    assert_eq!(d.u8().unwrap(), 0x04);
    assert_eq!(d.map().unwrap().unwrap(), 12);
    assert_eq!(d.str().unwrap(), "ep");
    assert!(!d.bool().unwrap()); // ea_enabled = false in this call
    assert_eq!(d.str().unwrap(), "rk");
    assert!(d.bool().unwrap());
    assert_eq!(d.str().unwrap(), "up");
    assert!(d.bool().unwrap());
    assert_eq!(d.str().unwrap(), "alwaysUv");
    assert!(!d.bool().unwrap()); // always_uv = false in this call
    assert_eq!(d.str().unwrap(), "credMgmt");
    assert!(d.bool().unwrap());
    assert_eq!(d.str().unwrap(), "authnrCfg");
    assert!(d.bool().unwrap());
    assert_eq!(d.str().unwrap(), "clientPin");
    assert!(d.bool().unwrap());
    assert_eq!(d.str().unwrap(), "largeBlobs");
    assert!(d.bool().unwrap());
    assert_eq!(d.str().unwrap(), "perCredMgmtRO");
    assert!(d.bool().unwrap());
    assert_eq!(d.str().unwrap(), "pinUvAuthToken");
    assert!(d.bool().unwrap());
    assert_eq!(d.str().unwrap(), "setMinPINLength");
    assert!(d.bool().unwrap());
    assert_eq!(d.str().unwrap(), "makeCredUvNotRqd");
    assert!(d.bool().unwrap());

    // 0x05 maxMsgSize
    assert_eq!(d.u8().unwrap(), 0x05);
    assert_eq!(d.u64().unwrap(), MAX_MSG_SIZE);

    // 0x06 pinUvAuthProtocols [2, 1]
    assert_eq!(d.u8().unwrap(), 0x06);
    assert_eq!(d.array().unwrap().unwrap(), 2);
    assert_eq!(d.u8().unwrap(), 2);
    assert_eq!(d.u8().unwrap(), 1);

    // 0x07 maxCredentialCountInList
    assert_eq!(d.u8().unwrap(), 0x07);
    assert_eq!(d.u64().unwrap(), MAX_CREDENTIAL_COUNT_IN_LIST);

    // 0x08 maxCredentialIdLength
    assert_eq!(d.u8().unwrap(), 0x08);
    assert_eq!(d.u64().unwrap(), MAX_CRED_ID_LENGTH);

    // 0x09 transports ["usb"]
    assert_eq!(d.u8().unwrap(), 0x09);
    assert_eq!(d.array().unwrap().unwrap(), 1);
    assert_eq!(d.str().unwrap(), "usb");

    // 0x0A algorithms: [{alg, type:"public-key"} …] — the NIST ECDSA curves,
    // then EdDSA (-8) unless `fido-conformance` suppresses it; `advertise-pqc`
    // prepends ML-DSA-65 (-49) then ML-DSA-44 (-48) (default stays without them:
    // Firefox authenticator-rs strict parse).
    assert_eq!(d.u8().unwrap(), 0x0A);
    let pqc = cfg!(feature = "advertise-pqc");
    let eddsa = cfg!(not(feature = "fido-conformance"));
    assert_eq!(
        d.array().unwrap().unwrap(),
        3 + 2 * u64::from(pqc) + u64::from(eddsa)
    );
    let mut algs = vec![];
    if pqc {
        algs.push(ALG_MLDSA65);
        algs.push(ALG_MLDSA44);
    }
    algs.extend([ALG_ES256, ALG_ES384, ALG_ES512]);
    if eddsa {
        algs.push(ALG_EDDSA);
    }
    for alg in algs {
        assert_eq!(d.map().unwrap().unwrap(), 2);
        assert_eq!(d.str().unwrap(), "alg");
        assert_eq!(d.i64().unwrap(), alg);
        assert_eq!(d.str().unwrap(), "type");
        assert_eq!(d.str().unwrap(), "public-key");
    }

    // 0x0B maxSerializedLargeBlobArray
    assert_eq!(d.u8().unwrap(), 0x0B);
    assert_eq!(d.u64().unwrap(), MAX_LARGE_BLOB_SIZE as u64);

    // 0x0C forceChangePin, 0x0D minPINLength
    assert_eq!(d.u8().unwrap(), 0x0C);
    assert!(!d.bool().unwrap());
    assert_eq!(d.u8().unwrap(), 0x0D);
    assert_eq!(d.u8().unwrap(), 4);

    // 0x0E firmwareVersion
    assert_eq!(d.u8().unwrap(), 0x0E);
    assert_eq!(d.u32().unwrap(), FIRMWARE_VERSION);

    // 0x0F maxCredBlobLength
    assert_eq!(d.u8().unwrap(), 0x0F);
    assert_eq!(d.u64().unwrap(), MAX_CREDBLOB_LENGTH as u64);

    // 0x10 maxRPIDsForSetMinPINLength
    assert_eq!(d.u8().unwrap(), 0x10);
    assert_eq!(d.u8().unwrap(), MAX_MIN_PIN_RPIDS as u8);

    // 0x14 remainingDiscoverableCredentials (= the value passed in)
    assert_eq!(d.u8().unwrap(), 0x14);
    assert_eq!(d.u16().unwrap(), 200);

    // 0x16 attestationFormats: only ["packed"] — every credential carries basic
    // attestation with the device x5c.
    assert_eq!(d.u8().unwrap(), 0x16);
    assert_eq!(d.array().unwrap().unwrap(), 1);
    assert_eq!(d.str().unwrap(), "packed");

    // 0x1D maxPINLength
    assert_eq!(d.u8().unwrap(), 0x1D);
    assert_eq!(d.u8().unwrap(), 63);

    // 0x1F authenticatorConfigCommands [enableEnterpriseAttestation (0x01),
    // toggleAlwaysUv (0x02), setMinPINLength (0x03), vendorPrototype (0xFF)]
    assert_eq!(d.u8().unwrap(), 0x1F);
    assert_eq!(d.array().unwrap().unwrap(), 4);
    assert_eq!(d.u8().unwrap(), 0x01);
    assert_eq!(d.u8().unwrap(), 0x02);
    assert_eq!(d.u8().unwrap(), 0x03);
    assert_eq!(d.u8().unwrap(), 0xFF);

    // Map fully consumed.
    assert!(d.datatype().is_err());
}

/// Read the `options` (0x04) map as `(key, value)` pairs.
fn option_pairs(builtin_uv: bool, pin_set: bool) -> std::vec::Vec<(std::string::String, bool)> {
    let mut buf = [0u8; 512];
    let n = get_info(pin_set, 4, false, false, false, builtin_uv, 256, &mut buf).unwrap();
    let mut d = Decoder::new(&buf[..n]);
    d.map().unwrap();
    for k in [0x01u8, 0x02, 0x03] {
        assert_eq!(d.u8().unwrap(), k);
        d.skip().unwrap();
    }
    assert_eq!(d.u8().unwrap(), 0x04);
    let m = d.map().unwrap().unwrap();
    (0..m)
        .map(|_| (d.str().unwrap().to_string(), d.bool().unwrap()))
        .collect()
}

/// `options.uv` (built-in user verification) is advertised only on a build that
/// can collect a PIN on its own UI, sorts right after `up`, and tracks whether a
/// PIN is configured. A screenless key omits it entirely.
#[test]
fn uv_option_present_only_with_builtin_uv() {
    // Screenless: no "uv" key.
    let plain = option_pairs(false, true);
    assert_eq!(plain.len(), N_OPTIONS);
    assert!(!plain.iter().any(|(k, _)| k == "uv"));

    // Display build, PIN set: "uv" = true, immediately after "up".
    let ready = option_pairs(true, true);
    assert_eq!(ready.len(), N_OPTIONS + 1);
    let up = ready.iter().position(|(k, _)| k == "up").unwrap();
    assert_eq!(ready[up + 1].0, "uv", "uv must sort right after up");
    assert!(ready[up + 1].1, "uv = true once a PIN is configured");

    // Display build, no PIN yet: "uv" present but false (supported, unconfigured).
    let unconfigured = option_pairs(true, false);
    assert!(!unconfigured.iter().find(|(k, _)| k == "uv").unwrap().1);
}

#[test]
fn client_pin_reflects_pin_state() {
    // options.clientPin is false before a PIN is set, true after.
    let mut buf = [0u8; 512];
    for pin_set in [false, true] {
        let n = get_info(pin_set, 4, false, false, false, false, 256, &mut buf).unwrap();
        let mut d = Decoder::new(&buf[..n]);
        d.map().unwrap();
        // skip to 0x04 options.
        assert_eq!(d.u8().unwrap(), 0x01);
        d.skip().unwrap();
        assert_eq!(d.u8().unwrap(), 0x02);
        d.skip().unwrap();
        assert_eq!(d.u8().unwrap(), 0x03);
        d.skip().unwrap();
        assert_eq!(d.u8().unwrap(), 0x04);
        d.map().unwrap();
        d.str().unwrap();
        d.bool().unwrap(); // ep
        d.str().unwrap();
        d.bool().unwrap(); // rk
        d.str().unwrap();
        d.bool().unwrap(); // up
        d.str().unwrap();
        d.bool().unwrap(); // alwaysUv
        d.str().unwrap();
        d.bool().unwrap(); // credMgmt
        d.str().unwrap();
        d.bool().unwrap(); // authnrCfg
        assert_eq!(d.str().unwrap(), "clientPin");
        assert_eq!(d.bool().unwrap(), pin_set);
    }
}

#[test]
fn min_pin_policy_reflected() {
    // 0x0D mirrors minPINLength, 0x0C the forceChangePin flag.
    let mut buf = [0u8; 512];
    let n = get_info(true, 8, true, false, false, false, 256, &mut buf).unwrap();
    let mut d = Decoder::new(&buf[..n]);
    d.map().unwrap();
    let (mut force, mut min) = (None, None);
    while let Ok(key) = d.u8() {
        match key {
            0x0C => force = Some(d.bool().unwrap()),
            0x0D => min = Some(d.u8().unwrap()),
            _ => d.skip().unwrap(),
        }
    }
    assert_eq!(force, Some(true));
    assert_eq!(min, Some(8));
}

#[test]
fn ep_reflects_ea_enabled() {
    // options.ep is always present and mirrors the enableEnterpriseAttestation
    // state: false at reset, true once EA has been enabled.
    for ea in [false, true] {
        let mut buf = [0u8; 512];
        let n = get_info(true, 4, false, ea, false, false, 256, &mut buf).unwrap();
        let mut d = Decoder::new(&buf[..n]);
        d.map().unwrap();
        for _ in 0..3 {
            // skip versions/extensions/aaguid (keys 0x01..0x03)
            d.u8().unwrap();
            d.skip().unwrap();
        }
        assert_eq!(d.u8().unwrap(), 0x04);
        d.map().unwrap();
        assert_eq!(d.str().unwrap(), "ep");
        assert_eq!(d.bool().unwrap(), ea);
    }
}

#[test]
fn always_uv_reflects_state() {
    // options.alwaysUv is always present and mirrors the toggleAlwaysUv state:
    // false at reset, true once alwaysUv has been enabled.
    for always_uv in [false, true] {
        let mut buf = [0u8; 512];
        let n = get_info(true, 4, false, false, always_uv, false, 256, &mut buf).unwrap();
        let mut d = Decoder::new(&buf[..n]);
        d.map().unwrap();
        for _ in 0..3 {
            // skip versions/extensions/aaguid (keys 0x01..0x03)
            d.u8().unwrap();
            d.skip().unwrap();
        }
        assert_eq!(d.u8().unwrap(), 0x04);
        d.map().unwrap();
        // ep, rk, up, then alwaysUv (4th option).
        for _ in 0..3 {
            d.str().unwrap();
            d.bool().unwrap();
        }
        assert_eq!(d.str().unwrap(), "alwaysUv");
        assert_eq!(d.bool().unwrap(), always_uv);
    }
}

#[test]
fn u2f_v2_dropped_when_always_uv() {
    // §7.2.4: alwaysUv disables the CTAP1/U2F interface, so getInfo must not keep
    // advertising U2F_V2 while it is on; the CTAP2 versions are unaffected.
    let cases: [(bool, &[&str]); 2] = [
        (false, &["U2F_V2", "FIDO_2_0", "FIDO_2_1", "FIDO_2_3"]),
        (true, &["FIDO_2_0", "FIDO_2_1", "FIDO_2_3"]),
    ];
    for (always_uv, want) in cases {
        let mut buf = [0u8; 512];
        let n = get_info(true, 4, false, false, always_uv, false, 256, &mut buf).unwrap();
        let mut d = Decoder::new(&buf[..n]);
        d.map().unwrap();
        assert_eq!(d.u8().unwrap(), 0x01);
        let nv = d.array().unwrap().unwrap();
        assert_eq!(nv as usize, want.len());
        for &v in want {
            assert_eq!(d.str().unwrap(), v);
        }
    }
}

#[test]
fn u2f_v2_survives_always_uv_behind_a_configured_pad() {
    // The other half of §7.2.4: the interface is disabled "unless the CTAP1/U2F
    // authenticator is protected by a built-in user verification method", so a
    // display build with a PIN keeps U2F_V2 — `process_u2f` then runs the pad on
    // every operation. A pad with no PIN yet protects nothing, so U2F still goes.
    let cases: [(bool, bool, bool); 4] = [
        // (builtin_uv, pin_set, U2F_V2 advertised under alwaysUv)
        (true, true, true),
        (true, false, false),
        (false, true, false),
        (false, false, false),
    ];
    for (builtin_uv, pin_set, want_u2f) in cases {
        let mut buf = [0u8; 512];
        let n = get_info(pin_set, 4, false, false, true, builtin_uv, 256, &mut buf).unwrap();
        let mut d = Decoder::new(&buf[..n]);
        d.map().unwrap();
        assert_eq!(d.u8().unwrap(), 0x01);
        let nv = d.array().unwrap().unwrap();
        assert_eq!(nv as usize, 3 + usize::from(want_u2f));
        if want_u2f {
            assert_eq!(d.str().unwrap(), "U2F_V2");
        }
        assert_eq!(d.str().unwrap(), "FIDO_2_0");
    }
}

#[test]
fn get_info_buffer_too_small() {
    let mut tiny = [0u8; 8];
    assert_eq!(
        get_info(false, 4, false, false, false, false, 256, &mut tiny),
        Err(CtapError::Other)
    );
}

#[test]
fn make_cred_uv_not_rqd_is_cleared_by_always_uv() {
    // Audit run-28 F2. §6.4, the alwaysUv row: "If the alwaysUv option ID is
    // present and true the authenticator MUST set the value of makeCredUvNotRqd
    // to false." §6.11.2 makes clearing it a step of toggleAlwaysUv, which this
    // device advertises. `enforce_pin` already refuses (fails closed) — this is
    // the advertisement catching up, so a platform stops sending the request.
    for always_uv in [false, true] {
        let mut buf = [0u8; 512];
        let n = get_info(true, 4, false, false, always_uv, false, 256, &mut buf).unwrap();
        let mut d = Decoder::new(&buf[..n]);
        d.map().unwrap();
        for _ in 0..3 {
            // skip versions/extensions/aaguid (keys 0x01..0x03)
            d.u8().unwrap();
            d.skip().unwrap();
        }
        assert_eq!(d.u8().unwrap(), 0x04);
        let opts = d.map().unwrap().unwrap();
        assert_eq!(opts as usize, N_OPTIONS, "no built-in UV on this build");
        // makeCredUvNotRqd is the longest key, so canonical order puts it last.
        for _ in 0..opts - 1 {
            d.str().unwrap();
            d.bool().unwrap();
        }
        assert_eq!(d.str().unwrap(), "makeCredUvNotRqd");
        assert_eq!(d.bool().unwrap(), !always_uv);
    }
}
