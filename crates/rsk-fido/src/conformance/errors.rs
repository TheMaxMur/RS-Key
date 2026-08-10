// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 error-code conformance: a malformed or spec-violating request must
//! map to the *exact* status word, not merely fail to crash. The fuzz targets
//! cover no-panic robustness on arbitrary input; this pins the CODE the way a
//! conformance tool does. Driven through the wire envelope (`process_cbor`).

use super::Authr;
use crate::consts::{
    ALG_ES256, CTAP_CLIENT_PIN, CTAP_CREDENTIAL_MGMT, CTAP_GET_ASSERTION, CTAP_MAKE_CREDENTIAL,
};
// Serving the CTAP 2.1 large-blob design, which a `largeblob-ext` build withdraws
// (§12.4), so these go with the tests that drive it.
#[cfg(not(feature = "largeblob-ext"))]
use crate::consts::CTAP_LARGE_BLOBS;
use crate::error::CtapError;
use minicbor::Encoder;
use minicbor::encode::write::Cursor;

/// CBOR-encode a request body with `f`.
fn enc(f: impl Fn(&mut Encoder<Cursor<&mut [u8]>>)) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        f(&mut e);
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// Assert `cmd ‖ params` answers exactly `err`.
fn expect(cmd: u8, params: &[u8], err: CtapError) {
    let r = Authr::fresh().send(cmd, params);
    assert_eq!(
        r.status,
        err.as_u8(),
        "unexpected status 0x{:02x} for a malformed request",
        r.status
    );
}

#[test]
fn makecred_empty_params_is_invalid_cbor() {
    expect(CTAP_MAKE_CREDENTIAL, &[], CtapError::InvalidCbor);
}

#[test]
fn makecred_missing_client_data_hash() {
    // A request that omits clientDataHash (starts at key 2) → MISSING_PARAMETER.
    let req = enc(|e| {
        e.map(3).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str("x.example")
            .unwrap();
        e.u8(3)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .bytes(&[1])
            .unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
    });
    expect(CTAP_MAKE_CREDENTIAL, &req, CtapError::MissingParameter);
}

#[test]
fn makecred_up_false_is_invalid_option() {
    // options.up=false is illegal for makeCredential (§6.1) → INVALID_OPTION.
    let req = enc(|e| {
        e.map(5).unwrap();
        e.u8(1).unwrap().bytes(&[0xCD; 32]).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str("x.example")
            .unwrap();
        e.u8(3)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .bytes(&[1])
            .unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(7)
            .unwrap()
            .map(1)
            .unwrap()
            .str("up")
            .unwrap()
            .bool(false)
            .unwrap();
    });
    expect(CTAP_MAKE_CREDENTIAL, &req, CtapError::InvalidOption);
}

#[test]
fn getassertion_empty_params_is_invalid_cbor() {
    expect(CTAP_GET_ASSERTION, &[], CtapError::InvalidCbor);
}

#[test]
fn clientpin_missing_subcommand() {
    // {1: proto} with no subCommand → MISSING_PARAMETER.
    let req = enc(|e| {
        e.map(1).unwrap();
        e.u8(1).unwrap().u64(2).unwrap();
    });
    expect(CTAP_CLIENT_PIN, &req, CtapError::MissingParameter);
}

#[test]
fn clientpin_invalid_protocol() {
    // getKeyAgreement with an unknown pinUvAuthProtocol → INVALID_PARAMETER.
    let req = enc(|e| {
        e.map(2).unwrap();
        e.u8(1).unwrap().u64(3).unwrap();
        e.u8(2).unwrap().u64(2).unwrap();
    });
    expect(CTAP_CLIENT_PIN, &req, CtapError::InvalidParameter);
}

#[test]
fn credmgmt_unknown_subcommand() {
    // An unknown subCommand (with a param present) → INVALID_PARAMETER.
    let req = enc(|e| {
        e.map(3).unwrap();
        e.u8(1).unwrap().u64(0x99).unwrap();
        e.u8(3).unwrap().u64(2).unwrap();
        e.u8(4).unwrap().bytes(&[0u8; 32]).unwrap();
    });
    expect(CTAP_CREDENTIAL_MGMT, &req, CtapError::InvalidParameter);
}

// The CTAP 2.1 large-blob design, which a `largeblob-ext` build withdraws
// wholesale (§12.4: "Authenticators MUST NOT support both extensions").
#[cfg(not(feature = "largeblob-ext"))]
#[test]
fn largeblobs_get_and_set_conflict() {
    // Supplying both get (0x01) and set (0x02) → INVALID_PARAMETER.
    let req = enc(|e| {
        e.map(3).unwrap();
        e.u8(1).unwrap().u64(0).unwrap();
        e.u8(2).unwrap().bytes(&[0]).unwrap();
        e.u8(3).unwrap().u64(0).unwrap();
    });
    expect(CTAP_LARGE_BLOBS, &req, CtapError::InvalidParameter);
}

// The CTAP 2.1 large-blob design, which a `largeblob-ext` build withdraws
// wholesale (§12.4: "Authenticators MUST NOT support both extensions").
#[cfg(not(feature = "largeblob-ext"))]
#[test]
fn largeblobs_missing_offset() {
    // A get without the mandatory offset (0x03) → INVALID_PARAMETER.
    let req = enc(|e| {
        e.map(1).unwrap();
        e.u8(1).unwrap().u64(0).unwrap();
    });
    expect(CTAP_LARGE_BLOBS, &req, CtapError::InvalidParameter);
}
