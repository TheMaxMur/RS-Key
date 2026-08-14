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
    // An unknown subCommand (with a param present) → INVALID_PARAMETER, which is
    // what a YubiKey 5.7.4 answers here (§8.1 would say INVALID_SUBCOMMAND).
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

/// §8: a CTAP2 request body is exactly one CBOR item. A trailing byte used to be
/// read as the end of the message and ignored, so two readers of the same wire
/// bytes could disagree about what was asked. A YubiKey 5.7.4 refuses one with
/// CTAP2_ERR_INVALID_CBOR on every command that parses a body — and answers
/// getInfo normally, because getInfo never looks at its body at all.
#[test]
fn trailing_bytes_after_the_request_map_are_invalid_cbor() {
    // {1: 2, 2: 2} — clientPIN getKeyAgreement, a request that SUCCEEDS, so a
    // refusal below can only come from the bytes after it.
    let ka = enc(|e| {
        e.map(2).unwrap();
        e.u8(1).unwrap().u8(2).unwrap();
        e.u8(2).unwrap().u8(2).unwrap();
    });
    assert_eq!(Authr::fresh().send(CTAP_CLIENT_PIN, &ka).status, 0);
    for tail in [&[0x00u8][..], &[0xA0], &[0xFF], &[0u8; 32]] {
        let mut req = ka.clone();
        req.extend_from_slice(tail);
        expect(CTAP_CLIENT_PIN, &req, CtapError::InvalidCbor);
    }

    // It is the decoder, not one command: same tail on two more bodies.
    let mut ga = enc(|e| {
        e.map(2).unwrap();
        e.u8(1).unwrap().str("x.example").unwrap();
        e.u8(2).unwrap().bytes(&[0xCDu8; 32]).unwrap();
    });
    ga.push(0x00);
    expect(CTAP_GET_ASSERTION, &ga, CtapError::InvalidCbor);
    expect(CTAP_MAKE_CREDENTIAL, &[0xA0, 0x00], CtapError::InvalidCbor);

    // A map header that under-counts its entries leaves the rest of the message
    // trailing, which is how the oracle reads it too (INVALID_CBOR, where we used
    // to answer MISSING_PARAMETER for the entries we never looked at).
    expect(
        CTAP_CLIENT_PIN,
        &[0xA1, 0x01, 0x02, 0x02, 0x02],
        CtapError::InvalidCbor,
    );

    // Every command that parses a body is behind the gate, not just the three
    // driven above: dropping one from the list must fail here.
    for cmd in [
        crate::consts::CTAP_CONFIG,
        crate::consts::CTAP_CREDENTIAL_MGMT,
        crate::consts::CTAP_VENDOR,
    ] {
        expect(cmd, &[0xA0, 0x00], CtapError::InvalidCbor);
    }
    // …and no command that this build does *not* implement is behind it: on a
    // `largeblob-ext` image `0x0C` is unimplemented, and a trailing byte must not
    // turn its INVALID_COMMAND into INVALID_CBOR. The body does not decide which
    // command was sent.
    expect(
        crate::consts::CTAP_LARGE_BLOBS,
        &[0xA0, 0x00],
        if crate::consts::LARGE_BLOB_EXT {
            CtapError::InvalidCommand
        } else {
            CtapError::InvalidCbor
        },
    );

    // getInfo takes no parameters and never parses them; the oracle ignores a tail
    // there, so this gate must not reach it.
    assert_eq!(
        Authr::fresh()
            .send(crate::consts::CTAP_GET_INFO, &[0x00])
            .status,
        0
    );
}

/// §8's canonical form has no CBOR tags, and a decoder that steps over one lets
/// two readers of the same message disagree about what was asked — the shape the
/// one-item rule above exists for. Measured on a YubiKey 5.7.4, which answers
/// INVALID_CBOR to a tag on a value it does not read; ours walked straight
/// through it and answered SUCCESS.
#[test]
fn a_cbor_tag_on_a_value_the_parser_skips_is_invalid_cbor() {
    // {1: 2, 2: 2, 99: tag(0, 1)} — clientPIN getKeyAgreement plus a tagged value
    // under a key no parser reads.
    let tagged = enc(|e| {
        e.map(3).unwrap();
        e.u8(1).unwrap().u8(2).unwrap();
        e.u8(2).unwrap().u8(2).unwrap();
        e.u8(99)
            .unwrap()
            .tag(minicbor::data::IanaTag::DateTime)
            .unwrap();
        e.u8(1).unwrap();
    });
    expect(CTAP_CLIENT_PIN, &tagged, CtapError::InvalidCbor);

    // Control: the same request with the tag removed succeeds, so the refusal is
    // the tag and not the extra key.
    let untagged = enc(|e| {
        e.map(3).unwrap();
        e.u8(1).unwrap().u8(2).unwrap();
        e.u8(2).unwrap().u8(2).unwrap();
        e.u8(99).unwrap().u8(1).unwrap();
    });
    assert_eq!(Authr::fresh().send(CTAP_CLIENT_PIN, &untagged).status, 0);

    // It is the decoder, not one command.
    let ga = enc(|e| {
        e.map(3).unwrap();
        e.u8(1).unwrap().str("x.example").unwrap();
        e.u8(2).unwrap().bytes(&[0xCDu8; 32]).unwrap();
        e.u8(99)
            .unwrap()
            .tag(minicbor::data::IanaTag::DateTime)
            .unwrap();
        e.u8(1).unwrap();
    });
    expect(CTAP_GET_ASSERTION, &ga, CtapError::InvalidCbor);
}
