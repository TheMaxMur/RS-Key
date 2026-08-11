// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §6.5 `authenticatorClientPIN` conformance assertions for the
//! unauthenticated subcommands, driven through the wire envelope
//! (`process_cbor`): getKeyAgreement's COSE_Key shape, getPINRetries, and the
//! rejection of a subcommand the build does not support.

use super::{Authr, assert_ok, field_at, int_map_keys};
use crate::consts::{ALG_ECDH_ES_HKDF_256, CTAP_CLIENT_PIN, MAX_PIN_RETRIES};
use crate::error::CtapError;
use minicbor::Encoder;
use minicbor::encode::write::Cursor;

/// A clientPIN request `{1: pinUvAuthProtocol, 2: subCommand}`.
fn cp_request(proto: u64, sub: u64) -> Vec<u8> {
    let mut buf = [0u8; 32];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(2).unwrap();
        e.u8(1).unwrap().u64(proto).unwrap();
        e.u8(2).unwrap().u64(sub).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

#[test]
fn clientpin_key_agreement_cose_key() {
    // getKeyAgreement (subCommand 0x02) returns the authenticator's ephemeral
    // ECDH public key as a COSE_Key: {1: {1:2, 3:-25, -1:1, -2:x, -3:y}} (§6.5.4).
    let r = Authr::fresh().send(CTAP_CLIENT_PIN, &cp_request(2, 2));
    assert_ok(&r);
    assert_eq!(int_map_keys(&r.body), vec![1u32]);
    let mut d = field_at(&r.body, 1).expect("keyAgreement (0x01) present");
    assert_eq!(
        d.map().unwrap().unwrap(),
        5,
        "an EC2 COSE_Key has 5 members"
    );
    assert_eq!(d.u8().unwrap(), 1, "kty label");
    assert_eq!(d.u8().unwrap(), 2, "kty must be EC2");
    assert_eq!(d.u8().unwrap(), 3, "alg label");
    assert_eq!(
        d.i64().unwrap(),
        ALG_ECDH_ES_HKDF_256,
        "alg must be ECDH-ES+HKDF-256"
    );
    assert_eq!(d.i8().unwrap(), -1, "crv label");
    assert_eq!(d.u8().unwrap(), 1, "crv must be P-256");
    assert_eq!(d.i8().unwrap(), -2, "x label");
    assert_eq!(d.bytes().unwrap().len(), 32, "x is a 32-byte coordinate");
    assert_eq!(d.i8().unwrap(), -3, "y label");
    assert_eq!(d.bytes().unwrap().len(), 32, "y is a 32-byte coordinate");
}

#[test]
fn clientpin_get_retries() {
    // getPINRetries (subCommand 0x01) on a fresh device returns the max counter.
    let r = Authr::fresh().send(CTAP_CLIENT_PIN, &cp_request(2, 1));
    assert_ok(&r);
    assert_eq!(int_map_keys(&r.body), vec![3u32]);
    let mut d = field_at(&r.body, 3).expect("retries (0x03) present");
    assert_eq!(d.u8().unwrap(), MAX_PIN_RETRIES);
}

#[test]
fn clientpin_unsupported_subcommand() {
    // getUVRetries (0x07) needs built-in UV; a screenless build does not
    // implement it, and §8.1 fixes the answer for an unimplemented subcommand at
    // CTAP2_ERR_INVALID_SUBCOMMAND.
    let r = Authr::fresh().send(CTAP_CLIENT_PIN, &cp_request(2, 7));
    assert_eq!(r.status, CtapError::InvalidSubcommand.as_u8());
    assert!(r.body.is_empty(), "an error response carries no CBOR body");
}
