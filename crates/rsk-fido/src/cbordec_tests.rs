// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

use minicbor::Encoder;
use minicbor::encode::write::Cursor;

/// Encode a credential-descriptor array from `(type, id)` pairs.
fn descriptors(entries: &[(&str, &[u8])]) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 4096];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.array(entries.len() as u64).unwrap();
        for (ty, id) in entries {
            e.map(2).unwrap();
            e.str("type").unwrap().str(ty).unwrap();
            e.str("id").unwrap().bytes(id).unwrap();
        }
        e.writer().position()
    };
    buf[..n].to_vec()
}

fn parse(entries: &[(&str, &[u8])], cap: usize) -> Result<usize, CtapError> {
    let enc = descriptors(entries);
    let mut out = [&[][..]; 8];
    parse_credential_descriptors(&mut Decoder::new(&enc), &mut out[..cap])
}

const ID: &[u8] = &[1, 2, 3, 4];

#[test]
fn unknown_nested_descriptor_fields_are_consumed_before_the_id() {
    let bytes = [
        0x81, 0xa3, 0x66, b'f', b'u', b't', b'u', b'r', b'e', 0x82, 0xa0, 0xf6, 0x62, b'i', b'd',
        0x44, 1, 2, 3, 4, 0x64, b't', b'y', b'p', b'e', 0x6a, b'p', b'u', b'b', b'l', b'i', b'c',
        b'-', b'k', b'e', b'y',
    ];
    let mut decoder = Decoder::new(&bytes);
    let mut ids = [&[][..]; 1];
    assert_eq!(parse_credential_descriptors(&mut decoder, &mut ids), Ok(1));
    assert_eq!(ids, [ID]);
    assert_eq!(decoder.position(), bytes.len());
    let truncated = [0x81, 0xa1, 0x61, b'x', 0x82, 0xf6];
    assert_eq!(
        parse_credential_descriptors(&mut Decoder::new(&truncated), &mut ids),
        Err(CtapError::InvalidCbor)
    );
}

#[test]
fn at_the_ceiling_is_accepted() {
    assert_eq!(parse(&[("public-key", ID); 4], 4), Ok(4));
}

#[test]
fn over_the_ceiling_is_limit_exceeded() {
    // One past the ceiling is refused outright — the platform is told to split
    // the list, never left to believe a dropped credential is absent.
    assert_eq!(
        parse(&[("public-key", ID); 5], 4),
        Err(CtapError::LimitExceeded)
    );
}

#[test]
fn foreign_types_are_skipped() {
    assert_eq!(parse(&[("not-a-key", ID)], 4), Ok(0));
    assert_eq!(
        parse(&[("not-a-key", ID), ("public-key", ID), ("", ID)], 4),
        Ok(1)
    );
}

#[test]
fn foreign_types_still_count_towards_the_ceiling() {
    // Otherwise padding a list with foreign descriptors would buy room past the
    // advertised maxCredentialCountInList.
    assert_eq!(
        parse(&[("not-a-key", ID); 5], 4),
        Err(CtapError::LimitExceeded)
    );
}

#[test]
fn descriptor_needs_both_type_and_id() {
    let mut buf = [0u8; 64];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.array(1).unwrap().map(1).unwrap();
        e.str("id").unwrap().bytes(ID).unwrap();
        e.writer().position()
    };
    let mut out = [&[][..]; 4];
    assert_eq!(
        parse_credential_descriptors(&mut Decoder::new(&buf[..n]), &mut out),
        Err(CtapError::MissingParameter)
    );
}

#[test]
fn type_must_be_text() {
    // A byte-string "type" is a major-type mismatch, not an unknown type.
    let mut buf = [0u8; 64];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.array(1).unwrap().map(2).unwrap();
        e.str("type").unwrap().bytes(b"public-key").unwrap();
        e.str("id").unwrap().bytes(ID).unwrap();
        e.writer().position()
    };
    let mut out = [&[][..]; 4];
    assert_eq!(
        parse_credential_descriptors(&mut Decoder::new(&buf[..n]), &mut out),
        Err(CtapError::CborUnexpectedType)
    );
}
