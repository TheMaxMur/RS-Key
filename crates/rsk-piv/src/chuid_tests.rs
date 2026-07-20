// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// A distinctive 32-byte hash so the GUID slice is trivial to eyeball.
const HASH: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

#[test]
fn total_length_is_fixed() {
    assert_eq!(CHUID_LEN, 59);
    assert_eq!(default_chuid(&HASH).len(), CHUID_LEN);
}

#[test]
fn is_wellformed_tlv() {
    let c = default_chuid(&HASH);
    let mut i = 0;
    for (tag, len) in [
        (0x30u8, 25usize),
        (0x34, 16),
        (0x35, 8),
        (0x3E, 0),
        (0xFE, 0),
    ] {
        assert_eq!(c[i], tag, "tag at {i}");
        assert_eq!(c[i + 1] as usize, len, "len at {i}");
        i += 2 + len;
    }
    assert_eq!(i, CHUID_LEN, "TLVs must cover the whole object exactly");
}

#[test]
fn guid_is_serial_hash_prefix() {
    // After 30(2+25)=27 and the 34 10 header, the 16-byte GUID lives at 29..45.
    let c = default_chuid(&HASH);
    assert_eq!(&c[29..45], &HASH[..16]);
}

#[test]
fn distinct_serials_yield_distinct_guid() {
    let mut other = HASH;
    other[0] ^= 0xFF;
    assert_ne!(default_chuid(&HASH), default_chuid(&other));
}

#[test]
fn deterministic() {
    assert_eq!(default_chuid(&HASH), default_chuid(&HASH));
}

#[test]
fn fasc_n_and_expiry_match_observed_yubikey() {
    // Anchor to the exact 25-byte FASC-N and expiry captured from a real YubiKey 5
    // and a ykman-generated CHUID on 2026-07-20; the Windows minidriver trusts
    // this shape. If these bytes ever drift, that's a compatibility regression.
    let c = default_chuid(&HASH);
    assert_eq!(
        &c[2..27],
        &[
            0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d, 0x83, 0x68, 0x58,
            0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0xc8, 0x42, 0x10, 0xc3, 0xeb,
        ]
    );
    assert_eq!(&c[47..55], b"20300101");
}
