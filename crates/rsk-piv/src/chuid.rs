// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Default CHUID (Card Holder Unique Identifier, PIV object `5FC102`) synthesized
//! when the card holds no host-provisioned one. Windows' PIV minidriver keys the
//! card identity and its container map off the 16-byte GUID in this object; a
//! card that answers `6A82` for `GET DATA 5FC102` still enumerates, but its
//! certificates stay unusable ("authentication pending") under CAPI. Serving a
//! default makes a freshly flashed device usable without a manual
//! `ykman piv objects generate chuid`. A real `PUT DATA` still overrides it —
//! [`crate::PivApplet::get_data`] reads flash first and only falls back here.
//!
//! Layout mirrors what ykman/YubiKey emit byte-for-byte except the GUID, which is
//! `sha256(serial)[..16]` — stable across reboots/reflash and unique per device,
//! so Windows never re-enrols the card. No cardholder is enrolled, so the FASC-N
//! is the well-known non-federal placeholder and the issuer signature / LRC are
//! empty (SP 800-73-4 §3.1.2, as ykman emits).

/// FASC-N (tag `0x30`, 25 bytes): the fixed non-federal placeholder ykman/YubiKey
/// write for a card with no PIV cardholder. Byte-identical to a real YubiKey's,
/// so the minidriver sees a shape it already trusts.
const FASC_N: [u8; 25] = [
    0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d, 0x83, 0x68, 0x58, 0x21, 0x08,
    0x42, 0x10, 0x84, 0x21, 0xc8, 0x42, 0x10, 0xc3, 0xeb,
];

/// Expiration (tag `0x35`, 8 ASCII `YYYYMMDD`): a fixed far date — the CHUID has
/// no real cardholder credential to expire; matches ykman's emitted value.
const EXPIRY: [u8; 8] = *b"20300101";

/// GUID length (tag `0x34`): the 16 bytes Windows treats as the card id.
const GUID_LEN: usize = 16;

/// Length of the assembled CHUID TLV: `30`(25) + `34`(16) + `35`(8) + `3E`(0) +
/// `FE`(0), each with its 2-byte tag+len header.
pub(crate) const CHUID_LEN: usize =
    (2 + FASC_N.len()) + (2 + GUID_LEN) + (2 + EXPIRY.len()) + 2 + 2;

/// Build the device's default CHUID; the GUID is `serial_hash[..16]`.
pub(crate) fn default_chuid(serial_hash: &[u8; 32]) -> [u8; CHUID_LEN] {
    let mut out = [0u8; CHUID_LEN];
    let mut i = 0;
    let mut push = |tag: u8, val: &[u8]| {
        let len = u8::try_from(val.len()).unwrap_or(u8::MAX);
        if let Some(entry) = out.get_mut(i..i + 2 + val.len())
            && let Some((head, body)) = entry.split_first_chunk_mut::<2>()
        {
            *head = [tag, len];
            body.copy_from_slice(val);
        }
        i += 2 + val.len();
    };
    push(0x30, &FASC_N);
    push(0x34, &serial_hash[..GUID_LEN]);
    push(0x35, &EXPIRY);
    push(0x3E, &[]); // issuer asymmetric signature — absent
    push(0xFE, &[]); // error detection code (LRC) — absent
    debug_assert_eq!(i, CHUID_LEN);
    out
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    reason = "a test's fixture is its own bound, and a panic is its failure report"
)]
#[path = "chuid_tests.rs"]
mod tests;
