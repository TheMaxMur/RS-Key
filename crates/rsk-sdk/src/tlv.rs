// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! BER-TLV walk/find. Tags are 1 or 2 bytes (the 2-byte form when the low 5 bits
//! are `0x1f`); lengths are short (`< 0x80`), `0x81 + 1 byte`, or `0x82 + 2 bytes`.

// Host bytes: a panic here is a board that answers nothing until unplugged.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

/// Iterator over the TLV objects in a byte slice. Yields `(tag, value)`.
/// Malformed/overrunning input simply ends iteration.
pub struct Tlv<'a> {
    rest: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Tlv { rest: data }
    }
}

impl<'a> Iterator for Tlv<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let b = self.rest;
        if b.is_empty() {
            return None;
        }
        let mut p = 0usize;
        let mut tag = *b.get(p)? as u16;
        p += 1;
        if tag & 0x1f == 0x1f {
            tag = (tag << 8) | *b.get(p)? as u16;
            p += 1;
        }
        let l0 = *b.get(p)?;
        p += 1;
        let len = match l0 {
            0x82 => {
                let v = ((*b.get(p)? as usize) << 8) | *b.get(p + 1)? as usize;
                p += 2;
                v
            }
            0x81 => {
                let v = *b.get(p)? as usize;
                p += 1;
                v
            }
            n => n as usize,
        };
        let end = p.checked_add(len)?;
        let value = b.get(p..end)?;
        self.rest = b.get(end..)?;
        Some((tag, value))
    }
}

/// Return the value of the first object with `tag`.
pub fn find_tag(data: &[u8], tag: u16) -> Option<&[u8]> {
    Tlv::new(data).find(|(t, _)| *t == tag).map(|(_, v)| v)
}

/// Number of bytes the encoded length field needs.
pub const fn format_len_size(len: u16) -> usize {
    if len < 128 {
        1
    } else if len < 256 {
        2
    } else {
        3
    }
}

/// Encode `len` into `out`, returning the number of bytes written.
pub fn format_len(len: u16, out: &mut [u8; 3]) -> usize {
    let [hi, lo] = len.to_be_bytes();
    if len < 128 {
        out[0] = lo;
        1
    } else if len < 256 {
        out[0] = 0x81;
        out[1] = lo;
        2
    } else {
        out[0] = 0x82;
        out[1] = hi;
        out[2] = lo;
        3
    }
}

/// Total encoded size of a TLV object with `tag` and `len`.
pub const fn len_tag(tag: u16, len: u16) -> usize {
    let base = 1 + format_len_size(len) + len as usize;
    if tag > 0x00ff { base + 1 } else { base }
}

/// Kani proof harnesses (`cargo kani -p rsk-sdk`): exhaustive over every input
/// up to the stated bound, where the unit tests above only sample.
#[cfg(kani)]
#[path = "tlv_kani.rs"]
mod proofs;

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    reason = "a test's fixture is its own bound, and a panic is its failure report"
)]
#[path = "tlv_tests.rs"]
mod tests;
