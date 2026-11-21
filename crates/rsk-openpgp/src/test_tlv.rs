// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! BER-TLV walking for the tests that read a DO where a host reads it: inside the
//! template that carries it.

/// Each child of a BER-TLV run, as `(tag, value)`.
pub(crate) fn children(mut b: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let (tag, mut pos) = if b[0] & 0x1F == 0x1F {
            (u16::from_be_bytes([b[0], b[1]]), 2)
        } else {
            (b[0] as u16, 1)
        };
        let n = crate::importdata::tag_len(b, &mut pos).unwrap();
        out.push((tag, b[pos..pos + n].to_vec()));
        b = &b[pos + n..];
    }
    out
}

/// The value of `tag` among `run`'s children.
pub(crate) fn child(run: &[(u16, Vec<u8>)], tag: u16) -> Vec<u8> {
    let hit = run.iter().find(|(t, _)| *t == tag);
    hit.unwrap_or_else(|| panic!("no {tag:#06x}")).1.clone()
}
