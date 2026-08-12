// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::{parse_ehl_body, parse_ehl_head, tag_len};
use crate::consts::{EF_PK_AUT, EF_PK_DEC, EF_PK_SIG};

/// `tag_len` never panics on any bytes/position; on success it advances `pos`
/// by the 1..=3 in-bounds bytes of the BER length field.
#[kani::proof]
fn tag_len_total() {
    const N: usize = 5;
    let data: [u8; N] = kani::any();
    let n: usize = kani::any();
    let start: usize = kani::any();
    kani::assume(n <= N);
    kani::assume(start <= n);
    let mut pos = start;
    if tag_len(&data[..n], &mut pos).is_some() {
        assert!(pos >= start + 1 && pos <= start + 3);
        assert!(pos <= n); // every byte it consumed was in bounds
    }
}

/// Parsing the `4D … CRT` header never panics; a success selects one of the
/// three key slots.
#[kani::proof]
fn parse_ehl_head_total() {
    const N: usize = 8;
    let data: [u8; N] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= N);
    if let Ok((fid, _)) = parse_ehl_head(&data[..n]) {
        assert!(fid == EF_PK_SIG || fid == EF_PK_DEC || fid == EF_PK_AUT);
    }
}

/// Walking the `7F48` template + `5F48` key data never panics and always
/// terminates, for any start position and any bytes — and the (offset, length)
/// pairs it hands back **carve the key data into disjoint, ascending pieces**,
/// each non-empty, each with `off + len` computable.
///
/// The carve is the claim. `try_import` reads element 0 as the RSA public
/// exponent, 1 as prime P and 2 as prime Q, and the parser reports offsets into
/// the host's own buffer rather than slices, so nothing in the type system says
/// two elements cannot name overlapping bytes: an import where P and Q share
/// their tail would be accepted and stored as a key whose modulus the device
/// cannot factor back. The old harness (`let _ =`) proved only that the parse
/// returns.
///
/// `off + len` is checked because that is the expression the caller evaluates —
/// `data.get(o..o + len[t])`. A wrapping add there is a panic under
/// `debug_assertions` and a silently absurd range without them.
#[kani::proof]
#[kani::unwind(12)]
fn parse_ehl_body_total() {
    const N: usize = 14;
    let data: [u8; N] = kani::any();
    let n: usize = kani::any();
    let pos: usize = kani::any();
    kani::assume(n <= N);
    kani::assume(pos <= n);
    let Ok((off, len)) = parse_ehl_body(&data[..n], pos) else {
        return;
    };
    let mut prev_end = 0usize;
    let mut t = 0usize;
    while t < off.len() {
        if let Some(o) = off[t] {
            assert!(len[t] > 0, "an element was carved out with no bytes in it");
            assert!(o >= prev_end, "elements overlap or run backwards");
            let end = o.checked_add(len[t]);
            assert!(end.is_some(), "off + len overflows at the call site");
            prev_end = end.unwrap_or(prev_end);
        }
        t += 1;
    }
    kani::cover!(
        off.iter().filter(|o| o.is_some()).count() >= 2,
        "two elements carved"
    );
}
