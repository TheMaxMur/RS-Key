// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// Walking ANY byte sequence (up to 16 bytes — past every tag/length form
/// with room for several nested objects) never panics, never overflows, and
/// always terminates; every yielded value lies inside the input.
#[kani::proof]
#[kani::unwind(18)]
fn walk_any_input() {
    const N: usize = 16;
    let data: [u8; N] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= N);
    for (_tag, value) in Tlv::new(&data[..n]) {
        assert!(value.len() <= n);
    }
}

/// An object headed by `format_len` walks back out of the REAL decoder as one
/// value of exactly that length at exactly the payload offset, and the iterator
/// then ends — so writer and reader agree across both length-form boundaries.
#[kani::proof]
fn format_len_roundtrip() {
    // 260 spans both boundaries (127/128 → the 0x81 form, 255/256 → the 0x82 form);
    // the buffer is the largest object that needs: tag + 3-byte length + value.
    const CAP: usize = 260;
    let len: u16 = kani::any();
    kani::assume(len as usize <= CAP);
    let mut buf = [0u8; 1 + 3 + CAP];
    // 0x5A: the low 5 bits are not 0x1f, so `Tlv::next` reads a 1-byte tag.
    buf[0] = 0x5A;
    let n = format_len(len, &mut buf[1..]);
    assert_eq!(n, format_len_size(len));

    let mut it = Tlv::new(&buf[..1 + n + len as usize]);
    let (tag, value) = it.next().expect("a well-formed object must decode");
    assert_eq!(tag, 0x5A);
    assert_eq!(value.len(), len as usize);
    // The value is the payload itself, not a same-length window at a shifted offset.
    assert!(core::ptr::eq(value.as_ptr(), buf[1 + n..].as_ptr()));
    assert!(it.next().is_none());
}

/// `format_len` writes exactly the `format_len_size` bytes it reports and not one
/// more, for EVERY `u16` length — the sizing contract `len_tag` and every applet's
/// response buffer rest on, past the length [`format_len_roundtrip`] can hold.
#[kani::proof]
#[kani::unwind(5)]
fn format_len_writes_exactly_its_size() {
    let len: u16 = kani::any();
    // The longest encoding is 3 bytes, so index 3 is a sentinel that must survive;
    // 4 is also the tail loop's iteration count, hence the unwind bound above.
    let mut buf = [0xFFu8; 4];
    let n = format_len(len, &mut buf);
    assert_eq!(n, format_len_size(len));
    let mut i = n;
    while i < buf.len() {
        assert_eq!(buf[i], 0xFF);
        i += 1;
    }
}
