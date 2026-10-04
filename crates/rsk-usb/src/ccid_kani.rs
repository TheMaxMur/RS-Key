// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[kani::proof]
fn header_encoding_preserves_every_byte_outside_a_complete_header() {
    let mut out: [u8; HEADER + 2] = kani::any();
    let before = out;
    let len: usize = kani::any();
    kani::assume(len <= out.len());
    let kind: u8 = kani::any();
    let length: u32 = kani::any();
    let seq: u8 = kani::any();
    let status: u8 = kani::any();
    put_header(&mut out[..len], kind, length, seq, status);
    if len < HEADER {
        assert!(out == before);
    } else {
        assert!(out[0] == kind);
        assert!(u32::from_le_bytes([out[1], out[2], out[3], out[4]]) == length);
        assert!(out[5] == 0 && out[6] == seq && out[7] == status);
        assert!(out[8] == 0 && out[9] == 0);
        assert!(out[HEADER..] == before[HEADER..]);
    }
    kani::cover!(len < HEADER, "short header refused");
    kani::cover!(len == HEADER, "exact header encoded");
    kani::cover!(len > HEADER, "body preserved");
}

/// `xfr_apdu` / `secure_apdu` never panic on any host message; they recognize
/// exactly their own message type, never both; and the range they return is
/// `HEADER..HEADER + min(dwLength, available)` — so the caller can slice
/// `msg[start..end]` (the untrusted APDU payload) without its own bounds check.
///
/// The four clauses are the ones a wrong clamp breaks, and each breaks
/// differently:
///
/// * *inside the message* — `s <= e <= msg.len()`, or the caller's slice panics;
/// * *never more than announced* — `e - s <= dwLength`, or a short `dwLength`
///   with a long message hands the applet trailing bytes the host did not send
///   as APDU, which is how one command's tail becomes the next one's prefix;
/// * *never less than delivered* — a message that really carries its announced
///   payload yields all of it, or a legitimate APDU is silently truncated and
///   answered as malformed;
/// * *one message, one meaning* — the CCID dispatcher picks the branch by
///   `msg[0]`, so a message that parsed as both would be read two ways.
///
/// `assert!`, not `assert_eq!`: Kani cannot format at runtime, so every
/// `assert_eq!` collapses into one shared `core::panicking` check and the
/// counterexample stops naming the clause that broke.
#[kani::proof]
fn xfr_and_secure_apdu_ranges_stay_in_bounds() {
    let buf: [u8; HEADER + 3] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= buf.len());
    let msg = &buf[..len];

    let xfr = xfr_apdu(msg);
    let secure = secure_apdu(msg);
    assert!(
        !(xfr.is_some() && secure.is_some()),
        "one message parsed as both an XFR block and a Secure request"
    );

    for (parsed, want_type) in [(xfr, CCID_XFR_BLOCK), (secure, CCID_SECURE)] {
        assert!(
            parsed.is_some() == (len >= HEADER && buf[0] == want_type),
            "recognition does not match the header the CCID spec defines"
        );
        let Some((s, e)) = parsed else { continue };
        // The length the host announced in dwLength, read off the same wire the
        // caller read: the clamp is a claim about this number, not about a
        // recomputation of the clamp.
        let announced = u32::from_le_bytes([msg[1], msg[2], msg[3], msg[4]]) as usize;
        let available = len - HEADER;
        assert!(s == HEADER, "payload does not start after the CCID header");
        assert!(s <= e && e <= len, "range escapes the message");
        assert!(
            e - s <= announced,
            "range is longer than dwLength announced"
        );
        assert!(
            announced > available || e - s == announced,
            "a fully delivered payload came back truncated"
        );
        kani::cover!(e - s == available && announced > available, "clamped");
        kani::cover!(e - s == announced && announced < available, "not clamped");
    }
}
