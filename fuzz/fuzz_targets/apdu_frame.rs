// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Command framing shared by the applet replay targets (`openpgp_apdu`,
//! `piv_apdu`, `mgmt_apdu`, `oath_apdu`, `otp_apdu`, `rescue_apdu`,
//! `cross_applet`). Each of those is its own `[[bin]]` and the fuzz package has
//! no lib, so they pull this in as `mod apdu_frame;` — one copy per target,
//! resolved out of this directory because a bin root *is* a crate root.
//!
//! The framing is `[len][apdu bytes…]*` with one escape. A one-byte length can
//! never build a command body over 255 bytes, so the whole extended-length band
//! was unreachable: OpenPGP PUT DATA up to `MAX_DO_BYTES` (2036), the IMPORT
//! extended header list, PIV certificate import, and the dispatcher's 2038-byte
//! chaining buffer. Raising the ceiling alone would not have helped —
//! `Apdu::parse`'s extended branch wants `buf[4] == 0` plus a be16 that exactly
//! equals the bytes that follow, a 3-byte exact match a mutator does not stumble
//! onto, which is why most framed chunks fail `Apdu::parse` outright today. So
//! `len == 0xFF` instead reads `cla ins p1 p2 hi lo` and *synthesises* the
//! header around the next `be16(hi, lo)` bytes.
//!
//! `0xFF` is the escape deliberately: it used to mean a 255-byte chunk, the
//! single rarest length, so the accumulated corpora keep essentially all of
//! their meaning.

/// Length prefix that introduces an extended-Lc header instead of 255 bytes.
const EXT_ESCAPE: u8 = 0xFF;
/// Bytes the escape consumes before the body: `cla ins p1 p2 hi lo`.
const EXT_HDR: usize = 6;

/// One framed command.
pub enum Frame<'a> {
    /// Length prefix 0. The targets that hold a selection re-SELECT on it; the
    /// rest see the empty command they saw before, which `Apdu::parse` rejects.
    Select,
    /// A chunk of the input, byte for byte — the pre-escape meaning.
    Raw(&'a [u8]),
    /// A synthesised case-3 extended-Lc APDU. Owned, because its header is
    /// built rather than borrowed.
    Ext(Vec<u8>),
}

impl Frame<'_> {
    /// The raw command bytes to hand to `Apdu::parse`.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Frame::Select => &[],
            Frame::Raw(b) => b,
            Frame::Ext(v) => v,
        }
    }
}

/// Split the next command off the front of `data`, returning it and the rest.
/// `None` only when `data` is empty.
pub fn next_frame(data: &[u8]) -> Option<(Frame<'_>, &[u8])> {
    let (&n, tail) = data.split_first()?;
    if n == EXT_ESCAPE && tail.len() >= EXT_HDR {
        let (hdr, body) = tail.split_at(EXT_HDR);
        // Clamp to what is left and re-encode Lc from the clamped value: the
        // synthesised APDU must satisfy `Apdu::parse`'s exact-length gate by
        // construction, or the escape buys nothing.
        let nc = (((hdr[4] as usize) << 8) | hdr[5] as usize).min(body.len());
        let mut raw = Vec::with_capacity(7 + nc);
        raw.extend_from_slice(&hdr[..4]);
        raw.extend_from_slice(&[0x00, (nc >> 8) as u8, nc as u8]);
        raw.extend_from_slice(&body[..nc]);
        return Some((Frame::Ext(raw), &body[nc..]));
    }
    if n == 0 {
        return Some((Frame::Select, tail));
    }
    let n = (n as usize).min(tail.len());
    Some((Frame::Raw(&tail[..n]), &tail[n..]))
}
