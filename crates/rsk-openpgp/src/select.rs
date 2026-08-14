// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! SELECT: the FCI returned on applet selection, the in-application SELECT, and
//! SELECT DATA.

use rsk_sdk::{Apdu, Sw};

use crate::consts::{CERT_OCCURRENCES, EF_CH_CERT, OPENPGP_AID};
use crate::files::{DoSource, source};
use crate::pin::Session;

/// Reported free memory in the SELECT FCI (`64 06 53 04 <heap>`) — a fixed
/// hint, not a live heap figure.
const HEAP_FREE: u32 = 0x0008_0000;

/// Build the SELECT-by-AID response FCI into `out`, returning its length:
/// `6F 20 | 62 16 (81 02 0000 · 82 01 01 · 83 02 0000 · 84 06 <AID> · 8A 01 05)
/// | 64 06 53 04 <heap32>` — the application DF (fid 0x0000, name = the full
/// 6-byte AID, working EF, transparent, activated).
pub fn build_fci(out: &mut [u8]) -> usize {
    const FCP_HEAD: [u8; 13] = [
        0x81, 0x02, 0x00, 0x00, // file size (DF → 0)
        0x82, 0x01, 0x01, // descriptor: working EF, transparent
        0x83, 0x02, 0x00, 0x00, // file id 0x0000
        0x84, 0x06, // DF name = AID (spliced in below)
    ];
    const FCP_TAIL: [u8; 3] = [0x8A, 0x01, 0x05]; // life-cycle: activated
    let fcp_len = FCP_HEAD.len() + OPENPGP_AID.len() + FCP_TAIL.len();
    let heap = HEAP_FREE.to_be_bytes();
    let body_len = 2 + fcp_len + 8; // 62-template + the 8-byte 64 DO
    let total = 2 + body_len;
    if out.len() < total {
        return 0;
    }
    let mut p = 0;
    out[p] = 0x6F;
    out[p + 1] = body_len as u8;
    p += 2;
    out[p] = 0x62;
    out[p + 1] = fcp_len as u8;
    p += 2;
    out[p..p + FCP_HEAD.len()].copy_from_slice(&FCP_HEAD);
    p += FCP_HEAD.len();
    out[p..p + OPENPGP_AID.len()].copy_from_slice(OPENPGP_AID);
    p += OPENPGP_AID.len();
    out[p..p + FCP_TAIL.len()].copy_from_slice(&FCP_TAIL);
    p += FCP_TAIL.len();
    out[p..p + 4].copy_from_slice(&[0x64, 0x06, 0x53, 0x04]);
    p += 4;
    out[p..p + 4].copy_from_slice(&heap);
    p += 4;
    p
}

/// In-application SELECT (the dispatcher already handles SELECT-by-AID before
/// this is reached). Returns `(len, sw)`; the FCI body is emitted only for
/// `P2 & 0xFC == 0x04`.
pub fn cmd_select(apdu: &Apdu, out: &mut [u8]) -> (usize, Sw) {
    let (p1, p2) = (apdu.p1, apdu.p2);
    let fid = if apdu.nc >= 2 {
        ((apdu.data[0] as u16) << 8) | apdu.data[1] as u16
    } else {
        0
    };
    let found = match p1 {
        0x00 if apdu.nc == 0 => true, // select MF / application root
        // Same rule GET DATA applies: an internal EF is not a file this command
        // has, so it answers what an absent fid answers. Anything else made a
        // second, unauthenticated way to locate the 28 storage FIDs the applet's
        // own tag space exposes. (The reference has no SELECT-by-fid at all —
        // `00 A4 P1<=03` is `6D00` there, over the whole 16-bit space.)
        0x00..=0x02 if apdu.nc == 2 => !matches!(source(fid), DoSource::None | DoSource::Internal),
        // Same rule the dispatcher applies (ISO 7816-4 truncated select): the
        // requested AID must be a PREFIX of ours. This arm is reachable — the
        // dispatcher only intercepts P2 `00`/`04`, so a `P2 = 05` SELECT lands
        // here — and it used to ask the opposite question, accepting
        // `AID ‖ anything` that the dispatcher had just started refusing. Two
        // paths, one rule.
        0x04 => !apdu.data.is_empty() && OPENPGP_AID.starts_with(apdu.data),
        _ => false,
    };
    if !found {
        return (0, Sw::REFERENCE_NOT_FOUND);
    }
    if p2 & 0xfc != 0x00 && p2 & 0xfc != 0x04 {
        return (0, Sw::INCORRECT_P1P2);
    }
    if p2 & 0xfc == 0x04 {
        let n = build_fci(out);
        return (n, Sw::OK);
    }
    (0, Sw::OK)
}

/// SELECT DATA (INS 0xA5): choose the occurrence (`P1` = 0/1/2) of a DO with
/// several instances — here only the cardholder certificate (7F21, occurrences
/// `EF_CH_1/2/3`); the choice is recorded in the session for GET / PUT DATA.
///
/// Command data is `60 <Lc> 5C <taglen> <tag>` with `P2 = 0x04`. Occurrence
/// selection is deliberately not PW3-gated: it is not itself a security
/// operation (the PUT DATA write stays PW3-gated), and it lets a non-admin
/// host read occurrences 1/2.
pub fn select_data(apdu: &Apdu, sess: &mut Session) -> Sw {
    if apdu.p2 != 0x04 {
        return Sw::INCORRECT_P1P2;
    }
    let d = apdu.data;
    // 60 <Lc> 5C <taglen> <tag…> — Lc counts everything after the length byte.
    if d.len() < 4 || d[0] != 0x60 || d.len() != d[1] as usize + 2 {
        return Sw::WRONG_LENGTH;
    }
    let taglen = d[3] as usize;
    if d[2] != 0x5C || taglen == 0 || taglen > 2 || d.len() < 4 + taglen {
        return Sw::WRONG_DATA;
    }
    let tag = if taglen == 2 {
        ((d[4] as u16) << 8) | d[5] as u16
    } else {
        d[4] as u16
    };
    // Only the cardholder certificate has occurrences; three of them (EF_CH_1/2/3).
    // The two failures are different bytes: an occurrence past the last one is P1
    // (a YubiKey 5.7.4 answers `6B00` to 3 and 4, measured 3/3, where 0-2 are
    // `9000`), while a tag with no occurrences at all is named in the data field.
    if tag != EF_CH_CERT {
        return Sw::REFERENCE_NOT_FOUND;
    }
    if apdu.p1 >= CERT_OCCURRENCES {
        return Sw::WRONG_P1P2;
    }
    sess.cert_occ = apdu.p1;
    Sw::OK
}

#[cfg(test)]
#[path = "select_tests.rs"]
mod tests;
