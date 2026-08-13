// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! PUT DATA (INS 0xDA): write the working DOs, with the algorithm-attribute
//! redirect (C1/C2/C3 → EF_ALGO_PRIV1/2/3). The reset code (0xD3) and PW-status
//! (0xC4) are routed by the dispatch to their own handlers (they touch the DEK
//! / status file, not the generic DO store).

use rsk_fs::{Fs, Storage};
use rsk_sdk::Sw;

use crate::consts::*;
use crate::files::{DoSource, source};
use crate::pin::Session;

/// The length OpenPGP 3.4 §4.4.1 fixes for `fid`, where it fixes one.
///
/// `C5`/`C6`/`CD` republish these DOs as fixed-width slices, so a value of any
/// other length reads back as two different things: itself standalone, and a
/// truncation (or a zero-pad) inside the aggregate. Refusing the write is the
/// only answer that keeps one DO one value — and it is what a YubiKey does, at
/// every length, leaving the DO untouched.
fn fixed_do_len(fid: u16) -> Option<usize> {
    match fid {
        EF_FP_SIG | EF_FP_DEC | EF_FP_AUT | EF_FP_CA1 | EF_FP_CA2 | EF_FP_CA3 => Some(FP_LEN),
        EF_TS_SIG | EF_TS_DEC | EF_TS_AUT => Some(TS_LEN),
        _ => None,
    }
}

/// The maximum §4.4.1 gives `fid`, where it gives one — a cap, not a fixed width,
/// so an empty write still deletes the DO.
///
/// Measured on a YubiKey 5.7.4, 3/3: 39 bytes of name and 8 of language
/// preference are `9000`, one byte more is `6A80`, and so are 254 and 255 — the
/// DO untouched every time. Ours took any length, and the cardholder reader that
/// feeds the trusted display carries an 8-byte language field, so a longer one
/// was already being shown cut.
fn max_do_len(fid: u16) -> Option<usize> {
    match fid {
        EF_CH_NAME => Some(NAME_MAX),
        EF_LANG_PREF => Some(LANG_MAX),
        EF_SEX => Some(1),
        _ => None,
    }
}

/// Write `data` to the DO addressed by `fid` (empty `data` deletes it, unless
/// the DO has a fixed length). ACL: private DOs 1/3 are the cardholder's and need
/// PW2 — §4.4.1 gives the admin no override on them, and a YubiKey 5.7.4 refuses
/// PW3 on both, 3/3 — everything else needs PW3.
pub fn put_data<S: Storage>(fs: &mut Fs<S>, sess: &Session, fid: u16, data: &[u8]) -> Sw {
    let target = match fid {
        // Routed away by the dispatch (put_reset_code / put_pw_status); rejected
        // here so a direct call cannot write them as raw DOs.
        EF_RESET_CODE | EF_PW_STATUS => return Sw::CONDITIONS_NOT_SATISFIED,
        // OpenPGP 3.4, "Access conditions for Data Objects": the DS-Counter is
        // WRITE = *Never*, reset only internally by generating or importing a new
        // signature key. It is the card's only evidence that the key was used while
        // its owner was away, so the admin PIN — the credential the evidence exists
        // to hold to account — must not roll it back. Deleting it was also a
        // post-crypto DoS: `inc_sig_count` runs *after* PSO:CDS has signed, so every
        // signature burned the private-key op and then returned 6A88 until reboot.
        EF_SIG_COUNT => return Sw::CONDITIONS_NOT_SATISFIED,
        // Algorithm attributes write to the private storage read back by `dobj`.
        EF_ALGO_SIG | EF_ALGO_DEC | EF_ALGO_AUT => algo_tag_to_priv(fid),
        f if matches!(source(f), DoSource::Flash) => f,
        // PUT DATA carries its target in P1P2, so a tag this command cannot write
        // is a wrong P1P2 and not a missing object: a YubiKey 5.7.4 answers `6B00`
        // to `C5`, `C6`, `CD`, `7A` and to a tag it does not know at all (measured,
        // 3/3). The computed aggregates are the ones a host actually reaches for —
        // they are read from `6E`/`73` and only look writable.
        _ => return Sw::WRONG_P1P2,
    };

    let priv13 = fid == EF_PRIV_DO_1 || fid == EF_PRIV_DO_3;
    let authorized = if priv13 { sess.has_pw2 } else { sess.has_pw3 };
    if !authorized {
        return Sw::SECURITY_STATUS_NOT_SATISFIED;
    }

    // Only the algorithms DO 0xFA advertises. Unvalidated, `nbits` came straight off
    // the wire into `RsaKeygen`, which took any 32-byte multiple — so PW3 could set
    // rsa512 and the key the *owner* generated afterwards was factorable, while
    // GET DATA C1 reported whatever was written. An empty value clears back to the
    // rsa2k default (`dobj::emit_algoinfo`).
    if matches!(fid, EF_ALGO_SIG | EF_ALGO_DEC | EF_ALGO_AUT)
        && !data.is_empty()
        && !crate::dobj::advertised_algo(fid, data)
    {
        return WRONG_DATA;
    }

    // Including the empty write, which would otherwise delete the DO: a YubiKey
    // refuses length 0 here too, and there is no way to express "no fingerprint"
    // in C5 anyway — an absent one already reads as zeroes.
    if fixed_do_len(fid).is_some_and(|want| data.len() != want) {
        return WRONG_DATA;
    }
    if max_do_len(fid).is_some_and(|max| data.len() > max) {
        return WRONG_DATA;
    }
    // §4.4.3.4 enumerates the sex DO's values rather than bounding them, so this
    // is a content gate, and the list is the card's rather than ISO 5218's: a
    // YubiKey answers `6A80` to `'A'` and to `'0'`, a code the standard defines.
    if fid == EF_SEX && !data.is_empty() && !SEX_VALUES.contains(&data[0]) {
        return WRONG_DATA;
    }

    // OpenPGP 3.4 §4.4.3.6 and the D6/D7/D8 DO table: UIF value 02 is "permanently
    // enabled … not changeable with PUT DATA", clearable only by a factory reset
    // (TERMINATE DF re-seeds UIF_DEFAULT). It is the one touch setting that is meant
    // to survive an admin-PIN compromise, so the generic writer must not lower it.
    if matches!(fid, EF_UIF_SIG | EF_UIF_DEC | EF_UIF_AUT) {
        let mut cur = [0u8; 2];
        if let Some(n) = fs.read(target, &mut cur)
            && n >= 1
            && cur[0] == UIF_PERMANENT
            && data.first() != Some(&UIF_PERMANENT)
        {
            return Sw::CONDITIONS_NOT_SATISFIED;
        }
        // Reject undefined flag values and a wrong general-feature-management byte
        // rather than storing something the card would echo back as meaningful.
        if !data.is_empty() && (data.len() != 2 || data[0] > UIF_PERMANENT) {
            return WRONG_DATA;
        }
    }

    if data.is_empty() {
        let _ = fs.delete(target);
    } else if fs.put(target, data).is_err() {
        return Sw::MEMORY_FAILURE;
    }
    Sw::OK
}

/// PUT DATA PW status (`0xC4` → `EF_PW_PRIV`): set the "PW1 valid for several
/// PSO:CDS" flag, the DO's only writable byte. Requires PW3.
pub fn put_pw_status<S: Storage>(fs: &mut Fs<S>, sess: &Session, data: &[u8]) -> Sw {
    if !sess.has_pw3 {
        return Sw::SECURITY_STATUS_NOT_SATISFIED;
    }
    // §4.4.2 on the max-length bytes: "should not be changed". A card that lets
    // them move publishes a claim about itself it does not enforce — C4 could be
    // made to announce max 6 while VERIFY went on comparing a 40-byte password.
    // A YubiKey 5.7.4 takes a ONE-byte write of 00 or 01 and refuses every other
    // length and value with 6A80, leaving the DO alone; the flag is the whole
    // writable surface.
    if data.len() != 1 || data[0] > 1 {
        return WRONG_DATA;
    }
    let mut pw = [0u8; 7];
    let n = match fs.read(EF_PW_PRIV, &mut pw) {
        Some(n) => n.min(pw.len()),
        None => return Sw::REFERENCE_NOT_FOUND,
    };
    pw[0] = data[0];
    if fs.put(EF_PW_PRIV, &pw[..n]).is_err() {
        return Sw::MEMORY_FAILURE;
    }
    Sw::OK
}

#[cfg(test)]
#[path = "putdata_tests.rs"]
mod tests;
