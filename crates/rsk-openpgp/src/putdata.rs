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

/// Write `data` to the DO addressed by `fid` (empty `data` deletes it). ACL:
/// private DOs 1/3 need PW2 or PW3; everything else needs PW3.
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
        _ => return Sw::REFERENCE_NOT_FOUND,
    };

    let priv13 = fid == EF_PRIV_DO_1 || fid == EF_PRIV_DO_3;
    let authorized = if priv13 {
        sess.has_pw2 || sess.has_pw3
    } else {
        sess.has_pw3
    };
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

/// PUT DATA PW status (`0xC4` → `EF_PW_PRIV`): update the leading status bytes
/// (the "PW1 valid for multiple signatures" flag + max-length bytes) in place,
/// preserving the retry counters. Requires PW3.
pub fn put_pw_status<S: Storage>(fs: &mut Fs<S>, sess: &Session, data: &[u8]) -> Sw {
    if !sess.has_pw3 {
        return Sw::SECURITY_STATUS_NOT_SATISFIED;
    }
    let mut pw = [0u8; 7];
    let n = match fs.read(EF_PW_PRIV, &mut pw) {
        Some(n) => n.min(pw.len()),
        None => return Sw::REFERENCE_NOT_FOUND,
    };
    // Only the leading bytes (flag + 3 max-length bytes) are writable via PUT
    // DATA; the retry counters that follow (indices PW1_RETRY_IDX..) are
    // read-only. Capping at the first counter stops a long field from zeroing
    // them and blocking every PIN across a power cycle.
    let m = data.len().min(n).min(PW1_RETRY_IDX);
    pw[..m].copy_from_slice(&data[..m]);
    if fs.put(EF_PW_PRIV, &pw[..n]).is_err() {
        return Sw::MEMORY_FAILURE;
    }
    Sw::OK
}

#[cfg(test)]
#[path = "putdata_tests.rs"]
mod tests;
