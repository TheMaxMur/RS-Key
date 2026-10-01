// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! SET PIN RETRIES (INS `F2`), Yubico's, what `ykman openpgp access set-retries`
//! sends: under PW3, how many tries PW1, the resetting code and PW3 each get, as a
//! YubiKey 5.8.0 answers it. The maxima are `EF_PW_RETRIES`, the record every path
//! that gives a PIN its tries back already reads.

// Host bytes: a panic here is a board that answers nothing until unplugged.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use rsk_fs::{Fs, Storage};
use rsk_sdk::Sw;

use crate::consts::*;
use crate::pin::Session;

/// The references F2's three bytes name, in their order.
const REFS: [u16; 3] = [EF_PW1, EF_RC, EF_PW3];

/// SET PIN RETRIES. Each byte of `data` is one reference's: 1..=255 makes it that
/// reference's maximum and its tries left, a blocked PIN unblocked with its value
/// kept; 0 leaves both. With no resetting code set, the code's maximum is kept and
/// its counter stays 0 until PUT DATA D3 starts it there. P1 and P2 are not judged.
/// Refines `RSKeyRetryLattice!CountWithinMaximum` — SEC-LAT-004 (fault-free histories).
pub fn set_pin_retries<S: Storage>(fs: &mut Fs<S>, sess: &Session, data: &[u8]) -> Sw {
    if !sess.has_pw3 {
        return Sw::SECURITY_STATUS_NOT_SATISFIED;
    }
    let Ok(wanted) = <[u8; 3]>::try_from(data) else {
        return Sw::WRONG_DATA;
    };
    // Read, not collapsed: a record the medium would not serve is not written over.
    let mut max = [0u8; 8];
    let mut left = [0u8; 8];
    let read = (
        fs.try_read(EF_PW_RETRIES, &mut max),
        fs.try_read(EF_PW_PRIV, &mut left),
        fs.try_has_data(EF_RC),
    );
    let (max_len, left_len, rc_set) = match read {
        (Ok(Some(m)), Ok(Some(l)), Ok(rc)) => (m.min(max.len()), l.min(left.len()), rc),
        (Err(_), _, _) | (_, Err(_), _) | (_, _, Err(_)) => return Sw::MEMORY_FAILURE,
        _ => return Sw::REFERENCE_NOT_FOUND,
    };
    let (Some(max), Some(left)) = (max.get_mut(..max_len), left.get_mut(..left_len)) else {
        return Sw::MEMORY_FAILURE;
    };
    for (fid, want) in REFS.into_iter().zip(wanted) {
        if want == 0 {
            continue;
        }
        let (Some(m), Some(l)) = (
            max.get_mut(usize::from(fid & 0xf)),
            left.get_mut(pw_retry_idx(fid)),
        ) else {
            return Sw::MEMORY_FAILURE;
        };
        *m = want;
        // A resetting code nobody set has no tries to give until PUT DATA D3 sets one.
        if fid != EF_RC || rc_set {
            *l = want;
        }
    }
    if wanted == [0; 3] {
        return Sw::OK;
    }
    // The counters before the maxima: a cut between leaves a lowered PIN its new tries
    // under the old maximum, never its old tries under the new one.
    if fs.put(EF_PW_PRIV, left).is_err() || fs.put(EF_PW_RETRIES, max).is_err() {
        return Sw::MEMORY_FAILURE;
    }
    Sw::OK
}
