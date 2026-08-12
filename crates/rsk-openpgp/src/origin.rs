// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Per-slot key origin, the status byte of DO `0xDE` (OpenPGP 3.4 §4.4.3.8):
//! `01` = generated on card, `02` = imported. Kept in one internal EF
//! (`EF_KEY_ORIGIN`), one byte per key slot, so it survives a power cycle the way
//! a YubiKey's does.
//!
//! **`02` is the safe value and therefore the default.** §4.4.3.8's first
//! sentence gives the DO its purpose — telling a host whether a key could have
//! been backed up — so claiming `01` without proof of on-card generation is the
//! one direction that misleads. A card provisioned before this record existed, a
//! short or missing record, and every torn write therefore read as imported.
//! That also settles the write ordering: GENERATE marks *after* the key is
//! committed and IMPORT marks *before*, so a power cut in either leaves `02`.

use rsk_fs::{Fs, KeyFid, Storage};
use rsk_sdk::Sw;

use crate::consts::*;

/// Generated on card (§4.4.3.8 status `01`).
pub const ORIGIN_GENERATED: u8 = 0x01;
/// Imported (§4.4.3.8 status `02`) — also what an unrecorded slot reports.
pub const ORIGIN_IMPORTED: u8 = 0x02;

/// The slot's index in `EF_KEY_ORIGIN`, mirroring DO `0xDE`'s key-reference
/// order (SIG, DEC, AUT).
fn slot_idx(pk: KeyFid) -> usize {
    if pk == EF_PK_SIG {
        0
    } else if pk == EF_PK_DEC {
        1
    } else {
        2
    }
}

/// The origin to report for the key in slot `pk`.
pub fn of<S: Storage>(fs: &mut Fs<S>, pk: KeyFid) -> u8 {
    let mut rec = [0u8; KEY_SLOTS];
    let idx = slot_idx(pk);
    match fs.read(EF_KEY_ORIGIN, &mut rec) {
        Some(n) if idx < n.min(rec.len()) && rec[idx] == ORIGIN_GENERATED => ORIGIN_GENERATED,
        _ => ORIGIN_IMPORTED,
    }
}

/// Record `origin` for slot `pk`, leaving the other slots as they were.
///
/// The error is the caller's to weigh, and the two callers weigh it opposite
/// ways: an IMPORT whose mark did not persist must not go on to store the key —
/// the slot would keep an older `01` over an imported one, the single claim the
/// DO exists to make — while a GENERATE marks after the key is already committed
/// and a failure there only under-claims.
pub fn mark<S: Storage>(fs: &mut Fs<S>, pk: KeyFid, origin: u8) -> Result<(), Sw> {
    let mut rec = [0u8; KEY_SLOTS];
    // A short record from an older build leaves the slots it did not cover at 0,
    // which `of` already reads as imported.
    let _ = fs.read(EF_KEY_ORIGIN, &mut rec);
    rec[slot_idx(pk)] = origin;
    fs.put(EF_KEY_ORIGIN, &rec).map_err(|_| Sw::MEMORY_FAILURE)
}

#[cfg(test)]
#[path = "origin_tests.rs"]
mod tests;
