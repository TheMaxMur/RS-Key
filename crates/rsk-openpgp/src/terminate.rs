// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! TERMINATE DF (0xE6): factory-reset the OpenPGP applet. The `Fs` is shared
//! with the FIDO applet, so only OpenPGP-owned files are deleted (a terminate
//! must not wipe FIDO state, and vice versa) before re-seeding via [`scan_files`].

use rsk_crypto::Device;
use rsk_fs::{Fs, Storage};
use rsk_sdk::{Apdu, Sw};

use crate::Rng;
use crate::consts::*;
use crate::init::scan_files;
use crate::pin::verifier_unusable;

/// Whether `fid` is an OpenPGP-owned flash file. The OpenPGP data-object tag space
/// (`0x00xx`/`0x01xx`/`0x5fxx`/`0x7fxx`) contains no FIDO files, so those are tested
/// as ranges; the internal EFs sit in the `0x10xx`/`0x1fxx` region that *interleaves*
/// with FIDO (FIDO `EF_PIN` 0x1080 falls between OpenPGP PW1 0x1081 and FIDO 0x1090),
/// so those are an explicit set — never a range. Verified disjoint from `is_fido_fid`.
pub fn is_openpgp_fid(fid: u16) -> bool {
    // Private-key + PW-DEK slots are `KeyFid`s (sealed secrets), so they can't be
    // `u16` match patterns — compare their raw FIDs explicitly.
    if fid == EF_PK_SIG.get()
        || fid == EF_PK_DEC.get()
        || fid == EF_PK_AUT.get()
        || fid == EF_DEK_PW1.get()
        || fid == EF_DEK_RC.get()
        || fid == EF_DEK_PW3.get()
    {
        return true;
    }
    (0x0001..0x0200).contains(&fid)
        || (0x5f00..0x6000).contains(&fid)
        || (0x7f00..0x8000).contains(&fid)
        || matches!(
            fid,
            EF_PW1
                | EF_RC
                | EF_PW3
                | EF_ALGO_PRIV1
                | EF_ALGO_PRIV2
                | EF_ALGO_PRIV3
                | EF_PW_PRIV
                | EF_PW_RETRIES
                | EF_PB_SIG
                | EF_PB_DEC
                | EF_PB_AUT
                | EF_DEK
                | EF_DEK_PWPIV
                | EF_CH_1
                | EF_CH_2
                | EF_CH_3
        )
}

/// Factory-reset the OpenPGP applet. Permitted only when the admin PIN (PW3) is
/// verified or already blocked (its retry counter has reached 0).
pub fn terminate_df<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    has_pw3: bool,
    apdu: &Apdu,
) -> Sw {
    if apdu.p1 != 0x00 || apdu.p2 != 0x00 {
        return Sw::INCORRECT_P1P2;
    }
    let mut pw = [0u8; 7];
    let n = match fs.read(EF_PW_PRIV, &mut pw) {
        Some(n) => n,
        None => return Sw::REFERENCE_NOT_FOUND,
    };
    // The live PW3 retry counter (`pin_wrong_retry` decrements it). A verifier that
    // can never be verified can never be decremented to blocked either, so count it
    // as blocked — else a card carrying one has no way back at all.
    if !has_pw3 && !verifier_unusable(fs, EF_PW3) && n > PW3_RETRY_IDX && pw[PW3_RETRY_IDX] > 0 {
        return Sw::SECURITY_STATUS_NOT_SATISFIED;
    }
    if apdu.nc != 0 {
        return Sw::WRONG_LENGTH;
    }
    wipe_openpgp(fs);
    if scan_files(dev, fs, rng).is_err() {
        return Sw::MEMORY_FAILURE;
    }
    Sw::OK
}

/// Delete every live OpenPGP file. Batched because `for_each_key` cannot delete
/// mid-iteration; each round deletes ≥1 key, so it converges (mirrors the FIDO reset).
fn wipe_openpgp<S: Storage>(fs: &mut Fs<S>) {
    loop {
        let mut keys = [0u16; 64];
        let mut k = 0usize;
        fs.for_each_key(&mut |fid| {
            if is_openpgp_fid(fid) && k < keys.len() {
                keys[k] = fid;
                k += 1;
            }
        });
        if k == 0 {
            break;
        }
        for &fid in &keys[..k] {
            let _ = fs.delete(fid);
        }
    }
}

#[cfg(test)]
#[path = "terminate_tests.rs"]
mod tests;
