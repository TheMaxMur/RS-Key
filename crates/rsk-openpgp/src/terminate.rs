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
        || fid == EF_DEK_STAGE_PW1.get()
        || fid == EF_DEK_STAGE_RC.get()
        || fid == EF_DEK_STAGE_PW3.get()
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
    // A sweep that could not prove it cleared the range must not report success — the
    // host would file the card as factory-reset over surviving private-key records.
    if let Err(sw) = wipe_openpgp(fs) {
        return sw;
    }
    if scan_files(dev, fs, rng).is_err() {
        return Sw::MEMORY_FAILURE;
    }
    Sw::OK
}

/// The records that *gate* the applet: the three PW verifiers, the retry/status
/// records they share, and the three UIF (touch) flags. Exists for the device-wide
/// `Fs::factory_wipe`, which must remove every applet's gate records only after
/// everything else is provably gone. It lives here rather than open-coded in the
/// firmware so the applet that owns the knowledge owns the list (audit run-36: the
/// list nobody could name from outside its crate was the one that got forgotten).
///
/// `wipe_openpgp` itself is deliberately single-phase, and that stays justified
/// for the *verifiers*: unlike PIV's, OpenPGP's private keys are sealed under a
/// PIN-derived DEK, so a re-seeded default PW1 opens nothing that survived the same
/// tear. It is **not** justified for the UIF flags, which [`scan_files`] re-seeds
/// to touch-OFF and which gate a key the surviving DEK can still open — so those
/// are deferred here too, and the applet-local sweep inherits the same set.
pub fn is_openpgp_gate_fid(fid: u16) -> bool {
    matches!(
        fid,
        EF_PW1 | EF_RC | EF_PW3 | EF_PW_PRIV | EF_PW_RETRIES | EF_UIF_SIG | EF_UIF_DEC | EF_UIF_AUT
    )
}

/// Largest number of deletions a single TERMINATE sweep may perform before it is
/// treated as non-converging. The applet's whole fid range is far smaller; this only
/// bounds a pathological store (mirrors PIV's `RESET_MAX_DELETES`).
const WIPE_MAX_DELETES: u32 = 512;

/// Delete every live OpenPGP file. Batched because `for_each_key` cannot delete
/// mid-iteration; each round deletes ≥1 key, so it converges (mirrors the FIDO and
/// PIV resets — including their two hardening rules, which this sweep predates:
/// `force_delete` rather than `delete`, and an incomplete enumeration must fail
/// rather than read as "the range is clear").
fn wipe_openpgp<S: Storage>(fs: &mut Fs<S>) -> Result<(), Sw> {
    // Two phases, the rule the three sibling sweeps carry: `for_each_key` yields in
    // flash-ring order, not FID order, so one combined sweep can reach a gate record
    // before the secrets it protects. The PW verifiers do not need it — the DEK chain
    // makes a restored default PW1 useless — but the UIF flags do: `scan_files`
    // re-seeds them to touch-OFF over a private key a surviving DEK can still open.
    let mut deleted = 0u32;
    for gates in [false, true] {
        loop {
            let mut keys = [0u16; 64];
            let mut k = 0usize;
            let complete = fs.for_each_key(&mut |fid| {
                if is_openpgp_fid(fid)
                    && is_openpgp_gate_fid(fid) == gates
                    && k < keys.len()
                    && !keys[..k].contains(&fid)
                {
                    keys[k] = fid;
                    k += 1;
                }
            });
            if k == 0 {
                // A truncated walk (flash read fault) can hide a live fid, so an empty
                // batch only proves the range is clear when the enumeration completed —
                // otherwise TERMINATE would answer 9000 over surviving key material.
                if !complete {
                    return Err(Sw::MEMORY_FAILURE);
                }
                break;
            }
            // Progress, not pass count: each pass deletes `k` distinct fids.
            deleted += k as u32;
            if deleted > WIPE_MAX_DELETES {
                return Err(Sw::MEMORY_FAILURE);
            }
            for &fid in &keys[..k] {
                // force_delete: `delete` skips a false-absent file that `for_each_key`
                // keeps yielding, so the sweep would spin instead of converging.
                fs.force_delete(fid).map_err(|_| Sw::MEMORY_FAILURE)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "terminate_tests.rs"]
mod tests;
