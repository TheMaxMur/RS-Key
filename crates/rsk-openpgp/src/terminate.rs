// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! TERMINATE DF (0xE6): factory-reset the OpenPGP applet. The `Fs` is shared
//! with the FIDO applet, so only OpenPGP-owned files are deleted (a terminate
//! must not wipe FIDO state, and vice versa) before re-seeding via [`scan_files`].

use rsk_crypto::Device;
use rsk_fs::{Fs, RearmAttempted, Storage};
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
        || fid == EF_PK_ATT.get()
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
                | EF_PB_ATT
                | EF_KEY_ORIGIN
                | EF_DEK
                | EF_DEK_PWPIV
                | EF_CH_1
                | EF_CH_2
                | EF_CH_3
        )
}

/// Factory-reset the OpenPGP applet and leave it terminated, answering `6285` until
/// ACTIVATE FILE. Permitted only when the admin PIN (PW3) is verified or already
/// blocked (its retry counter has reached 0).
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
    // The live PW3 retry counter (`spend_pin_retry` charges it). A verifier that
    // can never be verified can never be decremented to blocked either, so count it
    // as blocked — else a card carrying one has no way back at all.
    if !has_pw3 && !verifier_unusable(fs, EF_PW3) && n > PW3_RETRY_IDX && pw[PW3_RETRY_IDX] > 0 {
        return Sw::SECURITY_STATUS_NOT_SATISFIED;
    }
    if apdu.nc != 0 {
        return Sw::WRONG_LENGTH;
    }
    // The marker lands first: from it on the applet is terminated whatever the wipe
    // answers, and ACTIVATE FILE runs the wipe again before it removes the marker. A
    // marker that did not land wipes nothing, and the card is as it was.
    if fs.put(EF_TERMINATED, &[TERMINATED_MARK]).is_err() {
        return Sw::MEMORY_FAILURE;
    }
    wipe_and_reseed(dev, fs, rng)
}

/// The records every wipe removes LAST: the three PW verifiers, the retry/status
/// records they share, the four UIF (touch) flags, and the working DOs
/// [`scan_files`] re-seeds. Exists for the device-wide `Fs::factory_wipe`, which
/// must remove them only after everything else is provably gone; the applet-local
/// sweep inherits the same set. It lives here rather than open-coded in the
/// firmware so the applet that owns the knowledge owns the list (audit run-36: the
/// list nobody could name from outside its crate was the one that got forgotten).
///
/// The PW verifiers are uniformity: unlike PIV's, OpenPGP's private keys are sealed
/// under a PIN-derived DEK, so a re-seeded default PW1 opens nothing that survived
/// the same tear. Every other member is load-bearing for one reason — the re-seed
/// runs whatever the wipe answered, so a record taken in phase 1 comes back as a
/// FACTORY DEFAULT beside a key still on the card: touch-OFF for a UIF flag, a
/// rolled-back signature counter, factory cardholder data, and for `EF_KDF` a
/// lockout, since PW1/PW3 are verified over the KDF *output* and a card advertising
/// KDF-none makes `gpg` send the raw passphrase until both counters are spent.
pub fn is_openpgp_gate_fid(fid: u16) -> bool {
    matches!(
        fid,
        EF_PW1
            | EF_RC
            | EF_PW3
            | EF_PW_PRIV
            | EF_PW_RETRIES
            | EF_UIF_SIG
            | EF_UIF_DEC
            | EF_UIF_AUT
            | EF_UIF_ATT
            | EF_KDF
            | EF_SIG_COUNT
            | EF_SEX
            // Not the applet's own sweep's (`is_openpgp_fid` leaves it out): it stands
            // over that wipe. The device-wide wipe takes it last, so a cut there leaves
            // OpenPGP terminated rather than half-wiped.
            | EF_TERMINATED
    )
}

/// Largest number of deletions a single TERMINATE sweep may perform before it is
/// treated as non-converging. The applet's whole fid range is far smaller; this only
/// bounds a pathological store (mirrors PIV's `RESET_MAX_DELETES`).
const WIPE_MAX_DELETES: u32 = 512;

/// Fids one [`wipe_openpgp`] pass collects before deleting them. Named because the
/// wrap to a second pass is a code path, and the test that crosses it has to size
/// its fixture off this rather than off a copy of the number.
const SWEEP_BATCH: usize = 64;

/// Delete every live OpenPGP file, with the at-rest lap re-armed around the sweep.
fn wipe_openpgp<S: Storage>(fs: &mut Fs<S>) -> Result<(), Sw> {
    // A tombstone appends like a re-seal, and PW1 / PW3 / RC migrate only on their
    // own verify — so this can supersede a chip-serial-rooted verifier and owes the
    // at-rest lap (rsk-fs `EF_HARDENED`) a re-arm, ahead of the sweeps.
    //
    // The failure does NOT stop the write, unlike the gated sites: "leave the
    // record in force" means, on a wipe, leave the secrets live.
    let attempted = rsk_fs::attempt_rescrub(fs);
    let swept = sweep(fs, &attempted);
    // Retry, BETWEEN the sweep and its `?` rather than after its last one: a refused
    // head leaves the marker latched over every tombstone [`sweep`] appended, and a
    // sweep that faults on the way is exactly when that is true and unrecoverable.
    //
    // A single-shot refusal is the only kind either call recovers from, and where
    // the head landed this costs no append at all — `Fs::delete` skips a backend it
    // already marked absent.
    let _retried = rsk_fs::attempt_rescrub(fs);
    swept
}

/// The delete half of [`wipe_openpgp`]. Batched because `for_each_key` cannot delete
/// mid-iteration; each round deletes ≥1 key, so it converges (mirrors the FIDO and
/// PIV resets — including their two hardening rules, which this sweep predates:
/// `force_delete` rather than `delete`, and an incomplete enumeration must fail
/// rather than read as "the range is clear").
///
/// Its own function so the at-rest re-arm can stand between it and its caller's
/// answer: every early return in here is one a re-arm written BELOW them would be
/// skipped by, which is the case that re-arm exists for.
fn sweep<S: Storage>(fs: &mut Fs<S>, _attempted: &RearmAttempted) -> Result<(), Sw> {
    // Two phases, the rule the three sibling sweeps carry: `for_each_key` yields in
    // flash-ring order, not FID order, so one combined sweep can reach a deferred
    // record before the secrets it sits beside. The PW verifiers do not need it —
    // the DEK chain makes a restored default PW1 useless — but everything
    // `scan_files` re-seeds does, over a key a surviving DEK can still open.
    let mut deleted = 0u32;
    // A metadata record that could not be PROVEN dropped is carried to the end
    // rather than stopped on, for the reason `Fs::force_delete_halves` states:
    // EF_META is one blob shared by every applet, so a fault reading it would end
    // the wipe after a single file — at the same fid on every retry.
    let mut orphaned = false;
    for gates in [false, true] {
        loop {
            let mut keys = [0u16; SWEEP_BATCH];
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
                let gone = fs.force_delete_halves(fid);
                gone.value.map_err(|_| Sw::MEMORY_FAILURE)?;
                orphaned |= gone.record.is_err();
            }
        }
    }
    if orphaned {
        return Err(Sw::MEMORY_FAILURE);
    }
    Ok(())
}

/// What `EF_TERMINATED` holds. Its presence is the state; the byte is room for a format.
const TERMINATED_MARK: u8 = 0x01;

/// The wipe and the factory state after it, for TERMINATE DF and ACTIVATE FILE alike.
fn wipe_and_reseed<S: Storage>(dev: &Device, fs: &mut Fs<S>, rng: &mut dyn Rng) -> Sw {
    // A sweep that could not prove it cleared the range must not report success — the
    // host would file the card as factory-reset over surviving private-key records.
    let wiped = wipe_openpgp(fs);
    // Re-seed even when the sweep failed, the rule `rsk_piv::files::reset_files`
    // states: without EF_PW_PRIV the applet answers 6A88 once active again, until a
    // reboot runs `scan_files`. Safe because every record it re-seeds is swept LAST.
    let ensured = scan_files(dev, fs, rng).map_err(|_| Sw::MEMORY_FAILURE);
    match wiped.and(ensured) {
        Ok(()) => Sw::OK,
        Err(sw) => sw,
    }
}

/// Where TERMINATE DF has left the applet, read off `EF_TERMINATED` for every command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lifecycle {
    /// No marker: every command is served.
    Active,
    /// The marker stands: every command but ACTIVATE FILE answers `6285`.
    Terminated,
    /// The marker would not read: every command answers `6581`, ACTIVATE FILE too.
    Unread,
}

impl Lifecycle {
    /// What a command other than ACTIVATE FILE answers here; `None` where it is served.
    pub fn refusal(self) -> Option<Sw> {
        match self {
            Self::Active => None,
            Self::Terminated => Some(Sw::TERMINATED),
            Self::Unread => Some(Sw::MEMORY_FAILURE),
        }
    }
}

/// Read `EF_TERMINATED`. An unreadable marker is neither answer: taken for active the
/// card would serve what TERMINATE was wiping, for terminated ACTIVATE would wipe it.
pub fn lifecycle<S: Storage>(fs: &mut Fs<S>) -> Lifecycle {
    match fs.try_has_data(EF_TERMINATED) {
        Ok(false) => Lifecycle::Active,
        Ok(true) => Lifecycle::Terminated,
        Err(_) => Lifecycle::Unread,
    }
}

/// ACTIVATE FILE over a terminated applet: the wipe and the factory state again, then
/// the marker, last, so a cut anywhere leaves it terminated for the next ACTIVATE.
pub fn activate<S: Storage>(dev: &Device, fs: &mut Fs<S>, rng: &mut dyn Rng) -> Sw {
    let sw = wipe_and_reseed(dev, fs, rng);
    if !sw.is_ok() {
        return sw;
    }
    // `force_delete`: a present-cache false absence must not leave the marker on flash
    // to terminate the card again at the next boot, over what was set up since.
    match fs.force_delete(EF_TERMINATED) {
        Ok(()) => Sw::OK,
        Err(_) => Sw::MEMORY_FAILURE,
    }
}

#[cfg(test)]
#[path = "terminate_tests.rs"]
mod tests;
