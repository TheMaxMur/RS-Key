// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `authenticatorReset`: wipe all FIDO flash state and the in-RAM PIN/UV
//! session, then regenerate the device seed / counter / attestation cert. A
//! physical touch gates the wipe, inside the CTAP 2.1 §6.6 power-up window
//! ([`RESET_WINDOW_MS`]) on a build whose presence backend shows no prompt.

use rsk_fs::Storage;

use crate::consts::{
    EF_ALWAYS_UV, EF_ATT_CHAIN, EF_ATT_KEY, EF_BACKUP_SEALED, EF_COUNTER, EF_CRED, EF_CRED_BLOB,
    EF_CRED_CTR, EF_DEVICE_PIN, EF_EA_ENABLED, EF_EE_DEV, EF_KEY_DEV, EF_KEY_DEV_ENC, EF_LARGEBLOB,
    EF_MINPINLEN, EF_PAUTHTOKEN, EF_PIN, EF_RP, EF_RPNICK, MAX_RESIDENT_CREDENTIALS,
    RESET_WINDOW_MS,
};
use crate::error::{CtapError, CtapResult};
use crate::journal;
use crate::seed::ensure_seed;
use crate::{Ctx, Rng};

/// Progress backstop for one [`sweep`] phase: the FIDO predicate spans four
/// 256-slot ranges and 13 fixed records, so a converging sweep cannot exceed this.
const RESET_MAX_DELETES: u32 = 4 * MAX_RESIDENT_CREDENTIALS as u32 + 13;

/// `authenticatorReset`: factory-reset the FIDO applet. Replies with only the
/// status byte. Also the documented recovery from a soft lock with a lost lock
/// key: `EF_KEY_DEV_ENC` leads the wipe with the seed it wraps and a fresh seed is
/// generated (the old identity is gone — that is the design).
/// Refines `RSKeySecurityState!ResetNeverWeakensSurvivingState` — SEC-FIDO-006.
pub fn reset<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> CtapResult {
    if !ctx.presence.shows_confirm() && !in_reset_window(ctx) {
        return Err(CtapError::NotAllowed);
    }
    // A factory reset requires a physical touch, and §6.6 distinguishes the ways it
    // can fail: an explicit refusal is OPERATION_DENIED ("the platform SHOULD NOT
    // repeat"), a silent timeout is USER_ACTION_TIMEOUT ("the platform MAY repeat").
    match ctx
        .presence
        .request(crate::Confirm::titled("Erase everything?"))
    {
        crate::Presence::Confirmed => {}
        crate::Presence::Declined => return Err(CtapError::OperationDenied),
        crate::Presence::Timeout => return Err(CtapError::UserActionTimeout),
        crate::Presence::Cancelled => return Err(CtapError::KeepAliveCancel),
    }
    // Drop every FIDO file, then regenerate the seed. The flash `Fs` is shared
    // with the OpenPGP applet, so delete only live, FIDO-owned keys
    // ([`is_fido_fid`]) — a blind 0..256 EF_CRED/EF_RP sweep would write a
    // tombstone per absent slot, filling the partition and slowing the flash GC.
    //
    // Two phases for the sweeps, for the reason `rsk_piv::files::wipe_piv` and
    // `wipe_oath` state: `for_each_key` yields in flash-ring order, not FID order,
    // so one combined sweep can reach `EF_PIN` before the credentials — and a power
    // cut there leaves the owner's passkeys live with the PIN and `alwaysUv` gone,
    // i.e. assertable on a touch alone. Secrets first, gates last.
    //
    // The live session goes before any of it: `Ctx::load_keydev` prefers
    // `state.keydev_dec`, so a sweep that fails after the flash seed is gone would
    // otherwise leave the rest of the power cycle running on a seed nothing stores.
    ctx.state.reset();
    // And the seed leads the flash, in its own write ahead of the batch: ring order
    // otherwise reaches `EF_RP` before `EF_CRED`, and what a cut leaves behind must
    // at least be undecryptable. `EF_KEY_DEV_ENC` is the soft lock's copy of it.
    for fid in FIDO_SEED_FIDS {
        ctx.fs.force_delete(fid).map_err(|_| CtapError::Other)?;
    }
    sweep(ctx, |fid| is_fido_fid(fid) && !is_fido_gate_fid(fid))?;
    sweep(ctx, is_fido_gate_fid)?;
    ensure_seed(&ctx.dev, ctx.fs, ctx.rng).map_err(|_| CtapError::Other)?;
    // Privacy: fold the journal window into the epoch (per-event details are
    // scrubbed, aggregate history stays attested), then record the reset.
    journal::fold_and_scrub(ctx);
    journal::append(ctx, journal::EV_RESET, 0, &[]);
    Ok(0)
}

/// One phase of the reset sweep: delete every live FIDO-owned fid matching `pred`,
/// reporting success only when the enumeration provably completed over an empty
/// range. Batched because `for_each_key` cannot delete mid-iteration, and de-duped
/// because the flash walk can yield multiple stored versions of one fid.
/// Refines `RSKeySecurityState!ResetNeverWeakensSurvivingState` — SEC-FIDO-006.
fn sweep<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, pred: fn(u16) -> bool) -> Result<(), CtapError> {
    let mut deleted = 0u32;
    loop {
        let mut keys = [0u16; 64];
        let mut n = 0usize;
        let complete = ctx.fs.for_each_key(&mut |fid| {
            if pred(fid) && n < keys.len() && !keys[..n].contains(&fid) {
                keys[n] = fid;
                n += 1;
            }
        });
        if n == 0 {
            // An un-yielded FID is only evidence of absence when the walk finished;
            // a truncated one must fail rather than report the range clear.
            return if complete {
                Ok(())
            } else {
                Err(CtapError::Other)
            };
        }
        deleted += n as u32;
        if deleted > RESET_MAX_DELETES {
            return Err(CtapError::Other);
        }
        for &fid in &keys[..n] {
            // force_delete (unconditional), not delete: a false-absent key would be
            // skipped yet re-yielded by for_each_key every pass — an infinite loop.
            // Propagate a backend error rather than retry it, so the wipe progresses.
            ctx.fs.force_delete(fid).map_err(|_| CtapError::Other)?;
        }
    }
}

/// The two flash shapes of the device seed: the plain record, and the soft lock's
/// wrapped copy. Every credential box, rpId box, credBlob, hmac-secret key and
/// large-blob key is derived from it, so deleting it FIRST is what makes whatever a
/// torn wipe leaves behind undecryptable.
pub const FIDO_SEED_FIDS: [u16; 2] = [EF_KEY_DEV.get(), EF_KEY_DEV_ENC.get()];

/// [`FIDO_SEED_FIDS`] as a predicate. Public because the device-wide
/// `Fs::factory_wipe` bypasses [`reset`] and needs the same rule — it is the only
/// other path that can leave a live credential over a live seed.
pub fn is_fido_seed_fid(fid: u16) -> bool {
    FIDO_SEED_FIDS.contains(&fid)
}

/// The FIDO records that *gate* the applet rather than being the secret itself.
/// Deleted last by [`reset`], so no prefix of the wipe can leave live passkeys
/// with their PIN and `alwaysUv` requirement already removed. Public because the
/// device-wide `Fs::factory_wipe` bypasses this function and needs the same rule.
///
/// `EF_BACKUP_SEALED` is a gate of the same shape as OATH's access code: it is
/// never re-provisioned, its *absence* is the permissive state, and what it gates
/// is the master seed itself — the one-time `BACKUP_EXPORT` window and, on a
/// display build, the on-device recovery-phrase reveal. It sat in the same phase as
/// `EF_KEY_DEV`, so a torn wipe could take the marker first and re-open a window the
/// owner had closed over a seed that was still live (audit run-36 class sweep).
///
/// `EF_PAUTHTOKEN` is deliberately **not** here, though it was until it produced
/// the same class of tear from the other side: the `pcmr` grant is a permission, so
/// its absence is the RESTRICTIVE state, and deferring it alongside `EF_PIN` meant a
/// cut between the two left a live grant with no PIN behind it. It goes with the
/// secrets, where a prefix can only ever revoke it early.
/// Refines `RSKeySecurityState!NoAccessibleSecretWithoutGate` — SEC-FIDO-004.
pub fn is_fido_gate_fid(fid: u16) -> bool {
    matches!(
        fid,
        EF_PIN | EF_DEVICE_PIN | EF_ALWAYS_UV | EF_MINPINLEN | EF_BACKUP_SEALED
    )
}

/// CTAP 2.1 §6.6: a reset is honored only within [`RESET_WINDOW_MS`] of power-up,
/// so wiping a key takes a deliberate replug. A warm boot *closes* the window
/// rather than opening one — `sys_reset` is host-requestable ungated, so a window
/// the host can restart at will is no window at all.
fn in_reset_window<S: Storage, R: Rng>(ctx: &Ctx<S, R>) -> bool {
    !ctx.state.warm_boot && ctx.now_ms <= RESET_WINDOW_MS
}

/// Whether `fid` is cleared by `authenticatorReset` — every FIDO-owned flash file plus
/// the trusted-display device PIN. Never the OpenPGP applet's files (0x1081-0x10de /
/// 0x00xx / 0x5fxx / 0x1f2x — and note 0x10a0 inside that span is OATH's `EF_OTP_PIN`,
/// not OpenPGP's, so the band is not contiguously one applet's) or the vendor counter
/// (0xCC01). FIDO and OpenPGP interleave
/// in the 0x10xx range (FIDO `EF_PIN` 0x1080 vs OpenPGP PW1 0x1081), so this is an
/// explicit set plus the resident-credential ranges, not a range test.
fn is_fido_fid(fid: u16) -> bool {
    // EF_KEY_DEV / EF_KEY_DEV_ENC / EF_PAUTHTOKEN are `KeyFid`s (sealed slots), so
    // they can't sit in the `u16` match arm — compare their raw FIDs explicitly.
    fid == EF_KEY_DEV.get()
        || fid == EF_KEY_DEV_ENC.get()
        || fid == EF_PAUTHTOKEN.get()
        || matches!(
            fid,
            EF_BACKUP_SEALED
                | EF_EE_DEV
                | EF_COUNTER
                | EF_CRED_CTR
                | EF_PIN
                | EF_MINPINLEN
                | EF_LARGEBLOB
                | EF_EA_ENABLED
                | EF_ALWAYS_UV
                // The trusted-display device PIN: a host reset clears it too, so a
                // forgotten device PIN is recoverable (the lock gates on-device Settings,
                // so on-device factory reset can't be reached when locked).
                | EF_DEVICE_PIN
        )
        || (EF_CRED..EF_CRED + MAX_RESIDENT_CREDENTIALS).contains(&fid)
        || (EF_RP..EF_RP + MAX_RESIDENT_CREDENTIALS).contains(&fid)
        || (EF_RPNICK..EF_RPNICK + MAX_RESIDENT_CREDENTIALS).contains(&fid)
        // Swept in EVERY build, not just `largeblob-ext`: a key that once ran that
        // firmware must still be wipeable by the one it is flashed with next.
        || (EF_CRED_BLOB..EF_CRED_BLOB + MAX_RESIDENT_CREDENTIALS).contains(&fid)
}

/// Whether `fid` survives an on-device **factory reset** (the trusted-display
/// "erase everything" flow, which wipes FIDO *and* the other applets — wider than
/// `authenticatorReset`). Only the org-provisioned batch attestation is kept: it
/// is device identity, not user data, and `authenticatorReset` preserves it too.
/// The fused OTP / secure-boot state is untouched by a flash wipe regardless. The
/// display passes this predicate to [`rsk_fs::Fs::factory_wipe`].
/// Refines `RSKeySecurityState!ResetNeverWeakensSurvivingState` — SEC-FIDO-006.
pub fn survives_factory_reset(fid: u16) -> bool {
    fid == EF_ATT_KEY.get() || fid == EF_ATT_CHAIN
}

#[cfg(test)]
#[path = "reset_tests.rs"]
mod tests;
