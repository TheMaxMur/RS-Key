// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Read-only enumeration of resident (discoverable) credentials for the
//! trusted-display Passkeys view. It walks the same `EF_RP` / `EF_CRED` records as
//! the CTAP `authenticatorCredentialManagement` path but yields decrypted Rust
//! values for the on-device UI instead of a CBOR response, and never mutates flash.
//! The device seed is loaded from `EF_KEY_DEV`, used, and zeroized within each call,
//! so the display task never has to hold it.
//!
//! It deliberately does not reuse `credmgmt`'s `enumerate_rps` / `enumerate_creds`:
//! those are stateful (the begin/next cursor lives in `FidoState`), permission-gated
//! and FIDO-conformance-tested. A separate additive walk leaves that path untouched.

use zeroize::Zeroize;

use rsk_crypto::Device;
use rsk_fs::{Fs, Storage};

use crate::consts::{EF_CRED, EF_RP, EF_RPNICK, MAX_RESIDENT_CREDENTIALS};
use crate::credential::{
    CRED_REC_MAX, NICK_BOX_MAX, RECORD_PREFIX, RP_PREFIX, RP_REC_MAX, cred_record_box,
    credential_load, seal_nick, slot_map, unseal_nick, unseal_rp_id,
};

/// The trivial-PIN predicate the `strong-pin` / `fips-profile` builds enforce, re-exported
/// so the display PIN pad rejects a guessable PIN at entry (the host path already does).
#[cfg(any(feature = "strong-pin", feature = "fips-profile"))]
pub use crate::clientpin::pin_is_trivial;
/// The device-local PIN seam for a display-initiated action, re-exported here so the
/// trusted display reaches the whole on-device Passkeys/PIN seam — read walks,
/// [`delete_cred`], the PIN check ([`spend_and_verify_local_pin`]) and the on-device set/change
/// ([`store_local_pin`]) — through one module. Defined next to the canonical
/// `spend_and_verify_pin_hash` in `clientpin`. [`min_pin_length`] is the floor the set
/// flow shows on the pad and enforces.
pub use crate::clientpin::{
    LocalPin, MAX_PIN_LENGTH, SetPinError, device_pin_is_set, device_pin_retries_left,
    min_pin_length, pin_is_set, pin_retries_left, spend_and_verify_device_pin,
    spend_and_verify_local_pin, store_device_pin, store_local_pin,
};
/// The compile-time PIN-length floor (CTAP default 4, or the `fips-profile` minimum) that
/// [`store_device_pin`] enforces — the trusted-display device-PIN pad must use it as its
/// floor so a set the user types can actually be stored.
pub use crate::consts::MIN_PIN_LENGTH;
/// The on-device nickname length cap, re-exported here so the display sizes its rename
/// buffer from the same constant the store enforces.
pub use crate::consts::RP_NICK_MAX_LEN;
/// Seed-backup status for the trusted-display Backup screen — the same bits the host
/// reads over `BACKUP_STATE`, exposed `Ctx`-free for the display task, plus the on-device
/// seal action and the seed read the recovery-phrase reveal needs.
pub use crate::seed::load_keydev;
pub use crate::vendor::{BackupStatus, backup_sealed, backup_status, mark_backup_sealed};

/// A resident relying party as shown on-device.
pub struct RpView<'a> {
    /// Decrypted rpId domain (e.g. `"github.com"`), borrowed from internal scratch —
    /// copy it (sanitized) before the visitor returns.
    pub rp_id: &'a str,
    /// The rpIdHash — the stable key the per-RP credential walk takes.
    pub rp_id_hash: [u8; 32],
    /// How many resident credentials this RP holds.
    pub count: u8,
    /// The device-local display nickname ([`set_rp_nickname`]), if one is set —
    /// borrowed from internal scratch like `rp_id`. `None` falls back to the rpId.
    pub nickname: Option<&'a str>,
}

/// One resident credential's account identity, for the per-RP detail screen.
pub struct AccountView<'a> {
    /// `user.name` (e.g. `"alex@example.com"`), or empty if the RP stored none.
    pub user_name: &'a str,
    /// `user.displayName`, or empty.
    pub user_display_name: &'a str,
    /// `user.id` — the binary handle, a last-resort label when no name was stored.
    pub user_id: &'a [u8],
    /// credProtect level (0..=3); ≥2 marks a UV-gated credential.
    pub cred_protect: u64,
    /// The `EF_CRED` slot fid this credential occupies — the key
    /// [`delete_cred`] takes to remove it from the on-device Passkeys view.
    pub ef_cred_fid: u16,
}

/// Visit each resident RP (those with ≥1 credential), decrypting its rpId domain,
/// in slot order. The seed is loaded from `EF_KEY_DEV`, used, and zeroized before
/// returning; with no seed (unprovisioned) or no resident RPs the visitor is never
/// called. Returns the true total of RPs visited — even if the visitor keeps only
/// the first few (so a screen can show "N items" while listing a subset). Records
/// whose domain fails to unseal are skipped.
/// Refines `RSKeySecurityState!NoUnmanageableCredential` — SEC-FIDO-005.
pub fn for_each_rp<S, F>(dev: &Device, fs: &mut Fs<S>, mut f: F) -> usize
where
    S: Storage,
    F: FnMut(RpView<'_>),
{
    let Some(mut seed) = crate::seed::load_keydev(dev, fs) else {
        return 0;
    };
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(fs, EF_RP, &mut occupied);
    // Which slots carry a nickname, mapped in one pass so absent nickname slots are
    // never `fs.read`-probed (each such probe would rescan the whole partition).
    let mut nick_present = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(fs, EF_RPNICK, &mut nick_present);
    let mut buf = [0u8; RP_REC_MAX];
    let mut plain = [0u8; RP_REC_MAX];
    let mut nick_buf = [0u8; NICK_BOX_MAX];
    let mut nick_plain = [0u8; RP_NICK_MAX_LEN];
    let mut total = 0usize;
    for i in 0..MAX_RESIDENT_CREDENTIALS {
        if !occupied[i as usize] {
            continue;
        }
        let Some(n) = fs.read(EF_RP + i, &mut buf) else {
            continue;
        };
        let n = n.min(buf.len());
        if n < RP_PREFIX || buf[0] == 0 {
            continue;
        }
        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(&buf[1..RP_PREFIX]);
        let Some((rp_id, _)) = unseal_rp_id(&seed, &rp_id_hash, &buf[RP_PREFIX..n], &mut plain)
        else {
            continue;
        };
        // A nickname lives in the parallel EF_RPNICK slot; it opens only under this
        // rpIdHash (the AEAD's AAD), so a stale slot-reuse leftover reads as `None`.
        let nickname = if nick_present[i as usize] {
            fs.read(EF_RPNICK + i, &mut nick_buf).and_then(|m| {
                unseal_nick(
                    &seed,
                    &rp_id_hash,
                    &nick_buf[..m.min(NICK_BOX_MAX)],
                    &mut nick_plain,
                )
            })
        } else {
            None
        };
        total += 1;
        f(RpView {
            rp_id,
            rp_id_hash,
            count: buf[0],
            nickname,
        });
    }
    seed.zeroize();
    plain.zeroize(); // held the cleartext rp domains
    nick_plain.zeroize(); // held the cleartext nicknames
    total
}

/// Set (or clear) the device-local display nickname for a resident RP. An empty `nick`
/// deletes any existing nickname (the RP reverts to showing its rpId); a non-empty one
/// (≤ [`RP_NICK_MAX_LEN`] bytes) is sealed at rest under the device seed and stored in
/// the EF_RPNICK slot parallel to the RP's EF_RP record. Returns whether the change was
/// persisted; `false` if the RP has no resident credentials (nothing to name), the
/// nickname is too long, or the seed is unavailable. The credential box — and so the
/// signing key — is never touched, so the passkey keeps working across a rename.
pub fn set_rp_nickname<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rp_id_hash: &[u8; 32],
    nick: &str,
) -> bool {
    if nick.len() > RP_NICK_MAX_LEN {
        return false;
    }
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(fs, EF_RP, &mut occupied);
    let mut rp = [0u8; RP_REC_MAX];
    let mut slot: Option<u16> = None;
    for i in 0..MAX_RESIDENT_CREDENTIALS {
        if !occupied[i as usize] {
            continue;
        }
        if let Some(m) = fs.read(EF_RP + i, &mut rp)
            && m.min(rp.len()) >= RP_PREFIX
            && rp[1..RP_PREFIX] == *rp_id_hash
        {
            slot = Some(i);
            break;
        }
    }
    let Some(slot) = slot else {
        return false; // no such resident RP
    };
    if nick.is_empty() {
        let _ = fs.delete(EF_RPNICK + slot); // absent is fine — the RP ends up unnamed
        return true;
    }
    let Some(mut seed) = crate::seed::load_keydev(dev, fs) else {
        return false;
    };
    let mut rec = [0u8; NICK_BOX_MAX];
    let ok = match seal_nick(&seed, rp_id_hash, nick, &mut rec) {
        Ok(len) => fs.put(EF_RPNICK + slot, &rec[..len]).is_ok(),
        Err(_) => false,
    };
    seed.zeroize();
    ok
}

/// Visit each resident credential under `rp_id_hash` (slot order), decrypting its
/// account identity. Seed loaded + zeroized internally. Returns the true total
/// visited; credentials whose box fails to open are skipped.
pub fn for_each_cred<S, F>(dev: &Device, fs: &mut Fs<S>, rp_id_hash: &[u8; 32], mut f: F) -> usize
where
    S: Storage,
    F: FnMut(AccountView<'_>),
{
    let Some(mut seed) = crate::seed::load_keydev(dev, fs) else {
        return 0;
    };
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(fs, EF_CRED, &mut occupied);
    let mut buf = [0u8; CRED_REC_MAX];
    let mut scratch = [0u8; CRED_REC_MAX];
    let mut total = 0usize;
    for i in 0..MAX_RESIDENT_CREDENTIALS {
        if !occupied[i as usize] {
            continue;
        }
        let Some(n) = fs.read(EF_CRED + i, &mut buf) else {
            continue;
        };
        let n = n.min(buf.len());
        if n < RECORD_PREFIX || buf[..32] != *rp_id_hash {
            continue;
        }
        let Some(cred) =
            credential_load(&seed, cred_record_box(&buf[..n]), rp_id_hash, &mut scratch)
        else {
            continue;
        };
        total += 1;
        f(AccountView {
            user_name: cred.user_name,
            user_display_name: cred.user_display_name,
            user_id: cred.user_id,
            cred_protect: cred.ext.cred_protect,
            ef_cred_fid: EF_CRED + i,
        });
    }
    seed.zeroize();
    scratch.zeroize(); // held the decrypted account names
    total
}

/// Delete the resident credential stored at `ef_cred_fid` (an `EF_CRED` slot fid,
/// as surfaced by [`AccountView::ef_cred_fid`]), then decrement — or remove — its
/// `EF_RP` record. The rpIdHash is the cleartext record prefix, so unlike the read
/// walks this needs no seed. Returns whether a credential was removed; an
/// out-of-range fid or an empty/short slot is a no-op returning `false`.
///
/// This is the on-device counterpart of CTAP `deleteCredential` (0x06): the same
/// flash effect, but keyed by slot (what the on-device walk holds) instead of by
/// the host's resident id. Cred-first then RP-decrement matches that path's order.
pub fn delete_cred<S: Storage>(fs: &mut Fs<S>, ef_cred_fid: u16) -> bool {
    if !(EF_CRED..EF_CRED + MAX_RESIDENT_CREDENTIALS).contains(&ef_cred_fid) {
        return false;
    }
    let mut buf = [0u8; CRED_REC_MAX];
    let Some(n) = fs.read(ef_cred_fid, &mut buf) else {
        return false;
    };
    if n.min(buf.len()) < RECORD_PREFIX {
        return false;
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&buf[..32]);
    if fs.delete(ef_cred_fid).is_err() {
        return false;
    }
    // Same as the CTAP `deleteCredential`: the credential's large blob goes with
    // it, keyed by the slot the fid encodes.
    crate::largeblobext::discard(fs, ef_cred_fid - EF_CRED);
    let _ = crate::credmgmt::decrement_rp(fs, &rp_id_hash);
    true
}

#[cfg(test)]
#[path = "passkeys_tests.rs"]
mod tests;
