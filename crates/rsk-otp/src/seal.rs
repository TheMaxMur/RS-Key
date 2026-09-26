// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! At-rest sealing for Yubico OTP slot configs. A slot record carries the slot
//! secret in the clear — the AES-128 key (`OFF_AES_KEY`), the private UID
//! (`OFF_UID`), and, for an HMAC-SHA1 / OATH-HOTP slot, the challenge-response
//! secret assembled from those same bytes. The whole slot record (52-byte config
//! plus its use-counter tail) is AES-256-GCM-sealed before it reaches flash, key
//! = HKDF-SHA256(salt = serial_hash, ikm = kbase, info = "OTP/SLOT"), blob =
//! `nonce(12) ‖ ct ‖ tag(16)`, AAD = serial_hash. Device-sealed (no access code
//! in the key): the slot must type / answer without a separate at-rest unlock,
//! exactly like the OATH credential secrets ([`crate::seal`]'s sibling in
//! `rsk_oath`). With the OTP MKEK provisioned, `kbase` — and so this seal —
//! roots in the hardware fuse key.
//!
//! This closes the one applet whose secrets were still stored raw: FIDO / PIV /
//! OpenPGP / OATH all sealed theirs. [`crate::migrate_seal`] re-seals any
//! pre-existing plaintext slot at boot.

use rsk_crypto::{Device, aes256gcm_decrypt, aes256gcm_encrypt, hkdf_sha256};
use rsk_fs::{Fs, KeyFid, Rearmed, Sealed, Storage};
use rsk_sdk::error::Result;
use rsk_secret::Secret;

use crate::{CONFIG_SIZE, Rng, SLOT_SIZE, SlotRecord};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Largest sealed plaintext: a full slot record (config + counter tail).
const MAX_PLAIN: usize = SLOT_SIZE;
pub(crate) const MAX_BLOB: usize = NONCE_LEN + MAX_PLAIN + TAG_LEN;

// `crate::migrate_seal` takes a stored blob whose length is in
// `CONFIG_SIZE..=SLOT_SIZE` to be legacy plaintext and seals it in place. The
// shortest blob this module can produce must therefore be longer than the
// longest plaintext, or that boot pass would seal an already-sealed slot a
// second time — unrecoverably, since only the outer layer would ever unseal.
// Compile-time, not a Kani harness: it is arithmetic over four constants, and
// the build that ships is the one that has to hold it.
const _: () = assert!(NONCE_LEN + CONFIG_SIZE + TAG_LEN > SLOT_SIZE);

const INFO_OTP_SLOT: &[u8] = b"OTP/SLOT";

fn kenc(dev: &Device) -> Secret<[u8; 32]> {
    let mut kbase = dev.derive_kbase();
    let mut out = Secret::<[u8; 32]>::zeroed();
    hkdf_sha256(
        dev.serial_hash,
        kbase.expose(),
        INFO_OTP_SLOT,
        out.expose_mut(),
    )
    .expect("32-byte HKDF output is in range");
    kbase.wipe();
    out
}

/// Seal `rec` at its stored length and write it to `fid` as `nonce ‖ ct ‖ tag`.
/// `false` on a storage failure. A record is the only plaintext this takes, so
/// no writer chooses the tail's bytes ([`SlotRecord`] says who does).
pub fn seal_put<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    fid: KeyFid,
    rec: &SlotRecord,
) -> bool {
    seal_put_over(dev, fs, rng, fid, rec, None)
}

/// [`seal_put`] over a record another root sealed; see [`Fs::put_key_over`].
pub fn seal_put_over<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    fid: KeyFid,
    rec: &SlotRecord,
    rearmed: Option<&Rearmed>,
) -> bool {
    let plain = rec.stored();
    let mut blob = Secret::<[u8; MAX_BLOB]>::zeroed();
    let n = NONCE_LEN + plain.len() + TAG_LEN;
    rng.fill(&mut blob.expose_mut()[..NONCE_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob.expose()[..NONCE_LEN]);
    blob.expose_mut()[NONCE_LEN..NONCE_LEN + plain.len()].copy_from_slice(plain);
    let mut key = kenc(dev);
    let tag = aes256gcm_encrypt(
        key.expose(),
        &nonce,
        dev.serial_hash,
        &mut blob.expose_mut()[NONCE_LEN..NONCE_LEN + plain.len()],
    );
    key.wipe();
    blob.expose_mut()[NONCE_LEN + plain.len()..n].copy_from_slice(&tag);
    let ok = fs
        .put_key_over(fid, Sealed::wrap(&blob.expose()[..n]), rearmed)
        .is_ok();
    blob.wipe();
    ok
}

/// Read and unseal `fid` into `out`; returns the plaintext length, or `None` if
/// the slot is absent, malformed, or does not authenticate (e.g. legacy
/// plaintext — the caller treats that as "needs migration").
///
/// A read the medium REFUSED folds into that same `None`; [`try_seal_read`] is
/// the twin for the callers where it may not.
///
/// The plaintext is a slot's secrets, so it goes only into a buffer that wipes
/// itself; a bare array is refused at compile time:
///
/// ```compile_fail,E0308
/// # fn read<S: rsk_fs::Storage>(dev: &rsk_crypto::Device, fs: &mut rsk_fs::Fs<S>) {
/// let mut out = [0u8; 64];
/// rsk_otp::seal::seal_read(dev, fs, rsk_fs::KeyFid::new(0xC100), &mut out);
/// # }
/// ```
/// ```
/// # fn read<S: rsk_fs::Storage>(dev: &rsk_crypto::Device, fs: &mut rsk_fs::Fs<S>) {
/// let mut out = rsk_secret::Secret::<[u8; 64]>::zeroed();
/// rsk_otp::seal::seal_read(dev, fs, rsk_fs::KeyFid::new(0xC100), &mut out);
/// # }
/// ```
pub fn seal_read<S: Storage, const N: usize>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: KeyFid,
    out: &mut Secret<[u8; N]>,
) -> Option<usize> {
    try_seal_read(dev, fs, fid, out).ok().flatten()
}

/// [`seal_read`], fallible: `Err` is "the medium could not answer", `Ok(None)` a
/// slot that is genuinely absent, malformed, or unauthenticated. The fold the
/// plain one does is what lets a faulted read spell *unprogrammed* at a gate.
pub fn try_seal_read<S: Storage, const N: usize>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: KeyFid,
    out: &mut Secret<[u8; N]>,
) -> Result<Option<usize>> {
    let out = out.expose_mut();
    let mut blob = Secret::<[u8; MAX_BLOB]>::zeroed();
    let Some(n) = fs.try_read_key(fid, blob.expose_mut())? else {
        return Ok(None);
    };
    if !(NONCE_LEN + TAG_LEN..=MAX_BLOB).contains(&n) {
        blob.wipe();
        return Ok(None);
    }
    let pt_len = n - NONCE_LEN - TAG_LEN;
    if out.len() < pt_len {
        blob.wipe();
        return Ok(None);
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob.expose()[..NONCE_LEN]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&blob.expose()[n - TAG_LEN..n]);
    let mut key = kenc(dev);
    let r = aes256gcm_decrypt(
        key.expose(),
        &nonce,
        dev.serial_hash,
        &mut blob.expose_mut()[NONCE_LEN..NONCE_LEN + pt_len],
        &tag,
    );
    key.wipe();
    if r.is_err() {
        blob.wipe();
        return Ok(None);
    }
    out[..pt_len].copy_from_slice(&blob.expose()[NONCE_LEN..NONCE_LEN + pt_len]);
    blob.wipe();
    Ok(Some(pt_len))
}

#[cfg(test)]
#[path = "seal_tests.rs"]
mod tests;
