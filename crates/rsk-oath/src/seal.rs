// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! At-rest sealing for OATH credential secrets. Each credential's TLV blob — it
//! carries the shared HMAC seed (`TAG_KEY`), the actual TOTP/HOTP secret — is
//! AES-256-GCM-sealed before it reaches flash, key = HKDF-SHA256(salt =
//! serial_hash, ikm = kbase, info = "OATH/KEYS"), blob = `nonce(12) ‖ ct ‖
//! tag(16)`, AAD = serial_hash. Device-sealed (no OATH PIN in the key): the
//! credentials must compute without a separate at-rest unlock, exactly like the
//! PIV slot keys (`rsk_piv`). With the OTP MKEK provisioned, `kbase` — and so
//! this seal — roots in the hardware fuse key.
//!
//! This closes the one applet that stored its secrets in the clear: FIDO / PIV /
//! OpenPGP all sealed, OATH did not. [`crate::migrate_seal`] re-seals any
//! pre-existing plaintext credential at boot.

use rsk_crypto::{Device, aes256gcm_decrypt, aes256gcm_encrypt, hkdf_sha256};
use rsk_fs::{Fs, KeyFid, Rearmed, Sealed, Storage};
use rsk_secret::Secret;

use crate::{CRED_MAX, Rng};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Largest sealed plaintext: a full credential blob.
const MAX_PLAIN: usize = CRED_MAX;
pub(crate) const MAX_BLOB: usize = NONCE_LEN + MAX_PLAIN + TAG_LEN;

const INFO_OATH_KEYS: &[u8] = b"OATH/KEYS";

fn kenc(dev: &Device) -> Secret<[u8; 32]> {
    let mut kbase = dev.derive_kbase();
    let mut out = Secret::<[u8; 32]>::zeroed();
    #[expect(
        clippy::expect_used,
        reason = "HKDF-SHA256 refuses only an output past 255 × 32 bytes, and this one is 32"
    )]
    hkdf_sha256(
        dev.serial_hash,
        kbase.expose(),
        INFO_OATH_KEYS,
        out.expose_mut(),
    )
    .expect("32-byte HKDF output is in range");
    kbase.wipe();
    out
}

/// Seal `plain` and write it to `fid` as `nonce ‖ ct ‖ tag`. `false` on an
/// over-length plaintext or a storage failure.
pub fn seal_put<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    fid: KeyFid,
    plain: &[u8],
) -> bool {
    seal_put_over(dev, fs, rng, fid, plain, None)
}

/// [`seal_put`] over a record another root sealed; see [`Fs::put_key_over`].
pub fn seal_put_over<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    fid: KeyFid,
    plain: &[u8],
    rearmed: Option<&Rearmed>,
) -> bool {
    if plain.len() > MAX_PLAIN {
        return false;
    }
    let mut blob = Secret::<[u8; MAX_BLOB]>::zeroed();
    let n = NONCE_LEN + plain.len() + TAG_LEN;
    rng.fill(&mut blob.expose_mut()[..NONCE_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob.expose()[..NONCE_LEN]);
    // `plain` is at most `MAX_PLAIN` (tested above), so its seal fits the blob.
    let Some((ct, tag_out)) = blob
        .expose_mut()
        .get_mut(NONCE_LEN..n)
        .map(|body| body.split_at_mut(plain.len()))
    else {
        return false;
    };
    ct.copy_from_slice(plain);
    let mut key = kenc(dev);
    let tag = aes256gcm_encrypt(key.expose(), &nonce, dev.serial_hash, ct);
    key.wipe();
    tag_out.copy_from_slice(&tag);
    let ok = blob
        .expose()
        .get(..n)
        .is_some_and(|sealed| fs.put_key_over(fid, Sealed::wrap(sealed), rearmed).is_ok());
    blob.wipe();
    ok
}

/// Read and unseal `fid` into `out`; returns the plaintext length, or `None` if
/// the slot is absent, malformed, or does not authenticate (e.g. legacy
/// plaintext — the caller treats that as "needs migration"). The plaintext is a
/// credential's secret, so it goes only into a buffer that wipes itself.
pub fn seal_read<S: Storage, const N: usize>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: KeyFid,
    out: &mut Secret<[u8; N]>,
) -> Option<usize> {
    let out = out.expose_mut();
    let mut blob = Secret::<[u8; MAX_BLOB]>::zeroed();
    let n = fs.read_key(fid, blob.expose_mut())?;
    if !(NONCE_LEN + TAG_LEN..=MAX_BLOB).contains(&n) {
        blob.wipe();
        return None;
    }
    let pt_len = n - NONCE_LEN - TAG_LEN;
    if out.len() < pt_len {
        blob.wipe();
        return None;
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob.expose()[..NONCE_LEN]);
    let (Some((ct, stored_tag)), Some(pt)) = (
        blob.expose_mut()
            .get_mut(NONCE_LEN..n)
            .map(|body| body.split_at_mut(pt_len)),
        out.get_mut(..pt_len),
    ) else {
        blob.wipe();
        return None;
    };
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(stored_tag);
    let mut key = kenc(dev);
    let r = aes256gcm_decrypt(key.expose(), &nonce, dev.serial_hash, ct, &tag);
    key.wipe();
    if r.is_err() {
        blob.wipe();
        return None;
    }
    pt.copy_from_slice(ct);
    blob.wipe();
    Some(pt_len)
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    reason = "a test's fixture is its own bound, and a panic is its failure report"
)]
#[path = "seal_tests.rs"]
mod tests;
