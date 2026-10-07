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
use rsk_sdk::error::Result;
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
    try_seal_read(dev, fs, fid, out).ok().flatten()
}

/// [`seal_read`] with a storage fault kept distinct from an absent or invalid seal.
pub fn try_seal_read<S: Storage, const N: usize>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: KeyFid,
    out: &mut Secret<[u8; N]>,
) -> Result<Option<usize>> {
    let mut blob = Secret::<[u8; MAX_BLOB]>::zeroed();
    let r = fs
        .try_read_key(fid, blob.expose_mut())?
        .and_then(|n| open(dev, blob.expose().get(..n)?, out));
    blob.wipe();
    Ok(r)
}

/// [`seal_read`] past its read: unseal `blob`, bytes already read, into `out`, for a caller
/// that tries more than one arm over the SAME bytes — a second read is a second
/// chance for the flash to fail, and `None` cannot say which of the two it was.
pub fn open<const N: usize>(dev: &Device, blob: &[u8], out: &mut Secret<[u8; N]>) -> Option<usize> {
    let pt_len = blob.len().checked_sub(NONCE_LEN + TAG_LEN)?;
    if pt_len > MAX_PLAIN {
        return None;
    }
    let (nonce, rest) = blob.split_at_checked(NONCE_LEN)?;
    let (ct, stored_tag) = rest.split_at_checked(pt_len)?;
    let pt = out.expose_mut().get_mut(..pt_len)?;
    pt.copy_from_slice(ct);
    let mut iv = [0u8; NONCE_LEN];
    iv.copy_from_slice(nonce);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(stored_tag);
    let mut key = kenc(dev);
    let r = aes256gcm_decrypt(key.expose(), &iv, dev.serial_hash, pt, &tag);
    key.wipe();
    if r.is_err() {
        out.wipe();
        return None;
    }
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
