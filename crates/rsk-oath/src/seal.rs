// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! At-rest sealing for OATH credential secrets. Each credential's TLV blob — it
//! carries the shared HMAC seed (`TAG_KEY`), the actual TOTP/HOTP secret — is
//! AES-256-GCM-sealed before it reaches flash, key = HKDF-SHA256(salt =
//! serial_hash, ikm = kbase, info = "OATH/KEYS"), blob = `nonce(12) ‖ ct ‖
//! tag(16)`, AAD = serial_hash. Device-sealed (no OATH PIN in the key): the
//! credentials must compute without a separate at-rest unlock, exactly like the
//! PIV slot keys ([`rsk_piv`]). With the OTP MKEK provisioned, `kbase` — and so
//! this seal — roots in the hardware fuse key.
//!
//! This closes the one applet that stored its secrets in the clear: FIDO / PIV /
//! OpenPGP all sealed, OATH did not. [`crate::migrate_seal`] re-seals any
//! pre-existing plaintext credential at boot.

use rsk_crypto::{Device, aes256gcm_decrypt, aes256gcm_encrypt, hkdf_sha256};
use rsk_fs::{Fs, KeyFid, Sealed, Storage};
use zeroize::Zeroize;

use crate::{CRED_MAX, Rng};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Largest sealed plaintext: a full credential blob.
const MAX_PLAIN: usize = CRED_MAX;
pub(crate) const MAX_BLOB: usize = NONCE_LEN + MAX_PLAIN + TAG_LEN;

const INFO_OATH_KEYS: &[u8] = b"OATH/KEYS";

fn kenc(dev: &Device) -> [u8; 32] {
    let mut kbase = dev.derive_kbase();
    let mut out = [0u8; 32];
    hkdf_sha256(dev.serial_hash, &kbase, INFO_OATH_KEYS, &mut out)
        .expect("32-byte HKDF output is in range");
    kbase.zeroize();
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
    if plain.len() > MAX_PLAIN {
        return false;
    }
    let mut blob = [0u8; MAX_BLOB];
    let n = NONCE_LEN + plain.len() + TAG_LEN;
    rng.fill(&mut blob[..NONCE_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob[..NONCE_LEN]);
    blob[NONCE_LEN..NONCE_LEN + plain.len()].copy_from_slice(plain);
    let mut key = kenc(dev);
    let tag = aes256gcm_encrypt(
        &key,
        &nonce,
        dev.serial_hash,
        &mut blob[NONCE_LEN..NONCE_LEN + plain.len()],
    );
    key.zeroize();
    blob[NONCE_LEN + plain.len()..n].copy_from_slice(&tag);
    let ok = fs.put_key(fid, Sealed::wrap(&blob[..n])).is_ok();
    blob.zeroize();
    ok
}

/// Read and unseal `fid` into `out`; returns the plaintext length, or `None` if
/// the slot is absent, malformed, or does not authenticate (e.g. legacy
/// plaintext — the caller treats that as "needs migration").
pub fn seal_read<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: KeyFid,
    out: &mut [u8],
) -> Option<usize> {
    let mut blob = [0u8; MAX_BLOB];
    let n = fs.read_key(fid, &mut blob)?;
    if !(NONCE_LEN + TAG_LEN..=MAX_BLOB).contains(&n) {
        blob.zeroize();
        return None;
    }
    let pt_len = n - NONCE_LEN - TAG_LEN;
    if out.len() < pt_len {
        blob.zeroize();
        return None;
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob[..NONCE_LEN]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&blob[n - TAG_LEN..n]);
    let mut key = kenc(dev);
    let r = aes256gcm_decrypt(
        &key,
        &nonce,
        dev.serial_hash,
        &mut blob[NONCE_LEN..NONCE_LEN + pt_len],
        &tag,
    );
    key.zeroize();
    if r.is_err() {
        blob.zeroize();
        return None;
    }
    out[..pt_len].copy_from_slice(&blob[NONCE_LEN..NONCE_LEN + pt_len]);
    blob.zeroize();
    Some(pt_len)
}
