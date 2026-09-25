// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! At-rest sealing for PIV key material: private keys are AES-256-GCM-sealed
//! with key = HKDF-SHA256(salt = serial_hash, ikm = kbase, info = "PIV/KEYS"),
//! blob = `nonce(12) ‖ ct ‖ tag(16)`, AAD = serial_hash. Deliberately NOT
//! PIN-bound (unlike the OpenPGP DEK): management-key-only flows (keygen,
//! import) must reach the keys without a PIN session. With the OTP MKEK
//! provisioned, `kbase` — and so this seal — roots in the hardware fuse key.

use rsk_crypto::{Device, aes256gcm_decrypt, aes256gcm_encrypt, hkdf_sha256};
use rsk_ec::{Curve, PrivKey};
use rsk_fs::{Fs, KeyFid, Sealed, Storage};
use rsk_rsa::{RsaKey, crt};
use rsk_sdk::Rng;
use rsk_sdk::Sw;
use rsk_secret::Secret;

pub use rsk_rsa::RsaCrt;

use crate::files::{
    SLOT_ATTESTATION, SLOT_AUTHENTICATION, SLOT_CARDAUTH, SLOT_RETIRED_FIRST, SLOT_RETIRED_LAST,
};
use crate::rsa_sw;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Largest sealed plaintext: RSA-4096 `P ‖ Q ‖ dP ‖ dQ ‖ qInv`, five 256-byte
/// fields (the CRT parameters cached alongside the primes so signing skips the
/// per-op key rebuild). Older `P ‖ Q` blobs (two fields) still load — the real
/// length rides in the record and [`crt::parse_rsa_blob`] tells them apart.
const MAX_PLAIN: usize = rsk_rsa::MAX_CRT_PLAIN;
/// Largest sealed-record length (`nonce ‖ ct ‖ tag`). Public so other PIV paths
/// that move a sealed blob verbatim (MOVE KEY) can size their buffer to it.
pub const MAX_BLOB: usize = NONCE_LEN + MAX_PLAIN + TAG_LEN;

const INFO_PIV_KEYS: &[u8] = b"PIV/KEYS";

fn kenc(dev: &Device) -> Secret<[u8; 32]> {
    let mut kbase = dev.derive_kbase();
    let mut out = Secret::<[u8; 32]>::zeroed();
    hkdf_sha256(
        dev.serial_hash,
        kbase.expose(),
        INFO_PIV_KEYS,
        out.expose_mut(),
    )
    .expect("32-byte HKDF output is in range");
    kbase.wipe();
    out
}

/// Seal `plain` and write it to `fid` as `nonce ‖ ct ‖ tag`.
pub fn seal_put<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    fid: KeyFid,
    plain: &[u8],
) -> Result<(), Sw> {
    if plain.len() > MAX_PLAIN {
        return Err(Sw::WRONG_LENGTH);
    }
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
    let r = fs
        .put_key(fid, Sealed::wrap(&blob.expose()[..n]))
        .map_err(|_| Sw::MEMORY_FAILURE);
    blob.wipe();
    r
}

/// Read and unseal `fid` into `out`; returns the plaintext length.
/// `REFERENCE_NOT_FOUND` when the file is missing or empty. The plaintext is a
/// key, so it goes only into a buffer that wipes itself.
pub fn seal_read<S: Storage, const N: usize>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: KeyFid,
    out: &mut Secret<[u8; N]>,
) -> Result<usize, Sw> {
    let out = out.expose_mut();
    let mut blob = Secret::<[u8; MAX_BLOB]>::zeroed();
    let n = fs
        .read_key(fid, blob.expose_mut())
        .ok_or(Sw::REFERENCE_NOT_FOUND)?;
    if !(NONCE_LEN + TAG_LEN..=MAX_BLOB).contains(&n) {
        return Err(Sw::MEMORY_FAILURE);
    }
    let pt_len = n - NONCE_LEN - TAG_LEN;
    if out.len() < pt_len {
        return Err(Sw::WRONG_LENGTH);
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
        return Err(Sw::MEMORY_FAILURE);
    }
    out[..pt_len].copy_from_slice(&blob.expose()[NONCE_LEN..NONCE_LEN + pt_len]);
    blob.wipe();
    Ok(pt_len)
}

/// Boot-pass migration: re-seal every sealed key slot under the OTP kbase.
/// GCM authenticates, so generations are told apart by trial decrypt: a blob
/// that opens under the current `dev` is already migrated; one that opens only
/// under the pre-OTP arm is re-sealed; one that opens under neither is left
/// untouched (corrupt — re-sealing garbage would only destroy evidence).
/// Idempotent and crash-safe per slot.
pub fn migrate_kbase<S: Storage>(dev: &Device, fs: &mut Fs<S>, rng: &mut dyn Rng) {
    if dev.otp_key.is_none() {
        return;
    }
    let old = dev.without_otp();
    // Retired (82–95), active (9A–9E incl. the 9B management key), attestation.
    let slots = (SLOT_RETIRED_FIRST..=SLOT_RETIRED_LAST)
        .chain(SLOT_AUTHENTICATION..=SLOT_CARDAUTH)
        .chain([SLOT_ATTESTATION]);
    for slot in slots {
        let fid = crate::files::key_fid(slot);
        if !fs.has_key(fid) {
            continue;
        }
        let mut plain = Secret::<[u8; MAX_PLAIN]>::zeroed();
        if seal_read(dev, fs, fid, &mut plain).is_ok() {
            plain.wipe();
            continue;
        }
        // The copy this re-seal supersedes opened under `old`, i.e. the public chip
        // serial alone. Ahead of the write and gating it, per
        // `rsk_fs::request_rescrub` — a boot that skipped this slot already latched.
        //
        // RESIDUAL: [`seal_read`] opens the CURRENT arm only, so a skipped slot
        // answers `6581` at every command until a later boot migrates it (measured).
        // A reader fallback would re-admit the chip-serial arm at every command,
        // which is the at-rest widening this class exists to prevent.
        if let Ok(n) = seal_read(&old, fs, fid, &mut plain)
            && rsk_fs::request_rescrub(fs).is_ok()
        {
            let _ = seal_put(dev, fs, rng, fid, &plain.expose()[..n]);
        }
        plain.wipe();
    }
}

/// Seal an EC key as `[curve_id] ‖ scalar` — the same blob layout the OpenPGP
/// applet writes, under a different key (see the module doc).
pub fn store_ec_key<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    fid: KeyFid,
    key: &PrivKey,
) -> Result<(), Sw> {
    let scalar = key.scalar();
    let mut plain = Secret::<[u8; 1 + 66]>::zeroed();
    plain.expose_mut()[0] = key.curve().id();
    plain.expose_mut()[1..1 + scalar.len()].copy_from_slice(scalar);
    let r = seal_put(dev, fs, rng, fid, &plain.expose()[..1 + scalar.len()]);
    plain.wipe();
    r
}

/// Load an EC key sealed by [`store_ec_key`].
pub fn load_ec_key<S: Storage>(dev: &Device, fs: &mut Fs<S>, fid: KeyFid) -> Result<PrivKey, Sw> {
    let mut plain = Secret::<[u8; 1 + 66]>::zeroed();
    let n = seal_read(dev, fs, fid, &mut plain)?;
    let plain = plain.expose();
    if n < 2 {
        return Err(Sw::MEMORY_FAILURE);
    }
    let curve = curve_from_id(plain[0]).ok_or(Sw::MEMORY_FAILURE)?;
    PrivKey::from_scalar(curve, &plain[1..n]).ok_or(Sw::MEMORY_FAILURE)
}

/// Seal an RSA key as `P ‖ Q ‖ dP ‖ dQ ‖ qInv` (the shared CRT layout — see
/// [`crt::crt_plaintext`]), so a signature no longer rebuilds `d`, `dP`, `dQ`
/// and `qInv` (two modular inversions) every time.
pub fn store_rsa_key<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    fid: KeyFid,
    key: &RsaKey,
) -> Result<(), Sw> {
    let mut plain = Secret::<[u8; MAX_PLAIN]>::zeroed();
    let n = crt::crt_plaintext(key, plain.expose_mut()).map_err(rsa_sw)?;
    seal_put(dev, fs, rng, fid, &plain.expose()[..n])
}

/// Load a sealed RSA key and return ONLY its public modulus `N = p·q`, big-endian
/// into `out`, returning `N`'s length. Skips the CRT precompute a key rebuild
/// pays — the `dP/dQ/qInv` modular inverses cost ~50 ms on RSA-4096 — because GET
/// METADATA and ATTEST need only `N` and the fixed 65537 exponent, never the
/// private key.
/// Byte-identical to `rsa_from_pqe(..)?.n_be()`, just without the key rebuild,
/// which is also what leaves the primes' working copies in freed heap.
pub fn load_rsa_modulus<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: KeyFid,
    out: &mut [u8],
) -> Result<usize, Sw> {
    let mut plain = Secret::<[u8; MAX_PLAIN]>::zeroed();
    let n = seal_read(dev, fs, fid, &mut plain)?;
    let plain = plain.expose();
    // Only `half` and the first `2*half` bytes are read, so the 2-vs-5-field
    // length classification (the `_` bool) cannot change `N` — collision-immune.
    let (half, _) = crt::parse_rsa_blob(&plain[..n]).map_err(rsa_sw)?;
    rsk_rsa::modulus_be(&plain[..half], &plain[half..2 * half], out).map_err(rsa_sw)
}

/// Load the CRT signing parameters of an RSA key — new `P‖Q‖dP‖dQ‖qInv` blobs
/// slice directly, older `P‖Q` blobs recompute once (see
/// [`crt::crt_from_plain`]).
pub fn load_rsa_crt<S: Storage>(dev: &Device, fs: &mut Fs<S>, fid: KeyFid) -> Result<RsaCrt, Sw> {
    let mut plain = Secret::<[u8; MAX_PLAIN]>::zeroed();
    let n = seal_read(dev, fs, fid, &mut plain)?;
    crt::crt_from_plain(&plain.expose()[..n]).map_err(rsa_sw)
}

/// The read side is narrower than [`Curve::id`] on purpose: PIV stores only
/// P-256/P-384 and the 25519 pair, so a blob tagged with any other curve is a
/// record this applet never wrote and must not decode.
pub(crate) fn curve_from_id(b: u8) -> Option<Curve> {
    Some(match b {
        3 => Curve::P256,
        4 => Curve::P384,
        30 => Curve::Ed25519,
        31 => Curve::X25519,
        _ => return None, // PIV stores P-256/P-384 and the 25519 curves
    })
}

#[cfg(test)]
#[path = "seal_tests.rs"]
mod tests;
