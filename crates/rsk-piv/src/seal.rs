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
use rsk_rsa::{RSA_PUB_EXP_BE, RsaKey, crt};
use rsk_sdk::Rng;
use rsk_sdk::Sw;
use zeroize::Zeroize;

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

fn kenc(dev: &Device) -> [u8; 32] {
    let mut kbase = dev.derive_kbase();
    let mut out = [0u8; 32];
    hkdf_sha256(dev.serial_hash, &kbase, INFO_PIV_KEYS, &mut out)
        .expect("32-byte HKDF output is in range");
    kbase.zeroize();
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
    let r = fs
        .put_key(fid, Sealed::wrap(&blob[..n]))
        .map_err(|_| Sw::MEMORY_FAILURE);
    blob.zeroize();
    r
}

/// Read and unseal `fid` into `out`; returns the plaintext length.
/// `REFERENCE_NOT_FOUND` when the file is missing or empty.
pub fn seal_read<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: KeyFid,
    out: &mut [u8],
) -> Result<usize, Sw> {
    let mut blob = [0u8; MAX_BLOB];
    let n = fs.read_key(fid, &mut blob).ok_or(Sw::REFERENCE_NOT_FOUND)?;
    if !(NONCE_LEN + TAG_LEN..=MAX_BLOB).contains(&n) {
        return Err(Sw::MEMORY_FAILURE);
    }
    let pt_len = n - NONCE_LEN - TAG_LEN;
    if out.len() < pt_len {
        return Err(Sw::WRONG_LENGTH);
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
        return Err(Sw::MEMORY_FAILURE);
    }
    out[..pt_len].copy_from_slice(&blob[NONCE_LEN..NONCE_LEN + pt_len]);
    blob.zeroize();
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
        let mut plain = [0u8; MAX_PLAIN];
        if seal_read(dev, fs, fid, &mut plain).is_ok() {
            plain.zeroize();
            continue;
        }
        if let Ok(n) = seal_read(&old, fs, fid, &mut plain) {
            let _ = seal_put(dev, fs, rng, fid, &plain[..n]);
        }
        plain.zeroize();
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
    let mut plain = [0u8; 1 + 66];
    plain[0] = key.curve().id();
    plain[1..1 + scalar.len()].copy_from_slice(scalar);
    let r = seal_put(dev, fs, rng, fid, &plain[..1 + scalar.len()]);
    plain.zeroize();
    r
}

/// Load an EC key sealed by [`store_ec_key`].
pub fn load_ec_key<S: Storage>(dev: &Device, fs: &mut Fs<S>, fid: KeyFid) -> Result<PrivKey, Sw> {
    let mut plain = [0u8; 1 + 66];
    let n = seal_read(dev, fs, fid, &mut plain)?;
    let r = (|| {
        if n < 2 {
            return Err(Sw::MEMORY_FAILURE);
        }
        let curve = curve_from_id(plain[0]).ok_or(Sw::MEMORY_FAILURE)?;
        PrivKey::from_scalar(curve, &plain[1..n]).ok_or(Sw::MEMORY_FAILURE)
    })();
    plain.zeroize();
    r
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
    let mut plain = [0u8; MAX_PLAIN];
    let r = (|| {
        let n = crt::crt_plaintext(key, &mut plain).map_err(rsa_sw)?;
        seal_put(dev, fs, rng, fid, &plain[..n])
    })();
    plain.zeroize();
    r
}

/// Load a sealed RSA key and return ONLY its public modulus `N = p·q`, big-endian
/// into `out`, returning `N`'s length. Skips the CRT precompute a key rebuild
/// pays — the `dP/dQ/qInv` modular inverses cost ~50 ms on RSA-4096 — because GET
/// METADATA needs only `N` and the fixed 65537 exponent, never the private key.
/// Byte-identical to `load_rsa_key(..)?.n_be()`, just without the key rebuild.
pub fn load_rsa_modulus<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: KeyFid,
    out: &mut [u8],
) -> Result<usize, Sw> {
    let mut plain = [0u8; MAX_PLAIN];
    let n = seal_read(dev, fs, fid, &mut plain)?;
    let r = (|| {
        // Only `half` and the first `2*half` bytes are read, so the 2-vs-5-field
        // length classification (the `_` bool) cannot change `N` — collision-immune.
        let (half, _) = crt::parse_rsa_blob(&plain[..n]).map_err(rsa_sw)?;
        rsk_rsa::modulus_be(&plain[..half], &plain[half..2 * half], out).map_err(rsa_sw)
    })();
    plain.zeroize();
    r
}

/// Load an RSA key sealed by [`store_rsa_key`] (either layout) into an
/// [`RsaKey`] (`E` fixed at 65537). Used by the cert-build path (the retired
/// on-device RSA finish); signing uses [`load_rsa_crt`] and GET METADATA uses
/// [`load_rsa_modulus`], both of which skip the full key rebuild.
pub fn load_rsa_key<S: Storage>(dev: &Device, fs: &mut Fs<S>, fid: KeyFid) -> Result<RsaKey, Sw> {
    let mut plain = [0u8; MAX_PLAIN];
    let n = seal_read(dev, fs, fid, &mut plain)?;
    let r = (|| {
        let (half, _) = crt::parse_rsa_blob(&plain[..n]).map_err(rsa_sw)?;
        rsk_rsa::rsa_from_pqe(RSA_PUB_EXP_BE, &plain[..half], &plain[half..2 * half])
            .ok_or(Sw::MEMORY_FAILURE)
    })();
    plain.zeroize();
    r
}

/// Load the CRT signing parameters of an RSA key — new `P‖Q‖dP‖dQ‖qInv` blobs
/// slice directly, older `P‖Q` blobs recompute once (see
/// [`crt::crt_from_plain`]).
pub fn load_rsa_crt<S: Storage>(dev: &Device, fs: &mut Fs<S>, fid: KeyFid) -> Result<RsaCrt, Sw> {
    let mut plain = [0u8; MAX_PLAIN];
    let n = seal_read(dev, fs, fid, &mut plain)?;
    let r = crt::crt_from_plain(&plain[..n]).map_err(rsa_sw);
    plain.zeroize();
    r
}

/// The read side is narrower than [`Curve::id`] on purpose: PIV stores only
/// P-256/P-384 and the 25519 pair, so a blob tagged with any other curve is a
/// record this applet never wrote and must not decode.
fn curve_from_id(b: u8) -> Option<Curve> {
    Some(match b {
        3 => Curve::P256,
        4 => Curve::P384,
        30 => Curve::Ed25519,
        31 => Curve::X25519,
        _ => return None, // PIV stores P-256/P-384 and the 25519 curves
    })
}
