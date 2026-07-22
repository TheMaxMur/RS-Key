// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! At-rest sealing for PIV key material: private keys are AES-256-GCM-sealed
//! with key = HKDF-SHA256(salt = serial_hash, ikm = kbase, info = "PIV/KEYS"),
//! blob = `nonce(12) ‖ ct ‖ tag(16)`, AAD = serial_hash. Deliberately NOT
//! PIN-bound (unlike the OpenPGP DEK): management-key-only flows (keygen,
//! import) must reach the keys without a PIN session. With the OTP MKEK
//! provisioned, `kbase` — and so this seal — roots in the hardware fuse key.

use rsa::{BigUint, RsaPrivateKey};
use rsk_crypto::{Device, aes256gcm_decrypt, aes256gcm_encrypt, hkdf_sha256};
use rsk_fs::{Fs, KeyFid, Sealed, Storage};
use rsk_openpgp::Rng;
use rsk_openpgp::keys::{Curve, PrivKey};
use rsk_openpgp::rsa_crt;
use rsk_sdk::Sw;
use zeroize::{Zeroize, Zeroizing};

pub use rsk_openpgp::rsa_crt::RsaCrt;

use crate::files::{
    SLOT_ATTESTATION, SLOT_AUTHENTICATION, SLOT_CARDAUTH, SLOT_RETIRED_FIRST, SLOT_RETIRED_LAST,
};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Largest sealed plaintext: RSA-4096 `P ‖ Q ‖ dP ‖ dQ ‖ qInv`, five 256-byte
/// fields (the CRT parameters cached alongside the primes so signing skips the
/// per-op key rebuild). Older `P ‖ Q` blobs (two fields) still load — the real
/// length rides in the record and [`rsa_crt::parse_rsa_blob`] tells them apart.
const MAX_PLAIN: usize = 5 * rsk_rsa_asm::MAX_MOD;
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

/// Seal an EC key as `[curve_id] ‖ scalar` (the OpenPGP blob layout).
pub fn store_ec_key<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    fid: KeyFid,
    key: &PrivKey,
) -> Result<(), Sw> {
    let scalar = key.scalar();
    let mut plain = [0u8; 1 + 66];
    plain[0] = curve_id(key.curve());
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
/// [`rsa_crt::crt_plaintext`]), so a signature no longer rebuilds `d`, `dP`, `dQ`
/// and `qInv` (two modular inversions) every time.
pub fn store_rsa_key<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    fid: KeyFid,
    key: &RsaPrivateKey,
) -> Result<(), Sw> {
    let mut plain = [0u8; MAX_PLAIN];
    let r = (|| {
        let n = rsa_crt::crt_plaintext(key, &mut plain)?;
        seal_put(dev, fs, rng, fid, &plain[..n])
    })();
    plain.zeroize();
    r
}

/// Load a sealed RSA key and return ONLY its public modulus `N = p·q`, big-endian
/// into `out`, returning `N`'s length. Skips [`RsaPrivateKey::from_p_q`]'s CRT
/// precompute — the `dP/dQ/qInv` modular inverses that cost ~50 ms on RSA-4096 —
/// because GET METADATA needs only `N` and the fixed 65537 exponent, never the
/// private key. `p`/`q` ride in [`Zeroizing`] (num-bigint has no scrubbing `Drop`,
/// the recorded RSA hygiene lesson); the product `N` is public. Byte-identical to
/// `load_rsa_key(..)?.n().to_bytes_be()`, just without the key rebuild.
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
        let (half, _) = rsa_crt::parse_rsa_blob(&plain[..n])?;
        let p = Zeroizing::new(BigUint::from_bytes_be(&plain[..half]));
        let q = Zeroizing::new(BigUint::from_bytes_be(&plain[half..2 * half]));
        let nb = (&*p * &*q).to_bytes_be();
        if nb.len() > out.len() {
            return Err(Sw::WRONG_LENGTH);
        }
        out[..nb.len()].copy_from_slice(&nb);
        Ok(nb.len())
    })();
    plain.zeroize();
    r
}

/// Load an RSA key sealed by [`store_rsa_key`] (either layout) into an
/// [`RsaPrivateKey`] (`E` fixed at 65537). Used by the cert-build path (the retired
/// on-device RSA finish); signing uses [`load_rsa_crt`] and GET METADATA uses
/// [`load_rsa_modulus`], both of which skip the full key rebuild.
pub fn load_rsa_key<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: KeyFid,
) -> Result<RsaPrivateKey, Sw> {
    let mut plain = [0u8; MAX_PLAIN];
    let n = seal_read(dev, fs, fid, &mut plain)?;
    let r = (|| {
        let (half, _) = rsa_crt::parse_rsa_blob(&plain[..n])?;
        let p = BigUint::from_bytes_be(&plain[..half]);
        let q = BigUint::from_bytes_be(&plain[half..2 * half]);
        RsaPrivateKey::from_p_q(p, q, rsa_crt::rsa_e()).map_err(|_| Sw::MEMORY_FAILURE)
    })();
    plain.zeroize();
    r
}

/// Load the CRT signing parameters of an RSA key — new `P‖Q‖dP‖dQ‖qInv` blobs
/// slice directly, older `P‖Q` blobs recompute once (see
/// [`rsa_crt::crt_from_plain`]).
pub fn load_rsa_crt<S: Storage>(dev: &Device, fs: &mut Fs<S>, fid: KeyFid) -> Result<RsaCrt, Sw> {
    let mut plain = [0u8; MAX_PLAIN];
    let n = seal_read(dev, fs, fid, &mut plain)?;
    let r = rsa_crt::crt_from_plain(&plain[..n]);
    plain.zeroize();
    r
}

/// Our internal curve tags (shared values with rsk-openpgp's blob format).
fn curve_id(c: Curve) -> u8 {
    match c {
        Curve::P256 => 3,
        Curve::P384 => 4,
        Curve::P521 => 5,
        Curve::K256 => 12,
        // Shared tags with rsk-openpgp Curve::id(); PIV never generates brainpool
        // but the exhaustive match must cover every variant.
        Curve::Bp256 => 6,
        Curve::Bp384 => 7,
        Curve::Ed25519 => 30,
        Curve::X25519 => 31,
    }
}

fn curve_from_id(b: u8) -> Option<Curve> {
    Some(match b {
        3 => Curve::P256,
        4 => Curve::P384,
        30 => Curve::Ed25519,
        31 => Curve::X25519,
        _ => return None, // PIV stores P-256/P-384 and the 25519 curves
    })
}
