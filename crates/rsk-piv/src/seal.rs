// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! At-rest sealing for PIV key material: private keys are AES-256-GCM-sealed
//! with key = HKDF-SHA256(salt = serial_hash, ikm = kbase, info = "PIV/KEYS"),
//! blob = `nonce(12) ‖ ct ‖ tag(16)`, AAD = serial_hash. Deliberately NOT
//! PIN-bound (unlike the OpenPGP DEK): management-key-only flows (keygen,
//! import) must reach the keys without a PIN session. With the OTP MKEK
//! provisioned, `kbase` — and so this seal — roots in the hardware fuse key.

use rsa::traits::PrivateKeyParts;
use rsa::{BigUint, RsaPrivateKey};
use rsk_crypto::{Device, aes256gcm_decrypt, aes256gcm_encrypt, hkdf_sha256};
use rsk_fs::{Fs, KeyFid, Sealed, Storage};
use rsk_openpgp::Rng;
use rsk_openpgp::keys::{Curve, PrivKey};
use rsk_sdk::Sw;
use zeroize::{Zeroize, Zeroizing};

use crate::files::{
    SLOT_ATTESTATION, SLOT_AUTHENTICATION, SLOT_CARDAUTH, SLOT_RETIRED_FIRST, SLOT_RETIRED_LAST,
};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Largest sealed plaintext: RSA-4096 `P ‖ Q ‖ dP ‖ dQ ‖ qInv`, five 256-byte
/// fields (the CRT parameters cached alongside the primes so signing skips the
/// per-op key rebuild). Older `P ‖ Q` blobs (two fields) still load — the real
/// length rides in the record and [`parse_rsa_blob`] tells the layouts apart.
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

/// A single fixed-width CRT field buffer (a prime's max width).
const CRT_FIELD: usize = rsk_rsa_asm::MAX_MOD;

/// Copy a big-endian value (`≤ dst.len()` bytes) right-aligned into `dst`.
fn put_field(dst: &mut [u8], src: &[u8]) -> Result<(), Sw> {
    if src.len() > dst.len() {
        return Err(Sw::WRONG_LENGTH);
    }
    let off = dst.len() - src.len();
    dst[off..].copy_from_slice(src);
    Ok(())
}

/// The RSA public exponent, fixed at 65537 for every stored key.
fn rsa_e() -> BigUint {
    BigUint::from(65_537u32)
}

/// Seal an RSA key as `P ‖ Q ‖ dP ‖ dQ ‖ qInv` — five `half`-byte big-endian
/// fields. Caching the CRT parameters next to the primes lets [`load_rsa_crt`]
/// feed the asm CRT signer directly, so a signature no longer rebuilds `d`,
/// `dP`, `dQ` and `qInv` (two modular inversions) every time.
pub fn store_rsa_key<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    fid: KeyFid,
    key: &RsaPrivateKey,
) -> Result<(), Sw> {
    let primes = key.primes();
    if primes.len() != 2 {
        return Err(Sw::EXEC_ERROR);
    }
    // `from_p_q` (how every stored key is built) already precomputes; clone +
    // precompute defensively so dP/dQ/qInv are always present.
    let mut k = key.clone();
    let _ = k.precompute();
    let (dp, dq, qinv) = match (k.dp(), k.dq(), k.qinv()) {
        (Some(dp), Some(dq), Some(qinv)) => (dp, dq, qinv),
        _ => return Err(Sw::EXEC_ERROR),
    };
    let mut pb = primes[0].to_bytes_be();
    let mut qb = primes[1].to_bytes_be();
    let half = pb.len().max(qb.len());
    let n = 5 * half;
    let mut dpb = dp.to_bytes_be();
    let mut dqb = dq.to_bytes_be();
    let qi = Zeroizing::new(qinv.to_biguint().ok_or(Sw::EXEC_ERROR)?);
    let mut qib = qi.to_bytes_be();
    let mut plain = [0u8; MAX_PLAIN];
    let r = (|| {
        if n > MAX_PLAIN {
            return Err(Sw::WRONG_LENGTH);
        }
        put_field(&mut plain[0..half], &pb)?;
        put_field(&mut plain[half..2 * half], &qb)?;
        put_field(&mut plain[2 * half..3 * half], &dpb)?;
        put_field(&mut plain[3 * half..4 * half], &dqb)?;
        put_field(&mut plain[4 * half..5 * half], &qib)?;
        seal_put(dev, fs, rng, fid, &plain[..n])
    })();
    pb.zeroize();
    qb.zeroize();
    dpb.zeroize();
    dqb.zeroize();
    qib.zeroize();
    plain.zeroize();
    r
}

/// Tell the two sealed RSA layouts apart by plaintext length: `P‖Q` is `2·half`,
/// `P‖Q‖dP‖dQ‖qInv` is `5·half`. The two length sets ({128,256,384,512} vs
/// {320,640,960,1280}) are disjoint and only the 5-field form is a multiple of 5,
/// so this is unambiguous. Returns the prime width and whether it is the CRT form.
fn parse_rsa_blob(n: usize) -> Result<(usize, bool), Sw> {
    let (half, is_crt) = if n.is_multiple_of(5) {
        (n / 5, true)
    } else {
        (n / 2, false)
    };
    let expect = if is_crt { 5 * half } else { 2 * half };
    if half.is_multiple_of(32) && (32..=CRT_FIELD).contains(&half) && n == expect {
        Ok((half, is_crt))
    } else {
        Err(Sw::MEMORY_FAILURE)
    }
}

/// Load an RSA key sealed by [`store_rsa_key`] (either layout) into an
/// [`RsaPrivateKey`] (`E` fixed at 65537). Used by the non-signing paths (GET
/// METADATA, cert build); signing uses [`load_rsa_crt`], which skips the rebuild.
pub fn load_rsa_key<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: KeyFid,
) -> Result<RsaPrivateKey, Sw> {
    let mut plain = [0u8; MAX_PLAIN];
    let n = seal_read(dev, fs, fid, &mut plain)?;
    let r = (|| {
        let (half, _) = parse_rsa_blob(n)?;
        let p = BigUint::from_bytes_be(&plain[..half]);
        let q = BigUint::from_bytes_be(&plain[half..2 * half]);
        RsaPrivateKey::from_p_q(p, q, rsa_e()).map_err(|_| Sw::MEMORY_FAILURE)
    })();
    plain.zeroize();
    r
}

/// CRT parameters of an RSA private key, loaded for signing — each field
/// big-endian, `half` bytes wide. Zeroized on drop.
pub struct RsaCrt {
    half: usize,
    p: [u8; CRT_FIELD],
    q: [u8; CRT_FIELD],
    dp: [u8; CRT_FIELD],
    dq: [u8; CRT_FIELD],
    qinv: [u8; CRT_FIELD],
}

impl RsaCrt {
    fn zeroed(half: usize) -> Self {
        Self {
            half,
            p: [0; CRT_FIELD],
            q: [0; CRT_FIELD],
            dp: [0; CRT_FIELD],
            dq: [0; CRT_FIELD],
            qinv: [0; CRT_FIELD],
        }
    }
    /// Modulus width in bytes (`2·half` — the RSA signature/challenge length).
    pub fn modulus_len(&self) -> usize {
        2 * self.half
    }
    pub fn p(&self) -> &[u8] {
        &self.p[..self.half]
    }
    pub fn q(&self) -> &[u8] {
        &self.q[..self.half]
    }
    pub fn dp(&self) -> &[u8] {
        &self.dp[..self.half]
    }
    pub fn dq(&self) -> &[u8] {
        &self.dq[..self.half]
    }
    pub fn qinv(&self) -> &[u8] {
        &self.qinv[..self.half]
    }
}

impl Drop for RsaCrt {
    fn drop(&mut self) {
        self.p.zeroize();
        self.q.zeroize();
        self.dp.zeroize();
        self.dq.zeroize();
        self.qinv.zeroize();
    }
}

/// Load the CRT signing parameters of an RSA key. New `P‖Q‖dP‖dQ‖qInv` blobs
/// slice directly; older `P‖Q` blobs recompute `dP/dQ/qInv` once here (the cost
/// the new layout removes — such keys still get the fast asm CRT modexp, but keep
/// the one-time precompute per signature until re-provisioned).
pub fn load_rsa_crt<S: Storage>(dev: &Device, fs: &mut Fs<S>, fid: KeyFid) -> Result<RsaCrt, Sw> {
    let mut plain = [0u8; MAX_PLAIN];
    let n = seal_read(dev, fs, fid, &mut plain)?;
    let r = (|| {
        let (half, is_crt) = parse_rsa_blob(n)?;
        let mut crt = RsaCrt::zeroed(half);
        crt.p[..half].copy_from_slice(&plain[..half]);
        crt.q[..half].copy_from_slice(&plain[half..2 * half]);
        if is_crt {
            crt.dp[..half].copy_from_slice(&plain[2 * half..3 * half]);
            crt.dq[..half].copy_from_slice(&plain[3 * half..4 * half]);
            crt.qinv[..half].copy_from_slice(&plain[4 * half..5 * half]);
        } else {
            let p = BigUint::from_bytes_be(&plain[..half]);
            let q = BigUint::from_bytes_be(&plain[half..2 * half]);
            let mut k = RsaPrivateKey::from_p_q(p, q, rsa_e()).map_err(|_| Sw::MEMORY_FAILURE)?;
            let _ = k.precompute();
            match (k.dp(), k.dq(), k.qinv()) {
                (Some(dp), Some(dq), Some(qinv)) => {
                    let mut dpb = dp.to_bytes_be();
                    let mut dqb = dq.to_bytes_be();
                    let qi = Zeroizing::new(qinv.to_biguint().ok_or(Sw::EXEC_ERROR)?);
                    let mut qib = qi.to_bytes_be();
                    let put = put_field(&mut crt.dp[..half], &dpb)
                        .and(put_field(&mut crt.dq[..half], &dqb))
                        .and(put_field(&mut crt.qinv[..half], &qib));
                    dpb.zeroize();
                    dqb.zeroize();
                    qib.zeroize();
                    put?;
                }
                _ => return Err(Sw::EXEC_ERROR),
            }
        }
        Ok(crt)
    })();
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
