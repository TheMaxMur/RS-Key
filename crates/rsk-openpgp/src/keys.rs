// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Private-key sealing and the asymmetric operations. Keys live in the internal
//! EFs `EF_PK_SIG`/`DEC`/`AUT`, AES-256-GCM-sealed under the random DEK (key =
//! `dek[16..48]`, nonce-PRF key = `dek[0..16]`; the DEK itself is PIN-wrapped,
//! see [`crate::pin`]). EC blobs are `[curve_id] ‖ scalar`; signatures are raw
//! `r ‖ s` (fixed field width), NOT DER.

use alloc::boxed::Box;
use zeroize::{Zeroize, Zeroizing};

use rsk_crypto::aes::aes_decrypt_cfb_256;
use rsk_crypto::{Device, aes256gcm_decrypt, aes256gcm_encrypt, hmac_sha256};
use rsk_fs::{Fs, KeyFid, Sealed, Storage};
use rsk_sdk::Sw;

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::elliptic_curve::sec1::FromSec1Point;

use num_bigint_dig::prime::probably_prime_lucas;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, Pkcs1v15Encrypt, Pkcs1v15Sign};
use rsk_rsa::{IncrementalSieve, mod_small, passes_strong_mr_base2, self_test};

// Re-exported so the firmware can name the keygen result type without its own
// `rsa` dependency (the dual-core search returns `Box<RsaPrivateKey>`).
pub use rsa::RsaPrivateKey;

use crate::Rng;
use crate::consts::*;
use crate::dobj::{
    ATTR_BP256R1, ATTR_BP384R1, ATTR_CV25519, ATTR_ED25519, ATTR_P256K1, ATTR_P256R1, ATTR_P384R1,
    ATTR_P521R1,
};
use crate::pin::{Session, load_dek};
use crate::pkcs1v15;
use crate::rsa_crt::{self, RsaCrt};

/// Largest raw ECDSA signature: P-521 `r ‖ s` = 2×66 bytes.
pub const MAX_EC_SIG: usize = 132;
/// Largest EC public point: P-521 uncompressed `04 ‖ x ‖ y` = 1 + 2×66 bytes.
pub const MAX_EC_POINT: usize = 133;
/// Largest stored EC key blob: `[curve_id] ‖ scalar` (P-521 scalar = 66 bytes).
const MAX_EC_KDATA: usize = 1 + 66;

// ---------------------------------------------------------------- DEK seal ---
//
// Key blobs are AES-256-GCM-sealed under the PIN-wrapped DEK: the record is
// `nonce(12) ‖ ct ‖ tag(16)`, GCM key = `dek[16..48]`, AAD = the device serial
// hash. The 12-byte nonce is SYNTHETIC — `HMAC-SHA256(dek[0..16], fid ‖ plain)`
// truncated — so two distinct keys (or the same key in two slots) never share a
// nonce, killing the block-0 keystream reuse the old fixed-IV CFB seal had, and
// GCM adds the authentication CFB lacked. A synthetic nonce needs no RNG, so the
// (RNG-less) import path is unaffected. Records written by the older seal (bare
// fixed-IV CFB ciphertext) still load: `dek_unseal` trial-decrypts under GCM and,
// on an auth failure, falls back to the legacy CFB decrypt, and the caller then
// re-seals the key forward the first time it is loaded.

const DEK_NONCE_LEN: usize = 12;
const DEK_TAG_LEN: usize = 16;
/// Bytes the GCM seal adds over the plaintext (`nonce ‖ … ‖ tag`).
pub const DEK_SEAL_OVERHEAD: usize = DEK_NONCE_LEN + DEK_TAG_LEN;

/// Synthetic 12-byte nonce for `fid`'s `plain`: `HMAC(nonce_key, fid)` re-keys a
/// second HMAC over the plaintext, so distinct key material always yields a
/// distinct nonce (and identical material re-seals identically — no reuse risk).
fn synth_nonce(nonce_key: &[u8; IV_SIZE], fid: KeyFid, plain: &[u8]) -> [u8; DEK_NONCE_LEN] {
    let sub = hmac_sha256(nonce_key, &fid.get().to_be_bytes());
    let full = hmac_sha256(&sub, plain);
    let mut nonce = [0u8; DEK_NONCE_LEN];
    nonce.copy_from_slice(&full[..DEK_NONCE_LEN]);
    nonce
}

/// Seal `plain` under the split DEK halves into `out` as `nonce ‖ ct ‖ tag`;
/// returns the record length. Pure over the key material so it is unit-testable
/// without a PIN session.
fn seal_with(
    key: &[u8; 32],
    nonce_key: &[u8; IV_SIZE],
    serial_hash: &[u8],
    fid: KeyFid,
    plain: &[u8],
    out: &mut [u8],
) -> Result<usize, Sw> {
    let n = DEK_NONCE_LEN + plain.len() + DEK_TAG_LEN;
    if out.len() < n {
        return Err(Sw::WRONG_LENGTH);
    }
    let nonce = synth_nonce(nonce_key, fid, plain);
    out[..DEK_NONCE_LEN].copy_from_slice(&nonce);
    out[DEK_NONCE_LEN..DEK_NONCE_LEN + plain.len()].copy_from_slice(plain);
    let tag = aes256gcm_encrypt(
        key,
        &nonce,
        serial_hash,
        &mut out[DEK_NONCE_LEN..DEK_NONCE_LEN + plain.len()],
    );
    out[DEK_NONCE_LEN + plain.len()..n].copy_from_slice(&tag);
    Ok(n)
}

/// Unseal a `blob` under the split DEK halves into `out`; returns
/// `(plaintext_len, was_legacy)`. Tries the GCM format, falling back to the legacy
/// fixed-IV CFB decrypt only when `is_legacy_len` says the record is the width a
/// pre-GCM record for this slot would have. Pure over the key material.
///
/// The predicate is what makes the fallback safe. `aes_decrypt_cfb_256` takes a
/// fixed-size key and IV, so it *cannot* fail: without a shape test, any GCM
/// authentication failure — a wrong DEK after a torn TERMINATE, tampering, a flash
/// bit-flip — was silently reinterpreted as "this must be a legacy record", the
/// garbage plaintext was accepted as a key, and the callers below re-sealed it
/// **over the original ciphertext**. A legacy record is bare ciphertext of the
/// plaintext, a GCM one is that plus [`DEK_SEAL_OVERHEAD`], so the two widths are
/// disjoint for every slot and the shape decides unambiguously (audit run-33).
fn unseal_with(
    key: &[u8; 32],
    nonce_key: &[u8; IV_SIZE],
    serial_hash: &[u8],
    blob: &[u8],
    out: &mut [u8],
    is_legacy_len: fn(usize) -> bool,
) -> Result<(usize, bool), Sw> {
    if blob.len() >= DEK_NONCE_LEN + DEK_TAG_LEN {
        let pt_len = blob.len() - DEK_NONCE_LEN - DEK_TAG_LEN;
        if out.len() >= pt_len {
            let mut nonce = [0u8; DEK_NONCE_LEN];
            nonce.copy_from_slice(&blob[..DEK_NONCE_LEN]);
            let mut tag = [0u8; DEK_TAG_LEN];
            tag.copy_from_slice(&blob[blob.len() - DEK_TAG_LEN..]);
            out[..pt_len].copy_from_slice(&blob[DEK_NONCE_LEN..DEK_NONCE_LEN + pt_len]);
            if aes256gcm_decrypt(key, &nonce, serial_hash, &mut out[..pt_len], &tag).is_ok() {
                return Ok((pt_len, false));
            }
        }
    }
    // Legacy fixed-IV CFB record (bare ciphertext, no nonce/tag).
    if !is_legacy_len(blob.len()) {
        // A record of GCM shape whose tag did not verify: an authentication
        // failure, not a legacy record. Fail closed rather than hand back an
        // unauthenticated decrypt the caller would re-seal over the original.
        return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
    }
    if out.len() < blob.len() {
        return Err(Sw::WRONG_LENGTH);
    }
    out[..blob.len()].copy_from_slice(blob);
    aes_decrypt_cfb_256(key, nonce_key, &mut out[..blob.len()]).map_err(|_| Sw::EXEC_ERROR)?;
    Ok((blob.len(), true))
}

/// Legal widths of a pre-GCM **EC** record: the curve-id byte plus a scalar —
/// 32 (P-256/K-256/bp256/Ed25519/X25519), 48 (P-384/bp384) or 66 (P-521), the
/// largest of which is [`MAX_EC_KDATA`].
fn legacy_ec_len(n: usize) -> bool {
    matches!(n, 33 | 49 | 67)
}

/// Legal widths of a pre-GCM **AES** record: one raw AES key.
fn legacy_aes_len(n: usize) -> bool {
    matches!(n, 16 | 24 | 32)
}

/// Legal widths of a pre-GCM **RSA** record: `P‖Q`, or the five CRT fields, for a
/// half that [`rsa_crt::parse_rsa_blob`] would accept (32..=256, a multiple of 32).
fn legacy_rsa_len(n: usize) -> bool {
    let half_ok = |h: usize| (32..=256).contains(&h) && h.is_multiple_of(32);
    (n.is_multiple_of(2) && half_ok(n / 2)) || (n.is_multiple_of(5) && half_ok(n / 5))
}

/// Load the DEK and split it into the GCM key (`dek[16..48]`) and the nonce-PRF
/// key (`dek[0..16]`, also the legacy CFB IV) — disjoint bytes of one random DEK.
fn load_dek_keys<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
) -> Result<([u8; 32], [u8; IV_SIZE]), Sw> {
    let mut dek = [0u8; DEK_SIZE];
    load_dek(dev, fs, sess, &mut dek)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&dek[IV_SIZE..IV_SIZE + 32]);
    let mut nk = [0u8; IV_SIZE];
    nk.copy_from_slice(&dek[..IV_SIZE]);
    dek.zeroize();
    Ok((key, nk))
}

/// Seal `plain` under the DEK into `out` (`nonce ‖ ct ‖ tag`); returns its length.
fn dek_seal<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    fid: KeyFid,
    plain: &[u8],
    out: &mut [u8],
) -> Result<usize, Sw> {
    let (mut key, mut nk) = load_dek_keys(dev, fs, sess)?;
    let r = seal_with(&key, &nk, dev.serial_hash, fid, plain, out);
    key.zeroize();
    nk.zeroize();
    r
}

/// Unseal a DEK `blob` into `out`; returns `(plaintext_len, was_legacy)`.
/// `is_legacy_len` names the widths a pre-GCM record for this slot could have —
/// see [`unseal_with`] for why the fallback must not be shape-blind.
fn dek_unseal<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    blob: &[u8],
    out: &mut [u8],
    is_legacy_len: fn(usize) -> bool,
) -> Result<(usize, bool), Sw> {
    let (mut key, mut nk) = load_dek_keys(dev, fs, sess)?;
    let r = unseal_with(&key, &nk, dev.serial_hash, blob, out, is_legacy_len);
    key.zeroize();
    nk.zeroize();
    r
}

// ------------------------------------------------------------------ curves ---

/// The supported EC curves. The one-byte id is an internal tag (stored as
/// `kdata[0]`), only ever read back by this firmware.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Curve {
    P256,
    P384,
    P521,
    K256,
    /// brainpoolP256r1 (RFC 5639).
    Bp256,
    /// brainpoolP384r1 (RFC 5639).
    Bp384,
    Ed25519,
    /// Curve25519 ECDH (the decipher key); OpenPGP "Cv25519".
    X25519,
}

impl Curve {
    fn id(self) -> u8 {
        match self {
            Curve::P256 => 3,
            Curve::P384 => 4,
            Curve::P521 => 5,
            Curve::K256 => 12,
            Curve::Bp256 => 6,
            Curve::Bp384 => 7,
            Curve::Ed25519 => 30,
            Curve::X25519 => 31,
        }
    }

    fn from_id(b: u8) -> Option<Self> {
        Some(match b {
            3 => Curve::P256,
            4 => Curve::P384,
            5 => Curve::P521,
            12 => Curve::K256,
            6 => Curve::Bp256,
            7 => Curve::Bp384,
            30 => Curve::Ed25519,
            31 => Curve::X25519,
            _ => return None,
        })
    }
}

/// Map a stored algorithm-attribute (`[algo_id ‖ oid]`) to its curve by matching
/// the **OID only**: for a NIST curve the leading id byte is `ECDSA` (0x13) on a
/// signing key but `ECDH` (0x12) on the decipher key, yet both denote the same
/// curve. Unsupported curves (X448 / Ed448) return `None`.
pub fn curve_from_attr(attr: &[u8]) -> Option<Curve> {
    let oid = attr.get(1..)?;
    fn oid_of(tmpl: &[u8]) -> &[u8] {
        &tmpl[2..] // template = [tlv_len, algo_id, oid…]
    }
    if oid == oid_of(ATTR_P256R1) {
        Some(Curve::P256)
    } else if oid == oid_of(ATTR_P384R1) {
        Some(Curve::P384)
    } else if oid == oid_of(ATTR_P521R1) {
        Some(Curve::P521)
    } else if oid == oid_of(ATTR_BP256R1) {
        Some(Curve::Bp256)
    } else if oid == oid_of(ATTR_BP384R1) {
        Some(Curve::Bp384)
    } else if oid == oid_of(ATTR_P256K1) {
        Some(Curve::K256)
    } else if oid == oid_of(ATTR_ED25519) {
        Some(Curve::Ed25519)
    } else if oid == oid_of(ATTR_CV25519) {
        Some(Curve::X25519)
    } else {
        None
    }
}

// --------------------------------------------------------------- EC keypair --

/// A reconstructed EC private key, holding the raw (left-padded) scalar / seed.
/// Reconstructs the RustCrypto key on demand for each operation, then drops it.
pub enum PrivKey {
    P256([u8; 32]),
    P384([u8; 48]),
    P521([u8; 66]),
    K256([u8; 32]),
    Bp256([u8; 32]),
    Bp384([u8; 48]),
    Ed25519([u8; 32]),
    /// Curve25519 ECDH: the imported scalar as a big-endian MPI (reversed to the
    /// little-endian RFC 7748 form only at agreement time).
    X25519([u8; 32]),
}

impl Drop for PrivKey {
    fn drop(&mut self) {
        match self {
            PrivKey::P256(s) | PrivKey::K256(s) | PrivKey::Ed25519(s) | PrivKey::X25519(s) => {
                s.zeroize()
            }
            PrivKey::Bp256(s) => s.zeroize(),
            PrivKey::P384(s) | PrivKey::Bp384(s) => s.zeroize(),
            PrivKey::P521(s) => s.zeroize(),
        }
    }
}

/// Left-pad `s` into an `N`-byte big-endian buffer (OpenPGP MPIs drop leading
/// zeros, so a scalar may arrive shorter than the field width). `None` if `s`
/// is longer than `N`.
fn pad<const N: usize>(s: &[u8]) -> Option<[u8; N]> {
    if s.len() > N {
        return None;
    }
    let mut b = [0u8; N];
    b[N - s.len()..].copy_from_slice(s);
    Some(b)
}

impl PrivKey {
    /// Build the key for `curve` from the imported `scalar` (the private key
    /// material; for Ed25519 it is the 32-byte seed).
    pub fn from_scalar(curve: Curve, scalar: &[u8]) -> Option<Self> {
        Some(match curve {
            Curve::P256 => PrivKey::P256(pad::<32>(scalar)?),
            Curve::P384 => PrivKey::P384(pad::<48>(scalar)?),
            Curve::P521 => PrivKey::P521(pad::<66>(scalar)?),
            Curve::K256 => PrivKey::K256(pad::<32>(scalar)?),
            Curve::Bp256 => PrivKey::Bp256(pad::<32>(scalar)?),
            Curve::Bp384 => PrivKey::Bp384(pad::<48>(scalar)?),
            Curve::Ed25519 => PrivKey::Ed25519(pad::<32>(scalar)?),
            Curve::X25519 => PrivKey::X25519(pad::<32>(scalar)?),
        })
    }

    /// Generate a fresh key for `curve` from the TRNG. The Weierstrass scalars
    /// use the RustCrypto uniform sampler; Ed25519/X25519 keys are 32 random
    /// bytes (the seed / clamped scalar), stored big-endian like an import.
    pub fn generate(curve: Curve, rng: &mut dyn Rng) -> Option<Self> {
        // Each `to_bytes()` scalar copy is bound and wiped after `from_scalar`
        // clones it (the `SecretKey` itself zeroizes on drop).
        match curve {
            Curve::P256 => {
                let mut b = [0u8; 32];
                loop {
                    rng.fill(&mut b);
                    if p256::SecretKey::from_bytes(&p256::FieldBytes::from(b)).is_ok() {
                        break;
                    }
                }
                let k = Self::from_scalar(curve, &b);
                b.zeroize();
                k
            }
            Curve::P384 => {
                let mut b = [0u8; 48];
                loop {
                    rng.fill(&mut b);
                    if p384::SecretKey::from_bytes(&p384::FieldBytes::from(b)).is_ok() {
                        break;
                    }
                }
                let k = Self::from_scalar(curve, &b);
                b.zeroize();
                k
            }
            Curve::P521 => {
                let mut b = [0u8; 66];
                loop {
                    rng.fill(&mut b);
                    b[0] &= 0x01; // a P-521 scalar is 521 bits: keep only the top bit
                    if p521::SecretKey::from_bytes(&p521::FieldBytes::from(b)).is_ok() {
                        break;
                    }
                }
                let k = Self::from_scalar(curve, &b);
                b.zeroize();
                k
            }
            Curve::K256 => {
                let mut b = [0u8; 32];
                loop {
                    rng.fill(&mut b);
                    if k256::SecretKey::from_bytes(&k256::FieldBytes::from(b)).is_ok() {
                        break;
                    }
                }
                let k = Self::from_scalar(curve, &b);
                b.zeroize();
                k
            }
            // 0.14 `SecretKey::random` wants a rand_core 0.10 rng our `Rng` can't
            // supply; reject-sample raw bytes instead (`from_bytes` validates [1,n)).
            Curve::Bp256 => {
                let mut b = [0u8; 32];
                loop {
                    rng.fill(&mut b);
                    if bp256::r1::SecretKey::from_bytes(&bp256::r1::FieldBytes::from(b)).is_ok() {
                        break;
                    }
                }
                let k = Self::from_scalar(curve, &b);
                b.zeroize();
                k
            }
            Curve::Bp384 => {
                let mut b = [0u8; 48];
                loop {
                    rng.fill(&mut b);
                    if bp384::r1::SecretKey::from_bytes(&bp384::r1::FieldBytes::from(b)).is_ok() {
                        break;
                    }
                }
                let k = Self::from_scalar(curve, &b);
                b.zeroize();
                k
            }
            Curve::Ed25519 | Curve::X25519 => {
                let mut s = [0u8; 32];
                rng.fill(&mut s);
                let k = Self::from_scalar(curve, &s);
                s.zeroize();
                k
            }
        }
    }

    /// The key's curve. Public for the PIV applet, which reuses [`PrivKey`] with
    /// its own sealing format.
    pub fn curve(&self) -> Curve {
        match self {
            PrivKey::P256(_) => Curve::P256,
            PrivKey::P384(_) => Curve::P384,
            PrivKey::P521(_) => Curve::P521,
            PrivKey::K256(_) => Curve::K256,
            PrivKey::Bp256(_) => Curve::Bp256,
            PrivKey::Bp384(_) => Curve::Bp384,
            PrivKey::Ed25519(_) => Curve::Ed25519,
            PrivKey::X25519(_) => Curve::X25519,
        }
    }

    /// The raw private scalar / seed. Public for the PIV applet's own sealing
    /// format; treat as key material.
    pub fn scalar(&self) -> &[u8] {
        match self {
            PrivKey::P256(s)
            | PrivKey::K256(s)
            | PrivKey::Bp256(s)
            | PrivKey::Ed25519(s)
            | PrivKey::X25519(s) => s,
            PrivKey::P384(s) | PrivKey::Bp384(s) => s,
            PrivKey::P521(s) => s,
        }
    }

    /// Sign `prehash` (the message digest gpg sends for ECDSA, or the raw message
    /// for EdDSA) into `out` as raw `r ‖ s` (or the 64-byte EdDSA signature);
    /// returns the length. All curves now sign deterministically (RFC 6979; 0.14's
    /// p521 gained a deterministic signer), so no RNG is used — `_rng` is kept only
    /// for the shared applet signature.
    pub fn sign(&self, prehash: &[u8], _rng: &mut dyn Rng, out: &mut [u8]) -> Result<usize, Sw> {
        fn put(b: &[u8], out: &mut [u8]) -> usize {
            out[..b.len()].copy_from_slice(b);
            b.len()
        }
        match self {
            // NIST/secp curves sign through the shared fixed-base comb (k·G) —
            // byte-identical to the crate's `sign_prehash`, but without the wasted
            // public-key derivation the generic `SigningKey` did on every signature.
            PrivKey::P256(s) => {
                use p256::elliptic_curve::PrimeField;
                let d = Zeroizing::new(
                    Option::<p256::Scalar>::from(p256::Scalar::from_repr(p256::FieldBytes::from(
                        *s,
                    )))
                    .ok_or(Sw::EXEC_ERROR)?,
                );
                let nz = Zeroizing::new(
                    Option::<p256::NonZeroScalar>::from(p256::NonZeroScalar::new(*d))
                        .ok_or(Sw::EXEC_ERROR)?,
                );
                let sig = rsk_ec::sign_p256(&nz, prehash).ok_or(Sw::EXEC_ERROR)?;
                Ok(put(sig.to_bytes().as_slice(), out))
            }
            PrivKey::P384(s) => {
                use p384::elliptic_curve::PrimeField;
                let d = Zeroizing::new(
                    Option::<p384::Scalar>::from(p384::Scalar::from_repr(p384::FieldBytes::from(
                        *s,
                    )))
                    .ok_or(Sw::EXEC_ERROR)?,
                );
                let nz = Zeroizing::new(
                    Option::<p384::NonZeroScalar>::from(p384::NonZeroScalar::new(*d))
                        .ok_or(Sw::EXEC_ERROR)?,
                );
                let sig = rsk_ec::sign_p384(&nz, prehash).ok_or(Sw::EXEC_ERROR)?;
                Ok(put(sig.to_bytes().as_slice(), out))
            }
            PrivKey::K256(s) => {
                use k256::elliptic_curve::PrimeField;
                let d = Zeroizing::new(
                    Option::<k256::Scalar>::from(k256::Scalar::from_repr(k256::FieldBytes::from(
                        *s,
                    )))
                    .ok_or(Sw::EXEC_ERROR)?,
                );
                let nz = Zeroizing::new(
                    Option::<k256::NonZeroScalar>::from(k256::NonZeroScalar::new(*d))
                        .ok_or(Sw::EXEC_ERROR)?,
                );
                let sig = rsk_ec::sign_k256(&nz, prehash).ok_or(Sw::EXEC_ERROR)?;
                Ok(put(sig.to_bytes().as_slice(), out))
            }
            PrivKey::P521(s) => {
                // 0.14's p521 has a deterministic RFC 6979 signer (its `sha512` feature),
                // so no random nonce / rand_core adapter is needed here. (FIDO's comb path
                // instead signs P-521 with a random TRNG nonce -- both are safe.)
                let k = p521::ecdsa::SigningKey::from_bytes(&p521::FieldBytes::from(*s))
                    .map_err(|_| Sw::EXEC_ERROR)?;
                let sig: p521::ecdsa::Signature =
                    k.sign_prehash(prehash).map_err(|_| Sw::EXEC_ERROR)?;
                let b = sig.to_bytes();
                Ok(put(&b[..], out))
            }
            PrivKey::Bp256(s) => sign_bp256(s, prehash, out),
            PrivKey::Bp384(s) => sign_bp384(s, prehash, out),
            PrivKey::Ed25519(seed) => {
                use ed25519_dalek::Signer;
                let k = ed25519_dalek::SigningKey::from_bytes(seed);
                let sig = k.sign(prehash);
                Ok(put(&sig.to_bytes(), out))
            }
            PrivKey::X25519(_) => Err(Sw::FUNC_NOT_SUPPORTED), // ECDH-only, never signs
        }
    }

    /// The public point for the public-key DO: uncompressed `04 ‖ x ‖ y` for the
    /// Weierstrass curves, the 32-byte compressed point for Ed25519, the 32-byte
    /// little-endian u-coordinate for X25519. Returns the length written to `out`.
    pub fn public_point(&self, out: &mut [u8]) -> Result<usize, Sw> {
        fn put(b: &[u8], out: &mut [u8]) -> usize {
            out[..b.len()].copy_from_slice(b);
            b.len()
        }
        match self {
            // Public-key derivation `d·G` is fixed-base — the shared comb (identical
            // point to the crate's `verifying_key`, several× faster on Cortex-M33).
            PrivKey::P256(s) => {
                use p256::elliptic_curve::PrimeField;
                use p256::elliptic_curve::sec1::ToSec1Point;
                let d = Zeroizing::new(
                    Option::<p256::Scalar>::from(p256::Scalar::from_repr(p256::FieldBytes::from(
                        *s,
                    )))
                    .ok_or(Sw::EXEC_ERROR)?,
                );
                let nz = Zeroizing::new(
                    Option::<p256::NonZeroScalar>::from(p256::NonZeroScalar::new(*d))
                        .ok_or(Sw::EXEC_ERROR)?,
                );
                let pt = rsk_ec::comb_mul_p256(&nz).to_affine().to_sec1_point(false);
                Ok(put(pt.as_bytes(), out))
            }
            PrivKey::P384(s) => {
                use p384::elliptic_curve::PrimeField;
                use p384::elliptic_curve::sec1::ToSec1Point;
                let d = Zeroizing::new(
                    Option::<p384::Scalar>::from(p384::Scalar::from_repr(p384::FieldBytes::from(
                        *s,
                    )))
                    .ok_or(Sw::EXEC_ERROR)?,
                );
                let nz = Zeroizing::new(
                    Option::<p384::NonZeroScalar>::from(p384::NonZeroScalar::new(*d))
                        .ok_or(Sw::EXEC_ERROR)?,
                );
                let pt = rsk_ec::comb_mul_p384(&nz).to_affine().to_sec1_point(false);
                Ok(put(pt.as_bytes(), out))
            }
            PrivKey::K256(s) => {
                use k256::elliptic_curve::PrimeField;
                use k256::elliptic_curve::sec1::ToSec1Point;
                let d = Zeroizing::new(
                    Option::<k256::Scalar>::from(k256::Scalar::from_repr(k256::FieldBytes::from(
                        *s,
                    )))
                    .ok_or(Sw::EXEC_ERROR)?,
                );
                let nz = Zeroizing::new(
                    Option::<k256::NonZeroScalar>::from(k256::NonZeroScalar::new(*d))
                        .ok_or(Sw::EXEC_ERROR)?,
                );
                let pt = rsk_ec::comb_mul_k256(&nz).to_affine().to_sec1_point(false);
                Ok(put(pt.as_bytes(), out))
            }
            PrivKey::P521(s) => {
                use p521::elliptic_curve::PrimeField;
                use p521::elliptic_curve::sec1::ToSec1Point;
                let d = Zeroizing::new(
                    Option::<p521::Scalar>::from(p521::Scalar::from_repr(p521::FieldBytes::from(
                        *s,
                    )))
                    .ok_or(Sw::EXEC_ERROR)?,
                );
                let nz = Zeroizing::new(
                    Option::<p521::NonZeroScalar>::from(p521::NonZeroScalar::new(*d))
                        .ok_or(Sw::EXEC_ERROR)?,
                );
                let pt = rsk_ec::comb_mul_p521(&nz).to_affine().to_sec1_point(false);
                Ok(put(pt.as_bytes(), out))
            }
            PrivKey::Bp256(s) => pubkey_bp256(s, out),
            PrivKey::Bp384(s) => pubkey_bp384(s, out),
            PrivKey::Ed25519(seed) => {
                let k = ed25519_dalek::SigningKey::from_bytes(seed);
                Ok(put(&k.verifying_key().to_bytes(), out))
            }
            PrivKey::X25519(s) => {
                let mut le = *s;
                le.reverse();
                let pk = x25519_dalek::x25519(le, x25519_dalek::X25519_BASEPOINT_BYTES);
                le.zeroize();
                Ok(put(&pk, out))
            }
        }
    }

    /// ECDH: compute the shared secret with the peer's `peer_point`, writing it to
    /// `out` (the OpenPGP DECIPHER result). The Weierstrass curves (P-256/384/521,
    /// secp256k1) parse a SEC1 peer point and return the affine x-coordinate;
    /// X25519/Cv25519 (Montgomery, RFC 7748) is separate. Ed25519 is signing-only.
    pub fn ecdh(&self, peer_point: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
        match self {
            PrivKey::P256(s) => ecdh_p256(s, peer_point, out),
            PrivKey::P384(s) => ecdh_p384(s, peer_point, out),
            PrivKey::P521(s) => ecdh_p521(s, peer_point, out),
            PrivKey::K256(s) => ecdh_k256(s, peer_point, out),
            PrivKey::Bp256(s) => ecdh_bp256(s, peer_point, out),
            PrivKey::Bp384(s) => ecdh_bp384(s, peer_point, out),
            PrivKey::X25519(s) => ecdh_x25519(s, peer_point, out),
            PrivKey::Ed25519(_) => Err(Sw::FUNC_NOT_SUPPORTED),
        }
    }
}

/// P-256 ECDH: peer point parsed as a SEC1 uncompressed point, shared secret =
/// the affine x-coordinate.
fn ecdh_p256(scalar: &[u8; 32], peer_point: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
    let sk = p256::SecretKey::from_bytes(&p256::FieldBytes::from(*scalar))
        .map_err(|_| Sw::DATA_INVALID)?;
    let ep = p256::Sec1Point::from_bytes(peer_point).map_err(|_| Sw::DATA_INVALID)?;
    let peer = Option::<p256::PublicKey>::from(p256::PublicKey::from_sec1_point(&ep))
        .ok_or(Sw::DATA_INVALID)?;
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    let z = shared.raw_secret_bytes();
    out[..z.len()].copy_from_slice(z.as_slice());
    Ok(z.len())
}

/// P-384 ECDH — same SEC1 idiom as [`ecdh_p256`], 48-byte shared x-coordinate.
fn ecdh_p384(scalar: &[u8; 48], peer_point: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
    let sk = p384::SecretKey::from_bytes(&p384::FieldBytes::from(*scalar))
        .map_err(|_| Sw::DATA_INVALID)?;
    let ep = p384::Sec1Point::from_bytes(peer_point).map_err(|_| Sw::DATA_INVALID)?;
    let peer = Option::<p384::PublicKey>::from(p384::PublicKey::from_sec1_point(&ep))
        .ok_or(Sw::DATA_INVALID)?;
    let shared = p384::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    let z = shared.raw_secret_bytes();
    out[..z.len()].copy_from_slice(z.as_slice());
    Ok(z.len())
}

/// P-521 ECDH — 66-byte shared x-coordinate.
fn ecdh_p521(scalar: &[u8; 66], peer_point: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
    let sk = p521::SecretKey::from_bytes(&p521::FieldBytes::from(*scalar))
        .map_err(|_| Sw::DATA_INVALID)?;
    let ep = p521::Sec1Point::from_bytes(peer_point).map_err(|_| Sw::DATA_INVALID)?;
    let peer = Option::<p521::PublicKey>::from(p521::PublicKey::from_sec1_point(&ep))
        .ok_or(Sw::DATA_INVALID)?;
    let shared = p521::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    let z = shared.raw_secret_bytes();
    out[..z.len()].copy_from_slice(z.as_slice());
    Ok(z.len())
}

/// secp256k1 ECDH — 32-byte shared x-coordinate.
fn ecdh_k256(scalar: &[u8; 32], peer_point: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
    let sk = k256::SecretKey::from_bytes(&k256::FieldBytes::from(*scalar))
        .map_err(|_| Sw::DATA_INVALID)?;
    let ep = k256::Sec1Point::from_bytes(peer_point).map_err(|_| Sw::DATA_INVALID)?;
    let peer = Option::<k256::PublicKey>::from(k256::PublicKey::from_sec1_point(&ep))
        .ok_or(Sw::DATA_INVALID)?;
    let shared = k256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    let z = shared.raw_secret_bytes();
    out[..z.len()].copy_from_slice(z.as_slice());
    Ok(z.len())
}

// brainpoolP256r1 / brainpoolP384r1 (bp256/bp384 0.14, fiat-crypto backend). These
// crates leave `SigningKey`/`VerifyingKey` generic in `ecdsa`, so name them there;
// signing is deterministic RFC 6979 (bp `sha256`/`sha384` feature) like P-256/P-384.

/// brainpoolP256r1 ECDSA — raw `r ‖ s` (64 bytes).
fn sign_bp256(s: &[u8; 32], prehash: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
    use ecdsa::signature::hazmat::PrehashSigner;
    let k =
        ecdsa::SigningKey::<bp256::BrainpoolP256r1>::from_bytes(&bp256::r1::FieldBytes::from(*s))
            .map_err(|_| Sw::EXEC_ERROR)?;
    let sig: bp256::r1::ecdsa::Signature = k.sign_prehash(prehash).map_err(|_| Sw::EXEC_ERROR)?;
    let b = sig.to_bytes();
    out[..b.len()].copy_from_slice(&b);
    Ok(b.len())
}

/// brainpoolP384r1 ECDSA — raw `r ‖ s` (96 bytes).
fn sign_bp384(s: &[u8; 48], prehash: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
    use ecdsa::signature::hazmat::PrehashSigner;
    let k =
        ecdsa::SigningKey::<bp384::BrainpoolP384r1>::from_bytes(&bp384::r1::FieldBytes::from(*s))
            .map_err(|_| Sw::EXEC_ERROR)?;
    let sig: bp384::r1::ecdsa::Signature = k.sign_prehash(prehash).map_err(|_| Sw::EXEC_ERROR)?;
    let b = sig.to_bytes();
    out[..b.len()].copy_from_slice(&b);
    Ok(b.len())
}

/// brainpoolP256r1 public point: SEC1 uncompressed `04 ‖ x ‖ y` (65 bytes).
fn pubkey_bp256(s: &[u8; 32], out: &mut [u8]) -> Result<usize, Sw> {
    let k =
        ecdsa::SigningKey::<bp256::BrainpoolP256r1>::from_bytes(&bp256::r1::FieldBytes::from(*s))
            .map_err(|_| Sw::EXEC_ERROR)?;
    let pt = k.verifying_key().to_sec1_point(false);
    let b = pt.as_bytes();
    out[..b.len()].copy_from_slice(b);
    Ok(b.len())
}

/// brainpoolP384r1 public point: SEC1 uncompressed `04 ‖ x ‖ y` (97 bytes).
fn pubkey_bp384(s: &[u8; 48], out: &mut [u8]) -> Result<usize, Sw> {
    let k =
        ecdsa::SigningKey::<bp384::BrainpoolP384r1>::from_bytes(&bp384::r1::FieldBytes::from(*s))
            .map_err(|_| Sw::EXEC_ERROR)?;
    let pt = k.verifying_key().to_sec1_point(false);
    let b = pt.as_bytes();
    out[..b.len()].copy_from_slice(b);
    Ok(b.len())
}

/// brainpoolP256r1 ECDH — SEC1 peer point, 32-byte shared x-coordinate.
fn ecdh_bp256(scalar: &[u8; 32], peer_point: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
    let sk = bp256::r1::SecretKey::from_bytes(&bp256::r1::FieldBytes::from(*scalar))
        .map_err(|_| Sw::DATA_INVALID)?;
    let pk =
        bp256::elliptic_curve::PublicKey::<bp256::BrainpoolP256r1>::from_sec1_bytes(peer_point)
            .map_err(|_| Sw::DATA_INVALID)?;
    let shared =
        bp256::elliptic_curve::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    let z = shared.raw_secret_bytes();
    out[..z.len()].copy_from_slice(z.as_slice());
    Ok(z.len())
}

/// brainpoolP384r1 ECDH — SEC1 peer point, 48-byte shared x-coordinate.
fn ecdh_bp384(scalar: &[u8; 48], peer_point: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
    let sk = bp384::r1::SecretKey::from_bytes(&bp384::r1::FieldBytes::from(*scalar))
        .map_err(|_| Sw::DATA_INVALID)?;
    let pk =
        bp384::elliptic_curve::PublicKey::<bp384::BrainpoolP384r1>::from_sec1_bytes(peer_point)
            .map_err(|_| Sw::DATA_INVALID)?;
    let shared =
        bp384::elliptic_curve::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    let z = shared.raw_secret_bytes();
    out[..z.len()].copy_from_slice(z.as_slice());
    Ok(z.len())
}

/// X25519 ECDH (OpenPGP Cv25519). The stored scalar is the big-endian MPI; X25519
/// wants it little-endian (RFC 7748) — reverse it (x25519-dalek clamps). The peer
/// key arrives as the OpenPGP `0x40`-prefixed native point (little-endian
/// u-coordinate); accept it with or without the prefix. The shared secret is the
/// 32-byte little-endian X25519 result.
fn ecdh_x25519(scalar_be: &[u8; 32], peer_point: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
    let u = match peer_point.len() {
        33 if peer_point[0] == 0x40 => &peer_point[1..],
        32 => peer_point,
        _ => return Err(Sw::DATA_INVALID),
    };
    let mut peer = [0u8; 32];
    peer.copy_from_slice(u);
    let mut le = *scalar_be;
    le.reverse();
    let mut shared = x25519_dalek::x25519(le, peer);
    le.zeroize();
    out[..32].copy_from_slice(&shared);
    shared.zeroize();
    Ok(32)
}

// -------------------------------------------------------- store / load / DO --

/// Seal the EC private key under the DEK and write it to `fid`
/// (`EF_PK_SIG`/`DEC`/`AUT`). Blob = `dek_encrypt([curve_id] ‖ scalar)`.
pub fn store_ec_key<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    fid: KeyFid,
    key: &PrivKey,
) -> Result<(), Sw> {
    let scalar = key.scalar();
    let n = 1 + scalar.len();
    let mut kdata = [0u8; MAX_EC_KDATA];
    kdata[0] = key.curve().id();
    kdata[1..n].copy_from_slice(scalar);
    let mut blob = [0u8; MAX_EC_KDATA + DEK_SEAL_OVERHEAD];
    let r = (|| {
        let bn = dek_seal(dev, fs, sess, fid, &kdata[..n], &mut blob)?;
        fs.put_key(fid, Sealed::wrap(&blob[..bn]))
            .map_err(|_| Sw::MEMORY_FAILURE)
    })();
    kdata.zeroize();
    blob.zeroize();
    r
}

/// Read and unseal the EC key stored at `fid`. A key still in the legacy CFB
/// seal is transparently re-sealed to the authenticated fresh-nonce format.
pub fn load_ec_key<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    fid: KeyFid,
) -> Result<PrivKey, Sw> {
    let mut blob = [0u8; MAX_EC_KDATA + DEK_SEAL_OVERHEAD];
    let n = fs.read_key(fid, &mut blob).ok_or(Sw::REFERENCE_NOT_FOUND)?;
    let n = n.min(blob.len());
    let mut kdata = [0u8; MAX_EC_KDATA];
    let r = (|| {
        let (pt, legacy) = dek_unseal(dev, fs, sess, &blob[..n], &mut kdata, legacy_ec_len)?;
        if pt < 2 {
            return Err(Sw::WRONG_DATA);
        }
        let curve = Curve::from_id(kdata[0]).ok_or(Sw::WRONG_DATA)?;
        let key = PrivKey::from_scalar(curve, &kdata[1..pt]).ok_or(Sw::WRONG_DATA)?;
        Ok((key, legacy))
    })();
    kdata.zeroize();
    blob.zeroize();
    let (key, legacy) = r?;
    if legacy {
        let _ = store_ec_key(dev, fs, sess, fid, &key);
    }
    Ok(key)
}

/// Wrap a public point as the OpenPGP public-key DO `7F49 { 86 <point> }`, with
/// long-form lengths when the point ≥ 128 bytes (P-521). Returns the DO length.
pub fn make_ec_pubkey_do(point: &[u8], out: &mut [u8]) -> usize {
    let plen = point.len();
    let long = plen >= 128;
    let mut p = 0;
    out[p] = 0x7f;
    p += 1;
    out[p] = 0x49;
    p += 1;
    if long {
        out[p] = 0x81;
        p += 1;
    }
    out[p] = (plen + if long { 3 } else { 2 }) as u8;
    p += 1;
    out[p] = 0x86;
    p += 1;
    if long {
        out[p] = 0x81;
        p += 1;
    }
    out[p] = plen as u8;
    p += 1;
    out[p..p + plen].copy_from_slice(point);
    p + plen
}

/// Seal an AES key under the DEK and write it to `EF_AES_KEY`. A DEC GENERATE
/// seeds an AES-256 key when the DO is empty; `PUT DATA D5` installs a
/// host-supplied one, and nothing overwrites that.
///
/// [`AES_KEY_LENS`] is enforced HERE, not at the callers: the widths are what
/// `load_aes_key` and `aes_pso` can serve, and a slot sealed at any other one is
/// unreadable and undeletable. It is not unrecoverable — this writes through
/// without reading the old value, so `PUT DATA D5` repairs any unloadable record —
/// but two callers make the check a coin-flip away from living in only one.
pub fn store_aes_key<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    key: &[u8],
) -> Result<(), Sw> {
    if !AES_KEY_LENS.contains(&key.len()) {
        return Err(Sw::WRONG_DATA);
    }
    let mut blob = [0u8; 32 + DEK_SEAL_OVERHEAD];
    let r = (|| {
        let bn = dek_seal(dev, fs, sess, EF_AES_KEY, key, &mut blob)?;
        fs.put_key(EF_AES_KEY, Sealed::wrap(&blob[..bn]))
            .map_err(|_| Sw::MEMORY_FAILURE)
    })();
    blob.zeroize();
    r
}

/// Load + DEK-unseal the symmetric AES key (`EF_AES_KEY`) for the AES PSO
/// operations. Returns the key bytes in a 32-byte buffer plus the real length
/// (16/24/32 → AES-128/192/256); the caller zeroizes the buffer after use.
pub fn load_aes_key<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
) -> Result<([u8; 32], usize), Sw> {
    let mut blob = [0u8; 32 + DEK_SEAL_OVERHEAD];
    let bn = fs
        .read_key(EF_AES_KEY, &mut blob)
        .filter(|&n| n > 0)
        .ok_or(Sw::REFERENCE_NOT_FOUND)?;
    let bn = bn.min(blob.len());
    let mut kdata = [0u8; 32];
    let (n, legacy) = match dek_unseal(dev, fs, sess, &blob[..bn], &mut kdata, legacy_aes_len) {
        Ok(v) => v,
        Err(e) => {
            blob.zeroize();
            kdata.zeroize();
            return Err(e);
        }
    };
    blob.zeroize();
    // No legacy record can be narrower: GENERATE only ever minted 32 bytes, and
    // `PUT DATA D5` (which can write 16) has always sealed under GCM.
    if legacy && n == 32 {
        let _ = store_aes_key(dev, fs, sess, &kdata);
    }
    Ok((kdata, n))
}

// -------------------------------------------------------- signature counter --

/// Zero the PSO:CDS signature counter (on a new SIG key).
pub fn reset_sig_count<S: Storage>(fs: &mut Fs<S>) -> Result<(), Sw> {
    fs.put(EF_SIG_COUNT, &[0, 0, 0])
        .map_err(|_| Sw::MEMORY_FAILURE)
}

/// Bump the 3-byte big-endian PSO:CDS counter. If the PW-status "PW1 valid for
/// one signature" flag is set (`EF_PW_PRIV[0] == 0`), clears the PW1 session.
pub fn inc_sig_count<S: Storage>(fs: &mut Fs<S>, sess: &mut Session) -> Result<(), Sw> {
    let mut pw = [0u8; 8];
    if fs.read(EF_PW_PRIV, &mut pw).is_some() && pw[0] == 0 {
        sess.has_pw1 = false;
    }
    let mut c = [0u8; 3];
    fs.read(EF_SIG_COUNT, &mut c)
        .ok_or(Sw::REFERENCE_NOT_FOUND)?;
    let v = (((c[0] as u32) << 16) | ((c[1] as u32) << 8) | c[2] as u32).wrapping_add(1);
    let q = [(v >> 16) as u8, (v >> 8) as u8, v as u8];
    fs.put(EF_SIG_COUNT, &q).map_err(|_| Sw::MEMORY_FAILURE)
}

// ---------------------------------------------------------------------- RSA --
//
// Keygen, cert signing, and the public paths use the `rsa` crate (heap-backed);
// the applet's own PSO:CDS / INTERNAL AUTHENTICATE run the CRT private op on the
// UMAAL asm ([`rsa_crt`]). The stored blob is `P ‖ Q ‖ dP ‖ dQ ‖ qInv` (older
// `P ‖ Q` blobs still load); on load the exponent is forced to 65537 — gpg only
// ever imports e = 65537.

/// Largest RSA modulus handled (RSA-4096 = 512 bytes).
pub const MAX_RSA_BYTES: usize = 512;
/// Largest stored RSA blob: `P ‖ Q ‖ dP ‖ dQ ‖ qInv` for RSA-4096 (five 256-byte
/// fields — the CRT params cached alongside the primes; see [`rsa_crt`]).
const MAX_RSA_KDATA: usize = rsa_crt::MAX_CRT_PLAIN;
/// Largest RSA public-key DO `7F49 82 LL { 81 82 <N> · 82 <Elen> <E> }`.
pub const MAX_RSA_PUBDO: usize = 5 + 4 + MAX_RSA_BYTES + 2 + 8;

/// PKCS#1 DigestInfo prefixes (`SEQ { SEQ { OID, NULL }, OCTET STRING }` header,
/// without the trailing hash) for the five hashes `rsa_sign_em` recognises.
const DI_SHA1: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];
const DI_SHA224: &[u8] = &[
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
    0x00, 0x04, 0x1c,
];
const DI_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const DI_SHA384: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const DI_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];
const DIGESTINFOS: [(&[u8], usize); 5] = [
    (DI_SHA1, 20),
    (DI_SHA224, 28),
    (DI_SHA256, 32),
    (DI_SHA384, 48),
    (DI_SHA512, 64),
];

/// Build the RSA key from the imported exponent / primes (tags 0x91/0x92/0x93).
pub fn rsa_from_pqe(e: &[u8], p: &[u8], q: &[u8]) -> Option<RsaPrivateKey> {
    let p = BigUint::from_bytes_be(p);
    let q = BigUint::from_bytes_be(q);
    // from_p_q derives the totient via (p-1)(q-1); a zero prime MPI underflows
    // num-bigint's unsigned subtraction (a panic, not an Err) and halts the device
    // on import, so reject it here and let the caller's ok_or(EXEC_ERROR) do its job.
    if p < BigUint::from(2u8) || q < BigUint::from(2u8) {
        return None;
    }
    RsaPrivateKey::from_p_q(p, q, BigUint::from_bytes_be(e)).ok()
}

/// The RSA public exponent, fixed at 65537 (what `load_rsa_key` assumes).
const RSA_E: u32 = 65_537;

/// 65537 big-endian — the fixed PIV/generated RSA public exponent as bytes, so a
/// caller that already has the modulus (PIV GET METADATA) can build the public-key
/// DO without a `BigUint` or a magic literal. Equals `BigUint::from(RSA_E)` serialized.
pub const RSA_PUB_EXP_BE: &[u8] = &[0x01, 0x00, 0x01];

/// The RSA prime search as a *stepper*, so the CCID transport can yield — and
/// send time-extension keepalives — between candidates. Each
/// [`step`](RsaKeygen::step) tests ONE random candidate (a bounded chunk: one
/// `probably_prime`, ~tens of ms on-device), matching the `rsa` crate's keygen:
/// two `nbits/2`-bit primes with the top two bits set and `gcd(e, prime − 1) = 1`,
/// assembled with `RsaPrivateKey::from_p_q`. The primality decision is
/// Baillie-PSW split across backends: the strong Miller-Rabin base-2 half on
/// the KAT-gated asm modexp (ours, differentially tested against the library),
/// the strong Lucas half and key assembly the vetted library routines.
///
/// `step` decomposes into [`try_candidate`](RsaKeygen::try_candidate) (one
/// draw + test, stateless) and [`offer`](RsaKeygen::offer) (the two-prime
/// pool): the firmware runs `try_candidate` on BOTH RP2350 cores — each with
/// its own RNG stream — and funnels every find through one `offer` pool, so
/// the cores race for `p` and `q` and the expected search time roughly halves.
pub struct RsaKeygen {
    half_bytes: usize,
    e: BigUint,
    p: Option<BigUint>,
    /// Result of the asm modexp known-answer test, checked once up front: if the
    /// fast modexp is wrong on this build/silicon, refuse to generate (rather than
    /// emit a weak key). Always true on the host (num-bigint backend).
    asm_ok: bool,
}

// A keygen abandoned between steps still holds the first found prime.
impl Drop for RsaKeygen {
    fn drop(&mut self) {
        if let Some(p) = &mut self.p {
            p.zeroize();
        }
    }
}

/// The outcome of one [`RsaKeygen::step`]. The `Done` key is boxed so the enum
/// stays pointer-sized (it is returned up the call stack each step).
pub enum RsaStep {
    /// Candidate rejected, or the first prime was just found — call `step` again.
    More,
    /// Both primes found and the private key assembled.
    Done(Box<RsaPrivateKey>),
    /// Unusable parameters (unsupported modulus size) or a key-assembly failure.
    Failed,
}

impl RsaKeygen {
    /// Prepare to generate an `nbits`-bit modulus (only byte-aligned half-sizes —
    /// every real OpenPGP size, 2048/3072/4096, qualifies).
    pub fn new(nbits: usize) -> Self {
        RsaKeygen {
            half_bytes: nbits / 16,
            e: BigUint::from(RSA_E),
            p: None,
            asm_ok: self_test(),
        }
    }

    /// Whether this keygen can run at all: the modulus size is supported (the
    /// asm modexp needs the prime length to be a multiple of 32 bytes — every
    /// standard RSA size qualifies) and the modexp known-answer test passed
    /// (a broken fast modexp must never yield a key).
    pub fn usable(&self) -> bool {
        let half = self.half_bytes;
        self.asm_ok && half != 0 && half <= MAX_RSA_BYTES / 2 && half.is_multiple_of(32)
    }

    /// One prime's size in bytes (half the modulus).
    pub fn half_bytes(&self) -> usize {
        self.half_bytes
    }

    /// Draw and test ONE prime candidate of `half_bytes` — the bounded unit of
    /// search work. Stateless (an associated fn), so a second core can run it
    /// concurrently with its own RNG stream. The pipeline is Baillie-PSW split
    /// across backends: the cheap rejections (the small-prime sieve, the
    /// `gcd(e, n−1)` check), then the strong Miller-Rabin base-2 gate on the
    /// KAT-gated asm modexp, then the vetted software strong Lucas test for
    /// the final accept. Admitting a composite would take a simultaneous
    /// failure of both halves — the same combined guarantee
    /// `probably_prime(_, 0)` gives, with the modexp-heavy half on the fast
    /// path. The caller is responsible for the
    /// [`usable`](RsaKeygen::usable) gate.
    ///
    /// `sieve` is a running [`IncrementalSieve`] owned by the caller (one per
    /// core in the dual-core search): each call advances it by one candidate.
    /// A call that lands on a composite, or that reseeds an exhausted window,
    /// returns `None` cheaply; only a sieve survivor pays the modexp + Lucas.
    pub fn try_candidate(
        sieve: &mut IncrementalSieve,
        rng: &mut dyn Rng,
        half_bytes: usize,
    ) -> Option<BigUint> {
        match sieve.step() {
            None => {
                // Window exhausted (or never seeded) — draw a fresh random odd
                // top-two-bits start; this call yields no candidate.
                let mut seed = [0u8; MAX_RSA_BYTES / 2];
                rng.fill(&mut seed[..half_bytes]);
                sieve.reseed(half_bytes, &seed[..half_bytes]);
                seed.zeroize();
                return None;
            }
            Some(false) => return None, // composite by a small prime — cheap
            Some(true) => {}            // sieve survivor — run the dear tests
        }
        let n = sieve.candidate();
        // gcd(e, n − 1) == 1  ⇔  n ≢ 1 (mod e), since e is prime.
        if mod_small(n, RSA_E) == 1 {
            return None;
        }
        // The strong Miller-Rabin half of Baillie-PSW, on the asm modexp.
        if !passes_strong_mr_base2(n) {
            return None;
        }
        let cand = BigUint::from_bytes_le(n);
        // The strong Lucas half (vetted library code). Together with the MR
        // gate above this is exactly `probably_prime(_, 0)` — see the
        // `keygen_bpsw_split_matches_library` test.
        if !probably_prime_lucas(&cand) {
            return None;
        }
        Some(cand)
    }

    /// Feed a found prime into the two-prime pool: the first is held, a second
    /// *distinct* one completes the key (a duplicate is rejected and the held
    /// prime kept — the search just continues). Accepts primes found by any
    /// core, in any order.
    pub fn offer(&mut self, mut cand: BigUint) -> RsaStep {
        match self.p.take() {
            None => {
                self.p = Some(cand);
                RsaStep::More
            }
            Some(p) if p == cand => {
                self.p = Some(p);
                cand.zeroize();
                RsaStep::More
            }
            Some(p) => match RsaPrivateKey::from_p_q(p, cand, self.e.clone()) {
                Ok(k) => RsaStep::Done(Box::new(k)),
                Err(_) => RsaStep::Failed,
            },
        }
    }

    /// [`try_candidate`](RsaKeygen::try_candidate), returning the prime as
    /// little-endian bytes in `out` — the inter-core transport format (the
    /// second core ships raw bytes, not bignums, so the zeroize discipline
    /// stays in this crate). `out` must hold `half_bytes`; the candidate's top
    /// bits are set, so a find is always exactly `half_bytes` long.
    pub fn try_candidate_le(
        sieve: &mut IncrementalSieve,
        rng: &mut dyn Rng,
        half_bytes: usize,
        out: &mut [u8],
    ) -> Option<usize> {
        let mut p = Self::try_candidate(sieve, rng, half_bytes)?;
        let mut v = p.to_bytes_le();
        p.zeroize();
        let n = v.len();
        out[..n].copy_from_slice(&v);
        v.zeroize();
        Some(n)
    }

    /// [`offer`](RsaKeygen::offer) from little-endian bytes (the inter-core
    /// transport format); scrubs `bytes` after the conversion.
    pub fn offer_le(&mut self, bytes: &mut [u8]) -> RsaStep {
        // Belt-and-suspenders: a byte-transport find must be exactly this key's
        // half size — a wrong length is a stale prime from a prior different-size
        // job (mailbox scrubbed on engage, so never fires today); pooling corrupts n.
        if bytes.len() != self.half_bytes {
            bytes.zeroize();
            return RsaStep::More;
        }
        let cand = BigUint::from_bytes_le(bytes);
        bytes.zeroize();
        self.offer(cand)
    }

    /// Draw and test one prime candidate, feeding any find into the pool — the
    /// single-core step: [`try_candidate`](RsaKeygen::try_candidate) then
    /// [`offer`](RsaKeygen::offer). `sieve` is the caller's running window.
    pub fn step(&mut self, sieve: &mut IncrementalSieve, rng: &mut dyn Rng) -> RsaStep {
        if !self.usable() {
            return RsaStep::Failed;
        }
        match Self::try_candidate(sieve, rng, self.half_bytes) {
            None => RsaStep::More,
            Some(cand) => self.offer(cand),
        }
    }
}

/// Blocking RSA keygen — drives [`RsaKeygen`] to completion on one core. Used
/// by the synchronous `keypair_gen` (host tests, the non-CCID path); on the
/// device the firmware races `try_candidate` on both cores instead.
pub fn generate_rsa(rng: &mut dyn Rng, nbits: usize) -> Result<RsaPrivateKey, Sw> {
    let mut kg = RsaKeygen::new(nbits);
    let mut sieve = IncrementalSieve::new();
    loop {
        match kg.step(&mut sieve, rng) {
            RsaStep::Done(k) => return Ok(*k),
            RsaStep::Failed => return Err(Sw::EXEC_ERROR),
            RsaStep::More => {}
        }
    }
}

/// Seal the RSA key's CRT params `P ‖ Q ‖ dP ‖ dQ ‖ qInv` under the DEK and write
/// it to `fid`, so signing skips the per-op key rebuild (see [`rsa_crt`]).
pub fn store_rsa_key<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    fid: KeyFid,
    key: &RsaPrivateKey,
) -> Result<(), Sw> {
    let mut kdata = [0u8; MAX_RSA_KDATA];
    let mut blob = [0u8; MAX_RSA_KDATA + DEK_SEAL_OVERHEAD];
    let r = (|| {
        let n = rsa_crt::crt_plaintext(key, &mut kdata)?;
        let bn = dek_seal(dev, fs, sess, fid, &kdata[..n], &mut blob)?;
        fs.put_key(fid, Sealed::wrap(&blob[..bn]))
            .map_err(|_| Sw::MEMORY_FAILURE)
    })();
    kdata.zeroize();
    blob.zeroize();
    r
}

/// Read and unseal the RSA key at `fid`, rebuilding it from `P ‖ Q` (present at
/// the front of either the 2-field or the 5-field CRT layout) with `E = 65537`.
/// Used by the non-signing paths (DECIPHER, GET METADATA); signing uses
/// [`load_rsa_crt`], which skips the rebuild. A key still in the legacy CFB seal
/// is re-sealed forward.
pub fn load_rsa_key<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    fid: KeyFid,
) -> Result<RsaPrivateKey, Sw> {
    let mut blob = [0u8; MAX_RSA_KDATA + DEK_SEAL_OVERHEAD];
    let bn = fs.read_key(fid, &mut blob).ok_or(Sw::REFERENCE_NOT_FOUND)?;
    let bn = bn.min(blob.len());
    let mut kdata = [0u8; MAX_RSA_KDATA];
    let res = (|| {
        let (n, legacy) = dek_unseal(dev, fs, sess, &blob[..bn], &mut kdata, legacy_rsa_len)?;
        let (half, _) = rsa_crt::parse_rsa_blob(&kdata[..n]).map_err(|_| Sw::WRONG_DATA)?;
        let p = BigUint::from_bytes_be(&kdata[..half]);
        let q = BigUint::from_bytes_be(&kdata[half..2 * half]);
        let key =
            RsaPrivateKey::from_p_q(p, q, BigUint::from(RSA_E)).map_err(|_| Sw::WRONG_DATA)?;
        Ok((key, legacy))
    })();
    kdata.zeroize();
    blob.zeroize();
    let (key, legacy) = res?;
    if legacy {
        let _ = store_rsa_key(dev, fs, sess, fid, &key);
    }
    Ok(key)
}

/// Load the CRT signing parameters of an RSA key — new `P‖Q‖dP‖dQ‖qInv` blobs
/// slice directly, older `P‖Q` blobs recompute once (see [`rsa_crt::crt_from_plain`]).
/// A key still in the legacy CFB seal is re-sealed forward, upgrading it straight
/// to the 5-field authenticated layout.
pub fn load_rsa_crt<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    fid: KeyFid,
) -> Result<RsaCrt, Sw> {
    let mut blob = [0u8; MAX_RSA_KDATA + DEK_SEAL_OVERHEAD];
    let bn = fs.read_key(fid, &mut blob).ok_or(Sw::REFERENCE_NOT_FOUND)?;
    let bn = bn.min(blob.len());
    let mut kdata = [0u8; MAX_RSA_KDATA];
    let unsealed = dek_unseal(dev, fs, sess, &blob[..bn], &mut kdata, legacy_rsa_len);
    blob.zeroize();
    let (n, legacy) = match unsealed {
        Ok(v) => v,
        Err(e) => {
            kdata.zeroize();
            return Err(e);
        }
    };
    let crt = rsa_crt::crt_from_plain(&kdata[..n]);
    // Migrate a legacy CFB key forward — now straight to the 5-field GCM layout.
    if legacy
        && crt.is_ok()
        && let Ok((half, _)) = rsa_crt::parse_rsa_blob(&kdata[..n])
    {
        let p = BigUint::from_bytes_be(&kdata[..half]);
        let q = BigUint::from_bytes_be(&kdata[half..2 * half]);
        if let Ok(key) = RsaPrivateKey::from_p_q(p, q, BigUint::from(RSA_E)) {
            let _ = store_rsa_key(dev, fs, sess, fid, &key);
        }
    }
    kdata.zeroize();
    crt
}

/// Build the public-key DO `7F49 82 LL { 81 82 <N> · 82 <Elen> <E> }` (modulus
/// tag 0x81 with a 2-byte length, exponent tag 0x82 with a 1-byte one).
/// The inner RSA public-key body `81 82 <nlen:u16-be> N 82 <elen:u8> E` (no `7F49`
/// wrapper), from the modulus and exponent bytes. Returns its length
/// (`4 + n.len() + 2 + e.len()`). Shared by [`make_rsa_response`] and the PIV
/// GET METADATA path, which has `N` and `e` directly and must not rebuild the key.
pub fn make_rsa_pub_body(n: &[u8], e: &[u8], out: &mut [u8]) -> usize {
    out[0] = 0x81;
    out[1] = 0x82;
    out[2..4].copy_from_slice(&(n.len() as u16).to_be_bytes());
    let mut p = 4;
    out[p..p + n.len()].copy_from_slice(n);
    p += n.len();
    out[p] = 0x82;
    out[p + 1] = e.len() as u8;
    p += 2;
    out[p..p + e.len()].copy_from_slice(e);
    p + e.len()
}

pub fn make_rsa_response(key: &RsaPrivateKey, out: &mut [u8]) -> usize {
    out[0] = 0x7f;
    out[1] = 0x49;
    out[2] = 0x82; // 2-byte inner length, back-patched below
    // e stays sourced from the key: an imported OpenPGP key may carry a non-65537
    // exponent, so only the PIV metadata caller is allowed to hardcode 65537.
    let body = make_rsa_pub_body(
        &key.n().to_bytes_be(),
        &key.e().to_bytes_be(),
        &mut out[5..],
    );
    out[3..5].copy_from_slice(&(body as u16).to_be_bytes());
    5 + body
}

/// Find the recognised DigestInfo prefix + hash for a canonical PKCS#1 DigestInfo
/// (`SEQ { SEQ { OID, NULL }, OCTET STRING }`). gpg always sends the canonical
/// form, so a prefix + exact-length match identifies it without a full DER walk.
fn match_digestinfo(data: &[u8]) -> Option<(&'static [u8], &[u8])> {
    for (prefix, hlen) in DIGESTINFOS {
        if data.len() == prefix.len() + hlen && data.starts_with(prefix) {
            return Some((prefix, &data[prefix.len()..]));
        }
    }
    None
}

/// Largest DigestInfo `rsa_sign_em` builds: 19-byte prefix (SHA-512) + 64-byte hash.
pub const MAX_RSA_DIGESTINFO: usize = 19 + 64;

/// Decide what PKCS#1 v1.5 should sign: write the canonical DigestInfo
/// (`prefix ‖ hash`) for a recognised DigestInfo or a bare hash whose length
/// names the algorithm into `em`, returning its length; `None` means neither (the
/// raw private-op fallback). Pure (no key / modexp), so the `openpgp_rsa_sign`
/// fuzz target exercises the parser + buffer construction at full speed.
pub fn rsa_sign_em(data: &[u8], em: &mut [u8; MAX_RSA_DIGESTINFO]) -> Option<usize> {
    let (prefix, hash): (&[u8], &[u8]) = if let Some(di) = match_digestinfo(data) {
        di
    } else {
        let &(prefix, _) = DIGESTINFOS.iter().find(|&&(_, hlen)| hlen == data.len())?;
        (prefix, data)
    };
    let dlen = prefix.len() + hash.len();
    em[..prefix.len()].copy_from_slice(prefix);
    em[prefix.len()..dlen].copy_from_slice(hash);
    Some(dlen)
}

/// PKCS#1 v1.5 sign over the supplied data with the cached CRT params on the
/// UMAAL asm. If `data` is a DigestInfo (or a bare hash whose length names the
/// algorithm), build the EMSA-PKCS1-v1_5 encoding and sign that; otherwise treat
/// `data` as a raw block. Either way the block runs through the blinded,
/// Bellcore-fault-checked private op ([`rsa_crt::sign_crt`]).
pub fn rsa_sign_crt(
    crt: &RsaCrt,
    data: &[u8],
    rng: &mut dyn Rng,
    out: &mut [u8],
) -> Result<usize, Sw> {
    let mlen = crt.modulus_len();
    let mut em = [0u8; MAX_RSA_BYTES];
    let mut di = [0u8; MAX_RSA_DIGESTINFO];
    match rsa_sign_em(data, &mut di) {
        Some(dlen) => {
            // EM = 00 01 PS 00 ‖ DigestInfo, PS = 0xFF·(mlen−dlen−3), at least 8.
            if mlen < dlen + 11 {
                return Err(Sw::WRONG_LENGTH);
            }
            let ps_end = mlen - dlen - 1;
            em[1] = 0x01;
            em[2..ps_end].fill(0xff);
            em[ps_end + 1..mlen].copy_from_slice(&di[..dlen]);
        }
        // gpg never reaches this — it always sends a DigestInfo — but a raw block
        // still signs (left-padded to the modulus width) through the same blinded,
        // fault-checked op, so no non-conformant caller sees a different path.
        None => {
            if data.len() > mlen {
                return Err(Sw::WRONG_DATA);
            }
            em[mlen - data.len()..mlen].copy_from_slice(data);
        }
    }
    rsa_crt::sign_crt(crt, &em[..mlen], rng, out)
}

/// PKCS#1 v1.5 over the supplied data with a full [`RsaPrivateKey`] on the `rsa`
/// crate. Used by the PIV x509 cert-signing path (`rsk_piv::x509`); the OpenPGP
/// applet's own PSO:CDS / INTERNAL AUTHENTICATE use [`rsa_sign_crt`] (asm). If it
/// is a DigestInfo (or a bare hash whose length names the algorithm), sign that
/// digest; otherwise fall back to the raw private operation.
pub fn rsa_sign(
    key: &RsaPrivateKey,
    data: &[u8],
    rng: &mut dyn Rng,
    out: &mut [u8],
) -> Result<usize, Sw> {
    let mut em = [0u8; MAX_RSA_DIGESTINFO];
    let Some(dlen) = rsa_sign_em(data, &mut em) else {
        return rsa_raw(key, data, out, rng);
    };
    let sig = key
        .sign_with_rng(
            &mut RngAdapter(rng),
            Pkcs1v15Sign::new_unprefixed(),
            &em[..dlen],
        )
        .map_err(|_| Sw::EXEC_ERROR)?;
    out[..sig.len()].copy_from_slice(&sig);
    Ok(sig.len())
}

/// Run the raw RSA private operation `m^d mod n` (no padding scheme). gpg never
/// reaches this — it always sends a DigestInfo — but the operation is
/// base-blinded `(m·rᵉ)ᵈ·r⁻¹ mod n` with a fresh random `r`, so even a
/// non-conformant caller cannot turn `num-bigint-dig`'s variable-time
/// exponentiation into a Marvin-style timing oracle on the private exponent.
fn rsa_raw(
    key: &RsaPrivateKey,
    data: &[u8],
    out: &mut [u8],
    rng: &mut dyn Rng,
) -> Result<usize, Sw> {
    use num_bigint_dig::ModInverse;
    let key_size = key.size();
    if data.len() > key_size {
        return Err(Sw::WRONG_DATA);
    }
    let (n, e, d) = (key.n(), key.e(), key.d());
    let m = BigUint::from_bytes_be(data);
    // Fresh blinding factor r, invertible mod n (retry on the negligible chance
    // r shares a factor with n).
    let (r, r_inv) = loop {
        let mut rb = [0u8; MAX_RSA_BYTES];
        rng.fill(&mut rb[..key_size]);
        let cand = BigUint::from_bytes_be(&rb[..key_size]) % n;
        if let Some(inv) = (&cand).mod_inverse(n).and_then(|i| i.to_biguint()) {
            break (cand, inv);
        }
    };
    let blinded = (&m * r.modpow(e, n)) % n;
    let res = (blinded.modpow(d, n) * r_inv) % n;
    let rb = res.to_bytes_be();
    if rb.len() > key_size {
        return Err(Sw::EXEC_ERROR);
    }
    let off = key_size - rb.len();
    out[..off].fill(0);
    out[off..key_size].copy_from_slice(&rb);
    Ok(key_size)
}

/// PSO:DECIPHER for RSA: strip the leading OpenPGP padding-indicator byte, run
/// `cᵈ mod n` on the asm CRT core — blinded and Bellcore-fault-checked, the same
/// private op PSO:CDS uses — then unpad PKCS#1 v1.5 in constant time. `data` is
/// the raw command data field (`apdu.data`).
pub fn rsa_decipher(
    crt: &RsaCrt,
    rng: &mut dyn Rng,
    data: &[u8],
    out: &mut [u8],
) -> Result<usize, Sw> {
    let key_size = crt.modulus_len();
    let ct = data.get(1..1 + key_size).ok_or(Sw::WRONG_DATA)?;
    let mut em = [0u8; MAX_RSA_BYTES];
    // A malformed block answered `EXEC_ERROR` when the `rsa` crate owned this
    // path; keep that status word, so moving the implementation does not move the
    // wire surface with it.
    let res = rsa_crt::sign_crt(crt, ct, rng, &mut em[..key_size])
        .and_then(|_| pkcs1v15::unpad_encrypt(&em[..key_size], out).map_err(|_| Sw::EXEC_ERROR));
    em.zeroize();
    res
}

/// [`rsa_decipher`] for a key the asm CRT core cannot take: a legacy `P‖Q` blob
/// whose prime width is not a 32-multiple, which older firmware could store and
/// which [`rsa_crt::crt_from_plain`] refuses. Such a key already cannot sign; it
/// would lose the ability to decrypt its own archived messages too, so it keeps
/// the `rsa` crate's blinded decrypt — the one place RUSTSEC-2023-0071 still
/// touches this applet (`docs/limitations.md`).
pub fn rsa_decipher_legacy(
    key: &RsaPrivateKey,
    rng: &mut dyn Rng,
    data: &[u8],
    out: &mut [u8],
) -> Result<usize, Sw> {
    let key_size = key.size();
    let ct = data.get(1..1 + key_size).ok_or(Sw::WRONG_DATA)?;
    let mut pt = key
        .decrypt_blinded(&mut RngAdapter(rng), Pkcs1v15Encrypt, ct)
        .map_err(|_| Sw::EXEC_ERROR)?;
    out[..pt.len()].copy_from_slice(&pt);
    let n = pt.len();
    pt.zeroize();
    Ok(n)
}

/// Adapts the crate [`Rng`] to the `rsa` crate's `rand_core` (still 0.6, distinct
/// from the EC stack's 0.10) for RSA blinding / signing. The EC curves no longer
/// need it — deterministic signers, and keygen reject-samples raw bytes.
/// `pub(crate)` so the applet tests can drive the `rsa` crate's randomized APIs.
pub(crate) struct RngAdapter<'a>(pub(crate) &'a mut dyn Rng);

impl rsa::rand_core::RngCore for RngAdapter<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.0.fill(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.0.fill(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.0.fill(dst);
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.0.fill(dst);
        Ok(())
    }
}
impl rsa::rand_core::CryptoRng for RngAdapter<'_> {}

#[cfg(test)]
#[path = "keys_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "keys_rsa_tests.rs"]
mod rsa_tests;

#[cfg(test)]
#[path = "keys_x25519_tests.rs"]
mod x25519_tests;
