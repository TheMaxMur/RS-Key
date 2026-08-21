// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Private-key sealing and the asymmetric operations. Keys live in the internal
//! EFs `EF_PK_SIG`/`DEC`/`AUT`, AES-256-GCM-sealed under the random DEK (key =
//! `dek[16..48]`, nonce-PRF key = `dek[0..16]`; the DEK itself is PIN-wrapped,
//! see [`crate::pin`]). EC blobs are `[curve_id] ‖ scalar`; signatures are raw
//! `r ‖ s` (fixed field width), NOT DER.

use zeroize::Zeroize;

use rsk_crypto::aes::aes_decrypt_cfb_256;
use rsk_crypto::{Device, aes256gcm_decrypt, aes256gcm_encrypt, hmac_sha256};
use rsk_fs::{Fs, KeyFid, Sealed, Storage};
use rsk_sdk::Sw;

use rsk_ec::{Curve, EcError, PrivKey};
use rsk_rsa::{MAX_CRT_PLAIN, MAX_RSA_BYTES, RsaCrt, RsaError};

// Re-exported for `rsk-display`, the only caller that names the keygen result
// type (`Box<RsaKey>`, in its `Hooks`) without an `rsk-rsa` dependency of its
// own; the firmware and the emulator have one and go direct.
pub use rsk_rsa::RsaKey;

use crate::Rng;
use crate::consts::*;
use crate::dobj::{
    ATTR_BP256R1, ATTR_BP384R1, ATTR_CV25519, ATTR_ED25519, ATTR_P256K1, ATTR_P256R1, ATTR_P384R1,
    ATTR_P521R1,
};
use crate::pin::{Session, load_dek};

/// Hands the applet-tier randomness seam ([`rsk_sdk::Rng`]) to `rsk-rsa`, which
/// declares its own identical one: it is an algorithm crate two tiers down and
/// naming `rsk-sdk` would invert the dependency. Same bytes, one more vtable hop
/// on the paths that draw a blinding factor or PKCS#1 padding, not per limb.
pub(crate) struct RsaRng<'a>(pub(crate) &'a mut dyn Rng);

impl rsk_rsa::Rng for RsaRng<'_> {
    fn fill(&mut self, buf: &mut [u8]) {
        self.0.fill(buf);
    }
}

/// The same bridge for `rsk-ec`, which declares its own `Rng` for the same
/// reason. Only [`rsk_ec::PrivKey::generate`] draws from it — signing and
/// public-point derivation are deterministic.
pub(crate) struct EcRng<'a>(pub(crate) &'a mut dyn Rng);

impl rsk_ec::Rng for EcRng<'_> {
    fn fill(&mut self, buf: &mut [u8]) {
        self.0.fill(buf);
    }
}

/// The status word each [`EcError`] answers with. This table **is** wire
/// surface — `ec_sw_reproduces_every_status_word` pins all three arms — and
/// `rsk-piv` carries its own copy, for the reason `rsk_ec::EcError`'s module
/// doc gives: a shared mapping in `rsk-sdk` would put the EC crate in every
/// applet's dependency closure.
pub(crate) fn ec_sw(e: EcError) -> Sw {
    match e {
        EcError::Failed => Sw::EXEC_ERROR,
        EcError::BadPoint => Sw::DATA_INVALID,
        EcError::Unsupported => Sw::FUNC_NOT_SUPPORTED,
    }
}

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
/// half that [`rsk_rsa::crt::parse_rsa_blob`] would accept (32..=256, a multiple of 32).
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
// The algorithm lives in [`rsk_rsa`]; what stays here is the applet's own half —
// sealing a key into the DEK-protected store, loading it back, and the
// PSO:DECIPHER command framing. The stored blob is `P ‖ Q ‖ dP ‖ dQ ‖ qInv`
// (older `P ‖ Q` blobs still load); on load the exponent is forced to 65537 —
// gpg only ever imports e = 65537.

/// The status word each [`RsaError`] answers with. This table **is** wire
/// surface — `rsa_sw_reproduces_every_status_word` pins all four arms — and
/// `rsk-piv` carries its own copy: the one crate that could host a shared
/// mapping is `rsk-sdk`, and paying for it there would put the RSA crate in
/// every applet's dependency closure. Whole argument: `rsk-rsa/src/error.rs`.
pub(crate) fn rsa_sw(e: RsaError) -> Sw {
    match e {
        RsaError::BadWidth => Sw::WRONG_LENGTH,
        RsaError::BadBlock => Sw::WRONG_DATA,
        RsaError::BadBlob => Sw::MEMORY_FAILURE,
        RsaError::Failed => Sw::EXEC_ERROR,
    }
}

/// Seal the RSA key's CRT params `P ‖ Q ‖ dP ‖ dQ ‖ qInv` under the DEK and write
/// it to `fid`, so signing skips the per-op key rebuild (see [`rsk_rsa::crt`]).
pub fn store_rsa_key<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    fid: KeyFid,
    key: &RsaKey,
) -> Result<(), Sw> {
    let mut kdata = [0u8; MAX_CRT_PLAIN];
    let mut blob = [0u8; MAX_CRT_PLAIN + DEK_SEAL_OVERHEAD];
    let r = (|| {
        let n = rsk_rsa::crt::crt_plaintext(key, &mut kdata).map_err(rsa_sw)?;
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
) -> Result<RsaKey, Sw> {
    let mut blob = [0u8; MAX_CRT_PLAIN + DEK_SEAL_OVERHEAD];
    let bn = fs.read_key(fid, &mut blob).ok_or(Sw::REFERENCE_NOT_FOUND)?;
    let bn = bn.min(blob.len());
    let mut kdata = [0u8; MAX_CRT_PLAIN];
    let res = (|| {
        let (n, legacy) = dek_unseal(dev, fs, sess, &blob[..bn], &mut kdata, legacy_rsa_len)?;
        let (half, _) = rsk_rsa::crt::parse_rsa_blob(&kdata[..n]).map_err(|_| Sw::WRONG_DATA)?;
        let key = rsk_rsa::rsa_from_pqe(
            rsk_rsa::RSA_PUB_EXP_BE,
            &kdata[..half],
            &kdata[half..2 * half],
        )
        .ok_or(Sw::WRONG_DATA)?;
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
/// slice directly, older `P‖Q` blobs recompute once (see
/// [`rsk_rsa::crt::crt_from_plain`]). A key still in the legacy CFB seal is
/// re-sealed forward, upgrading it straight to the 5-field authenticated layout.
pub fn load_rsa_crt<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    fid: KeyFid,
) -> Result<RsaCrt, Sw> {
    let mut blob = [0u8; MAX_CRT_PLAIN + DEK_SEAL_OVERHEAD];
    let bn = fs.read_key(fid, &mut blob).ok_or(Sw::REFERENCE_NOT_FOUND)?;
    let bn = bn.min(blob.len());
    let mut kdata = [0u8; MAX_CRT_PLAIN];
    let unsealed = dek_unseal(dev, fs, sess, &blob[..bn], &mut kdata, legacy_rsa_len);
    blob.zeroize();
    let (n, legacy) = match unsealed {
        Ok(v) => v,
        Err(e) => {
            kdata.zeroize();
            return Err(e);
        }
    };
    let crt = rsk_rsa::crt::crt_from_plain(&kdata[..n]);
    // Migrate a legacy CFB key forward — now straight to the 5-field GCM layout.
    if legacy
        && crt.is_ok()
        && let Ok((half, _)) = rsk_rsa::crt::parse_rsa_blob(&kdata[..n])
        && let Some(key) = rsk_rsa::rsa_from_pqe(
            rsk_rsa::RSA_PUB_EXP_BE,
            &kdata[..half],
            &kdata[half..2 * half],
        )
    {
        let _ = store_rsa_key(dev, fs, sess, fid, &key);
    }
    kdata.zeroize();
    crt.map_err(rsa_sw)
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
    let res = rsk_rsa::crt::private_op(crt, ct, &mut RsaRng(rng), &mut em[..key_size])
        .map_err(rsa_sw)
        .and_then(|_| {
            rsk_rsa::pkcs1v15::unpad_encrypt(&em[..key_size], out).map_err(|_| Sw::EXEC_ERROR)
        });
    em.zeroize();
    res
}

/// [`rsa_decipher`] for a key the asm CRT core cannot take: a legacy `P‖Q` blob
/// whose prime width is not a 32-multiple, which older firmware could store and
/// which [`rsk_rsa::crt::crt_from_plain`] refuses. Such a key already cannot
/// sign; it would lose the ability to decrypt its own archived messages too, so
/// it takes the software private op instead — blinded and Bellcore-fault-checked
/// like the asm one, and ending in the same constant-time unpad.
pub fn rsa_decipher_legacy(
    key: &RsaKey,
    rng: &mut dyn Rng,
    data: &[u8],
    out: &mut [u8],
) -> Result<usize, Sw> {
    let key_size = key.size();
    let ct = data.get(1..1 + key_size).ok_or(Sw::WRONG_DATA)?;
    // Every failure here is `EXEC_ERROR`, which is what the `rsa` crate's
    // `decrypt_blinded` collapsed to. Deliberately coarser than the asm arm,
    // which answers `rsa_sw` for the private op and only collapses on the unpad.
    rsk_rsa::pkcs1v15::rsa_decrypt(key, ct, &mut RsaRng(rng), out).map_err(|_| Sw::EXEC_ERROR)
}

#[cfg(test)]
#[path = "keys_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "keys_rsa_tests.rs"]
mod rsa_tests;

#[cfg(test)]
#[path = "keys_seal_tests.rs"]
mod seal_tests;
