// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! EC signing keys for FIDO credentials: [`P256Key`] (U2F + the attestation
//! cert) and the multi-scheme CTAP2 [`CredKey`]. Each curve signs with its
//! canonical digest; ECDSA nonces are deterministic RFC 6979 where the crate
//! supports it (P-256 / P-384 / secp256k1) and random for P-521 (`p521` 0.13
//! has no deterministic signer). ECDSA signatures are DER-encoded.

use alloc::boxed::Box;

use minicbor::Encoder;
use minicbor::encode::{Error as CborError, Write};
use p256::FieldBytes;
use p256::ecdsa::SigningKey;
use zeroize::Zeroize;

use crate::Rng;
use crate::consts::{
    ALG_EDDSA, ALG_ES256, ALG_ES256K, ALG_ES384, ALG_ES512, ALG_MLDSA44, ALG_MLDSA65,
    CURVE_ED25519, CURVE_MLDSA44, CURVE_MLDSA65, CURVE_P256, CURVE_P256K1, CURVE_P384, CURVE_P521,
};
use crate::cose::{cose_key_akp, cose_key_ec2_var, cose_key_okp_var};

/// Maximum DER-encoded P-256 ECDSA signature length.
pub const MAX_DER_SIG: usize = 72;
/// Max signature length across all credential schemes — an ML-DSA-65
/// signature; ML-DSA-44 is 2420 and the EC curves top out at 141 (P-521 DER).
pub const MAX_SIG_LEN: usize = rsk_crypto::MLDSA65_SIG_LEN; // 3309
/// Bytes the key-derivation ratchet must produce — a P-521 scalar is 66 bytes
/// (the ML-DSA-44 seed needs only the first 32).
pub const RATCHET_LEN: usize = 66;

/// Test helper: the SEC1 uncompressed encoding `04 ‖ x ‖ y`, to rebuild a point
/// from affine coordinates (0.14 dropped `Sec1Point::from_affine_coordinates`).
#[cfg(test)]
pub(crate) fn sec1_uncompressed(x: impl AsRef<[u8]>, y: impl AsRef<[u8]>) -> alloc::vec::Vec<u8> {
    let (x, y) = (x.as_ref(), y.as_ref());
    let mut b = alloc::vec::Vec::with_capacity(1 + x.len() + y.len());
    b.push(0x04);
    b.extend_from_slice(x);
    b.extend_from_slice(y);
    b
}

/// Deterministic ECDSA-SHA256 over `msg` with scalar `d`, DER into `out`; the comb
/// signer ([`rsk_ec::sign_p256`]) — byte-identical to `p256::ecdsa::SigningKey::sign`.
pub(crate) fn sign_p256_comb(d: &p256::Scalar, msg: &[u8], out: &mut [u8]) -> usize {
    let h = rsk_crypto::sha256(msg);
    let sig = rsk_ec::sign_p256(d, &h).expect("nonzero r, s");
    let der = sig.to_der();
    let b = der.as_bytes();
    out[..b.len()].copy_from_slice(b);
    b.len()
}

/// Deterministic ECDSA-SHA384 over `msg` with P-384 scalar `d`, DER into `out`;
/// byte-identical to `p384::ecdsa::SigningKey::sign` ([`rsk_ec::sign_p384`]).
fn sign_p384_comb(d: &p384::Scalar, msg: &[u8], out: &mut [u8]) -> usize {
    let h = rsk_crypto::sha384(msg);
    let sig = rsk_ec::sign_p384(d, &h).expect("nonzero r, s");
    let der = sig.to_der();
    let b = der.as_bytes();
    out[..b.len()].copy_from_slice(b);
    b.len()
}

/// Deterministic ECDSA-SHA256 over `msg` with secp256k1 scalar `d` (low-S), DER into
/// `out`; byte-identical to `k256::ecdsa::SigningKey::sign` ([`rsk_ec::sign_k256`]).
fn sign_k256_comb(d: &k256::Scalar, msg: &[u8], out: &mut [u8]) -> usize {
    let h = rsk_crypto::sha256(msg);
    let sig = rsk_ec::sign_k256(d, &h).expect("nonzero r, s");
    let der = sig.to_der();
    let b = der.as_bytes();
    out[..b.len()].copy_from_slice(b);
    b.len()
}

/// A P-256 signing keypair derived from a 32-byte scalar.
pub struct P256Key {
    signing: SigningKey,
}

impl P256Key {
    /// Build the keypair from a 32-byte big-endian scalar (the key-derivation
    /// ratchet output). Returns `None` if the scalar is out of range `[1, n)` —
    /// the caller treats that as a derivation failure.
    pub fn from_scalar(scalar: &[u8; 32]) -> Option<Self> {
        let fb = FieldBytes::from(*scalar);
        SigningKey::from_bytes(&fb)
            .ok()
            .map(|signing| Self { signing })
    }

    /// Uncompressed public point as `(x, y)`, each 32 bytes — the COSE key coords.
    pub fn public_xy(&self) -> ([u8; 32], [u8; 32]) {
        let pt = self.signing.verifying_key().to_sec1_point(false);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(pt.x().expect("uncompressed point has x"));
        y.copy_from_slice(pt.y().expect("uncompressed point has y"));
        (x, y)
    }

    /// Deterministic ECDSA-SHA256 over `msg`, DER-encoded into `out`; returns the
    /// signature length. `out` must hold at least [`MAX_DER_SIG`] bytes. Signs via the
    /// fixed-base comb (`sign_p256_comb`) — byte-identical to the crate's signer.
    pub fn sign_der(&self, msg: &[u8], out: &mut [u8]) -> usize {
        sign_p256_comb(self.signing.as_nonzero_scalar(), msg, out)
    }
}

/// A multi-scheme CTAP2 credential signing key, selected by the credential's
/// stored `curve`.
pub enum CredKey {
    // All four Weierstrass curves hold the bare scalar, not a `SigningKey`: building a
    // `SigningKey` eagerly derives the public key (a fixed-base mul) that getAssertion
    // never needs — it only signs. Both signing's `k·G` and `cose_public`'s `d·G` go
    // through the fixed-base comb (`comb_mul_p256`/`_p384`/`_p521`/`comb_mul_k256`),
    // which bypasses the crate's variable-time scalar-mul (slow on Cortex-M33).
    P256(p256::NonZeroScalar),
    P384(p384::NonZeroScalar),
    P521(p521::NonZeroScalar),
    K256(k256::NonZeroScalar),
    Ed25519(ed25519_dalek::SigningKey),
    // ML-DSA-44's ~13 KB expanded key (the in-tree `rsk-mldsa`, which streams the
    // matrix A so signing fits the RP2350 stack). HEAP-BOXED, not inline: signing
    // (`getAssertion`) nearly fills the RP2350's ~222 KiB worker stack on its own,
    // so the key inline on that frame tipped it into overflow → a hard wedge
    // (panic-halt, FIDO dark until replug). The heap is idle during a FIDO request
    // (applet keys are reconstructed per-op); `rsk-mldsa` zeroizes on drop and the
    // `Box` adds no `Drop` of its own.
    MlDsa44(Box<rsk_crypto::MlDsa44>),
    // ML-DSA-65's ~23 KB expanded key, same crate and boxing rationale as -44.
    MlDsa65(Box<rsk_crypto::MlDsa65>),
}

// The bare Weierstrass scalars need explicit zeroize (`NonZeroScalar` has no `Drop`);
// Ed25519's `SigningKey` and the boxed ML-DSA keys zeroize themselves.
impl Drop for CredKey {
    fn drop(&mut self) {
        match self {
            Self::P256(s) => s.zeroize(),
            Self::P384(s) => s.zeroize(),
            Self::P521(s) => s.zeroize(),
            Self::K256(s) => s.zeroize(),
            _ => {}
        }
    }
}

/// Build a boxed ML-DSA-44 credential key from the ratchet seed. `#[inline(never)]`
/// is load-bearing: `MlDsa44::from_seed` has a ~100 KiB matrix-expansion frame, and
/// folding it into [`CredKey::from_raw`] would size that function's frame for the
/// lattice worst case on EVERY curve — a P-256 getAssertion would then reserve
/// ~100 KiB it never uses and overflow the worker stack (a hard, replug-only wedge).
#[inline(never)]
fn mldsa44_from_raw(raw: &[u8]) -> Option<CredKey> {
    let mut xi = [0u8; 32];
    xi.copy_from_slice(raw.get(..32)?);
    let key = Box::new(rsk_crypto::MlDsa44::from_seed(&xi));
    xi.zeroize();
    Some(CredKey::MlDsa44(key))
}

/// Boxed ML-DSA-65 credential key from the ratchet seed — same
/// stack-isolation rationale as [`mldsa44_from_raw`].
#[inline(never)]
fn mldsa65_from_raw(raw: &[u8]) -> Option<CredKey> {
    let mut xi = [0u8; 32];
    xi.copy_from_slice(raw.get(..32)?);
    let key = Box::new(rsk_crypto::MlDsa65::from_seed(&xi));
    xi.zeroize();
    Some(CredKey::MlDsa65(key))
}

/// Hedged FIPS 204 ML-DSA-44 signing (32 fresh RNG bytes per signature), kept
/// `#[inline(never)]` for the same reason as [`mldsa44_from_raw`]: the streaming
/// sign has a ~50 KiB frame that must not be folded into [`CredKey::sign`]'s frame
/// — which every EC assertion pays.
#[inline(never)]
fn mldsa44_sign<R: Rng>(k: &rsk_crypto::MlDsa44, msg: &[u8], rng: &mut R, out: &mut [u8]) -> usize {
    let mut rnd = [0u8; 32];
    rng.fill(&mut rnd);
    let n = k.sign(msg, &rnd, out).unwrap_or(0);
    rnd.zeroize();
    n
}

/// ML-DSA-65 counterpart of [`mldsa44_sign`].
#[inline(never)]
fn mldsa65_sign<R: Rng>(k: &rsk_crypto::MlDsa65, msg: &[u8], rng: &mut R, out: &mut [u8]) -> usize {
    let mut rnd = [0u8; 32];
    rng.fill(&mut rnd);
    let n = k.sign(msg, &rnd, out).unwrap_or(0);
    rnd.zeroize();
    n
}

impl CredKey {
    /// Build the key for `curve` (a `CURVE_*` id) from the ratchet output
    /// `raw`: read the curve's scalar byte length, masking the P-521 top byte
    /// down to 521 bits. `None` if `raw` is too short, the curve is
    /// unsupported, or the scalar is out of range `[1, n)` (a derivation failure).
    pub fn from_raw(curve: i64, raw: &[u8]) -> Option<Self> {
        match curve {
            c if c == CURVE_P256 as i64 => {
                use p256::elliptic_curve::PrimeField;
                let mut fb = p256::FieldBytes::try_from(raw.get(..32)?).ok()?;
                let scalar = Option::<p256::Scalar>::from(p256::Scalar::from_repr(fb));
                fb.zeroize();
                Some(Self::P256(Option::from(p256::NonZeroScalar::new(scalar?))?))
            }
            c if c == CURVE_P384 as i64 => {
                use p384::elliptic_curve::PrimeField;
                let mut fb = p384::FieldBytes::try_from(raw.get(..48)?).ok()?;
                let scalar = Option::<p384::Scalar>::from(p384::Scalar::from_repr(fb));
                fb.zeroize();
                Some(Self::P384(Option::from(p384::NonZeroScalar::new(scalar?))?))
            }
            c if c == CURVE_P521 as i64 => {
                use p521::elliptic_curve::PrimeField;
                let mut buf = [0u8; 66];
                buf.copy_from_slice(raw.get(..66)?);
                buf[0] >>= 7; // a P-521 scalar is 521 bits: keep only the top byte's bit
                let mut fb = p521::FieldBytes::try_from(&buf[..]).ok()?;
                buf.zeroize();
                let scalar = Option::<p521::Scalar>::from(p521::Scalar::from_repr(fb));
                fb.zeroize();
                Some(Self::P521(Option::from(p521::NonZeroScalar::new(scalar?))?))
            }
            c if c == CURVE_P256K1 as i64 => {
                use k256::elliptic_curve::PrimeField;
                let mut fb = k256::FieldBytes::try_from(raw.get(..32)?).ok()?;
                let scalar = Option::<k256::Scalar>::from(k256::Scalar::from_repr(fb));
                fb.zeroize();
                Some(Self::K256(Option::from(k256::NonZeroScalar::new(scalar?))?))
            }
            c if c == CURVE_ED25519 as i64 => {
                // The 32-byte seed is hashed to the scalar internally; the
                // top-byte mask (Ed25519 is a 255-bit field) is part of the
                // credential derivation — changing it changes existing keys.
                let mut seed = [0u8; 32];
                seed.copy_from_slice(raw.get(..32)?);
                seed[0] >>= 1;
                let key = ed25519_dalek::SigningKey::from_bytes(&seed);
                seed.zeroize();
                Some(Self::Ed25519(key))
            }
            // The lattice keygen (`from_seed`) has a ~100 KiB matrix-expansion
            // frame; keep it behind an `#[inline(never)]` call so it is NOT folded
            // into `from_raw`'s own frame, which would otherwise reserve that
            // ~100 KiB on EVERY credential — even a P-256 getAssertion — and
            // overflow the worker stack. See [`mldsa44_from_raw`].
            c if c == CURVE_MLDSA44 as i64 => mldsa44_from_raw(raw),
            c if c == CURVE_MLDSA65 as i64 => mldsa65_from_raw(raw),
            _ => None,
        }
    }

    /// The COSE algorithm id this key signs with.
    pub fn alg(&self) -> i64 {
        match self {
            Self::P256(_) => ALG_ES256,
            Self::P384(_) => ALG_ES384,
            Self::P521(_) => ALG_ES512,
            Self::K256(_) => ALG_ES256K,
            Self::Ed25519(_) => ALG_EDDSA,
            Self::MlDsa44(_) => ALG_MLDSA44,
            Self::MlDsa65(_) => ALG_MLDSA65,
        }
    }

    /// Sign `msg` (authData ‖ clientDataHash) into `out`; returns the length
    /// (≤ [`MAX_SIG_LEN`]). ECDSA curves emit DER using the curve's canonical
    /// digest: P-256 / P-384 / secp256k1 deterministic RFC 6979 (P-256 signs `k·G`
    /// with the fixed-base [`rsk_ec::comb_mul_p256`], see `sign_p256_comb`); P-521
    /// a random nonce from `rng`, with `k·G` via the fixed-base
    /// [`rsk_ec::comb_mul_p521`]. EdDSA emits the raw 64 bytes; ML-DSA-44 the raw
    /// 2420-byte FIPS 204 signature, hedged with 32 `rng` bytes.
    pub fn sign(&self, msg: &[u8], rng: &mut impl Rng, out: &mut [u8]) -> usize {
        fn put(bytes: &[u8], out: &mut [u8]) -> usize {
            out[..bytes.len()].copy_from_slice(bytes);
            bytes.len()
        }
        match self {
            Self::P256(k) => sign_p256_comb(k, msg, out),
            Self::P384(d) => sign_p384_comb(d, msg, out),
            Self::K256(d) => sign_k256_comb(d, msg, out),
            Self::P521(d) => {
                // P-521 here signs with a RANDOM nonce: this comb path reject-samples a
                // fresh 521-bit scalar from the device TRNG via the closure. A deterministic
                // RFC 6979 signer exists (OpenPGP uses it) -- both safe; don't drop this feed.
                let d: &p521::Scalar = d; // deref-coerce &NonZeroScalar → &Scalar
                let h = rsk_crypto::sha512(msg);
                let sig = rsk_ec::sign_p521(d, &h, &mut |b| rng.fill(b)).expect("nonzero r, s");
                put(sig.to_der().as_bytes(), out)
            }
            Self::Ed25519(k) => {
                // EdDSA is deterministic; the signature is the raw 64 bytes, not DER.
                // ed25519-dalek is on signature 2.2 (its own `Signer`), not the EC
                // stack's 3.0 — bring the matching trait in locally.
                use ed25519_dalek::Signer;
                let s: ed25519_dalek::Signature = k.sign(msg);
                put(&s.to_bytes(), out)
            }
            // Kept behind `#[inline(never)]` so the ~50 KiB streaming-sign frame is
            // not folded into this function's frame (paid by every EC assertion).
            Self::MlDsa44(k) => mldsa44_sign(k, msg, rng, out),
            Self::MlDsa65(k) => mldsa65_sign(k, msg, rng, out),
        }
    }

    /// Encode the COSE EC2 public key (`{1: 2, 3: alg, -1: crv, -2: x, -3: y}`).
    pub fn cose_public<W: Write>(&self, enc: &mut Encoder<W>) -> Result<(), CborError<W::Error>> {
        match self {
            Self::P256(d) => {
                // Derive the public key d·G with the fixed-base comb (no SigningKey).
                use p256::elliptic_curve::sec1::ToSec1Point;
                let p = rsk_ec::comb_mul_p256(d).to_affine().to_sec1_point(false);
                cose_key_ec2_var(
                    enc,
                    ALG_ES256,
                    CURVE_P256,
                    p.x().expect("x"),
                    p.y().expect("y"),
                )
            }
            Self::P384(d) => {
                use p384::elliptic_curve::sec1::ToSec1Point;
                let p = rsk_ec::comb_mul_p384(d).to_affine().to_sec1_point(false);
                cose_key_ec2_var(
                    enc,
                    ALG_ES384,
                    CURVE_P384,
                    p.x().expect("x"),
                    p.y().expect("y"),
                )
            }
            Self::P521(d) => {
                // Derive the public key d·G with the fixed-base comb (no SigningKey).
                use p521::elliptic_curve::sec1::ToSec1Point;
                let p = rsk_ec::comb_mul_p521(d).to_affine().to_sec1_point(false);
                cose_key_ec2_var(
                    enc,
                    ALG_ES512,
                    CURVE_P521,
                    p.x().expect("x"),
                    p.y().expect("y"),
                )
            }
            Self::K256(d) => {
                use k256::elliptic_curve::sec1::ToSec1Point;
                let p = rsk_ec::comb_mul_k256(d).to_affine().to_sec1_point(false);
                cose_key_ec2_var(
                    enc,
                    ALG_ES256K,
                    CURVE_P256K1,
                    p.x().expect("x"),
                    p.y().expect("y"),
                )
            }
            Self::Ed25519(k) => {
                let pk = k.verifying_key().to_bytes();
                cose_key_okp_var(enc, ALG_EDDSA, CURVE_ED25519, &pk)
            }
            Self::MlDsa44(k) => cose_key_akp(enc, ALG_MLDSA44, &k.public_key()),
            Self::MlDsa65(k) => cose_key_akp(enc, ALG_MLDSA65, &k.public_key()),
        }
    }

    /// The uncompressed public point for the EC schemes we cache in the EF_CRED
    /// record (SEC1 `04 ‖ x ‖ y` for the NIST/secp curves, the raw 32-byte key
    /// for Ed25519), written into `out`; returns its length. `None` for the
    /// lattice schemes, whose public keys are far too large for the record (they
    /// keep deriving per enumeration). The point is already computed for authData
    /// at makeCredential, so caching it there costs no extra scalar mul.
    pub fn public_point(&self, out: &mut [u8]) -> Option<usize> {
        fn put(bytes: &[u8], out: &mut [u8]) -> Option<usize> {
            out.get_mut(..bytes.len())?.copy_from_slice(bytes);
            Some(bytes.len())
        }
        match self {
            Self::P256(d) => {
                use p256::elliptic_curve::sec1::ToSec1Point;
                put(
                    rsk_ec::comb_mul_p256(d)
                        .to_affine()
                        .to_sec1_point(false)
                        .as_bytes(),
                    out,
                )
            }
            Self::P384(d) => {
                use p384::elliptic_curve::sec1::ToSec1Point;
                put(
                    rsk_ec::comb_mul_p384(d)
                        .to_affine()
                        .to_sec1_point(false)
                        .as_bytes(),
                    out,
                )
            }
            Self::K256(d) => {
                use k256::elliptic_curve::sec1::ToSec1Point;
                put(
                    rsk_ec::comb_mul_k256(d)
                        .to_affine()
                        .to_sec1_point(false)
                        .as_bytes(),
                    out,
                )
            }
            Self::P521(d) => {
                use p521::elliptic_curve::sec1::ToSec1Point;
                put(
                    rsk_ec::comb_mul_p521(d)
                        .to_affine()
                        .to_sec1_point(false)
                        .as_bytes(),
                    out,
                )
            }
            Self::Ed25519(k) => put(&k.verifying_key().to_bytes(), out),
            Self::MlDsa44(_) | Self::MlDsa65(_) => None,
        }
    }
}

/// Byte length of the cached uncompressed public point for `curve`, or `None`
/// for a scheme we do not cache (the lattice schemes). Credential enumeration
/// validates a stored trailer against this before emitting it.
pub fn cached_point_len(curve: i64) -> Option<usize> {
    Some(match curve {
        c if c == CURVE_P256 as i64 || c == CURVE_P256K1 as i64 => 65,
        c if c == CURVE_P384 as i64 => 97,
        c if c == CURVE_P521 as i64 => 133,
        c if c == CURVE_ED25519 as i64 => 32,
        _ => return None,
    })
}

/// Encode the COSE public key from a cached uncompressed point (produced by
/// [`CredKey::public_point`]) for `curve` — byte-identical to
/// [`CredKey::cose_public`] but with NO scalar multiplication. The caller
/// validates the point length against [`cached_point_len`] first; the guards
/// here are defensive (a mismatch yields an encode error, not a bad key).
pub fn cose_public_from_point<W: Write>(
    curve: i64,
    point: &[u8],
    enc: &mut Encoder<W>,
) -> Result<(), CborError<W::Error>> {
    fn ec2<W: Write>(
        enc: &mut Encoder<W>,
        alg: i64,
        crv: u8,
        point: &[u8],
        f: usize,
    ) -> Result<(), CborError<W::Error>> {
        let body = point
            .strip_prefix(&[0x04])
            .filter(|b| b.len() == 2 * f)
            .ok_or(CborError::message("bad cached point"))?;
        cose_key_ec2_var(enc, alg, crv, &body[..f], &body[f..])
    }
    match curve {
        c if c == CURVE_P256 as i64 => ec2(enc, ALG_ES256, CURVE_P256, point, 32),
        c if c == CURVE_P384 as i64 => ec2(enc, ALG_ES384, CURVE_P384, point, 48),
        c if c == CURVE_P521 as i64 => ec2(enc, ALG_ES512, CURVE_P521, point, 66),
        c if c == CURVE_P256K1 as i64 => ec2(enc, ALG_ES256K, CURVE_P256K1, point, 32),
        c if c == CURVE_ED25519 as i64 && point.len() == 32 => {
            cose_key_okp_var(enc, ALG_EDDSA, CURVE_ED25519, point)
        }
        _ => Err(CborError::message("uncacheable curve")),
    }
}

#[cfg(test)]
#[path = "ec_tests.rs"]
mod tests;
