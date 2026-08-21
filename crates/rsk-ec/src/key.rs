// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The EC private key both card applets hold, and its three operations: ECDSA /
//! EdDSA signing, public-point derivation, and ECDH agreement.
//!
//! [`PrivKey`] holds only the raw scalar (or the Ed25519 seed), left-padded to
//! the field width, and rebuilds the RustCrypto key for each operation — so the
//! sealed blob an applet writes is `[curve_id] ‖ scalar` and nothing else. That
//! blob format is what makes this shared rather than applet-owned: `rsk-openpgp`
//! seals it under the PIN-wrapped DEK and `rsk-piv` under its kbase-rooted key,
//! but both read back the same bytes into the same type.
//!
//! Nothing here names a status word or a filesystem: the applets own the APDU
//! framing and the seal I/O, and map [`EcError`] at their edge.

use zeroize::{Zeroize, Zeroizing};

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::elliptic_curve::sec1::FromSec1Point;

use crate::{Curve, EcError, Rng};

/// Largest raw ECDSA signature: P-521 `r ‖ s` = 2×66 bytes.
pub const MAX_EC_SIG: usize = 132;
/// Largest EC public point: P-521 uncompressed `04 ‖ x ‖ y` = 1 + 2×66 bytes.
pub const MAX_EC_POINT: usize = 133;

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
    /// returns the length. Every curve here signs deterministically (RFC 6979;
    /// 0.14's p521 gained a deterministic signer), so this takes no randomness.
    pub fn sign(&self, prehash: &[u8], out: &mut [u8]) -> Result<usize, EcError> {
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
                    .ok_or(EcError::Failed)?,
                );
                let nz = Zeroizing::new(
                    Option::<p256::NonZeroScalar>::from(p256::NonZeroScalar::new(*d))
                        .ok_or(EcError::Failed)?,
                );
                let sig = crate::sign_p256(&nz, prehash).ok_or(EcError::Failed)?;
                Ok(put(sig.to_bytes().as_slice(), out))
            }
            PrivKey::P384(s) => {
                use p384::elliptic_curve::PrimeField;
                let d = Zeroizing::new(
                    Option::<p384::Scalar>::from(p384::Scalar::from_repr(p384::FieldBytes::from(
                        *s,
                    )))
                    .ok_or(EcError::Failed)?,
                );
                let nz = Zeroizing::new(
                    Option::<p384::NonZeroScalar>::from(p384::NonZeroScalar::new(*d))
                        .ok_or(EcError::Failed)?,
                );
                let sig = crate::sign_p384(&nz, prehash).ok_or(EcError::Failed)?;
                Ok(put(sig.to_bytes().as_slice(), out))
            }
            PrivKey::K256(s) => {
                use k256::elliptic_curve::PrimeField;
                let d = Zeroizing::new(
                    Option::<k256::Scalar>::from(k256::Scalar::from_repr(k256::FieldBytes::from(
                        *s,
                    )))
                    .ok_or(EcError::Failed)?,
                );
                let nz = Zeroizing::new(
                    Option::<k256::NonZeroScalar>::from(k256::NonZeroScalar::new(*d))
                        .ok_or(EcError::Failed)?,
                );
                let sig = crate::sign_k256(&nz, prehash).ok_or(EcError::Failed)?;
                Ok(put(sig.to_bytes().as_slice(), out))
            }
            PrivKey::P521(s) => {
                // 0.14's p521 has a deterministic RFC 6979 signer (its `sha512` feature),
                // so no random nonce / rand_core adapter is needed here. (FIDO's comb path
                // instead signs P-521 with a random TRNG nonce -- both are safe.)
                let k = p521::ecdsa::SigningKey::from_bytes(&p521::FieldBytes::from(*s))
                    .map_err(|_| EcError::Failed)?;
                let sig: p521::ecdsa::Signature =
                    k.sign_prehash(prehash).map_err(|_| EcError::Failed)?;
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
            PrivKey::X25519(_) => Err(EcError::Unsupported), // ECDH-only, never signs
        }
    }

    /// The public point for the public-key DO: uncompressed `04 ‖ x ‖ y` for the
    /// Weierstrass curves, the 32-byte compressed point for Ed25519, the 32-byte
    /// little-endian u-coordinate for X25519. Returns the length written to `out`.
    pub fn public_point(&self, out: &mut [u8]) -> Result<usize, EcError> {
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
                    .ok_or(EcError::Failed)?,
                );
                let nz = Zeroizing::new(
                    Option::<p256::NonZeroScalar>::from(p256::NonZeroScalar::new(*d))
                        .ok_or(EcError::Failed)?,
                );
                let pt = crate::comb_mul_p256(&nz).to_affine().to_sec1_point(false);
                Ok(put(pt.as_bytes(), out))
            }
            PrivKey::P384(s) => {
                use p384::elliptic_curve::PrimeField;
                use p384::elliptic_curve::sec1::ToSec1Point;
                let d = Zeroizing::new(
                    Option::<p384::Scalar>::from(p384::Scalar::from_repr(p384::FieldBytes::from(
                        *s,
                    )))
                    .ok_or(EcError::Failed)?,
                );
                let nz = Zeroizing::new(
                    Option::<p384::NonZeroScalar>::from(p384::NonZeroScalar::new(*d))
                        .ok_or(EcError::Failed)?,
                );
                let pt = crate::comb_mul_p384(&nz).to_affine().to_sec1_point(false);
                Ok(put(pt.as_bytes(), out))
            }
            PrivKey::K256(s) => {
                use k256::elliptic_curve::PrimeField;
                use k256::elliptic_curve::sec1::ToSec1Point;
                let d = Zeroizing::new(
                    Option::<k256::Scalar>::from(k256::Scalar::from_repr(k256::FieldBytes::from(
                        *s,
                    )))
                    .ok_or(EcError::Failed)?,
                );
                let nz = Zeroizing::new(
                    Option::<k256::NonZeroScalar>::from(k256::NonZeroScalar::new(*d))
                        .ok_or(EcError::Failed)?,
                );
                let pt = crate::comb_mul_k256(&nz).to_affine().to_sec1_point(false);
                Ok(put(pt.as_bytes(), out))
            }
            PrivKey::P521(s) => {
                use p521::elliptic_curve::PrimeField;
                use p521::elliptic_curve::sec1::ToSec1Point;
                let d = Zeroizing::new(
                    Option::<p521::Scalar>::from(p521::Scalar::from_repr(p521::FieldBytes::from(
                        *s,
                    )))
                    .ok_or(EcError::Failed)?,
                );
                let nz = Zeroizing::new(
                    Option::<p521::NonZeroScalar>::from(p521::NonZeroScalar::new(*d))
                        .ok_or(EcError::Failed)?,
                );
                let pt = crate::comb_mul_p521(&nz).to_affine().to_sec1_point(false);
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
    pub fn ecdh(&self, peer_point: &[u8], out: &mut [u8]) -> Result<usize, EcError> {
        match self {
            PrivKey::P256(s) => ecdh_p256(s, peer_point, out),
            PrivKey::P384(s) => ecdh_p384(s, peer_point, out),
            PrivKey::P521(s) => ecdh_p521(s, peer_point, out),
            PrivKey::K256(s) => ecdh_k256(s, peer_point, out),
            PrivKey::Bp256(s) => ecdh_bp256(s, peer_point, out),
            PrivKey::Bp384(s) => ecdh_bp384(s, peer_point, out),
            PrivKey::X25519(s) => ecdh_x25519(s, peer_point, out),
            PrivKey::Ed25519(_) => Err(EcError::Unsupported),
        }
    }
}

/// P-256 ECDH: peer point parsed as a SEC1 uncompressed point, shared secret =
/// the affine x-coordinate.
fn ecdh_p256(scalar: &[u8; 32], peer_point: &[u8], out: &mut [u8]) -> Result<usize, EcError> {
    let sk = p256::SecretKey::from_bytes(&p256::FieldBytes::from(*scalar))
        .map_err(|_| EcError::BadPoint)?;
    let ep = p256::Sec1Point::from_bytes(peer_point).map_err(|_| EcError::BadPoint)?;
    let peer = Option::<p256::PublicKey>::from(p256::PublicKey::from_sec1_point(&ep))
        .ok_or(EcError::BadPoint)?;
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    let z = shared.raw_secret_bytes();
    out[..z.len()].copy_from_slice(z.as_slice());
    Ok(z.len())
}

/// P-384 ECDH — same SEC1 idiom as [`ecdh_p256`], 48-byte shared x-coordinate.
fn ecdh_p384(scalar: &[u8; 48], peer_point: &[u8], out: &mut [u8]) -> Result<usize, EcError> {
    let sk = p384::SecretKey::from_bytes(&p384::FieldBytes::from(*scalar))
        .map_err(|_| EcError::BadPoint)?;
    let ep = p384::Sec1Point::from_bytes(peer_point).map_err(|_| EcError::BadPoint)?;
    let peer = Option::<p384::PublicKey>::from(p384::PublicKey::from_sec1_point(&ep))
        .ok_or(EcError::BadPoint)?;
    let shared = p384::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    let z = shared.raw_secret_bytes();
    out[..z.len()].copy_from_slice(z.as_slice());
    Ok(z.len())
}

/// P-521 ECDH — 66-byte shared x-coordinate.
fn ecdh_p521(scalar: &[u8; 66], peer_point: &[u8], out: &mut [u8]) -> Result<usize, EcError> {
    let sk = p521::SecretKey::from_bytes(&p521::FieldBytes::from(*scalar))
        .map_err(|_| EcError::BadPoint)?;
    let ep = p521::Sec1Point::from_bytes(peer_point).map_err(|_| EcError::BadPoint)?;
    let peer = Option::<p521::PublicKey>::from(p521::PublicKey::from_sec1_point(&ep))
        .ok_or(EcError::BadPoint)?;
    let shared = p521::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    let z = shared.raw_secret_bytes();
    out[..z.len()].copy_from_slice(z.as_slice());
    Ok(z.len())
}

/// secp256k1 ECDH — 32-byte shared x-coordinate.
fn ecdh_k256(scalar: &[u8; 32], peer_point: &[u8], out: &mut [u8]) -> Result<usize, EcError> {
    let sk = k256::SecretKey::from_bytes(&k256::FieldBytes::from(*scalar))
        .map_err(|_| EcError::BadPoint)?;
    let ep = k256::Sec1Point::from_bytes(peer_point).map_err(|_| EcError::BadPoint)?;
    let peer = Option::<k256::PublicKey>::from(k256::PublicKey::from_sec1_point(&ep))
        .ok_or(EcError::BadPoint)?;
    let shared = k256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    let z = shared.raw_secret_bytes();
    out[..z.len()].copy_from_slice(z.as_slice());
    Ok(z.len())
}

// brainpoolP256r1 / brainpoolP384r1 (bp256/bp384 0.14, fiat-crypto backend). These
// crates leave `SigningKey`/`VerifyingKey` generic in `ecdsa`, so name them there;
// signing is deterministic RFC 6979 (bp `sha256`/`sha384` feature) like P-256/P-384.

/// brainpoolP256r1 ECDSA — raw `r ‖ s` (64 bytes).
fn sign_bp256(s: &[u8; 32], prehash: &[u8], out: &mut [u8]) -> Result<usize, EcError> {
    use ecdsa::signature::hazmat::PrehashSigner;
    let k =
        ecdsa::SigningKey::<bp256::BrainpoolP256r1>::from_bytes(&bp256::r1::FieldBytes::from(*s))
            .map_err(|_| EcError::Failed)?;
    let sig: bp256::r1::ecdsa::Signature = k.sign_prehash(prehash).map_err(|_| EcError::Failed)?;
    let b = sig.to_bytes();
    out[..b.len()].copy_from_slice(&b);
    Ok(b.len())
}

/// brainpoolP384r1 ECDSA — raw `r ‖ s` (96 bytes).
fn sign_bp384(s: &[u8; 48], prehash: &[u8], out: &mut [u8]) -> Result<usize, EcError> {
    use ecdsa::signature::hazmat::PrehashSigner;
    let k =
        ecdsa::SigningKey::<bp384::BrainpoolP384r1>::from_bytes(&bp384::r1::FieldBytes::from(*s))
            .map_err(|_| EcError::Failed)?;
    let sig: bp384::r1::ecdsa::Signature = k.sign_prehash(prehash).map_err(|_| EcError::Failed)?;
    let b = sig.to_bytes();
    out[..b.len()].copy_from_slice(&b);
    Ok(b.len())
}

/// brainpoolP256r1 public point: SEC1 uncompressed `04 ‖ x ‖ y` (65 bytes).
fn pubkey_bp256(s: &[u8; 32], out: &mut [u8]) -> Result<usize, EcError> {
    let k =
        ecdsa::SigningKey::<bp256::BrainpoolP256r1>::from_bytes(&bp256::r1::FieldBytes::from(*s))
            .map_err(|_| EcError::Failed)?;
    let pt = k.verifying_key().to_sec1_point(false);
    let b = pt.as_bytes();
    out[..b.len()].copy_from_slice(b);
    Ok(b.len())
}

/// brainpoolP384r1 public point: SEC1 uncompressed `04 ‖ x ‖ y` (97 bytes).
fn pubkey_bp384(s: &[u8; 48], out: &mut [u8]) -> Result<usize, EcError> {
    let k =
        ecdsa::SigningKey::<bp384::BrainpoolP384r1>::from_bytes(&bp384::r1::FieldBytes::from(*s))
            .map_err(|_| EcError::Failed)?;
    let pt = k.verifying_key().to_sec1_point(false);
    let b = pt.as_bytes();
    out[..b.len()].copy_from_slice(b);
    Ok(b.len())
}

/// brainpoolP256r1 ECDH — SEC1 peer point, 32-byte shared x-coordinate.
fn ecdh_bp256(scalar: &[u8; 32], peer_point: &[u8], out: &mut [u8]) -> Result<usize, EcError> {
    let sk = bp256::r1::SecretKey::from_bytes(&bp256::r1::FieldBytes::from(*scalar))
        .map_err(|_| EcError::BadPoint)?;
    let pk =
        bp256::elliptic_curve::PublicKey::<bp256::BrainpoolP256r1>::from_sec1_bytes(peer_point)
            .map_err(|_| EcError::BadPoint)?;
    let shared =
        bp256::elliptic_curve::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    let z = shared.raw_secret_bytes();
    out[..z.len()].copy_from_slice(z.as_slice());
    Ok(z.len())
}

/// brainpoolP384r1 ECDH — SEC1 peer point, 48-byte shared x-coordinate.
fn ecdh_bp384(scalar: &[u8; 48], peer_point: &[u8], out: &mut [u8]) -> Result<usize, EcError> {
    let sk = bp384::r1::SecretKey::from_bytes(&bp384::r1::FieldBytes::from(*scalar))
        .map_err(|_| EcError::BadPoint)?;
    let pk =
        bp384::elliptic_curve::PublicKey::<bp384::BrainpoolP384r1>::from_sec1_bytes(peer_point)
            .map_err(|_| EcError::BadPoint)?;
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
fn ecdh_x25519(scalar_be: &[u8; 32], peer_point: &[u8], out: &mut [u8]) -> Result<usize, EcError> {
    let u = match peer_point.len() {
        33 if peer_point[0] == 0x40 => &peer_point[1..],
        32 => peer_point,
        _ => return Err(EcError::BadPoint),
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

#[cfg(test)]
#[path = "key_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "key_x25519_tests.rs"]
mod x25519_tests;

#[cfg(test)]
#[path = "key_bp_kat.rs"]
mod bp_kat;
