// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP2 PIN/UV-auth protocols one and two.
//!
//! Both protocols agree a shared secret over P-256 ECDH, then derive AES/HMAC
//! keys from the shared point's x-coordinate:
//! - **v1:** `sharedSecret = SHA-256(Z)` (32 bytes); AES-256-CBC with a zero IV and
//!   no IV prefix; the MAC is the first 16 bytes of HMAC-SHA-256.
//! - **v2:** `sharedSecret = HKDF(Z, "CTAP2 HMAC key") ‖ HKDF(Z, "CTAP2 AES key")`
//!   (64 bytes); AES-256-CBC with a random 16-byte IV prepended to the
//!   ciphertext; the MAC is the full 32-byte HMAC-SHA-256.
//!
//! The authenticator's ephemeral ECDH key is owned by the caller (`rsk-fido`'s
//! `FidoState`); the scalar and the peer's public point are passed in, keeping
//! the module pure and host-testable.

use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use p256::{FieldBytes, PublicKey, Sec1Point, SecretKey, ecdh};
use zeroize::Zeroize;

use crate::aes::{Mode, aes_decrypt, aes_encrypt};
use crate::hash::sha256;
use crate::mac::{ct_eq, hkdf_sha256, hmac_sha256};
use crate::{Error, Result};

/// 16-byte AES-CBC IV / IV prefix.
pub const IV_SIZE: usize = 16;

/// PIN/UV-auth protocol version (`pinUvAuthProtocol`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinProto {
    One,
    Two,
}

impl PinProto {
    /// Map the wire value (1 or 2); any other value is unsupported.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            1 => Some(PinProto::One),
            2 => Some(PinProto::Two),
            _ => None,
        }
    }

    /// Shared-secret length: 32 (v1) or 64 (v2).
    pub fn shared_len(self) -> usize {
        match self {
            PinProto::One => 32,
            PinProto::Two => 64,
        }
    }

    /// Bytes the encryption prepends to the ciphertext: 0 (v1) or 16 (v2, the IV).
    pub fn iv_overhead(self) -> usize {
        match self {
            PinProto::One => 0,
            PinProto::Two => IV_SIZE,
        }
    }

    /// MAC length: 16 (v1) or 32 (v2).
    pub fn mac_len(self) -> usize {
        match self {
            PinProto::One => 16,
            PinProto::Two => 32,
        }
    }

    /// The 32-byte AES key within a shared secret (v1: the secret; v2: the second
    /// half).
    fn aes_key(self, shared: &[u8]) -> &[u8] {
        match self {
            PinProto::One => &shared[..32],
            PinProto::Two => &shared[32..64],
        }
    }
}

/// Derive the public point of the authenticator's ephemeral ECDH key as
/// `(x, y)`, each 32 bytes — the COSE key coordinates returned by
/// `getKeyAgreement`. `None` if the scalar is out of range.
pub fn public_xy(scalar: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
    let sk = SecretKey::from_bytes(&FieldBytes::from(*scalar)).ok()?;
    let pt = sk.public_key().to_sec1_point(false);
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(pt.x()?);
    y.copy_from_slice(pt.y()?);
    Some((x, y))
}

/// Derive the shared secret from the ECDH x-coordinate `z`, writing it into
/// `out` (length [`PinProto::shared_len`]).
fn kdf(proto: PinProto, z: &[u8; 32], out: &mut [u8]) {
    match proto {
        PinProto::One => out[..32].copy_from_slice(&sha256(z)),
        PinProto::Two => {
            hkdf_sha256(&[], z, b"CTAP2 HMAC key", &mut out[..32]).expect("32-byte HKDF output");
            hkdf_sha256(&[], z, b"CTAP2 AES key", &mut out[32..64]).expect("32-byte HKDF output");
        }
    }
}

/// Compute the shared secret between our scalar and the peer's public point
/// `(peer_x, peer_y)`, writing it into `out`; returns its length. `Err` if the
/// peer point is not a valid P-256 public key.
pub fn ecdh(
    proto: PinProto,
    our_scalar: &[u8; 32],
    peer_x: &[u8; 32],
    peer_y: &[u8; 32],
    out: &mut [u8],
) -> Result<usize> {
    let n = proto.shared_len();
    if out.len() < n {
        return Err(Error::BadLength);
    }
    let mut z = ecdh_raw(our_scalar, peer_x, peer_y)?;
    kdf(proto, &z, &mut out[..n]);
    z.zeroize();
    Ok(n)
}

/// Raw P-256 ECDH: the 32-byte shared X coordinate with no protocol KDF applied.
/// The MSE backup channel ([`crate::chachapoly`] + HKDF) derives its own channel
/// key from this, so it needs the bare secret rather than the clientPIN `kdf`
/// output. `Err` if the peer point is not a valid P-256 public key.
pub fn ecdh_raw(our_scalar: &[u8; 32], peer_x: &[u8; 32], peer_y: &[u8; 32]) -> Result<[u8; 32]> {
    let sk = SecretKey::from_bytes(&FieldBytes::from(*our_scalar)).map_err(|_| Error::Ecdh)?;
    // 0.14 dropped `Sec1Point::from_affine_coordinates`; splice `04 ‖ x ‖ y`.
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(peer_x);
    sec1[33..].copy_from_slice(peer_y);
    let ep = Sec1Point::from_bytes(&sec1).map_err(|_| Error::Ecdh)?;
    let peer = Option::<PublicKey>::from(PublicKey::from_sec1_point(&ep)).ok_or(Error::Ecdh)?;
    let shared = ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    let mut z = [0u8; 32];
    z.copy_from_slice(shared.raw_secret_bytes());
    Ok(z)
}

/// AES-256-CBC `plaintext` under the shared secret, writing the result (v2
/// prepends `iv`) into `out`; returns its length. `iv` is ignored for v1
/// (which uses a zero IV); the caller draws it from the RNG for v2.
pub fn encrypt(
    proto: PinProto,
    shared: &[u8],
    iv: &[u8; IV_SIZE],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    let off = proto.iv_overhead();
    if out.len() < off + plaintext.len() {
        return Err(Error::BadLength);
    }
    let (cbc_iv, body) = match proto {
        PinProto::One => ([0u8; IV_SIZE], &mut out[..plaintext.len()]),
        PinProto::Two => {
            out[..IV_SIZE].copy_from_slice(iv);
            (*iv, &mut out[IV_SIZE..IV_SIZE + plaintext.len()])
        }
    };
    body.copy_from_slice(plaintext);
    aes_encrypt(proto.aes_key(shared), &cbc_iv, Mode::Cbc, body)?;
    Ok(off + plaintext.len())
}

/// Inverse of [`encrypt`]; writes the plaintext into `out` and returns its
/// length.
pub fn decrypt(proto: PinProto, shared: &[u8], input: &[u8], out: &mut [u8]) -> Result<usize> {
    let off = proto.iv_overhead();
    if input.len() < off {
        return Err(Error::BadLength);
    }
    let pt_len = input.len() - off;
    if out.len() < pt_len {
        return Err(Error::BadLength);
    }
    let mut iv = [0u8; IV_SIZE];
    if proto == PinProto::Two {
        iv.copy_from_slice(&input[..IV_SIZE]);
    }
    out[..pt_len].copy_from_slice(&input[off..]);
    aes_decrypt(proto.aes_key(shared), &iv, Mode::Cbc, &mut out[..pt_len])?;
    Ok(pt_len)
}

/// HMAC-SHA-256 over `data` under the shared secret's HMAC key (its first 32
/// bytes), truncated to [`PinProto::mac_len`]; writes it into `out` and returns
/// its length.
pub fn authenticate(proto: PinProto, shared: &[u8], data: &[u8], out: &mut [u8]) -> Result<usize> {
    let n = proto.mac_len();
    if out.len() < n {
        return Err(Error::BadLength);
    }
    let mac = hmac_sha256(&shared[..32], data);
    out[..n].copy_from_slice(&mac[..n]);
    Ok(n)
}

/// Constant-time check that `sign` is the [`authenticate`] MAC of `data`.
pub fn verify(proto: PinProto, shared: &[u8], data: &[u8], sign: &[u8]) -> bool {
    let n = proto.mac_len();
    let mac = hmac_sha256(&shared[..32], data);
    ct_eq(&mac[..n], sign)
}

#[cfg(test)]
#[path = "pinproto_tests.rs"]
mod tests;
