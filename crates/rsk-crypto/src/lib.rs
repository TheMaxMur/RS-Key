// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg_attr(not(test), no_std)]

//! `rsk-crypto` — the firmware's crypto surface over RustCrypto: hashes,
//! HMAC/HKDF, CRC-32, base64url, AES + AEADs, the PIN KDF, the CTAP2 PIN/UV-auth
//! protocol, an HMAC-DRBG, and ML-DSA/ML-KEM wrappers. Pure and host-testable:
//! device inputs (serial hash, OTP key, RNG) are passed in by the caller.

pub mod aes;
pub mod base64url;
pub mod chachapoly;
pub mod crc;
pub mod des;
pub mod drbg;
pub mod hash;
pub mod kdf;
pub mod mac;
pub mod mlkem;
pub mod pinproto;

pub use aes::{
    Mode, aes_decrypt, aes_ecb_decrypt_block, aes_ecb_encrypt_block, aes_encrypt,
    aes128_encrypt_block, aes256gcm_decrypt, aes256gcm_encrypt,
};
pub use chachapoly::{chacha20poly1305_decrypt, chacha20poly1305_encrypt};
pub use crc::crc32;
pub use des::{des3_decrypt_block, des3_encrypt_block};
pub use drbg::HmacDrbg;
pub use hash::{sha1, sha256, sha384, sha512};
pub use kdf::{Device, FusedKey, FusedRead, PinKdf, read_fused};
pub use mac::{ct_eq, hkdf_sha256, hkdf_sha512, hmac_sha1, hmac_sha256, hmac_sha512};
pub use mlkem::{MlKem768Pair, mlkem768_encapsulate};
pub use pinproto::PinProto;
// ML-DSA-44 and -65 both come from the in-tree stack-optimized `rsk-mldsa`: it
// streams the matrix A so signing fits the RP2350 stack (the by-value fips204
// crate's -65 overflowed it). Re-exported so downstream keeps the `rsk_crypto::`
// path.
pub use rsk_mldsa::{
    MLDSA44_PK_LEN, MLDSA44_SIG_LEN, MLDSA65_PK_LEN, MLDSA65_SIG_LEN, MlDsa44, MlDsa65,
    mldsa44_verify, mldsa65_verify,
};

/// Errors from the fallible crypto operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// An output buffer was too small, or a length was out of range.
    BadLength,
    /// Malformed base64url input.
    Base64,
    /// AEAD authentication failed.
    Decrypt,
    /// ECDH failed — an out-of-range scalar or an off-curve peer point.
    Ecdh,
    /// A PQC operation failed — a malformed ML-KEM encapsulation key.
    Pqc,
}

pub type Result<T> = core::result::Result<T, Error>;
