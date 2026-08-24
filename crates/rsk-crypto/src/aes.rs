// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! AES — in-place CBC and CFB-128 (`aes_encrypt`/`aes_decrypt`, AES-128/192/256
//! picked from the key length) plus the raw AES-256-GCM primitive behind the PIN
//! AEAD. CBC needs a block-multiple length; CFB-128 is a stream and takes any
//! length (CFB decryption uses the forward cipher; `cfb_mode` handles that).

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{AsyncStreamCipher, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{Aes256Gcm, KeyInit};

use crate::{Error, Result};

/// Block cipher mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Cbc,
    Cfb,
}

macro_rules! cbc_encrypt {
    ($aes:ty, $key:expr, $iv:expr, $data:expr) => {{
        let len = $data.len();
        cbc::Encryptor::<$aes>::new_from_slices($key, $iv)
            .map_err(|_| Error::BadLength)?
            .encrypt_padded_mut::<NoPadding>($data, len)
            .map(|_| ())
            .map_err(|_| Error::BadLength)
    }};
}

macro_rules! cbc_decrypt {
    ($aes:ty, $key:expr, $iv:expr, $data:expr) => {{
        cbc::Decryptor::<$aes>::new_from_slices($key, $iv)
            .map_err(|_| Error::BadLength)?
            .decrypt_padded_mut::<NoPadding>($data)
            .map(|_| ())
            .map_err(|_| Error::BadLength)
    }};
}

macro_rules! cfb_encrypt {
    ($aes:ty, $key:expr, $iv:expr, $data:expr) => {{
        cfb_mode::Encryptor::<$aes>::new_from_slices($key, $iv)
            .map_err(|_| Error::BadLength)?
            .encrypt($data);
        Ok(())
    }};
}

macro_rules! cfb_decrypt {
    ($aes:ty, $key:expr, $iv:expr, $data:expr) => {{
        cfb_mode::Decryptor::<$aes>::new_from_slices($key, $iv)
            .map_err(|_| Error::BadLength)?
            .decrypt($data);
        Ok(())
    }};
}

/// In-place AES encrypt. Key length selects AES-128/192/256.
pub fn aes_encrypt(key: &[u8], iv: &[u8; 16], mode: Mode, data: &mut [u8]) -> Result<()> {
    match (mode, key.len()) {
        (Mode::Cbc, 16) => cbc_encrypt!(Aes128, key, iv, data),
        (Mode::Cbc, 24) => cbc_encrypt!(Aes192, key, iv, data),
        (Mode::Cbc, 32) => cbc_encrypt!(Aes256, key, iv, data),
        (Mode::Cfb, 16) => cfb_encrypt!(Aes128, key, iv, data),
        (Mode::Cfb, 24) => cfb_encrypt!(Aes192, key, iv, data),
        (Mode::Cfb, 32) => cfb_encrypt!(Aes256, key, iv, data),
        _ => Err(Error::BadLength),
    }
}

/// In-place AES decrypt. Key length selects AES-128/192/256.
pub fn aes_decrypt(key: &[u8], iv: &[u8; 16], mode: Mode, data: &mut [u8]) -> Result<()> {
    match (mode, key.len()) {
        (Mode::Cbc, 16) => cbc_decrypt!(Aes128, key, iv, data),
        (Mode::Cbc, 24) => cbc_decrypt!(Aes192, key, iv, data),
        (Mode::Cbc, 32) => cbc_decrypt!(Aes256, key, iv, data),
        (Mode::Cfb, 16) => cfb_decrypt!(Aes128, key, iv, data),
        (Mode::Cfb, 24) => cfb_decrypt!(Aes192, key, iv, data),
        (Mode::Cfb, 32) => cfb_decrypt!(Aes256, key, iv, data),
        _ => Err(Error::BadLength),
    }
}

/// AES-128-ECB single-block encrypt in place — the Yubico OTP primitive (the
/// token body and the Yubico-mode challenge-response are one ECB block each).
/// Not a general ECB mode on purpose.
pub fn aes128_encrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    use aes::cipher::BlockEncrypt;
    let cipher = Aes128::new(GenericArray::from_slice(key));
    cipher.encrypt_block(GenericArray::from_mut_slice(block));
}

/// AES-ECB single-block encrypt in place, AES-128/192/256 picked from the key
/// length — the PIV GENERAL AUTHENTICATE management-key primitive (witness /
/// challenge / response are one ECB block each). Not a general ECB mode on
/// purpose.
pub fn aes_ecb_encrypt_block(key: &[u8], block: &mut [u8; 16]) -> Result<()> {
    use aes::cipher::BlockEncrypt;
    let b = GenericArray::from_mut_slice(block);
    match key.len() {
        16 => Aes128::new(GenericArray::from_slice(key)).encrypt_block(b),
        24 => Aes192::new(GenericArray::from_slice(key)).encrypt_block(b),
        32 => Aes256::new(GenericArray::from_slice(key)).encrypt_block(b),
        _ => return Err(Error::BadLength),
    }
    Ok(())
}

/// AES-ECB single-block decrypt in place — the inverse of
/// [`aes_ecb_encrypt_block`], for the PIV mutual-auth response check.
pub fn aes_ecb_decrypt_block(key: &[u8], block: &mut [u8; 16]) -> Result<()> {
    use aes::cipher::BlockDecrypt;
    let b = GenericArray::from_mut_slice(block);
    match key.len() {
        16 => Aes128::new(GenericArray::from_slice(key)).decrypt_block(b),
        24 => Aes192::new(GenericArray::from_slice(key)).decrypt_block(b),
        32 => Aes256::new(GenericArray::from_slice(key)).decrypt_block(b),
        _ => return Err(Error::BadLength),
    }
    Ok(())
}

/// AES-256-CFB encrypt in place. **Never for a new record.** It exists as the
/// inverse of [`aes_decrypt_cfb_256`], and its only caller outside this crate's
/// own round-trip is `rsk-openpgp`'s `legacy_cfb_blob_still_unseals_and_is_flagged`,
/// which manufactures a pre-GCM record so the reader below can be tested against
/// one. The IV that path passes is the nonce key — fixed for the life of the key,
/// so two records sealed under one key repeat the keystream. That is why the
/// format moved to GCM, and why nothing shipping calls this.
pub fn aes_encrypt_cfb_256(key: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) -> Result<()> {
    aes_encrypt(key, iv, Mode::Cfb, data)
}

/// AES-256-CFB decrypt in place — read-only compatibility for records an older
/// build wrote, and nothing else: `rsk-openpgp`'s `unseal_with` is the one caller,
/// behind a width predicate without which any GCM authentication failure was
/// reinterpreted as "this must be legacy" (see `keys.rs`'s own note).
pub fn aes_decrypt_cfb_256(key: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) -> Result<()> {
    aes_decrypt(key, iv, Mode::Cfb, data)
}

/// AES-256-GCM encrypt in place; returns the 16-byte tag (detached). The raw
/// primitive behind the PIN KDF's `encrypt_with_aad`.
pub fn aes256gcm_encrypt(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buf)
        .expect("GCM in-place encryption is infallible for in-range lengths");
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag);
    out
}

/// AES-256-GCM decrypt in place, verifying `tag`; `Err(Decrypt)` on auth failure.
pub fn aes256gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> Result<()> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            aad,
            buf,
            GenericArray::from_slice(tag),
        )
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
#[path = "aes_tests.rs"]
mod tests;
