// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! PIN key derivation and the device-key AEAD. Device inputs (serial hash, raw
//! serial, optional OTP root key) come in via an explicit [`Device`] context and
//! the GCM nonce is caller-supplied, so the module is pure and host-testable.
//! Intermediate keys (`kbase`, `kver`, `kenc`) are zeroized after use.

use zeroize::{Zeroize, Zeroizing};

use crate::aes::{aes256gcm_decrypt, aes256gcm_encrypt};
use crate::mac::{hkdf_sha256, hmac_sha256};
use crate::{Error, Result};

use sha2::{Digest, Sha256};

// HKDF `info` strings. NOTE: "DEVICE/ROOT" is passed with length 12 — it
// *includes the trailing NUL*; the PIN/* infos do not.
const INFO_ROOT: &[u8] = b"DEVICE/ROOT\0";
const INFO_VERIFY: &[u8] = b"PIN/VERIFY";
const INFO_TOKEN: &[u8] = b"PIN/TOKEN";
const INFO_ENC: &[u8] = b"PIN/ENC";
const INFO_ENC2: &[u8] = b"PIN/ENC2";
const SALT_NOOTP: &[u8] = b"NO-OTP";

/// GCM framing: `nonce(12) | ciphertext | tag(16)`.
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// PIN-KDF version; V2 is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinKdf {
    V1,
    V2,
}

/// How a holder obtains a fused device key at the moment it needs one: a read of
/// the OTP fuses, not a copy kept in RAM. Carried instead of the key itself so a
/// bug that discloses adjacent memory has nothing to disclose — the OTP window is
/// not RAM. `None` on an unprovisioned device.
pub type FusedKey = fn() -> Option<[u8; 32]>;

/// One operation's copy of a fused key, or `None` when unprovisioned. Zeroized
/// when the binding drops, so it must be a local of whoever builds the [`Device`]
/// that borrows it — that lifetime IS the exposure window.
pub type FusedRead = Option<Zeroizing<[u8; 32]>>;

/// Read a fused key for one operation. The result is the only copy in RAM and is
/// zeroized when the caller's binding drops, which is the whole point of holding a
/// [`FusedKey`]: keep the live window as short as the operation that needs it.
pub fn read_fused(src: Option<FusedKey>) -> FusedRead {
    src.and_then(|read| read()).map(Zeroizing::new)
}

/// Device-specific key-derivation inputs, borrowed for the call.
#[derive(Clone, Copy)]
pub struct Device<'a> {
    /// Device serial hash — HKDF salt / GCM AAD.
    pub serial_hash: &'a [u8],
    /// Raw device serial, mixed into `hash_multi`.
    pub serial_id: &'a [u8],
    /// The OTP root key, if one is provisioned.
    pub otp_key: Option<&'a [u8; 32]>,
}

impl<'a> Device<'a> {
    /// The same device with the OTP root key dropped — the pre-provisioning
    /// derivation context. Migration code decrypts old blobs under this and
    /// re-seals them under `self`.
    pub fn without_otp(&self) -> Device<'a> {
        Device {
            otp_key: None,
            ..*self
        }
    }
}

impl Device<'_> {
    /// The device root key: HKDF(salt = serial_hash, ikm = otp_key) with the
    /// `"DEVICE/ROOT"` info, or HKDF(salt = `"NO-OTP"`, ikm = serial_hash)
    /// when no OTP key is provisioned.
    pub fn derive_kbase(&self) -> [u8; 32] {
        let mut kbase = [0u8; 32];
        match self.otp_key {
            Some(otp) => hkdf_sha256(self.serial_hash, otp, INFO_ROOT, &mut kbase),
            None => hkdf_sha256(SALT_NOOTP, self.serial_hash, INFO_ROOT, &mut kbase),
        }
        .expect("32-byte HKDF output is in range");
        kbase
    }

    /// The PIN verification key: HMAC-SHA256(kbase, pin).
    pub fn derive_kver(&self, pin: &[u8]) -> [u8; 32] {
        let mut kbase = self.derive_kbase();
        let kver = hmac_sha256(&kbase, pin);
        kbase.zeroize();
        kver
    }

    /// The stored PIN verifier: HKDF(serial_hash, kver, "PIN/VERIFY").
    pub fn pin_derive_verifier(&self, pin: &[u8]) -> [u8; 32] {
        let mut kver = self.derive_kver(pin);
        let out = self.expand(&kver, INFO_VERIFY);
        kver.zeroize();
        out
    }

    /// The session token: HKDF(serial_hash, kver, "PIN/TOKEN").
    pub fn pin_derive_session(&self, pin: &[u8]) -> [u8; 32] {
        let mut kver = self.derive_kver(pin);
        let out = self.expand(&kver, INFO_TOKEN);
        kver.zeroize();
        out
    }

    /// The V1 encryption key: HKDF(serial_hash, pin_token, "PIN/ENC").
    pub fn pin_derive_kenc(&self, token: &[u8; 32]) -> [u8; 32] {
        self.expand(token, INFO_ENC)
    }

    /// The V2 encryption key: HKDF(serial_hash, kbase || pin_token, "PIN/ENC2").
    pub fn pin_derive_kenc2(&self, token: &[u8; 32]) -> [u8; 32] {
        let mut ikm = [0u8; 64];
        let mut kbase = self.derive_kbase();
        ikm[..32].copy_from_slice(&kbase);
        ikm[32..].copy_from_slice(token);
        kbase.zeroize();
        let mut out = [0u8; 32];
        hkdf_sha256(self.serial_hash, &ikm, INFO_ENC2, &mut out).expect("32-byte HKDF output");
        ikm.zeroize();
        out
    }

    fn expand(&self, ikm: &[u8], info: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        hkdf_sha256(self.serial_hash, ikm, info, &mut out).expect("32-byte HKDF output");
        out
    }

    fn derive_kenc(&self, token: &[u8; 32], version: PinKdf) -> [u8; 32] {
        match version {
            PinKdf::V2 => self.pin_derive_kenc2(token),
            PinKdf::V1 => self.pin_derive_kenc(token),
        }
    }

    /// AES-256-GCM under the version's `kenc`, AAD = serial hash, writing
    /// `nonce | ciphertext | tag` into `out`; returns its length. The caller
    /// supplies `nonce` (fresh RNG bytes in firmware).
    pub fn encrypt_with_aad(
        &self,
        token: &[u8; 32],
        plaintext: &[u8],
        version: PinKdf,
        nonce: &[u8; NONCE_LEN],
        out: &mut [u8],
    ) -> Result<usize> {
        let total = NONCE_LEN + plaintext.len() + TAG_LEN;
        if out.len() < total {
            return Err(Error::BadLength);
        }
        let mut kenc = self.derive_kenc(token, version);
        out[..NONCE_LEN].copy_from_slice(nonce);
        let ct = &mut out[NONCE_LEN..NONCE_LEN + plaintext.len()];
        ct.copy_from_slice(plaintext);
        let tag = aes256gcm_encrypt(&kenc, nonce, self.serial_hash, ct);
        kenc.zeroize();
        out[NONCE_LEN + plaintext.len()..total].copy_from_slice(&tag);
        Ok(total)
    }

    /// Inverse of [`encrypt_with_aad`]; writes the plaintext into `out` and
    /// returns its length. `Err(Decrypt)` on auth failure.
    pub fn decrypt_with_aad(
        &self,
        token: &[u8; 32],
        input: &[u8],
        version: PinKdf,
        out: &mut [u8],
    ) -> Result<usize> {
        if input.len() < NONCE_LEN + TAG_LEN {
            return Err(Error::BadLength);
        }
        let pt_len = input.len() - NONCE_LEN - TAG_LEN;
        if out.len() < pt_len {
            return Err(Error::BadLength);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&input[..NONCE_LEN]);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&input[input.len() - TAG_LEN..]);
        out[..pt_len].copy_from_slice(&input[NONCE_LEN..NONCE_LEN + pt_len]);

        let mut kenc = self.derive_kenc(token, version);
        let res = aes256gcm_decrypt(&kenc, &nonce, self.serial_hash, &mut out[..pt_len], &tag);
        kenc.zeroize();
        res?;
        Ok(pt_len)
    }

    /// SHA-256 of the serial id followed by `input` repeated to 256 bytes; empty
    /// input hashes only the serial.
    pub fn hash_multi(&self, input: &[u8]) -> [u8; 32] {
        let mut ctx = Sha256::new();
        ctx.update(self.serial_id);
        let len = input.len();
        if len > 0 {
            let mut iters = 256usize;
            while iters > len {
                ctx.update(input);
                iters -= len;
            }
            if iters > 0 {
                ctx.update(&input[..iters]);
            }
        }
        let digest = ctx.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Legacy double PIN hash, kept only for compatibility — not a secure KDF.
    /// Empty input skips the XOR step instead of dividing by zero.
    pub fn double_hash_pin(&self, pin: &[u8]) -> [u8; 32] {
        let mut o1 = self.hash_multi(pin);
        if !pin.is_empty() {
            for (i, b) in o1.iter_mut().enumerate() {
                *b ^= pin[i % pin.len()];
            }
        }
        let out = self.hash_multi(&o1);
        o1.zeroize();
        out
    }
}

#[cfg(test)]
#[path = "kdf_tests.rs"]
mod tests;
