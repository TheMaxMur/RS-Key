// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! hmac-secret extension, shared by getAssertion (`hmac-secret`) and
//! makeCredential (`hmac-secret-mc`): ECDH against the platform's keyAgreement,
//! verify the platform salt MAC, decrypt the salts, HMAC each under the
//! credential's `cred_random` (the UV half selected by the UV flag), re-encrypt.
//! The ECDH key is the same ephemeral one `clientPIN getKeyAgreement`
//! published, so the platform must have fetched it first.

use minicbor::Decoder;
use zeroize::Zeroize;

use rsk_crypto::hmac_sha256;
use rsk_crypto::pinproto::{self, IV_SIZE, PinProto};

use crate::Rng;
use crate::cbordec::{cbor, def_map};
use crate::credential::derive_hmac_key;
use crate::error::CtapError;

/// Max saltEnc: two 32-byte salts + the PIN-protocol-2 IV — also the max [`eval`]
/// output length (`pinproto::encrypt` output = IV overhead + plaintext).
pub const SALT_ENC_MAX: usize = 64 + 16;
/// Headroom over the 32-byte protocol-2 saltAuth MAC — kept at the existing
/// size, not a spec formula.
pub const SALT_AUTH_MAX: usize = 48;

/// A parsed hmac-secret / hmac-secret-mc request map.
pub struct HmacSecretReq<'a> {
    pub peer_x: [u8; 32],
    pub peer_y: [u8; 32],
    pub salt_enc: &'a [u8],
    pub salt_auth: &'a [u8],
    pub proto: u64,
    pub present: bool,
}

impl Default for HmacSecretReq<'_> {
    fn default() -> Self {
        Self {
            peer_x: [0; 32],
            peer_y: [0; 32],
            salt_enc: &[],
            salt_auth: &[],
            proto: 1,
            present: false,
        }
    }
}

/// A COSE P-256 coordinate: exactly 32 bytes, big-endian, never left-padded —
/// the twin of `clientpin::coord`, and measured on a YubiKey 5.7.4 at this site
/// too (31 and 33 bytes both INVALID_PARAMETER).
fn coord(dst: &mut [u8; 32], src: &[u8]) -> Result<(), CtapError> {
    *dst = src.try_into().map_err(|_| CtapError::InvalidParameter)?;
    Ok(())
}

/// Parse the extension map `{1: keyAgreement(COSE), 2: salt_enc, 3: salt_auth,
/// 4: pinUvAuthProtocol}`.
pub fn parse<'a>(d: &mut Decoder<'a>) -> Result<HmacSecretReq<'a>, CtapError> {
    let mut req = HmacSecretReq {
        present: true,
        ..Default::default()
    };
    let m = def_map(d)?;
    for _ in 0..m {
        match cbor(d.u32())? {
            0x01 => {
                let km = def_map(d)?;
                for _ in 0..km {
                    match cbor(d.i32())? {
                        -2 => coord(&mut req.peer_x, cbor(d.bytes())?)?,
                        -3 => coord(&mut req.peer_y, cbor(d.bytes())?)?,
                        _ => cbor(d.skip())?,
                    }
                }
            }
            0x02 => req.salt_enc = cbor(d.bytes())?,
            0x03 => req.salt_auth = cbor(d.bytes())?,
            0x04 => req.proto = cbor(d.u32())? as u64,
            _ => cbor(d.skip())?,
        }
    }
    Ok(req)
}

/// Parse an hmac-secret extension map from raw CBOR bytes (test / fuzz entry).
pub fn parse_bytes(data: &[u8]) -> Result<HmacSecretReq<'_>, CtapError> {
    parse(&mut Decoder::new(data))
}

/// Validate `salt_enc.len()` for `proto`, returning the plaintext salt length (32
/// for one salt, 64 for two).
fn salt_plaintext_len(proto: PinProto, salt_enc_len: usize) -> Option<usize> {
    let off = proto.iv_overhead();
    if salt_enc_len == 32 + off {
        Some(32)
    } else if salt_enc_len == 64 + off {
        Some(64)
    } else {
        None
    }
}

/// Evaluate hmac-secret for `cred_id`: write the encrypted HMAC output into `out`
/// and return its length (= `req.salt_enc.len()`). `ephemeral` is the
/// authenticator's clientPIN ECDH scalar.
#[allow(clippy::too_many_arguments)]
pub fn eval<R: Rng>(
    req: &HmacSecretReq,
    ephemeral: &[u8; 32],
    seed: &[u8; 32],
    cred_id: &[u8],
    uv: bool,
    rng: &mut R,
    out: &mut [u8],
) -> Result<usize, CtapError> {
    let proto = PinProto::from_u64(req.proto).ok_or(CtapError::InvalidParameter)?;
    let n_salt = salt_plaintext_len(proto, req.salt_enc.len()).ok_or(CtapError::InvalidLength)?;

    let mut shared = [0u8; 64];
    let slen = pinproto::ecdh(proto, ephemeral, &req.peer_x, &req.peer_y, &mut shared)
        .map_err(|_| CtapError::InvalidParameter)?;

    if !pinproto::verify(proto, &shared[..slen], req.salt_enc, req.salt_auth) {
        shared.zeroize();
        return Err(CtapError::ExtensionFirst);
    }

    let mut salt_dec = [0u8; 64];
    let r = pinproto::decrypt(proto, &shared[..slen], req.salt_enc, &mut salt_dec);
    if r.is_err() {
        shared.zeroize();
        return Err(CtapError::InvalidParameter);
    }

    let mut cred_random = derive_hmac_key(seed, cred_id);
    let crd: &[u8] = if uv {
        &cred_random[32..]
    } else {
        &cred_random[..32]
    };
    let mut out1 = [0u8; 64];
    out1[..32].copy_from_slice(&hmac_sha256(crd, &salt_dec[..32]));
    if n_salt == 64 {
        let h2 = hmac_sha256(crd, &salt_dec[32..64]);
        out1[32..64].copy_from_slice(&h2);
    }

    let mut iv = [0u8; IV_SIZE];
    rng.fill(&mut iv);
    let nout = pinproto::encrypt(proto, &shared[..slen], &iv, &out1[..n_salt], out)
        .map_err(|_| CtapError::Other)?;

    shared.zeroize();
    salt_dec.zeroize();
    cred_random.zeroize();
    out1.zeroize();
    Ok(nout)
}

#[cfg(test)]
#[path = "hmacsecret_tests.rs"]
mod tests;
