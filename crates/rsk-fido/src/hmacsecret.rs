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
use crate::cbordec::{cbor, def_map, skip_value};
use crate::credential::derive_hmac_key;
use crate::error::CtapError;

/// Max saltEnc: two 32-byte salts + the PIN-protocol-2 IV — also the max [`eval`]
/// output length (`pinproto::encrypt` output = IV overhead + plaintext).
pub const SALT_ENC_MAX: usize = 64 + 16;
/// Headroom over the 32-byte protocol-2 saltAuth MAC — kept at the existing
/// size, not a spec formula.
pub const SALT_AUTH_MAX: usize = 48;

/// Every `saltEnc` wire length §12.5 can produce: one or two 32-byte salts, with
/// or without protocol two's 16-byte IV. Deliberately protocol-agnostic — a
/// YubiKey 5.7.4 accepts all four under *both* protocols and leaves what the
/// protocol actually allows to the post-decryption check below.
const SALT_ENC_LENGTHS: [usize; 4] = [32, 48, 64, 80];
// The gate above and the buffer below are one number: `FidoState`'s getNextAssertion
// replay copy is sized by `SALT_ENC_MAX`, and a length this list accepts but that
// buffer cannot hold would be truncated on the second assertion, not refused.
const _: () = assert!(SALT_ENC_LENGTHS[SALT_ENC_LENGTHS.len() - 1] == SALT_ENC_MAX);
/// `saltAuth` MAC lengths: protocol one truncates to 16 bytes, protocol two keeps
/// 32. Also protocol-agnostic on the oracle, and also judged before the MAC.
const SALT_AUTH_LENGTHS: [usize; 2] = [16, 32];

/// A parsed hmac-secret / hmac-secret-mc request map.
pub struct HmacSecretReq<'a> {
    pub peer_x: [u8; 32],
    pub peer_y: [u8; 32],
    /// `None` = the sub-field was absent (MISSING_PARAMETER); a zero-length one
    /// was sent and is simply the wrong length (INVALID_LENGTH).
    pub salt_enc: Option<&'a [u8]>,
    pub salt_auth: Option<&'a [u8]>,
    pub proto: u64,
    pub present: bool,
}

impl Default for HmacSecretReq<'_> {
    fn default() -> Self {
        Self {
            peer_x: [0; 32],
            peer_y: [0; 32],
            salt_enc: None,
            salt_auth: None,
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
                        _ => skip_value(d)?,
                    }
                }
            }
            0x02 => req.salt_enc = Some(cbor(d.bytes())?),
            0x03 => req.salt_auth = Some(cbor(d.bytes())?),
            0x04 => req.proto = cbor(d.u32())? as u64,
            _ => skip_value(d)?,
        }
    }
    Ok(req)
}

/// Parse an hmac-secret extension map from raw CBOR bytes (test / fuzz entry).
pub fn parse_bytes(data: &[u8]) -> Result<HmacSecretReq<'_>, CtapError> {
    parse(&mut Decoder::new(data))
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
    // The callers judge absence first so it lands ahead of their own extension
    // rules (§12.5's up-refusal, hmac-secret-mc's flag); this keeps `eval` total.
    let salt_enc = req.salt_enc.ok_or(CtapError::MissingParameter)?;
    let salt_auth = req.salt_auth.ok_or(CtapError::MissingParameter)?;
    // Both lengths before the MAC: cheap refusal on unauthenticated input, leaking
    // nothing the wire length does not already show — and it is where a YubiKey
    // 5.7.4 puts them (a 47-byte saltEnc with a good MAC is refused, a 32-byte one
    // with a broken MAC is not).
    if !SALT_ENC_LENGTHS.contains(&salt_enc.len()) || !SALT_AUTH_LENGTHS.contains(&salt_auth.len())
    {
        return Err(CtapError::InvalidLength);
    }

    let mut shared = [0u8; 64];
    let slen = pinproto::ecdh(proto, ephemeral, &req.peer_x, &req.peer_y, &mut shared)
        .map_err(|_| CtapError::InvalidParameter)?;

    // §12.5: "Authenticator calls verify(shared secret, saltEnc, saltAuth) — if the
    // verification fails, return CTAP2_ERR_PIN_AUTH_INVALID."
    if !pinproto::verify(proto, &shared[..slen], salt_enc, salt_auth) {
        shared.zeroize();
        return Err(CtapError::PinAuthInvalid);
    }

    // §12.5: the decrypted result must be 32 or 64 bytes, else INVALID_PARAMETER.
    // The wire gate above is the union over both protocols, so this is where a
    // length the *sending* protocol cannot produce (48 bytes under protocol one)
    // is refused — after the MAC, exactly as §12.5 orders it.
    let n_salt = salt_enc.len() - proto.iv_overhead();
    if n_salt != 32 && n_salt != 64 {
        shared.zeroize();
        return Err(CtapError::InvalidParameter);
    }

    let mut salt_dec = [0u8; 64];
    let r = pinproto::decrypt(proto, &shared[..slen], salt_enc, &mut salt_dec);
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
