// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Small CBOR-decode helpers shared by the command parsers: map minicbor errors
//! to `CtapError` and require definite-length maps/arrays (CTAP2 canonical CBOR).

use minicbor::Decoder;

use crate::consts::PUBLIC_KEY_TYPE;
use crate::error::CtapError;

pub fn cbor<T>(r: core::result::Result<T, minicbor::decode::Error>) -> Result<T, CtapError> {
    // A major-type mismatch (e.g. a text string where an int is expected) maps to
    // CTAP2_ERR_CBOR_UNEXPECTED_TYPE; anything else is CTAP2_ERR_INVALID_CBOR.
    r.map_err(|e| {
        if e.is_type_mismatch() {
            CtapError::CborUnexpectedType
        } else {
            CtapError::InvalidCbor
        }
    })
}

pub fn def_map(d: &mut Decoder) -> Result<u64, CtapError> {
    cbor(d.map())?.ok_or(CtapError::InvalidCbor)
}

pub fn def_arr(d: &mut Decoder) -> Result<u64, CtapError> {
    cbor(d.array())?.ok_or(CtapError::InvalidCbor)
}

/// Parse a credential-descriptor array — getAssertion's `allowList` (key 3) or
/// makeCredential's `excludeList` (key 5) — into `out`, returning how many ids
/// are usable.
///
/// `out` is sized by `MAX_CREDENTIAL_COUNT_IN_LIST`, the ceiling getInfo 0x07
/// advertises: a longer array is `CTAP2_ERR_LIMIT_EXCEEDED`, which tells the
/// platform to split it. Never truncate — a dropped tail reads to the platform
/// as "no such credential" on getAssertion and, worse, silently forfeits
/// excludeList's re-registration protection on makeCredential.
///
/// A descriptor whose `type` is not `public-key` is skipped, not matched on its
/// id, but still counts towards the ceiling.
pub fn parse_credential_descriptors<'a>(
    d: &mut Decoder<'a>,
    out: &mut [&'a [u8]],
) -> Result<usize, CtapError> {
    let n = def_arr(d)?;
    if n > out.len() as u64 {
        return Err(CtapError::LimitExceeded);
    }
    let mut len = 0;
    for _ in 0..n {
        let m = def_map(d)?;
        let mut id: &[u8] = &[];
        let (mut id_present, mut type_present, mut is_public_key) = (false, false, false);
        for _ in 0..m {
            match cbor(d.str())? {
                "id" => {
                    id = cbor(d.bytes())?;
                    id_present = true;
                }
                // Read "type" as text so a byte-string yields CborUnexpectedType.
                "type" => {
                    is_public_key = cbor(d.str())? == PUBLIC_KEY_TYPE;
                    type_present = true;
                }
                _ => cbor(d.skip())?,
            }
        }
        // A credential descriptor needs both "type" and "id".
        if !type_present || !id_present {
            return Err(CtapError::MissingParameter);
        }
        if is_public_key {
            out[len] = id;
            len += 1;
        }
    }
    Ok(len)
}

#[cfg(test)]
#[path = "cbordec_tests.rs"]
mod tests;
