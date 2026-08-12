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

/// Skip a value the parser does not read — but refuse a CBOR **tag** rather than
/// walking through it. §8's canonical form has no tags at all, and a decoder that
/// silently steps over one lets two readers of the same message disagree about
/// what was sent, which is the request-smuggling shape [`one_cbor_item`] exists
/// for. Measured on a YubiKey 5.7.4: a tag on a value it does not read is
/// `CTAP2_ERR_INVALID_CBOR`, on one it does read `CTAP1_ERR_INVALID_PARAMETER`,
/// and on a map *key* `CTAP2_ERR_CBOR_UNEXPECTED_TYPE` — which is what the typed
/// readers here already answer, so only the skipped ones needed the rule.
pub fn skip_value(d: &mut Decoder) -> Result<(), CtapError> {
    if cbor(d.datatype())? == minicbor::data::Type::Tag {
        return Err(CtapError::InvalidCbor);
    }
    cbor(d.skip())
}

/// §8: a CTAP2 request body is exactly ONE CBOR item. Anything after it is a
/// request-smuggling shape — two readers of the same message can disagree about
/// what was asked — and a YubiKey 5.7.4 refuses it with CTAP2_ERR_INVALID_CBOR on
/// every command that parses a body.
///
/// A body the decoder cannot even walk is left to the command parser: it has the
/// context for the specific code, and this pass must not pre-empt it. `skip` is
/// the counter-based no-alloc one, so an adversarially nested body costs no stack.
pub fn one_cbor_item(params: &[u8]) -> Result<(), CtapError> {
    let mut d = Decoder::new(params);
    if d.skip().is_ok() && d.position() != params.len() {
        return Err(CtapError::InvalidCbor);
    }
    Ok(())
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
                _ => skip_value(d)?,
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
