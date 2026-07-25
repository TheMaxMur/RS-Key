// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `authenticatorLargeBlobs`: an opaque, platform-managed serialized array in
//! EF_LARGEBLOB. `get` reads a fragment at an offset; `set` accumulates
//! fragments across commands and commits only once the whole array (length
//! fixed by the first fragment, trailing 16 bytes = left half of
//! SHA-256(body)) has arrived and verified.

use minicbor::encode::write::Cursor;
use minicbor::encode::{Error, Write};
use minicbor::{Decoder, Encoder};
use rsk_fs::Storage;

use rsk_crypto::pinproto::PinProto;
use rsk_crypto::sha256;

use crate::cbordec::{cbor, def_map};
use crate::consts::{
    CTAP_LARGE_BLOBS, EF_LARGEBLOB, LARGEBLOB_MIN, MAX_FRAGMENT_LENGTH, MAX_LARGE_BLOB_SIZE,
};
use crate::error::{CtapError, CtapResult};
use crate::state::PERM_LBW;
use crate::{Ctx, Rng};

struct Req<'a> {
    get: u64,                            // 0x01 — bytes to read (valid when get_present)
    get_present: bool,                   // whether 0x01 was supplied (get=0 reads nothing)
    set: Option<&'a [u8]>,               // 0x02 — fragment to write
    offset: u64,                         // 0x03 — UINT64_MAX sentinel = absent
    length: u64,                         // 0x04 — total array length (first fragment)
    pin_uv_auth_param: Option<&'a [u8]>, // 0x05
    proto: u64,                          // 0x06
}

fn parse(data: &[u8]) -> Result<Req<'_>, CtapError> {
    let mut d = Decoder::new(data);
    let mut req = Req {
        get: 0,
        get_present: false,
        set: None,
        offset: u64::MAX,
        length: 0,
        pin_uv_auth_param: None,
        proto: 0,
    };
    let n = def_map(&mut d)?;
    // Keys must be strictly ascending; unlike authenticatorConfig, key 1 is not
    // mandatory (a write has no key 1).
    let mut expected = 1u64;
    for _ in 0..n {
        let key = cbor(d.u64())?;
        if key < expected {
            return Err(CtapError::InvalidCbor);
        }
        // `key + 1` would overflow on a `u64::MAX` key (no real CTAP key is
        // anywhere near it); reject rather than wrap the ascending watermark.
        expected = key.checked_add(1).ok_or(CtapError::InvalidCbor)?;
        match key {
            0x01 => {
                req.get = cbor(d.u64())?;
                req.get_present = true;
            }
            0x02 => req.set = Some(cbor(d.bytes())?),
            0x03 => req.offset = cbor(d.u64())?,
            0x04 => req.length = cbor(d.u64())?,
            0x05 => req.pin_uv_auth_param = Some(cbor(d.bytes())?),
            0x06 => req.proto = cbor(d.u64())?,
            _ => cbor(d.skip())?,
        }
    }
    Ok(req)
}

/// `authenticatorLargeBlobs`: read or write a fragment of the large-blob array.
pub fn large_blobs<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    data: &[u8],
    out: &mut [u8],
) -> CtapResult {
    let req = parse(data)?;

    // offset (0x03) is mandatory; exactly one of get / set must be present.
    // get=0 is a valid read of zero bytes (conformance LargeBlobs-1 P-2), so the
    // get/set choice keys off whether 0x01 was *supplied*, not its value.
    if req.offset == u64::MAX {
        return Err(CtapError::InvalidParameter);
    }
    if req.get_present == req.set.is_some() {
        return Err(CtapError::InvalidParameter);
    }

    if req.get_present {
        read_fragment(ctx, &req, out)
    } else {
        write_fragment(ctx, &req, out)
    }
}

fn read_fragment<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req, out: &mut [u8]) -> CtapResult {
    if req.length != 0 {
        return Err(CtapError::InvalidParameter);
    }
    let mut blob = [0u8; MAX_LARGE_BLOB_SIZE];
    let size = ctx
        .fs
        .read(EF_LARGEBLOB, &mut blob)
        .unwrap_or(0)
        .min(blob.len());
    let offset = req.offset as usize;
    if offset > size {
        return Err(CtapError::InvalidParameter);
    }
    let take = core::cmp::min(req.get as usize, size - offset);
    let mut enc = Encoder::new(Cursor::new(out));
    write_get(&mut enc, &blob[offset..offset + take]).map_err(|_| CtapError::Other)?;
    Ok(enc.writer().position())
}

fn write_get<W: Write>(enc: &mut Encoder<W>, fragment: &[u8]) -> Result<(), Error<W::Error>> {
    enc.map(1)?.u8(0x01)?.bytes(fragment)?;
    Ok(())
}

fn write_fragment<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Req,
    out: &mut [u8],
) -> CtapResult {
    let _ = out; // a write replies with only the status byte
    let set = req.set.ok_or(CtapError::InvalidParameter)?;
    if set.len() > MAX_FRAGMENT_LENGTH {
        return Err(CtapError::InvalidLength);
    }
    // `usize` is 32-bit on the firmware target, so narrow BEFORE bounding: checking
    // the ceiling on a truncated length while checking the floor on the raw u64 let
    // a length ≥ 2^32 with small low bits pass both and store a value under
    // LARGEBLOB_MIN, which then underflowed `total - 16` at the commit below.
    let offset = usize::try_from(req.offset).map_err(|_| CtapError::InvalidParameter)?;
    if offset == 0 {
        let length = usize::try_from(req.length).map_err(|_| CtapError::LargeBlobStorageFull)?;
        if length == 0 {
            return Err(CtapError::InvalidParameter);
        }
        if length > MAX_LARGE_BLOB_SIZE {
            return Err(CtapError::LargeBlobStorageFull);
        }
        if length < LARGEBLOB_MIN {
            return Err(CtapError::InvalidParameter);
        }
        ctx.state.lba.expected_length = length;
        ctx.state.lba.expected_next_offset = 0;
    } else if req.length != 0 {
        return Err(CtapError::InvalidParameter);
    }
    if offset != ctx.state.lba.expected_next_offset {
        return Err(CtapError::InvalidSeq);
    }

    // pinUvAuthParam MAC over 0xff×32 ‖ 0x0c ‖ 0x00 ‖ offset_le(4) ‖ sha256(set).
    let param = req.pin_uv_auth_param.ok_or(CtapError::PuatRequired)?;
    if req.proto == 0 {
        return Err(CtapError::MissingParameter);
    }
    let proto = PinProto::from_u64(req.proto).ok_or(CtapError::InvalidParameter)?;
    let mut vd = [0u8; 70];
    vd[..32].fill(0xff);
    vd[32] = CTAP_LARGE_BLOBS;
    vd[34..38].copy_from_slice(&(offset as u32).to_le_bytes());
    vd[38..70].copy_from_slice(&sha256(set));
    if !ctx.state.verify_token(proto, &vd, param) || ctx.state.paut.permissions & PERM_LBW == 0 {
        return Err(CtapError::PinAuthInvalid);
    }
    ctx.state.mark_token_used(ctx.now_ms);

    if offset + set.len() > ctx.state.lba.expected_length {
        return Err(CtapError::InvalidParameter);
    }
    if offset == 0 {
        ctx.state.lba.temp.fill(0);
    }
    let next = ctx.state.lba.expected_next_offset;
    ctx.state.lba.temp[next..next + set.len()].copy_from_slice(set);
    ctx.state.lba.expected_next_offset += set.len();

    if ctx.state.lba.expected_next_offset == ctx.state.lba.expected_length {
        let total = ctx.state.lba.expected_length;
        // The platform appends left16(SHA-256(body)) as an integrity tag; verify
        // it (skipped for the 17-byte empty-array minimum, body = 1 byte).
        let sha = sha256(&ctx.state.lba.temp[..total.saturating_sub(16)]);
        if total > LARGEBLOB_MIN && sha[..16] != ctx.state.lba.temp[total - 16..total] {
            return Err(CtapError::IntegrityFailure);
        }
        ctx.fs
            .put(EF_LARGEBLOB, &ctx.state.lba.temp[..total])
            .map_err(|_| CtapError::Other)?;
    }
    Ok(0)
}

#[cfg(test)]
#[path = "largeblobs_tests.rs"]
mod tests;
