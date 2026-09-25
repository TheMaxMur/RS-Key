// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Every other `5Fxxxx` a host stores, as a YubiKey 5.8.0 stores it — the Yubico
//! minidriver's `5FFF10`–`5FFF15` among them: one file of [`POOL`] each, behind the
//! low two bytes of its id, found by a walk the `Fs` cache answers for absent files.

use rsk_fs::{Fs, Storage};
use rsk_sdk::Sw;
use rsk_sdk::error::Error;

use crate::MAX_OBJECT;
use crate::files::object_fid;

/// The pool's files, one object each. Outside every other applet's range, and inside
/// [`crate::files::is_piv_fid`], so a PIV reset takes them.
pub(crate) const POOL: core::ops::RangeInclusive<u16> = 0xD600..=0xD6FF;
/// The id bytes a stored object carries ahead of its body; the first is always `5F`.
const TAG_LEN: usize = 2;
/// A pool record at its largest: the id tag and a [`MAX_OBJECT`] body.
pub(crate) const RECORD_MAX: usize = TAG_LEN + MAX_OBJECT;
/// The bodies the pool holds in all. A YubiKey keeps about 21.5 KB of objects in all;
/// this bounds what a management-key holder can put into the flash every applet's
/// PIN counters share, where 256 full objects would take over 500 KB of it.
pub(crate) const POOL_BYTES: usize = 32 * 1024;

/// Whether `id` is an object the pool holds: a three-byte `5Fxxxx` with no fixed file.
pub(crate) fn in_pool(id: u32) -> bool {
    id >> 16 == 0x5F && object_fid(id).is_none()
}

fn tag(id: u32) -> [u8; TAG_LEN] {
    [(id >> 8) as u8, id as u8]
}

/// One walk of the pool for `id`.
struct Scan {
    /// The file holding `id`, and its body's length.
    held: Option<(u16, usize)>,
    /// The first file holding nothing.
    free: Option<u16>,
    /// The bodies the pool holds, `id`'s included.
    bytes: usize,
}

/// Walk the whole pool. A probe the medium cannot serve refuses: read as absent, a
/// write would store the object a second time beside the copy it missed.
fn scan<S: Storage>(fs: &mut Fs<S>, id: u32) -> Result<Scan, Sw> {
    let mut s = Scan {
        held: None,
        free: None,
        bytes: 0,
    };
    for fid in POOL {
        let mut head = [0u8; TAG_LEN];
        match fs
            .try_read(fid, &mut head)
            .map_err(|_| Sw::MEMORY_FAILURE)?
        {
            Some(n) if n >= TAG_LEN => {
                s.bytes += n - TAG_LEN;
                if head == tag(id) && s.held.is_none() {
                    s.held = Some((fid, n - TAG_LEN));
                }
            }
            Some(_) => {}
            None => {
                s.free.get_or_insert(fid);
            }
        }
    }
    Ok(s)
}

/// Read `id`'s body to the front of `out` (at least [`RECORD_MAX`] long): its length,
/// or `None` when the pool does not hold it.
pub(crate) fn read<S: Storage>(
    fs: &mut Fs<S>,
    id: u32,
    out: &mut [u8],
) -> Result<Option<usize>, Sw> {
    let Some((fid, _)) = scan(fs, id)?.held else {
        return Ok(None);
    };
    let out = &mut out[..RECORD_MAX];
    let n = fs
        .try_read(fid, out)
        .map_err(|_| Sw::MEMORY_FAILURE)?
        .ok_or(Sw::MEMORY_FAILURE)?
        .clamp(TAG_LEN, RECORD_MAX);
    out.copy_within(TAG_LEN..n, 0);
    Ok(Some(n - TAG_LEN))
}

/// Store `obj` as `id`: over its current copy, else in the first free file. `6A84`,
/// what a YubiKey answers once its object store is full, when no file is free or the
/// bodies would pass [`POOL_BYTES`]; a body over [`MAX_OBJECT`] is `6700`.
pub(crate) fn write<S: Storage>(fs: &mut Fs<S>, id: u32, obj: &[u8]) -> Result<(), Sw> {
    if obj.len() > MAX_OBJECT {
        return Err(Sw::WRONG_LENGTH);
    }
    let s = scan(fs, id)?;
    let replaced = s.held.map_or(0, |(_, n)| n);
    if s.bytes - replaced + obj.len() > POOL_BYTES {
        return Err(Sw::FILE_FULL);
    }
    let fid = s.held.map(|(fid, _)| fid).or(s.free).ok_or(Sw::FILE_FULL)?;
    let mut rec = [0u8; RECORD_MAX];
    rec[..TAG_LEN].copy_from_slice(&tag(id));
    rec[TAG_LEN..TAG_LEN + obj.len()].copy_from_slice(obj);
    fs.put(fid, &rec[..TAG_LEN + obj.len()]).map_err(put_sw)
}

/// Drop `id`. An object the pool does not hold is already gone: a YubiKey answers
/// `9000` for it.
pub(crate) fn delete<S: Storage>(fs: &mut Fs<S>, id: u32) -> Result<(), Sw> {
    match scan(fs, id)?.held {
        Some((fid, _)) => fs.delete(fid).map_err(|_| Sw::MEMORY_FAILURE),
        None => Ok(()),
    }
}

/// A refused `Fs::put`, as PUT DATA answers it: past the device's shared file budget
/// (`NoMemory`) is `6A84`, as a full YubiKey answers; anything else, a full flash
/// included, is `6581`.
pub(crate) fn put_sw(e: Error) -> Sw {
    match e {
        Error::NoMemory => Sw::FILE_FULL,
        _ => Sw::MEMORY_FAILURE,
    }
}
