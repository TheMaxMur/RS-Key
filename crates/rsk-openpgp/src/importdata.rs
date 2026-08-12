// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! IMPORT (INS 0xDB): write an externally generated key pair into a slot via the
//! extended header list `4D { <CRT> 7F48 { tag-length list } 5F48 { key data } }`.
//! The CRT tag picks the slot; the algorithm comes from the slot's
//! algorithm-attribute DO (`EF_ALGO_PRIV{1,2,3}`), set beforehand via PUT DATA.

use rsk_crypto::Device;
use rsk_fs::{Fs, KeyFid, Storage};
use rsk_sdk::Sw;

use crate::consts::*;
use crate::keys::{
    MAX_EC_POINT, MAX_RSA_PUBDO, PrivKey, RSA_PUB_EXP_BE, curve_from_attr, make_ec_pubkey_do,
    make_rsa_response, reset_sig_count, rsa_from_pqe, store_ec_key, store_rsa_key,
};
use crate::origin;
use crate::pin::Session;

/// BER length: a byte < 0x80 is the length; `0x81` introduces a 1-byte length,
/// `0x82` a 2-byte one. Advances `pos`.
pub(crate) fn tag_len(data: &[u8], pos: &mut usize) -> Option<usize> {
    let b = *data.get(*pos)?;
    *pos += 1;
    Some(match b {
        0x82 => {
            let hi = *data.get(*pos)? as usize;
            let lo = *data.get(*pos + 1)? as usize;
            *pos += 2;
            (hi << 8) | lo
        }
        0x81 => {
            let l = *data.get(*pos)? as usize;
            *pos += 1;
            l
        }
        l => l as usize,
    })
}

/// IMPORT (INS 0xDB, P1P2 = 3F FF).
pub fn import_data<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> Sw {
    if p1 != 0x3F || p2 != 0xFF {
        return Sw::WRONG_P1P2;
    }
    if data.len() < 5 {
        return Sw::WRONG_LENGTH;
    }
    match try_import(dev, fs, sess, data) {
        Ok(()) => Sw::OK,
        Err(sw) => sw,
    }
}

/// Parse the `4D` header through the control-reference template tag: returns the
/// key-slot FID and the position just after the (skipped) CRT body. Pure (no fs /
/// crypto), so it is fuzzable in isolation.
pub fn parse_ehl_head(data: &[u8]) -> Result<(KeyFid, usize), Sw> {
    let mut pos = 0usize;
    // 4D extended-header-list tag + its (ignored) length.
    if *data.first().ok_or(WRONG_DATA)? != (EF_EXT_HEADER & 0xff) as u8 {
        return Err(WRONG_DATA);
    }
    pos += 1;
    tag_len(data, &mut pos).ok_or(WRONG_DATA)?;

    // Control-reference template tag selects the key slot.
    let fid = crt_slot(*data.get(pos).ok_or(WRONG_DATA)?).ok_or(WRONG_DATA)?;
    pos += 1;
    // Skip the CRT body: a 1-byte length followed by that many bytes.
    let crt_body = *data.get(pos).ok_or(WRONG_DATA)? as usize;
    Ok((fid, pos + 1 + crt_body))
}

/// Parse the `7F48` template + `5F48` key data starting at `pos`: returns, for
/// each tag 0x91..=0x99, the (offset, length) of its value within `data`. Pure.
#[allow(clippy::type_complexity)]
pub fn parse_ehl_body(data: &[u8], mut pos: usize) -> Result<([Option<usize>; 9], [usize; 9]), Sw> {
    // 7F48: the private-key template (tag-length pairs only).
    if *data.get(pos).ok_or(WRONG_DATA)? != 0x7F || *data.get(pos + 1).ok_or(WRONG_DATA)? != 0x48 {
        return Err(WRONG_DATA);
    }
    pos += 2;
    let tmpl_len = tag_len(data, &mut pos).ok_or(WRONG_DATA)?;
    let tmpl_end = pos.checked_add(tmpl_len).ok_or(WRONG_DATA)?;
    let mut len = [0usize; 9];
    while pos < tmpl_end {
        let tag = *data.get(pos).ok_or(WRONG_DATA)?;
        pos += 1;
        if (0x91..=0x97).contains(&tag) || tag == 0x99 {
            len[(tag - 0x91) as usize] = tag_len(data, &mut pos).ok_or(WRONG_DATA)?;
        } else {
            return Err(WRONG_DATA);
        }
    }

    // 5F48: the concatenated key data; carve out each element by its length.
    if *data.get(pos).ok_or(WRONG_DATA)? != 0x5F || *data.get(pos + 1).ok_or(WRONG_DATA)? != 0x48 {
        return Err(WRONG_DATA);
    }
    pos += 2;
    let kd_len = tag_len(data, &mut pos).ok_or(WRONG_DATA)?;
    let kd_end = pos.checked_add(kd_len).ok_or(WRONG_DATA)?;
    let mut off = [None::<usize>; 9];
    let mut sp = pos;
    for (t, l) in len.iter().enumerate() {
        if sp >= kd_end {
            break;
        }
        if *l > 0 {
            off[t] = Some(sp);
            sp = sp.checked_add(*l).ok_or(WRONG_DATA)?;
        }
    }
    Ok((off, len))
}

fn try_import<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    data: &[u8],
) -> Result<(), Sw> {
    let (fid, pos) = parse_ehl_head(data)?;
    // Key import is an admin (PW3) operation.
    if !sess.has_pw3 {
        return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
    }
    let (off, len) = parse_ehl_body(data, pos)?;

    // The algorithm attribute decides RSA vs EC and (for EC) the curve.
    let algo_fid = slot_algo_fid(fid);
    let mut algo_buf = [0u8; 16];
    let algo: &[u8] = match fs.read(algo_fid, &mut algo_buf) {
        // Clamp: `Storage::read` reports the DO's full stored length and PUT DATA
        // caps nothing, so an over-long C1/C2/C3 must not slice OOB = brick.
        Some(n) if n > 0 => &algo_buf[..n.min(algo_buf.len())],
        _ => DEFAULT_ALGO,
    };
    match algo[0] {
        ALGO_RSA => {
            // Exponent (0x91), prime P (0x92) and prime Q (0x93) must all be present.
            let e = match off[0] {
                Some(o) => data.get(o..o + len[0]).ok_or(WRONG_DATA)?,
                None => return Err(WRONG_DATA),
            };
            let p = match off[1] {
                Some(o) => data.get(o..o + len[1]).ok_or(WRONG_DATA)?,
                None => return Err(WRONG_DATA),
            };
            let q = match off[2] {
                Some(o) => data.get(o..o + len[2]).ok_or(WRONG_DATA)?,
                None => return Err(WRONG_DATA),
            };
            if e.is_empty() || p.is_empty() || q.is_empty() {
                return Err(WRONG_DATA);
            }
            // The CRT signer / DECIPHER hardcode e = 65537 (rsa_crt.rs); another
            // exponent signs with the wrong e while the public DO advertises the
            // real one -- silently unusable. gpg only ever imports e = 65537.
            if !e
                .iter()
                .copied()
                .skip_while(|&b| b == 0)
                .eq(RSA_PUB_EXP_BE.iter().copied())
            {
                return Err(WRONG_DATA);
            }
            let key = rsa_from_pqe(e, p, q).ok_or(Sw::EXEC_ERROR)?;
            // Before the key is committed, never after: a tear in between leaves
            // the slot reading as imported, which is the honest claim either way.
            // Its failure is fatal for the same reason — storing on top of a mark
            // that did not persist keeps an older `01` over an imported key.
            origin::mark(fs, fid, origin::ORIGIN_IMPORTED)?;
            store_rsa_key(dev, fs, sess, fid, &key)?;

            // Public-key DO → EF_PB_* (slot FID + 3).
            let mut pub_do = [0u8; MAX_RSA_PUBDO];
            let don = make_rsa_response(&key, &mut pub_do);
            fs.put(slot_pub_fid(fid), &pub_do[..don])
                .map_err(|_| Sw::MEMORY_FAILURE)?;

            if fid == EF_PK_SIG {
                reset_sig_count(fs)?;
            }
            Ok(())
        }
        ALGO_ECDSA | ALGO_ECDH | ALGO_EDDSA => {
            let curve = curve_from_attr(algo).ok_or(Sw::FUNC_NOT_SUPPORTED)?;
            // The private scalar / seed is tag 0x92 (index 1).
            let scalar = match off[1] {
                Some(o) => data.get(o..o + len[1]).ok_or(WRONG_DATA)?,
                None => return Err(WRONG_DATA),
            };
            let key = PrivKey::from_scalar(curve, scalar).ok_or(WRONG_DATA)?;

            // Derive the public point BEFORE committing the key. `pad` bounds only
            // the length, so a zero or out-of-range scalar reaches this far and is
            // first rejected here — storing first meant a *failed* import destroyed
            // the previous private key while EF_PB_*, DO 0xDE and the signature
            // counter went on describing it, and the host saw only an error. The
            // sibling applet orders it this way for the same reason
            // (`rsk_piv::keygen`).
            let mut point = [0u8; MAX_EC_POINT];
            let plen = key.public_point(&mut point)?;

            origin::mark(fs, fid, origin::ORIGIN_IMPORTED)?;
            store_ec_key(dev, fs, sess, fid, &key)?;

            // Store the public-key DO into EF_PB_* (slot FID + 3).
            let mut pub_do = [0u8; 8 + MAX_EC_POINT];
            let don = make_ec_pubkey_do(&point[..plen], &mut pub_do);
            fs.put(slot_pub_fid(fid), &pub_do[..don])
                .map_err(|_| Sw::MEMORY_FAILURE)?;

            if fid == EF_PK_SIG {
                reset_sig_count(fs)?;
            }
            Ok(())
        }
        _ => Err(Sw::FUNC_NOT_SUPPORTED),
    }
}

/// Kani proof harnesses (`cargo kani -p rsk-openpgp`): the IMPORT extended-header
/// -list parser walks attacker-controlled BER bytes, so prove the hand-rolled
/// length reader and the two walkers are panic-free and terminating for every
/// input up to the bound (the `openpgp_import` fuzz target samples larger ones).
/// The offsets `parse_ehl_body` returns may point past the data by design —
/// `try_import` carves each element with a bounds-checked `data.get(o..o + len)`,
/// turning an out-of-range offset into `WRONG_DATA`, never a panic — so the
/// proofs assert panic-freedom, not offset containment.
#[cfg(kani)]
#[path = "importdata_kani.rs"]
mod proofs;
