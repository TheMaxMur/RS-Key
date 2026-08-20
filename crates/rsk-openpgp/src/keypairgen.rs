// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! GENERATE ASYMMETRIC KEY PAIR (INS 0x47): `P1 = 0x80` generates a fresh key
//! pair into the slot named by the control-reference template (`B6`→SIG,
//! `B8`→DEC, `A4`→AUT) and returns its public-key DO; `P1 = 0x81` reads it back.

use rsk_crypto::Device;
use rsk_fs::{Fs, KeyFid, Storage};
use rsk_sdk::Sw;

use crate::Rng;
use crate::consts::*;
use crate::keys::{
    MAX_EC_POINT, PrivKey, curve_from_attr, make_ec_pubkey_do, reset_sig_count, store_aes_key,
    store_ec_key, store_rsa_key,
};
use crate::origin;
use crate::pin::Session;
use rsk_rsa::{MAX_RSA_PUBDO, RsaKey, generate_rsa, make_rsa_response};

/// GENERATE ASYMMETRIC KEY PAIR (INS 0x47). Returns `(response_len, status)`;
/// the response (written to `out`) is the public-key DO `7F49 { … }`.
#[allow(clippy::too_many_arguments)]
pub fn keypair_gen<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    rng: &mut dyn Rng,
    p1: u8,
    p2: u8,
    data: &[u8],
    out: &mut [u8],
) -> (usize, Sw) {
    if p2 != 0x00 {
        return (0, Sw::WRONG_P1P2);
    }
    if data.len() != 2 && data.len() != 5 {
        return (0, Sw::WRONG_LENGTH);
    }
    // Generating overwrites a key, so it is an admin (PW3) operation; reading the
    // public key is not gated.
    if !sess.has_pw3 && p1 == 0x80 {
        return (0, Sw::SECURITY_STATUS_NOT_SATISFIED);
    }
    let Some(fid) = data.first().and_then(|&t| crt_slot(t)) else {
        return (0, Sw::WRONG_DATA);
    };

    let r = match p1 {
        0x80 => generate(dev, fs, sess, rng, fid, out),
        0x81 => read_public(fs, fid, out),
        _ => return (0, Sw::WRONG_P1P2),
    };
    match r {
        Ok(n) => (n, Sw::OK),
        Err(sw) => (0, sw),
    }
}

/// The slot's algorithm attribute, refused unless DO `0xFA` advertises it. Shared
/// with IMPORT, which reaches the same slot by the other door.
///
/// `put_data` gates the *writer*, but a value stored by a build that predates that
/// gate survives a firmware upgrade untouched — `EF_ALGO_PRIV*` is `DoSource::Internal`
/// with no default and no migration, and only TERMINATE DF clears it. The floor
/// underneath, `RsaKeygen::usable`, is an assembly alignment constraint (any 32-byte
/// multiple, i.e. 512 bits), not a policy one. So the check has to run here, where the
/// value is used, or the *owner's* next GENERATE mints the factorable key the writer
/// gate exists to prevent.
///
/// Clamps to the buffer: `Storage::read` reports the DO's full stored length and PUT
/// DATA caps nothing, so an over-long C1/C2/C3 must not slice OOB = brick.
pub(crate) fn read_advertised_algo<'a, S: Storage>(
    fs: &mut Fs<S>,
    fid: KeyFid,
    buf: &'a mut [u8; 16],
) -> Result<&'a [u8], Sw> {
    let priv_fid = slot_algo_fid(fid);
    // `advertised_algo` keys off the public C1/C2/C3 tag; `slot_algo_fid` gives the
    // private companion EF (`algo_tag_to_priv` = `0x1000 | tag`), so undo that or
    // every lookup falls through to the `_ => false` arm and refuses valid keys.
    let tag = priv_fid & !0x1000;
    match fs.read(priv_fid, buf) {
        Some(n) if n > 0 => {
            let algo = &buf[..n.min(buf.len())];
            if crate::dobj::advertised_algo(tag, algo) {
                Ok(algo)
            } else {
                Err(Sw::WRONG_DATA)
            }
        }
        _ => Ok(DEFAULT_ALGO),
    }
}

/// `P1 = 0x80`: generate the key pair, seal it, store + return its public-key DO.
fn generate<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    rng: &mut dyn Rng,
    fid: KeyFid,
    out: &mut [u8],
) -> Result<usize, Sw> {
    // The algorithm attribute (slot FID − 0x10) decides RSA vs EC and the curve.
    // Clamp to the buffer: `Storage::read` reports the DO's full stored length and
    // PUT DATA caps nothing, so an over-long C1/C2/C3 must not slice OOB = brick.
    let mut algo_buf = [0u8; 16];
    let algo = read_advertised_algo(fs, fid, &mut algo_buf)?;

    let n = match algo[0] {
        ALGO_RSA => {
            // The RSA modulus size lives in bytes 1..3; a host can PUT DATA a
            // short (0/1/2-byte) C1/C2/C3 that PUT never length-checks, so guard
            // before indexing — else the slice read panics (device reset). The
            // sibling reader `info::slot_algo` has the same `attr.len() >= 3` gate.
            if algo.len() < 3 {
                return Err(Sw::WRONG_DATA);
            }
            let nbits = ((algo[1] as usize) << 8) | algo[2] as usize;
            let key = generate_rsa(rng, nbits).map_err(crate::keys::rsa_sw)?;
            store_rsa_key(dev, fs, sess, fid, &key)?;
            let mut pub_do = [0u8; MAX_RSA_PUBDO];
            let n = make_rsa_response(&key, &mut pub_do);
            store_public(fs, fid, &pub_do[..n], out)?
        }
        ALGO_ECDSA | ALGO_ECDH | ALGO_EDDSA => {
            let curve = curve_from_attr(algo).ok_or(Sw::FUNC_NOT_SUPPORTED)?;
            let key = PrivKey::generate(curve, rng).ok_or(Sw::EXEC_ERROR)?;
            store_ec_key(dev, fs, sess, fid, &key)?;
            let mut point = [0u8; MAX_EC_POINT];
            let plen = key.public_point(&mut point)?;
            let mut pub_do = [0u8; 8 + MAX_EC_POINT];
            let n = make_ec_pubkey_do(&point[..plen], &mut pub_do);
            store_public(fs, fid, &pub_do[..n], out)?
        }
        _ => return Err(Sw::FUNC_NOT_SUPPORTED),
    };

    keygen_tail(dev, fs, sess, rng, fid)?;
    Ok(n)
}

/// The post-store tail shared by EC and RSA generate: record the slot's origin
/// for DO 0xDE; reset the signature counter on the SIG slot; seed `D5` on the DEC
/// slot if it is empty (OpenPGP cannot generate a symmetric key directly; a
/// storage failure is non-fatal).
///
/// The seed never **replaces** a standing key. §7.2.14 lets GENERATE reset the DS
/// counter and "other related DO (e. g. certificates)", and `D5` is related to no
/// key pair: §7.2.12 gives PSO:ENCIPHER no key reference at all, so one card-level
/// AES key serves a command that never touches the DEC slot.
fn keygen_tail<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    rng: &mut dyn Rng,
    fid: KeyFid,
) -> Result<(), Sw> {
    // After the key is committed, never before: a tear in between leaves the
    // slot reading as imported, which is the claim that cannot be too strong —
    // and for that same reason a mark that does not persist is not worth failing
    // a keygen the host already paid for.
    let _ = origin::mark(fs, fid, origin::ORIGIN_GENERATED);
    if fid == EF_PK_SIG {
        reset_sig_count(fs)?;
    } else if fid == EF_PK_DEC && !fs.has_key(EF_AES_KEY) {
        let mut aes = [0u8; 32];
        rng.fill(&mut aes);
        let _ = store_aes_key(dev, fs, sess, &aes);
        use zeroize::Zeroize;
        aes.zeroize();
    }
    Ok(())
}

/// Persist the public-key DO to `EF_PB_*` (slot FID + 3) and copy it into the
/// response.
fn store_public<S: Storage>(
    fs: &mut Fs<S>,
    fid: KeyFid,
    pub_do: &[u8],
    out: &mut [u8],
) -> Result<usize, Sw> {
    fs.put(slot_pub_fid(fid), pub_do)
        .map_err(|_| Sw::MEMORY_FAILURE)?;
    out[..pub_do.len()].copy_from_slice(pub_do);
    Ok(pub_do.len())
}

/// `P1 = 0x81`: return the stored public-key DO from `EF_PB_*` (slot FID + 3).
fn read_public<S: Storage>(fs: &mut Fs<S>, fid: KeyFid, out: &mut [u8]) -> Result<usize, Sw> {
    if !fs.has_data(slot_pub_fid(fid)) {
        return Err(Sw::REFERENCE_NOT_FOUND);
    }
    // Fs::read returns the value's full stored length; the backend copied only
    // min(len, out.len()). Clamp before returning, like every other reader in the
    // crate, so the caller's `scratch[..n]` slice can never run past `out`.
    fs.read(slot_pub_fid(fid), out)
        .map(|n| n.min(out.len()))
        .ok_or(Sw::REFERENCE_NOT_FOUND)
}

// --- CCID keepalive path: split RSA generate so the slow keygen can run async ---
//
// RSA key generation runs for seconds and would exceed the CCID transaction
// timeout, so the firmware drives the [`rsk_rsa::RsaKeygen`] prime search
// itself (on both RP2350 cores), the transport sending time-extensions between
// candidates. These two helpers are the bookends; EC generate and read-public
// stay synchronous in [`keypair_gen`].

/// Validate a GENERATE (0x47) and, for an RSA slot, return `(fid, nbits)` so
/// the caller can run the keygen asynchronously; `Ok(None)` means EC or
/// read-public — fall back to the synchronous [`keypair_gen`].
pub fn rsa_generate_params<S: Storage>(
    fs: &mut Fs<S>,
    sess: &Session,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> Result<Option<(KeyFid, usize)>, Sw> {
    if p1 != 0x80 {
        return Ok(None); // read-public (0x81) is fast
    }
    if p2 != 0x00 {
        return Err(Sw::WRONG_P1P2);
    }
    if data.len() != 2 && data.len() != 5 {
        return Err(Sw::WRONG_LENGTH);
    }
    if !sess.has_pw3 {
        return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
    }
    let fid = data
        .first()
        .and_then(|&t| crt_slot(t))
        .ok_or(Sw::WRONG_DATA)?;
    let mut algo_buf = [0u8; 16];
    let algo = read_advertised_algo(fs, fid, &mut algo_buf)?;
    if algo[0] != ALGO_RSA {
        return Ok(None); // EC generate — synchronous path handles it
    }
    // Guard the modulus-size read against a short host-written attribute (see the
    // synchronous `generate`); indexing a 1/2-byte slice would panic (device reset).
    if algo.len() < 3 {
        return Err(Sw::WRONG_DATA);
    }
    let nbits = ((algo[1] as usize) << 8) | algo[2] as usize;
    Ok(Some((fid, nbits)))
}

/// Finish an RSA GENERATE once the key has been produced (by stepping
/// [`rsk_rsa::RsaKeygen`]): seal it, store + return the public-key DO, and run
/// the shared SIG/DEC tail. Mirrors the RSA branch + tail of [`keypair_gen`].
pub fn rsa_generate_finish<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    rng: &mut dyn Rng,
    fid: KeyFid,
    key: &RsaKey,
    out: &mut [u8],
) -> (usize, Sw) {
    let r = (|| {
        store_rsa_key(dev, fs, sess, fid, key)?;
        let mut pub_do = [0u8; MAX_RSA_PUBDO];
        let n = make_rsa_response(key, &mut pub_do);
        let resp_len = store_public(fs, fid, &pub_do[..n], out)?;
        keygen_tail(dev, fs, sess, rng, fid)?;
        Ok(resp_len)
    })();
    match r {
        Ok(n) => (n, Sw::OK),
        Err(sw) => (0, sw),
    }
}

#[cfg(test)]
#[path = "keypairgen_tests.rs"]
mod tests;
