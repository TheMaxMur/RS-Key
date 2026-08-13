// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! PERFORM SECURITY OPERATION (INS 0x2A): `9E 9A` COMPUTE DIGITAL SIGNATURE
//! (PW1, bumps the signature counter), `80 86` DECIPHER (PW2; RSA, ECDH, or AES
//! by the `0x02` padding indicator), `86 80` ENCIPHER (PW2, AES-only).

use rsk_crypto::Device;
use rsk_fs::{Fs, Storage};
use rsk_sdk::{Apdu, Sw};

use rsk_crypto::aes::{Mode, aes_decrypt, aes_encrypt};
use zeroize::Zeroize;

use crate::consts::*;
use crate::importdata::tag_len;
use crate::keys::{
    inc_sig_count, load_aes_key, load_ec_key, load_rsa_crt, load_rsa_key, rsa_decipher,
    rsa_sign_crt,
};
use crate::pin::Session;
use crate::{Rng, UserPresence, check_uif};

/// Read the algorithm attribute stored at `algo_fid` into `buf`, defaulting to
/// RSA-2048.
fn algo_id<S: Storage>(fs: &mut Fs<S>, algo_fid: u16, buf: &mut [u8; 16]) -> u8 {
    match fs.read(algo_fid, buf) {
        Some(n) if n > 0 => buf[0],
        _ => DEFAULT_ALGO[0],
    }
}

/// PERFORM SECURITY OPERATION (INS 0x2A).
pub fn pso<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &mut Session,
    rng: &mut dyn Rng,
    presence: &mut dyn UserPresence,
    apdu: &Apdu,
    out: &mut [u8],
) -> (usize, Sw) {
    match try_pso(dev, fs, sess, rng, presence, apdu, out) {
        Ok(n) => (n, Sw::OK),
        Err(sw) => (0, sw),
    }
}

fn try_pso<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &mut Session,
    rng: &mut dyn Rng,
    presence: &mut dyn UserPresence,
    apdu: &Apdu,
    out: &mut [u8],
) -> Result<usize, Sw> {
    let (p1, p2, data) = (apdu.p1, apdu.p2, apdu.data);

    // AES symmetric PSO over `EF_AES_KEY` — the DEC slot's AES key, minted by
    // GENERATE and settable by `PUT DATA D5`. DECIPHER carries the `0x02` padding
    // indicator — unambiguous against RSA's `0x00` / ECDH's `0xA6` — so it routes
    // here; ENCIPHER (`86 80`) is AES-only per the card spec (input = plaintext,
    // output = `0x02 || cryptogram`). Both need the DEC password (PW2/PW3) and
    // honour the DEC UIF touch policy.
    let aes_enc = (p1, p2) == (0x86, 0x80);
    let aes_dec = (p1, p2) == (0x80, 0x86) && data.first() == Some(&0x02);
    if aes_enc || aes_dec {
        // §7.2.11 names PW1 no. 82, and only that. A YubiKey has no AES DO to
        // measure here, but it refuses PW3 on every other key operation, so this
        // arm follows the same rule as its siblings rather than the odd one out.
        if !sess.has_pw2 {
            return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        check_uif(fs, EF_UIF_DEC, presence)?;
        return aes_pso(dev, fs, sess, aes_enc, data, out);
    }

    let (algo_fid, pk_fid) = match (p1, p2) {
        (0x9E, 0x9A) => {
            // §7.2.10 gives PSO:CDS the access condition PW1 (No. 81) and names no
            // other. The admin PIN used to stand in "for parity with the cards in
            // the field"; the only card in the field we can measure refuses it —
            // 6982 across three runs of the whole 8x3 matrix on a YubiKey 5.7.4.
            if !sess.has_pw1 {
                return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
            }
            (EF_ALGO_PRIV1, EF_PK_SIG)
        }
        (0x80, 0x86) => {
            // §7.2.11: PW1 no. 82. Same measurement, same rule as CDS above.
            if !sess.has_pw2 {
                return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
            }
            (sess.algo_dec, sess.pk_dec)
        }
        _ => return Err(Sw::INCORRECT_P1P2),
    };

    // UIF (touch policy) of the slot actually used — follows an MSE repoint so a
    // DECIPHER on a cross-wired AUT key still enforces the AUT touch policy. A
    // no-op unless the DO is set; a missed touch → SECURE_MESSAGE_EXEC_ERROR.
    check_uif(fs, slot_uif(pk_fid), presence)?;

    let mut algo_buf = [0u8; 16];
    let algo0 = algo_id(fs, algo_fid, &mut algo_buf);
    if algo0 == ALGO_RSA {
        if (p1, p2) == (0x9E, 0x9A) {
            let crt = load_rsa_crt(dev, fs, sess, pk_fid)?;
            let n = rsa_sign_crt(&crt, data, rng, out)?;
            inc_sig_count(fs, sess)?;
            return Ok(n);
        }
        // DECIPHER: PKCS#1 v1.5 decrypt the ciphertext that follows the leading
        // OpenPGP padding-indicator byte.
        let key = load_rsa_key(dev, fs, sess, pk_fid)?;
        return rsa_decipher(&key, rng, data, out);
    }

    let key = load_ec_key(dev, fs, sess, pk_fid)?;
    if (p1, p2) == (0x9E, 0x9A) {
        // COMPUTE SIGNATURE over the supplied digest / message.
        let n = key.sign(data, rng, out)?;
        inc_sig_count(fs, sess)?;
        Ok(n)
    } else {
        // DECIPHER (ECDH): extract the peer public point and agree.
        let point = parse_ecdh_point(data).ok_or(WRONG_DATA)?;
        key.ecdh(point, out)
    }
}

/// AES-CBC (zero IV) symmetric PSO with the stored `EF_AES_KEY` — the raw mode an
/// OpenPGP card uses (no padding, so the data must be block-aligned). `encipher`
/// true = PSO:ENCIPHER (input = plaintext, output = `0x02 || cryptogram`); false =
/// PSO:DECIPHER (input = `0x02 || cryptogram`, output = plaintext). The key is
/// loaded DEK-unsealed and zeroized after the operation.
fn aes_pso<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    encipher: bool,
    data: &[u8],
    out: &mut [u8],
) -> Result<usize, Sw> {
    let (mut key, klen) = load_aes_key(dev, fs, sess)?;
    let iv = [0u8; 16];
    let r = (|| {
        if encipher {
            // Input = plaintext (the whole body, block-aligned — the card pads
            // nothing). Output = 0x02 || AES-CBC(plaintext).
            if data.is_empty() || !data.len().is_multiple_of(16) || out.len() < data.len() + 1 {
                return Err(Sw::WRONG_LENGTH);
            }
            out[0] = 0x02;
            out[1..=data.len()].copy_from_slice(data);
            aes_encrypt(&key[..klen], &iv, Mode::Cbc, &mut out[1..=data.len()])
                .map_err(|_| Sw::EXEC_ERROR)?;
            Ok(data.len() + 1)
        } else {
            // Input = 0x02 || ciphertext (block-aligned). Output = plaintext.
            let ct = &data[1..];
            if ct.is_empty() || !ct.len().is_multiple_of(16) || out.len() < ct.len() {
                return Err(Sw::WRONG_LENGTH);
            }
            out[..ct.len()].copy_from_slice(ct);
            aes_decrypt(&key[..klen], &iv, Mode::Cbc, &mut out[..ct.len()])
                .map_err(|_| Sw::EXEC_ERROR)?;
            Ok(ct.len())
        }
    })();
    key.zeroize();
    r
}

/// Parse `A6 { 7F49 { 86 <point> } }` and return the `0x86` value (the peer's
/// ephemeral public point). Pure and `pub` so the `openpgp_ecdh` fuzz target
/// can hit it directly — it is only reachable on-device after an EC DEC key is
/// provisioned, so the whole-applet `openpgp_apdu` target cannot exercise it.
pub fn parse_ecdh_point(data: &[u8]) -> Option<&[u8]> {
    let mut pos = 0usize;
    if *data.get(pos)? != 0xA6 {
        return None;
    }
    pos += 1;
    tag_len(data, &mut pos)?;
    if *data.get(pos)? != 0x7F || *data.get(pos + 1)? != 0x49 {
        return None;
    }
    pos += 2;
    tag_len(data, &mut pos)?;
    if *data.get(pos)? != 0x86 {
        return None;
    }
    pos += 1;
    let plen = tag_len(data, &mut pos)?;
    data.get(pos..pos + plen)
}
