// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! INTERNAL AUTHENTICATE (INS 0x88): signs the challenge with the
//! authentication slot (`sess.pk_aut`/`sess.algo_aut`, repointed by MSE 0x22);
//! needs PW2 (or PW3). Unlike PSO:CDS it does not touch the signature counter.

use rsk_crypto::Device;
use rsk_fs::{Fs, Storage};
use rsk_sdk::{Apdu, Sw};

use crate::consts::*;
use crate::keys::{load_ec_key, load_rsa_crt, rsa_sign_crt};
use crate::pin::Session;
use crate::{Rng, UserPresence, check_uif};

/// INTERNAL AUTHENTICATE (INS 0x88, P1P2 = 00 00).
pub fn internal_aut<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    rng: &mut dyn Rng,
    presence: &mut dyn UserPresence,
    apdu: &Apdu,
    out: &mut [u8],
) -> (usize, Sw) {
    match try_internal_aut(dev, fs, sess, rng, presence, apdu, out) {
        Ok(n) => (n, Sw::OK),
        Err(sw) => (0, sw),
    }
}

fn try_internal_aut<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    rng: &mut dyn Rng,
    presence: &mut dyn UserPresence,
    apdu: &Apdu,
    out: &mut [u8],
) -> Result<usize, Sw> {
    if apdu.p1 != 0x00 || apdu.p2 != 0x00 {
        return Err(Sw::WRONG_P1P2);
    }
    if !sess.has_pw3 && !sess.has_pw2 {
        return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
    }
    // UIF (touch policy) of the slot actually used — follows an MSE repoint so
    // an INTERNAL AUTHENTICATE on a cross-wired DEC key still enforces the DEC
    // touch policy. No-op unless the DO is set.
    check_uif(fs, slot_uif(sess.pk_aut), presence)?;
    let mut algo_buf = [0u8; 16];
    let algo0 = match fs.read(sess.algo_aut, &mut algo_buf) {
        Some(n) if n > 0 => algo_buf[0],
        _ => DEFAULT_ALGO[0],
    };
    if algo0 == ALGO_RSA {
        let crt = load_rsa_crt(dev, fs, sess, sess.pk_aut)?;
        return rsa_sign_crt(&crt, apdu.data, rng, out);
    }
    let key = load_ec_key(dev, fs, sess, sess.pk_aut)?;
    key.sign(apdu.data, rng, out)
}
