// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Applet initialisation: creates the absent EFs (DEK, PIN verifiers, default
//! working DOs). Idempotent — every write is guarded by an emptiness check —
//! and run once at boot.

use zeroize::Zeroize;

use rsk_crypto::{Device, PinKdf};
use rsk_fs::{Fs, Sealed, Storage};

use crate::Rng;
use crate::consts::*;
use crate::files::PW_STATUS_DEFAULT;

/// Errors from [`scan_files`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A flash write failed.
    Storage,
    /// An AEAD seal failed (a buffer-size invariant was violated).
    Crypto,
}

const KDF_DEFAULT: &[u8] = &[0x81, 0x01, 0x00];
const UIF_DEFAULT: &[u8] = &[0x00, 0x20];
const SEX_DEFAULT: &[u8] = &[0x30];
const SIG_COUNT_ZERO: &[u8] = &[0x00, 0x00, 0x00];
const PW_RETRIES_INIT: &[u8] = &[
    0x01,
    PW_RETRIES_DEFAULT,
    PW_RETRIES_DEFAULT,
    PW_RETRIES_DEFAULT,
];

fn put<S: Storage>(fs: &mut Fs<S>, fid: u16, data: &[u8]) -> Result<(), Error> {
    fs.put(fid, data).map_err(|_| Error::Storage)
}

/// Build a PIN verifier record `[len, 0x01, verifier(32)]` and store it.
fn put_pin_verifier<S: Storage>(
    fs: &mut Fs<S>,
    dev: &Device,
    fid: u16,
    pin: &[u8],
) -> Result<(), Error> {
    crate::pin::put_verifier(dev, fs, fid, pin).map_err(|_| Error::Storage)
}

/// Initialise the OpenPGP EFs: the DEK (sealed under the default PINs), the PIN
/// verifiers, and the default working DOs.
pub fn scan_files<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
) -> Result<(), Error> {
    // DEK: generate once, and judge BOTH wrapped copies together. One power cut
    // between the two writes below used to be permanent — `has_key(EF_DEK_PW1)`
    // alone made this guard false on the next boot, so PW3's copy was never
    // created, while the verifier further down still went in. PW3 then verified
    // for good and everything needing the DEK answered `6A88`, with TERMINATE DF
    // the only way out. Same two-record class as the PIN update E29 closed.
    //
    // Only while NEITHER verifier exists: past that the card has been provisioned,
    // and a missing copy is a lost record rather than an interrupted first boot —
    // regenerating the DEK there would throw the keys away. Nothing can be lost in
    // the window this does cover: no key can exist before the first boot finishes.
    let provisioning = !fs.has_data(EF_PW1) && !fs.has_data(EF_PW3);
    let mut reset_dek = false;
    if provisioning
        && (!fs.has_key(EF_DEK_PW1) || !fs.has_key(EF_DEK_PW3))
        && !fs.has_key(EF_DEK_RC)
        && !fs.has_data(EF_DEK)
    {
        let mut random_dek = [0u8; DEK_SIZE];
        rng.fill(&mut random_dek);
        let mut session_pw1 = dev.pin_derive_session(PW1_DEFAULT);
        let mut session_pw3 = dev.pin_derive_session(PW3_DEFAULT);
        let mut def = [0u8; DEK_FILE_SIZE];
        def[0] = DEK_FORMAT_V3;
        let mut nonce = [0u8; 12];

        rng.fill(&mut nonce);
        dev.encrypt_with_aad(&session_pw1, &random_dek, PinKdf::V2, &nonce, &mut def[1..])
            .map_err(|_| Error::Crypto)?;
        fs.put_key(EF_DEK_PW1, Sealed::wrap(&def))
            .map_err(|_| Error::Storage)?;

        // PW3's DEK copy, sealed under the PW3 session. No `EF_DEK_RC` is created:
        // the resetting code is deactivated until `PUT DATA 0xD3` (put_reset_code)
        // seals its own copy under the admin-chosen RC.
        rng.fill(&mut nonce);
        dev.encrypt_with_aad(&session_pw3, &random_dek, PinKdf::V2, &nonce, &mut def[1..])
            .map_err(|_| Error::Crypto)?;
        fs.put_key(EF_DEK_PW3, Sealed::wrap(&def))
            .map_err(|_| Error::Storage)?;

        random_dek.zeroize();
        session_pw1.zeroize();
        session_pw3.zeroize();
        def.zeroize();
        reset_dek = true;
    }

    if reset_dek || !fs.has_data(EF_PW1) {
        put_pin_verifier(fs, dev, EF_PW1, PW1_DEFAULT)?;
    }
    // No EF_RC verifier at init: the resetting code stays unset until an admin
    // sets it via PUT DATA 0xD3. (Seeding it to PW3_DEFAULT made RESET RETRY P1=0
    // an unauthenticated PW1-reset backdoor.)
    if reset_dek || !fs.has_data(EF_PW3) {
        put_pin_verifier(fs, dev, EF_PW3, PW3_DEFAULT)?;
    }

    if !fs.has_data(EF_SIG_COUNT) {
        put(fs, EF_SIG_COUNT, SIG_COUNT_ZERO)?;
    }
    if !fs.has_data(EF_PW_PRIV) {
        put(fs, EF_PW_PRIV, PW_STATUS_DEFAULT)?;
    }
    for fid in [EF_UIF_SIG, EF_UIF_DEC, EF_UIF_AUT] {
        if !fs.has_data(fid) {
            put(fs, fid, UIF_DEFAULT)?;
        }
    }
    if !fs.has_data(EF_KDF) {
        put(fs, EF_KDF, KDF_DEFAULT)?;
    }
    if !fs.has_data(EF_SEX) {
        put(fs, EF_SEX, SEX_DEFAULT)?;
    }
    if !fs.has_data(EF_PW_RETRIES) {
        put(fs, EF_PW_RETRIES, PW_RETRIES_INIT)?;
    }
    neutralize_default_reset_code(dev, fs)?;
    settle_rc_retry_counter(fs)?;
    settle_pw_status_maxima(fs)?;
    Ok(())
}

/// SECURITY: firmware through bcdDevice 0x07F6 seeded the resetting code to the
/// public admin default "12345678" with an active retry counter, making
/// `RESET RETRY P1=0` an unauthenticated PW1-reset backdoor. Neutralise any
/// already-provisioned card still carrying that default RC — delete the RC
/// verifier and its DEK copy — restoring the spec's "reset code deactivated
/// until PUT DATA 0xD3" state. A real admin-set RC (a different verifier) is
/// left untouched. The retry counter is not zeroed here: `settle_rc_retry_counter`
/// owns that byte for every card, including the ones this function cannot reach.
fn neutralize_default_reset_code<S: Storage>(dev: &Device, fs: &mut Fs<S>) -> Result<(), Error> {
    let mut rec = [0u8; 64];
    // RC verifier record is [len, 0x01, verifier(32)].
    let stored = match fs.read(EF_RC, &mut rec) {
        Some(n) if n >= 34 && rec[0] != 0 => &rec[2..34],
        _ => return Ok(()),
    };
    let is_default = rsk_crypto::ct_eq(stored, &dev.pin_derive_verifier(PW3_DEFAULT))
        || (dev.otp_key.is_some()
            && rsk_crypto::ct_eq(stored, &dev.without_otp().pin_derive_verifier(PW3_DEFAULT)));
    if !is_default {
        return Ok(());
    }
    let _ = fs.delete(EF_RC);
    let _ = fs.delete_key(EF_DEK_RC);
    Ok(())
}

/// Hold DO C4's RC error counter to 0 while no resetting code exists (OpenPGP
/// Card 3.4 §4.3.4). Firmware 0x07F7..=0x0852 stopped seeding an RC verifier but
/// still wrote a live RC counter into `EF_PW_PRIV`, and init only writes that
/// record when it is absent — so those cards advertise a reset code they do not
/// have, and `neutralize_default_reset_code` never sees them (it keys on an RC
/// that is already gone). Idempotent: the flash write happens only on repair.
fn settle_rc_retry_counter<S: Storage>(fs: &mut Fs<S>) -> Result<(), Error> {
    if fs.has_data(EF_RC) {
        return Ok(());
    }
    let mut pw = [0u8; 8];
    let Some(n) = fs.read(EF_PW_PRIV, &mut pw) else {
        return Ok(());
    };
    let n = n.min(pw.len());
    let idx = pw_retry_idx(EF_RC);
    if idx < n && pw[idx] != 0 {
        pw[idx] = 0;
        put(fs, EF_PW_PRIV, &pw[..n])?;
    }
    Ok(())
}

/// Restore DO C4's three max-length bytes on a card an older build let move them.
/// Firmware through bcdDevice 0x0897 copied a PUT DATA `0xC4` body across the
/// flag *and* all three maxima, so `01 06 06 06` announced max 6 for good; the
/// writer touches the flag only now, and nothing else in the applet ever rewrites
/// those bytes — so without this a card carrying one is stuck announcing a limit
/// `gpg` then refuses to let its owner exceed, with TERMINATE DF the only escape.
/// Idempotent: the flash write happens only on repair.
fn settle_pw_status_maxima<S: Storage>(fs: &mut Fs<S>) -> Result<(), Error> {
    let mut pw = [0u8; 8];
    let Some(n) = fs.read(EF_PW_PRIV, &mut pw) else {
        return Ok(());
    };
    let n = n.min(pw.len());
    let mut moved = false;
    for (i, want) in PW_STATUS_DEFAULT
        .iter()
        .enumerate()
        .take(PW1_RETRY_IDX)
        .skip(1)
    {
        if i < n && pw[i] != *want {
            pw[i] = *want;
            moved = true;
        }
    }
    if moved {
        put(fs, EF_PW_PRIV, &pw[..n])?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "init_tests.rs"]
mod tests;
