// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! PIN model: VERIFY / CHANGE / RESET RETRY, the DEK unwrap ([`load_dek`]) and
//! retry-counter bookkeeping. PINs are verifier records `[len, 0x01, verifier(32)]`;
//! VERIFY derives the session key that unwraps the DEK, CHANGE / RESET re-wrap it.

use zeroize::Zeroize;

use rsk_crypto::{Device, PinKdf};
use rsk_fs::{Fs, KeyFid, Sealed, Storage};
use rsk_sdk::Sw;

use crate::Rng;
use crate::consts::*;

/// Per-power-cycle PIN auth state. Zeroized on Drop and on applet
/// deselect/reset.
pub struct Session {
    pub has_pw1: bool,
    pub has_pw2: bool,
    pub has_pw3: bool,
    /// Resetting-code (RC) session established — gates [`load_dek`]'s `EF_DEK_RC`
    /// branch for RESET RETRY via the reset code (P1=0).
    pub has_rc: bool,
    /// MSE-selectable key slots for DECIPHER / INTERNAL AUTHENTICATE. Default to
    /// the DEC / AUT slots; MANAGE SECURITY ENVIRONMENT (0x22) can repoint them,
    /// and a deselect resets them.
    pub algo_dec: u16,
    pub pk_dec: KeyFid,
    pub algo_aut: u16,
    pub pk_aut: KeyFid,
    /// Cardholder-certificate occurrence (0/1/2) selected by SELECT DATA,
    /// picking `EF_CH_1/2/3` for GET/PUT DATA of DO 7F21. Reset on deselect.
    pub cert_occ: u8,
    session_pw1: [u8; 32],
    session_pw3: [u8; 32],
    session_rc: [u8; 32],
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub const fn new() -> Self {
        Self {
            has_pw1: false,
            has_pw2: false,
            has_pw3: false,
            has_rc: false,
            algo_dec: EF_ALGO_PRIV2,
            pk_dec: EF_PK_DEC,
            algo_aut: EF_ALGO_PRIV3,
            pk_aut: EF_PK_AUT,
            cert_occ: 0,
            session_pw1: [0u8; 32],
            session_pw3: [0u8; 32],
            session_rc: [0u8; 32],
        }
    }

    /// Clear all auth state (applet deselect) and restore the default MSE key
    /// slots.
    pub fn reset(&mut self) {
        self.has_pw1 = false;
        self.has_pw2 = false;
        self.has_pw3 = false;
        self.has_rc = false;
        self.algo_dec = EF_ALGO_PRIV2;
        self.pk_dec = EF_PK_DEC;
        self.algo_aut = EF_ALGO_PRIV3;
        self.pk_aut = EF_PK_AUT;
        self.cert_occ = 0;
        self.session_pw1.zeroize();
        self.session_pw3.zeroize();
        self.session_rc.zeroize();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.session_pw1.zeroize();
        self.session_pw3.zeroize();
        self.session_rc.zeroize();
    }
}

/// Constant-time equality (avoids a verifier timing leak).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    rsk_crypto::ct_eq(a, b)
}

/// Decrement the PIN's retry counter in EF_PW_PRIV. Returns the remaining
/// tries, or `Err` when blocked.
fn pin_wrong_retry<S: Storage>(fs: &mut Fs<S>, fid: u16) -> Result<u8, ()> {
    let mut pw = [0u8; 8];
    let n = fs.read(EF_PW_PRIV, &mut pw).ok_or(())?;
    let idx = pw_retry_idx(fid);
    if idx >= n || pw[idx] == 0 {
        return Err(());
    }
    pw[idx] -= 1;
    let remaining = pw[idx];
    fs.put(EF_PW_PRIV, &pw[..n]).map_err(|_| ())?;
    if remaining == 0 {
        Err(())
    } else {
        Ok(remaining)
    }
}

/// Restore the PIN's retry counter to its max (EF_PW_RETRIES). `force` resets
/// even a blocked (0) counter.
fn pin_reset_retries<S: Storage>(fs: &mut Fs<S>, fid: u16, force: bool) -> Result<(), Sw> {
    let mut pw = [0u8; 8];
    let n = fs
        .read(EF_PW_PRIV, &mut pw)
        .ok_or(Sw::REFERENCE_NOT_FOUND)?;
    let mut retr = [0u8; 8];
    let rn = fs
        .read(EF_PW_RETRIES, &mut retr)
        .ok_or(Sw::REFERENCE_NOT_FOUND)?;
    let slot = (fid & 0xf) as usize;
    let idx = pw_retry_idx(fid);
    if idx >= n || slot >= rn {
        return Err(Sw::MEMORY_FAILURE);
    }
    if pw[idx] == 0 && !force {
        return Err(Sw::PIN_BLOCKED);
    }
    pw[idx] = retr[slot];
    fs.put(EF_PW_PRIV, &pw[..n]).map_err(|_| Sw::MEMORY_FAILURE)
}

/// Set PIN `fid`'s retry counter in EF_PW_PRIV to an explicit value. Used to
/// deactivate the resetting code (counter 0) when it is cleared.
fn set_pin_retry_counter<S: Storage>(fs: &mut Fs<S>, fid: u16, value: u8) -> Result<(), Sw> {
    let mut pw = [0u8; 8];
    let n = fs
        .read(EF_PW_PRIV, &mut pw)
        .ok_or(Sw::REFERENCE_NOT_FOUND)?;
    let idx = pw_retry_idx(fid);
    if idx >= n {
        return Err(Sw::MEMORY_FAILURE);
    }
    pw[idx] = value;
    fs.put(EF_PW_PRIV, &pw[..n]).map_err(|_| Sw::MEMORY_FAILURE)
}

/// Verify `data` against the stored verifier of PIN `fid`. On success resets
/// the retry counter and sets the matching `has_pw*` flag + session key; on
/// failure decrements the counter and returns `63 Cx` / blocked.
pub fn check_pin<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &mut Session,
    rng: &mut dyn Rng,
    fid: u16,
    p2: u8,
    data: &[u8],
) -> Sw {
    // The retry-block floor comes first, as PIV `check_ref` and FIDO `clientpin` do:
    // deriving — and worse, migrating — ahead of it made a blocked reference do two
    // flash writes for the correct value and none for a wrong one, an oracle.
    let mut pw = [0u8; 8];
    if let Some(n) = fs.read(EF_PW_PRIV, &mut pw) {
        let n = n.min(pw.len());
        let idx = pw_retry_idx(fid);
        if idx < n && pw[idx] == 0 {
            return Sw::PIN_BLOCKED;
        }
    }
    let mut rec = [0u8; 64];
    let size = match fs.read(fid, &mut rec) {
        Some(n) if n >= 3 && rec[0] != 0 => n,
        _ => return Sw::REFERENCE_NOT_FOUND,
    };
    // Format 0x01: record = [len, 0x01, verifier(32)] (off = 2).
    let off = 2usize;
    if size - off != 32 {
        return Sw::CONDITIONS_NOT_SATISFIED;
    }
    let verifier = dev.pin_derive_verifier(data);
    if !ct_eq(&rec[off..off + 32], &verifier) {
        // kbase-migration fallback: a verifier stored before the OTP key was
        // provisioned. A match under the pre-OTP arm is the correct PIN — re-wrap
        // this PIN's DEK copy and re-store the verifier under the OTP generation,
        // without burning a retry.
        let migrated = dev.otp_key.is_some()
            && ct_eq(
                &rec[off..off + 32],
                &dev.without_otp().pin_derive_verifier(data),
            );
        if !migrated {
            return match pin_wrong_retry(fs, fid) {
                Ok(retries) => Sw::retries(retries),
                Err(()) => Sw::PIN_BLOCKED,
            };
        }
        if let Err(sw) = migrate_pin_kbase(dev, fs, rng, fid, data) {
            return sw;
        }
    }
    if let Err(sw) = pin_reset_retries(fs, fid, false) {
        return sw;
    }
    // PW1.81 (PSO:CDS), PW1.82 (DECIPHER/INTERNAL AUTH) and PW3 are INDEPENDENT
    // access latches: a successful VERIFY raises only its own, never clears a
    // sibling. gpg/scdaemon verifies one PIN entry into both PW1 modes (82 then
    // 81); clearing here dropped PW1.82 and bricked the next DECIPHER with 6982 (#25).
    if fid == EF_PW1 {
        if p2 == PW1_MODE81 {
            sess.has_pw1 = true;
        } else {
            sess.has_pw2 = true;
        }
        sess.session_pw1 = dev.pin_derive_session(data);
    } else if fid == EF_PW3 {
        sess.has_pw3 = true;
        sess.session_pw3 = dev.pin_derive_session(data);
    }
    Sw::OK
}

/// Lazy kbase migration for one OpenPGP PIN: re-wrap its DEK copy and re-store
/// its verifier under the OTP generation. Runs only from the [`check_pin`]
/// fallback, i.e. with the correct PIN in hand. DEK first, verifier second — a
/// crash between the two re-enters the fallback on the next verify, where the
/// already-migrated DEK copy is detected by trial decrypt (GCM authenticates,
/// so the generations cannot be confused).
fn migrate_pin_kbase<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    fid: u16,
    pin: &[u8],
) -> Result<(), Sw> {
    let dek_fid = match fid {
        EF_PW1 => EF_DEK_PW1,
        EF_PW3 => EF_DEK_PW3,
        EF_RC => EF_DEK_RC,
        _ => return Err(Sw::EXEC_ERROR),
    };
    let mut blob = [0u8; DEK_FILE_SIZE];
    if let Some(n) = fs.read_key(dek_fid, &mut blob).map(|n| n.min(blob.len())) {
        if n < 1 || blob[0] != DEK_FORMAT_V3 {
            return Err(Sw::EXEC_ERROR);
        }
        let old = dev.without_otp();
        let mut old_session = old.pin_derive_session(pin);
        let mut dek = [0u8; DEK_SIZE];
        let opened_old = old
            .decrypt_with_aad(&old_session, &blob[1..n], PinKdf::V2, &mut dek)
            .is_ok();
        old_session.zeroize();
        if opened_old {
            let r = rewrap_dek(dev, fs, rng, dek_fid, pin, &dek);
            dek.zeroize();
            r?;
        } else {
            // Crash recovery: an earlier attempt re-wrapped the DEK but died
            // before the verifier write — the copy must open under the OTP
            // generation, else the blob is corrupt and we fail closed.
            let mut session = dev.pin_derive_session(pin);
            let r = dev.decrypt_with_aad(&session, &blob[1..n], PinKdf::V2, &mut dek);
            session.zeroize();
            dek.zeroize();
            r.map_err(|_| Sw::EXEC_ERROR)?;
        }
    }
    store_verifier(dev, fs, fid, pin)
}

/// Decrypt the random DEK into `out` (48 bytes = IV(16)|key(32)) using the
/// session key established by a prior VERIFY. `Err` if no PIN is verified or
/// the wrapped copy is malformed.
pub fn load_dek<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    out: &mut [u8; DEK_SIZE],
) -> Result<(), Sw> {
    let (fid, key) = if sess.has_pw1 || sess.has_pw2 {
        (EF_DEK_PW1, &sess.session_pw1)
    } else if sess.has_pw3 {
        (EF_DEK_PW3, &sess.session_pw3)
    } else if sess.has_rc {
        // RESET RETRY via the reset code: unseal the RC-sealed copy, consistent
        // with how `init` and PUT 0xD3 seal `EF_DEK_RC` under the RC session.
        (EF_DEK_RC, &sess.session_rc)
    } else {
        return Err(Sw::CONDITIONS_NOT_SATISFIED); // no PIN verified
    };
    let mut blob = [0u8; DEK_FILE_SIZE];
    let n = fs
        .read_key(fid, &mut blob)
        .ok_or(Sw::REFERENCE_NOT_FOUND)?
        .min(blob.len());
    if n < 1 || blob[0] != DEK_FORMAT_V3 {
        return Err(Sw::EXEC_ERROR);
    }
    dev.decrypt_with_aad(key, &blob[1..n], PinKdf::V2, out)
        .map_err(|_| Sw::EXEC_ERROR)?;
    Ok(())
}

/// The verifier EF for a VERIFY/CHANGE PIN mode: the internal-EF namespace puts
/// PW verifiers at `0x1000 | mode` (`EF_PW1`/`EF_RC`/`EF_PW3`).
fn pw_fid(p2: u8) -> u16 {
    0x1000 | p2 as u16
}

/// VERIFY (INS 0x20).
pub fn verify<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &mut Session,
    rng: &mut dyn Rng,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> Sw {
    if p1 == 0xFF {
        if !data.is_empty() {
            return Sw::INCORRECT_PARAMS;
        }
        match p2 {
            PW1_MODE81 => sess.has_pw1 = false,
            PW1_MODE82 => sess.has_pw2 = false,
            PW3_MODE83 => sess.has_pw3 = false,
            _ => {}
        }
        return Sw::OK;
    }
    if p1 != 0x00 || (p2 & 0x60) != 0x00 {
        return Sw::WRONG_P1P2;
    }
    let mut fid = pw_fid(p2);
    if fid == EF_RC {
        // PW2 (p2 = 0x82) shares the PW1 verifier and its retry counter — for a
        // status query too, else an empty-data probe reads the (absent) EF_RC.
        fid = EF_PW1;
    }
    let mut rec = [0u8; 64];
    let size = match fs.read(fid, &mut rec) {
        Some(n) if n >= 1 && rec[0] != 0 => n,
        _ => return Sw::REFERENCE_NOT_FOUND,
    };
    if !data.is_empty() {
        let _ = size;
        return check_pin(dev, fs, sess, rng, fid, p2, data);
    }
    // Status query: report the remaining retries / current auth state.
    let mut pw = [0u8; 8];
    let pn = fs.read(EF_PW_PRIV, &mut pw).unwrap_or(0);
    let idx = pw_retry_idx(fid);
    let retries = if idx < pn { pw[idx] } else { 0 };
    if retries == 0 {
        return Sw::PIN_BLOCKED;
    }
    let authed = (p2 == PW1_MODE81 && sess.has_pw1)
        || (p2 == PW1_MODE82 && sess.has_pw2)
        || (p2 == PW3_MODE83 && sess.has_pw3);
    if authed { Sw::OK } else { Sw::retries(retries) }
}

/// Length limits for a *new* reference value ([`PW1_MIN_LEN`] / [`PW3_MIN_LEN`] /
/// [`PIN_MAX_LEN`]). A path that re-seals the DEK before storing the verifier must
/// call this itself, else [`put_verifier`]'s refusal leaves the DEK sealed under a
/// value whose verifier was never written.
fn check_pin_len(fid: u16, len: usize) -> Result<(), Sw> {
    let min = if fid == EF_PW1 {
        PW1_MIN_LEN
    } else {
        PW3_MIN_LEN
    };
    if len < min || len > PIN_MAX_LEN {
        return Err(Sw::WRONG_LENGTH);
    }
    Ok(())
}

/// Whether `fid`'s stored verifier is one [`check_pin`] can never accept — too
/// short for the record shape, or carrying a zero length byte. Such a reference can
/// never be decremented to blocked either, so TERMINATE DF counts it as blocked.
pub(crate) fn verifier_unusable<S: Storage>(fs: &mut Fs<S>, fid: u16) -> bool {
    let mut rec = [0u8; 3];
    matches!(fs.read(fid, &mut rec), Some(n) if n < 3 || rec[0] == 0)
}

/// Write a verifier record `[len, 0x01, verifier(32)]` for `pin`, refusing a
/// length the applet could not work with afterwards.
pub(crate) fn put_verifier<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: u16,
    pin: &[u8],
) -> Result<(), Sw> {
    // A zero-length verifier is unrecoverable: check_pin's `rec[0] != 0` shape test
    // short-circuits before pin_wrong_retry, so the reference can neither be
    // verified nor blocked, and terminate.rs' escape hatch is refused forever.
    check_pin_len(fid, pin.len())?;
    store_verifier(dev, fs, fid, pin)
}

/// Store the verifier record without the length check — for re-storing a reference
/// that already exists (the kbase migration), where a value an earlier firmware
/// accepted must keep working.
fn store_verifier<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: u16,
    pin: &[u8],
) -> Result<(), Sw> {
    let mut rec = [0u8; 34];
    rec[0] = pin.len() as u8;
    rec[1] = PIN_FORMAT_V1;
    rec[2..].copy_from_slice(&dev.pin_derive_verifier(pin));
    let r = fs.put(fid, &rec).map_err(|_| Sw::MEMORY_FAILURE);
    rec.zeroize();
    r
}

/// Re-wrap `dek` under `pin`'s session key and store it to `dek_fid`; returns the
/// fresh session key for the caller to record.
fn rewrap_dek<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    dek_fid: KeyFid,
    pin: &[u8],
    dek: &[u8; DEK_SIZE],
) -> Result<[u8; 32], Sw> {
    let session = dev.pin_derive_session(pin);
    let mut def = [0u8; DEK_FILE_SIZE];
    def[0] = DEK_FORMAT_V3;
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce);
    dev.encrypt_with_aad(&session, dek, PinKdf::V2, &nonce, &mut def[1..])
        .map_err(|_| Sw::EXEC_ERROR)?;
    let r = fs
        .put_key(dek_fid, Sealed::wrap(&def))
        .map_err(|_| Sw::MEMORY_FAILURE);
    def.zeroize();
    r.map(|()| session)
}

/// CHANGE REFERENCE DATA (INS 0x24): verify the old PIN, re-wrap the DEK under
/// the new PIN, and store the new verifier. `data` is `old_pin || new_pin`.
pub fn change_pin<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &mut Session,
    rng: &mut dyn Rng,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> Sw {
    if p1 != 0x00 {
        return Sw::WRONG_P1P2;
    }
    // Reject an unsupported P2 before any verifier write. P2=0x82 maps via
    // pw_fid to EF_RC; letting put_verifier rewrite it before the trailing
    // `match p2` rejected desynced the RC verifier from its EF_DEK_RC seal.
    if p2 != PW1_MODE81 && p2 != PW3_MODE83 {
        return Sw::WRONG_P1P2;
    }
    let fid = pw_fid(p2);
    let mut rec = [0u8; 64];
    let old_len = match fs.read(fid, &mut rec) {
        Some(n) if n >= 1 => rec[0] as usize,
        _ => return Sw::REFERENCE_NOT_FOUND,
    };
    if old_len > data.len() {
        return Sw::WRONG_LENGTH;
    }
    let sw = check_pin(dev, fs, sess, rng, fid, p2, &data[..old_len]);
    if !sw.is_ok() {
        return sw;
    }
    let mut dek = [0u8; DEK_SIZE];
    if let Err(sw) = load_dek(dev, fs, sess, &mut dek) {
        return sw;
    }
    let new_pin = &data[old_len..];
    let result = (|| {
        put_verifier(dev, fs, fid, new_pin)?;
        match p2 {
            PW1_MODE81 => {
                sess.session_pw1 = rewrap_dek(dev, fs, rng, EF_DEK_PW1, new_pin, &dek)?;
            }
            PW3_MODE83 => {
                sess.session_pw3 = rewrap_dek(dev, fs, rng, EF_DEK_PW3, new_pin, &dek)?;
            }
            _ => return Err(Sw::WRONG_P1P2),
        }
        Ok(())
    })();
    dek.zeroize();
    match result {
        Ok(()) => Sw::OK,
        Err(sw) => sw,
    }
}

/// RESET RETRY COUNTER (INS 0x2C): reset PW1 to a new value, either via the
/// resetting code (P1=0x00) or via a verified admin PIN (P1=0x02). Both re-seal
/// the DEK under the new PW1 and reset its retry counter.
pub fn reset_retry<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &mut Session,
    rng: &mut dyn Rng,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> Sw {
    if p2 != PW1_MODE81 {
        return Sw::REFERENCE_NOT_FOUND;
    }
    if p1 == 0x00 {
        // Via the resetting code (RC): `data` is RC(`rc_len`) || new PW1, where
        // `rc_len` is the stored RC length (`EF_RC[0]`).
        let mut rc_rec = [0u8; 64];
        let rc_len = match fs.read(EF_RC, &mut rc_rec) {
            Some(n) if n >= 1 => rc_rec[0] as usize,
            _ => return Sw::REFERENCE_NOT_FOUND,
        };
        if data.len() <= rc_len {
            return Sw::WRONG_LENGTH;
        }
        let sw = check_pin(dev, fs, sess, rng, EF_RC, p2, &data[..rc_len]);
        if !sw.is_ok() {
            return sw;
        }
        // RC verified: establish the RC session so `load_dek` unseals `EF_DEK_RC`.
        sess.has_pw1 = false;
        sess.has_pw2 = false;
        sess.has_pw3 = false;
        sess.has_rc = true;
        sess.session_rc = dev.pin_derive_session(&data[..rc_len]);
        let new_pin = &data[rc_len..];
        let mut dek = [0u8; DEK_SIZE];
        if let Err(sw) = load_dek(dev, fs, sess, &mut dek) {
            return sw;
        }
        let result = (|| {
            check_pin_len(EF_PW1, new_pin.len())?;
            sess.session_pw1 = rewrap_dek(dev, fs, rng, EF_DEK_PW1, new_pin, &dek)?;
            put_verifier(dev, fs, EF_PW1, new_pin)?;
            pin_reset_retries(fs, EF_PW1, true)
        })();
        dek.zeroize();
        return match result {
            Ok(()) => Sw::OK,
            Err(sw) => sw,
        };
    }
    if p1 != 0x02 {
        return Sw::INCORRECT_P1P2;
    }
    if !sess.has_pw3 {
        return Sw::CONDITIONS_NOT_SATISFIED;
    }
    let new_pin = data;
    let mut dek = [0u8; DEK_SIZE];
    if let Err(sw) = load_dek(dev, fs, sess, &mut dek) {
        return sw;
    }
    let result = (|| {
        check_pin_len(EF_PW1, new_pin.len())?;
        let session = rewrap_dek(dev, fs, rng, EF_DEK_PW1, new_pin, &dek)?;
        sess.session_pw1 = session;
        put_verifier(dev, fs, EF_PW1, new_pin)?;
        pin_reset_retries(fs, EF_PW1, true)
    })();
    dek.zeroize();
    match result {
        Ok(()) => Sw::OK,
        Err(sw) => sw,
    }
}

/// PUT DATA reset code (`0xD3` → `EF_RC`): set the resetting code so a later
/// RESET RETRY (P1=0) can unwrap the DEK. Requires PW3 (admin). Seals the DEK
/// under the new RC session into the AEAD `EF_DEK_RC` (matching `init` /
/// [`load_dek`]'s RC branch) and stores the RC verifier; empty data clears the
/// reset code.
pub fn put_reset_code<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &mut Session,
    rng: &mut dyn Rng,
    data: &[u8],
) -> Sw {
    if !sess.has_pw3 {
        return Sw::SECURITY_STATUS_NOT_SATISFIED;
    }
    if data.is_empty() {
        let _ = fs.delete(EF_RC);
        let _ = fs.delete_key(EF_DEK_RC);
        let _ = set_pin_retry_counter(fs, EF_RC, 0);
        sess.has_rc = false;
        return Sw::OK;
    }
    sess.has_rc = false;
    let mut dek = [0u8; DEK_SIZE];
    if let Err(sw) = load_dek(dev, fs, sess, &mut dek) {
        return sw;
    }
    let result = (|| {
        put_verifier(dev, fs, EF_RC, data)?;
        rewrap_dek(dev, fs, rng, EF_DEK_RC, data, &dek)?;
        // Activate the resetting code: it ships deactivated (counter 0), so
        // enable its retry counter now that a real RC exists.
        pin_reset_retries(fs, EF_RC, true)?;
        Ok::<(), Sw>(())
    })();
    dek.zeroize();
    match result {
        Ok(()) => Sw::OK,
        Err(sw) => sw,
    }
}

#[cfg(test)]
#[path = "pin_tests.rs"]
mod tests;
