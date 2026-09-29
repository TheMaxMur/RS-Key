// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! PIN model: VERIFY / CHANGE / RESET RETRY, the DEK unwrap ([`load_dek`]) and
//! retry-counter bookkeeping. PINs are verifier records `[len, 0x01, verifier(32)]`;
//! VERIFY derives the session key that unwraps the DEK, CHANGE / RESET re-wrap it.

use zeroize::Zeroize;

use rsk_crypto::{Device, PinKdf};
use rsk_fs::{Fs, KeyFid, Rearmed, Sealed, Storage};
use rsk_sdk::Sw;
use rsk_secret::Secret;

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

    /// Re-point the standing PW1/PW3 sessions at reference values that were just
    /// re-seeded underneath them ([`crate::kdf::put_kdf`]).
    ///
    /// The access statuses are deliberately left alone — a YubiKey 5.7.4 keeps
    /// them across a KDF-DO write (measured: `PUT DATA 5E` straight after
    /// `PUT DATA F9`, no re-VERIFY, answers `9000`). Ours cannot simply keep them
    /// too: the session key a VERIFY derived is the one that opens the DEK, and
    /// the re-seed has just sealed it under a different password. So the status
    /// survives and the key it carries is replaced.
    pub(crate) fn adopt_reseeded(&mut self, pw1: &Secret<[u8; 32]>, pw3: &Secret<[u8; 32]>) {
        self.session_pw1.copy_from_slice(pw1.expose());
        self.session_pw3.copy_from_slice(pw3.expose());
    }

    /// Clear all auth state (applet deselect) and restore the default MSE key
    /// slots. The assignment drops the old session in place, so its `Drop` wipes
    /// the keys, and a field added later is reset by the `new` it must join.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Every field is named: a new one does not compile until someone decides
        // whether it is a secret.
        let Self {
            has_pw1: _,
            has_pw2: _,
            has_pw3: _,
            has_rc: _,
            algo_dec: _,
            pk_dec: _,
            algo_aut: _,
            pk_aut: _,
            cert_occ: _,
            session_pw1,
            session_pw3,
            session_rc,
        } = self;
        #[expect(
            clippy::disallowed_methods,
            reason = "the session keys live in the Session between commands; its drop is their wipe point, reset's included"
        )]
        {
            session_pw1.zeroize();
            session_pw3.zeroize();
            session_rc.zeroize();
        }
    }
}

/// Constant-time equality (avoids a verifier timing leak).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    rsk_crypto::ct_eq(a, b)
}

/// Charge one attempt against PIN `fid`'s retry counter in EF_PW_PRIV, then read
/// the counter back before trusting it. `Ok(0)` = the last try was just spent.
///
/// Charged BEFORE the comparison, as `rsk-piv`'s `check_ref`, `rsk-fido`'s
/// `spend_and_verify_pin_hash` and `rsk-oath`'s `spend_and_match_otp_pin` do. This
/// counter is the applet's only rate limit — unlike clientPIN there is no per-boot
/// soft lock — so charging after the comparison left a window where a program that
/// silently did not land answered `63Cx` to a wrong password with the counter
/// frozen: guesses at one power cycle apiece. The read-back does not close that on
/// its own, because on a full counter the success path rewrites the value it
/// already holds. The cost is that a cut here spends a try the holder did not use,
/// which is the direction to fail in.
/// Refines `RSKeyRetryLattice!WrongAttemptIsCharged` — SEC-LAT-002.
fn spend_pin_retry<S: Storage>(fs: &mut Fs<S>, fid: u16) -> Result<u8, Sw> {
    let mut pw = [0u8; 8];
    // `Fs::read` reports the record's *stored* length, not what it copied, so a
    // longer record would panic the `&pw[..n]` write-back — and a panic-halt image
    // never comes back. Clamp at every EF_PW_PRIV site, as `check_pin` does.
    let n = fs
        .read(EF_PW_PRIV, &mut pw)
        .ok_or(Sw::MEMORY_FAILURE)?
        .min(pw.len());
    let idx = pw_retry_idx(fid);
    if idx >= n {
        return Err(Sw::MEMORY_FAILURE);
    }
    if pw[idx] == 0 {
        return Err(Sw::PIN_BLOCKED);
    }
    pw[idx] -= 1;
    let remaining = pw[idx];
    fs.put(EF_PW_PRIV, &pw[..n])
        .map_err(|_| Sw::MEMORY_FAILURE)?;
    let mut back = [0u8; 8];
    match fs.read(EF_PW_PRIV, &mut back) {
        Some(m) if idx < m.min(back.len()) && back[idx] == remaining => Ok(remaining),
        _ => Err(Sw::MEMORY_FAILURE),
    }
}

/// Restore the PIN's retry counter to its max (EF_PW_RETRIES). `force` resets
/// even a blocked (0) counter.
fn pin_reset_retries<S: Storage>(fs: &mut Fs<S>, fid: u16, force: bool) -> Result<(), Sw> {
    let mut pw = [0u8; 8];
    let n = fs
        .read(EF_PW_PRIV, &mut pw)
        .ok_or(Sw::REFERENCE_NOT_FOUND)?
        .min(pw.len());
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
        .ok_or(Sw::REFERENCE_NOT_FOUND)?
        .min(pw.len());
    let idx = pw_retry_idx(fid);
    if idx >= n {
        return Err(Sw::MEMORY_FAILURE);
    }
    pw[idx] = value;
    fs.put(EF_PW_PRIV, &pw[..n]).map_err(|_| Sw::MEMORY_FAILURE)
}

/// Refines `RSKeyAppletSeams!NoStatusAfterARefusedAuth` — SEC-SEAM-002.
/// Drop the compared reference's status by `fid`, never `p2`: RESET RETRY checks
/// `EF_RC` with `p2 = 0x81`, and a wrong resetting code leaves PW1.81 standing.
fn clear_access_status(sess: &mut Session, fid: u16, p2: u8) {
    if fid == EF_PW1 {
        if p2 == PW1_MODE81 {
            sess.has_pw1 = false;
        } else {
            sess.has_pw2 = false;
        }
    } else if fid == EF_PW3 {
        sess.has_pw3 = false;
    }
}

/// Verify `data` against the stored verifier of PIN `fid`. On success resets
/// the retry counter and sets the matching `has_pw*` flag + session key; on
/// failure clears that reference's access status and returns `63 Cx` / blocked.
/// The attempt is charged before the comparison and given back on success.
/// Refines `RSKeyRetryLattice!NoAuthWhenBlocked` — SEC-LAT-001.
/// Refines `RSKeyRetryLattice!WrongAttemptIsCharged` — SEC-LAT-002.
pub fn check_pin<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &mut Session,
    rng: &mut dyn Rng,
    fid: u16,
    p2: u8,
    data: &[u8],
) -> Sw {
    // A length no reference of this kind could hold is a malformed request, not a
    // wrong password: measured on a YubiKey 5.7.4, 3/3 at every boundary, it
    // answers `6A80`, spends no retry and leaves the standing access status up —
    // and it does so BEFORE the blocked check, as E47's precedence note has it.
    if offered_len_impossible(fs, fid, data.len()) {
        return Sw::WRONG_DATA;
    }
    // The retry-block floor comes next, as PIV `check_ref` and FIDO `clientpin` do:
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
    // Charged here, after the record reads above, so a card-state fault still costs
    // nothing and only a real comparison is charged. See `spend_pin_retry`.
    let remaining = match spend_pin_retry(fs, fid) {
        Ok(left) => left,
        Err(sw) => return sw,
    };
    let verifier = dev.pin_derive_verifier(data);
    if !ct_eq(&rec[off..off + 32], verifier.expose()) {
        // kbase-migration fallback: a verifier stored before the OTP key was
        // provisioned. A match under the pre-OTP arm is the correct PIN — re-wrap
        // this PIN's DEK copy and re-store the verifier under the OTP generation;
        // the attempt charged above is given back by the success path below.
        let migrated = dev.otp_key.is_some()
            && ct_eq(
                &rec[off..off + 32],
                dev.without_otp().pin_derive_verifier(data).expose(),
            );
        if !migrated {
            // §4.2's list of what invalidates an access status omits a failed
            // comparison, but a YubiKey 5.7.4 clears exactly the addressed
            // reference here — in VERIFY and CHANGE alike — so a wrong password
            // stops PSO:CDS and the admin surface instead of leaving them open.
            clear_access_status(sess, fid, p2);
            // 6982 where OpenPGP 3.4 §7.2.2 says 63Cx: a YubiKey 5.8.0's answer, the
            // one yubikit reads as a wrong PIN. The count stays on the empty VERIFY.
            return if remaining == 0 {
                Sw::PIN_BLOCKED
            } else {
                Sw::SECURITY_STATUS_NOT_SATISFIED
            };
        }
        if let Err(sw) = migrate_pin_kbase(dev, fs, rng, fid, data) {
            return sw;
        }
    }
    // The attempt is given back. `force`, because the charge above can have taken
    // the counter to zero on a last try that turned out to be the right password.
    if let Err(sw) = pin_reset_retries(fs, fid, true) {
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
        sess.session_pw1
            .copy_from_slice(dev.pin_derive_session(data).expose());
    } else if fid == EF_PW3 {
        sess.has_pw3 = true;
        sess.session_pw3
            .copy_from_slice(dev.pin_derive_session(data).expose());
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
    // This migration is lazy — it runs on the first VERIFY, long after the boot-time
    // at-rest scrub latched. Both writes below are appends, so the pre-OTP DEK copy
    // and the pre-OTP verifier end up superseded but still readable in a flash dump,
    // and both are rooted in the *public* chip serial (so the verifier is
    // brute-forceable offline). Re-arm the scrub AHEAD of them and gate them on it:
    // the re-arm is its own append, so a reset between the two keeps whichever landed,
    // and a medium that refuses it reaches the losing state with no reset at all.
    let rearmed = rsk_fs::request_rescrub(fs).map_err(|_| Sw::MEMORY_FAILURE)?;
    let mut blob = [0u8; DEK_FILE_SIZE];
    // `try_read_key`: a read this medium could not serve is not a copy that was
    // never written. Skipping the re-wrap and storing the verifier anyway leaves a
    // PIN that verifies forever over a DEK nothing can open — `6A00` on every
    // operation, with TERMINATE DF the only way back.
    let copy = fs
        .try_read_key(dek_fid, &mut blob)
        .map_err(|_| Sw::MEMORY_FAILURE)?;
    if let Some(n) = copy.map(|n| n.min(blob.len())) {
        if n < 1 || blob[0] != DEK_FORMAT_V3 {
            return Err(Sw::EXEC_ERROR);
        }
        let old = dev.without_otp();
        let mut old_session = old.pin_derive_session(pin);
        let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
        let opened_old = old
            .decrypt_with_aad(
                old_session.expose(),
                &blob[1..n],
                PinKdf::V2,
                dek.expose_mut(),
            )
            .is_ok();
        old_session.wipe();
        if opened_old {
            let r = rewrap_dek(dev, fs, rng, dek_fid, pin, dek.expose(), &rearmed);
            dek.wipe();
            r?;
        } else {
            // Crash recovery: an earlier attempt re-wrapped the DEK but died
            // before the verifier write — the copy must open under the OTP
            // generation, else the blob is corrupt and we fail closed.
            let mut session = dev.pin_derive_session(pin);
            let r =
                dev.decrypt_with_aad(session.expose(), &blob[1..n], PinKdf::V2, dek.expose_mut());
            session.wipe();
            dek.wipe();
            r.map_err(|_| Sw::EXEC_ERROR)?;
        }
    }
    store_verifier(dev, fs, fid, pin, Some(&rearmed))?;
    Ok(())
}

/// Decrypt the random DEK into `out` (48 bytes = IV(16)|key(32)) using the
/// session key established by a prior VERIFY. `Err` if no PIN is verified or
/// the wrapped copy is malformed.
pub fn load_dek<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    out: &mut Secret<[u8; DEK_SIZE]>,
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
    let opened = match fs.read_key(fid, &mut blob) {
        Some(n) => {
            let n = n.min(blob.len());
            n >= 1
                && blob[0] == DEK_FORMAT_V3
                && dev
                    .decrypt_with_aad(key, &blob[1..n], PinKdf::V2, out.expose_mut())
                    .is_ok()
        }
        // Absent, not merely unopenable. `EF_DEK_RC` legitimately does not exist
        // until a reset code is set, so the very first PUT DATA 0xD3 can tear
        // with no committed record at all — recover from the stage rather than
        // returning here, which is where an `ok_or(…)?` used to stop.
        None => false,
    };
    if opened {
        // The committed copy opened, which is proof that THIS target's stage is
        // garbage: either the update completed, or it was abandoned before its
        // verifier landed and the old PIN is still the one that works. A stage
        // that is still worth something is unreachable from here — the PIN that
        // opens the committed copy is the PIN the stage would replace. Retiring
        // it is what stops a refused or interrupted update leaving a live record
        // holding the DEK sealed under a value nobody uses.
        if let Some(stage) = stage_fid(fid)
            && fs.has_key(stage)
        {
            // The re-arm leads, as at every lazy re-key: a tombstone is an append
            // like any other. A refused one skips this retirement rather than failing
            // the load — it is already best-effort, and a later load retries it.
            if let Ok(rearmed) = rsk_fs::request_rescrub(fs) {
                let _ = fs.delete_key_over(stage, Some(&rearmed));
            }
        }
        return Ok(());
    }
    // The caller's PIN verified and yet its own copy will not open. The only way
    // both are true is an update that lost power between its two records, leaving
    // the new verifier standing over a copy sealed under the old PIN.
    recover_staged_dek(dev, fs, fid, key, out)
}

/// The staging slot belonging to a DEK target.
fn stage_fid(dek_fid: KeyFid) -> Option<KeyFid> {
    match dek_fid.get() {
        f if f == EF_DEK_PW1.get() => Some(EF_DEK_STAGE_PW1),
        f if f == EF_DEK_PW3.get() => Some(EF_DEK_STAGE_PW3),
        f if f == EF_DEK_RC.get() => Some(EF_DEK_STAGE_RC),
        _ => None,
    }
}

/// Whether a staged record is one [`commit_staged_dek`] may apply to `dek_fid`.
/// The two readers of this record share one guard on purpose: a commit that
/// accepted less than a recovery does would write a short or corrupt blob over
/// the live copy and then delete the only thing that could have restored it.
fn staged_is_for(staged: &[u8], dek_fid: KeyFid) -> bool {
    staged.len() >= 3 && staged[0] == dek_fid.get() as u8 && staged[1] == DEK_FORMAT_V3
}

/// Complete an interrupted PIN update from its staging slot: open the staged copy
/// under the session key that just verified, commit it, and retire the stage.
/// `Err` leaves everything untouched.
fn recover_staged_dek<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: KeyFid,
    key: &[u8; 32],
    out: &mut Secret<[u8; DEK_SIZE]>,
) -> Result<(), Sw> {
    let stage = stage_fid(fid).ok_or(Sw::EXEC_ERROR)?;
    let mut staged = Secret::<[u8; 1 + DEK_FILE_SIZE]>::zeroed();
    let n = match fs.read_key(stage, staged.expose_mut()) {
        Some(n) => n.min(1 + DEK_FILE_SIZE),
        None => return Err(Sw::EXEC_ERROR),
    };
    if !staged_is_for(&staged.expose()[..n], fid) {
        staged.wipe();
        return Err(Sw::EXEC_ERROR);
    }
    let opened = dev
        .decrypt_with_aad(key, &staged.expose()[2..n], PinKdf::V2, out.expose_mut())
        .is_ok();
    // The copy the commit below supersedes is rooted in a PIN the owner has
    // replaced; the same reasoning as `migrate_pin_kbase`'s re-arm applies, and so
    // do its order and its gate — ahead of the write, and the write only if it landed.
    let rearmed = rsk_fs::request_rescrub(fs);
    let commit = match &rearmed {
        Err(_) => Err(Sw::MEMORY_FAILURE),
        Ok(rearmed) if opened => fs
            .put_key_over(fid, Sealed::wrap(&staged.expose()[1..n]), Some(rearmed))
            .map_err(|_| Sw::MEMORY_FAILURE),
        Ok(_) => Err(Sw::EXEC_ERROR),
    };
    staged.wipe();
    if let Err(sw) = commit {
        // `decrypt_with_aad` writes the plaintext before it checks the tag, and
        // on this path it may have *succeeded* — so an error return can leave the
        // real DEK in the caller's buffer, which no caller of `load_dek` expects
        // to have to scrub.
        out.wipe();
        return Err(sw);
    }
    let _ = fs.delete_key_over(stage, rearmed.as_ref().ok());
    Ok(())
}

/// Seal `dek` under `pin` into `dek_fid`'s staging slot, ahead of the verifier
/// write that makes `pin` the one a host presents. Returns the session key the
/// caller keeps, as [`rewrap_dek`] does, and the re-arm its verifier and commit
/// writes take — a caller stages, writes the
/// verifier, then [`commit_staged_dek`]s, and a power cut at any point leaves a
/// state [`load_dek`] can finish. **Validate the new PIN before calling this**:
/// staging first would leave an orphan record behind a refused value.
fn stage_dek<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    dek_fid: KeyFid,
    pin: &[u8],
    dek: &[u8; DEK_SIZE],
) -> Result<(Secret<[u8; 32]>, Rearmed), Sw> {
    let stage = stage_fid(dek_fid).ok_or(Sw::EXEC_ERROR)?;
    // The ONLY re-arm on `change_pin`, both `reset_retry` arms and `put_reset_code`'s
    // set arm: each verifies one reference and re-keys ANOTHER its `check_pin` never
    // migrated. It sits here, at the FIRST append of the stage/verifier/commit
    // sequence, rather than at the commit that ends it — every one of those three is
    // its own append, so a re-arm at the end is one a reset can take while the
    // superseded copies stand. Make it conditional and all four open silently.
    let rearmed = rsk_fs::request_rescrub(fs).map_err(|_| Sw::MEMORY_FAILURE)?;
    let session = dev.pin_derive_session(pin);
    let mut rec = Secret::<[u8; 1 + DEK_FILE_SIZE]>::zeroed();
    rec.expose_mut()[0] = dek_fid.get() as u8;
    rec.expose_mut()[1] = DEK_FORMAT_V3;
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce);
    let r = match dev.encrypt_with_aad(
        session.expose(),
        dek,
        PinKdf::V2,
        &nonce,
        &mut rec.expose_mut()[2..],
    ) {
        Ok(_) => fs
            .put_key_over(stage, Sealed::wrap(rec.expose()), Some(&rearmed))
            .map_err(|_| Sw::MEMORY_FAILURE),
        Err(_) => Err(Sw::EXEC_ERROR),
    };
    rec.wipe();
    r.map(|()| (session, rearmed))
}

/// Move the staged copy onto its target and retire the stage. Called after the
/// verifier write; a power cut before it leaves the work for [`load_dek`].
fn commit_staged_dek<S: Storage>(
    fs: &mut Fs<S>,
    dek_fid: KeyFid,
    rearmed: &Rearmed,
) -> Result<(), Sw> {
    let stage = stage_fid(dek_fid).ok_or(Sw::EXEC_ERROR)?;
    let mut staged = Secret::<[u8; 1 + DEK_FILE_SIZE]>::zeroed();
    let n = match fs.read_key(stage, staged.expose_mut()) {
        Some(n) => n.min(1 + DEK_FILE_SIZE),
        None => return Err(Sw::EXEC_ERROR),
    };
    if !staged_is_for(&staged.expose()[..n], dek_fid) {
        staged.wipe();
        return Err(Sw::EXEC_ERROR);
    }
    let r = fs
        .put_key_over(dek_fid, Sealed::wrap(&staged.expose()[1..n]), Some(rearmed))
        .map_err(|_| Sw::MEMORY_FAILURE);
    staged.wipe();
    r?;
    let _ = fs.delete_key_over(stage, Some(rearmed));
    Ok(())
}

/// The verifier EF for a VERIFY/CHANGE PIN mode: the internal-EF namespace puts
/// PW verifiers at `0x1000 | mode` (`EF_PW1`/`EF_RC`/`EF_PW3`).
fn pw_fid(p2: u8) -> u16 {
    0x1000 | p2 as u16
}

/// Make `new` the reference value of PW1 or PW3, re-sealing that PIN's DEK copy
/// under it and giving the counter its retries back. `dek` is the plaintext a
/// prior [`load_dek`] produced, so a caller re-seeding BOTH references opens the
/// DEK once — the two copies hold the same key. Returns the session key `new`
/// now derives, for a caller keeping its access status ([`Session::adopt_reseeded`]).
///
/// The authority is the caller's: unlike [`change_pin`] this compares no old
/// value, so it may only be reached from a path that has already established one
/// ([`crate::kdf::put_kdf`] runs under PW3). Stage / verifier / commit and their
/// tear behaviour are [`stage_dek`]'s.
pub(crate) fn reseed_pin<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    fid: u16,
    new: &[u8],
    dek: &[u8; DEK_SIZE],
) -> Result<Secret<[u8; 32]>, Sw> {
    let dek_fid = match fid {
        EF_PW1 => EF_DEK_PW1,
        EF_PW3 => EF_DEK_PW3,
        _ => return Err(Sw::EXEC_ERROR),
    };
    check_pin_len(fid, new.len())?;
    let (session, rearmed) = stage_dek(dev, fs, rng, dek_fid, new, dek)?;
    put_verifier(dev, fs, fid, new, Some(&rearmed))?;
    commit_staged_dek(fs, dek_fid, &rearmed)?;
    pin_reset_retries(fs, fid, true)?;
    Ok(session)
}

/// Deactivate the resetting code: drop its verifier, the DEK copy sealed under
/// it, its STAGE slot and its retry budget — the four together are what RESET
/// RETRY P1=0 walks in through, so an `Ok` over a survivor revokes a credential
/// only on paper. The stage is the one a reader forgets: a torn or refused PUT
/// DATA 0xD3 leaves it holding the whole DEK under the code being revoked, and
/// nothing else retires it — `load_dek`'s retirement needs an `sess.has_rc` that
/// needs the EF_RC this function has just deleted, and the at-rest lap cannot
/// touch it because it is LIVE rather than superseded.
/// `init`'s repair pass reaches the FACTORY reset code alone, so nothing else on
/// the card clears a set one.
///
/// The third is not a delete, and folding its other two failures into `6581` is
/// deliberate: `set_pin_retry_counter`'s REFERENCE_NOT_FOUND would name
/// EF_PW_PRIV, a record neither caller ever mentions. Neither is reachable
/// anyway — every writer puts back `&pw[..n]` or the whole default, so the record
/// cannot shorten past the RC index. The half of that a test can hold is in
/// `pin_tests.rs`.
pub(crate) fn clear_reset_code<S: Storage>(fs: &mut Fs<S>, sess: &mut Session) -> Result<(), Sw> {
    // Ahead of everything below because it holds on every exit, the refused re-arm
    // included: the session must not keep a reset code answered for here.
    sess.has_rc = false;
    // Re-arm the one-shot at-rest lap (rsk-fs `EF_HARDENED`): EF_RC migrates only
    // through its own verify, so both records tombstoned below can still be keyed
    // under the pre-OTP arm — and clearing the code does not rotate the DEK. Ahead
    // of the tombstones, which are appends of their own, and gating them: a reset
    // between them and a trailing re-arm would leave the marker standing over both.
    let rearmed = rsk_fs::request_rescrub(fs).map_err(|_| Sw::MEMORY_FAILURE)?;
    let verifier = fs.delete_over(EF_RC, Some(&rearmed)).is_ok();
    let dek = fs.delete_key_over(EF_DEK_RC, Some(&rearmed)).is_ok();
    let staged = fs.delete_key_over(EF_DEK_STAGE_RC, Some(&rearmed)).is_ok();
    let counter = set_pin_retry_counter(fs, EF_RC, 0).is_ok();
    if verifier && dek && staged && counter {
        Ok(())
    } else {
        Err(Sw::MEMORY_FAILURE)
    }
}

/// VERIFY (INS 0x20) with P1 = FF: drop a password's security status. It needs no
/// key, so the dispatcher runs it before the fused one is read: a status stays
/// droppable while that key does not read past the latch.
pub fn logout(sess: &mut Session, p2: u8, data: &[u8]) -> Sw {
    if !data.is_empty() {
        return Sw::WRONG_DATA;
    }
    // §7.2.2 defines P2 = 81 / 82 / 83 and nothing else, so an undefined one
    // names a password reference that does not exist and there is nothing to
    // reset. Falling through to OK reported success for a security-status
    // reset that never happened — and the SAME undefined P2 on the P1=00 path
    // below already answered 6B00, so the one command disagreed with itself.
    // A YubiKey 5.7.4 answers 6B00 to every undefined P2 here, measured.
    match p2 {
        PW1_MODE81 => sess.has_pw1 = false,
        PW1_MODE82 => sess.has_pw2 = false,
        PW3_MODE83 => sess.has_pw3 = false,
        _ => return Sw::WRONG_P1P2,
    }
    Sw::OK
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
        return logout(sess, p2, data);
    }
    // Enumerate the three defined modes, the way `change_pin` already does. The
    // bit filter `(p2 & 0x60) != 0` let 64 values through, and `pw_fid` turns each
    // into `0x1000 | p2` — internal FIDs belonging to other applets, FIDO's `EF_PIN`
    // among them. Only a one-byte coincidence (`check_pin` wants exactly 34 bytes,
    // `PIN_FILE_LEN` is 35) kept that from being a live cross-applet primitive, and
    // that constant is owned by a different crate (audit run-34 #21).
    if p1 != 0x00 || !matches!(p2, PW1_MODE81 | PW1_MODE82 | PW3_MODE83) {
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
    // Status query: §7.2.2's empty-Lc form reports the *verification state*, so
    // the latch is read before the counter. Answering PIN_BLOCKED on `retries == 0`
    // was wrong at both ends: a standing latch still authorises PSO:DECIPHER and
    // INTERNAL AUTHENTICATE after PW1 blocks, and an unlatched blocked reference
    // is `63C0` — a YubiKey 5.7.4 never answers 6983 to this form at all.
    let mut pw = [0u8; 8];
    let pn = fs.read(EF_PW_PRIV, &mut pw).unwrap_or(0);
    let idx = pw_retry_idx(fid);
    let retries = if idx < pn { pw[idx] } else { 0 };
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
    // `6985`, not `6700`: the APDU's length is fine, it is the value inside it the
    // card will not take. Measured on a YubiKey 5.7.4, 3/3 on both references and
    // at every boundary — 0, 1 and 5 are `6985` for PW1, 0 through 7 for PW3, and
    // 128 and 200 for both, with no retry spent.
    if len < min || len > PIN_MAX_LEN {
        return Err(Sw::CONDITIONS_NOT_SATISFIED);
    }
    Ok(())
}

/// Whether an offered password is a length the stored reference could not be.
///
/// Only when that reference is itself inside the policy. `PIN_MAX_LEN` arrived
/// with `055ef86`, whose diff *adds* `check_pin_len` — so a build before it stored
/// whatever it was given, and `docs/guides/openpgp.md` still promises a shorter
/// legacy value keeps working. Gating unconditionally would lock such an owner out
/// of their own key, and losing a credential is never the parity answer. The
/// verifier record's first byte is the stored length, which is what makes the
/// question answerable at all.
///
/// The policy is the gate, never the stored length itself: refusing exactly the
/// lengths that cannot match would publish the password's length to anyone with
/// the card. `C4` publishes the policy already.
fn offered_len_impossible<S: Storage>(fs: &mut Fs<S>, fid: u16, len: usize) -> bool {
    let mut rec = [0u8; 1];
    let stored = match fs.read(fid, &mut rec) {
        Some(n) if n >= 1 => rec[0] as usize,
        _ => return false,
    };
    check_pin_len(fid, stored).is_ok() && check_pin_len(fid, len).is_err()
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
    rearmed: Option<&Rearmed>,
) -> Result<(), Sw> {
    // A zero-length verifier is unrecoverable: check_pin's `rec[0] != 0` shape test
    // short-circuits before spend_pin_retry, so the reference can neither be
    // verified nor blocked, and terminate.rs' escape hatch is refused forever.
    check_pin_len(fid, pin.len())?;
    store_verifier(dev, fs, fid, pin, rearmed)
}

/// Store the verifier record without the length check — for re-storing a reference
/// that already exists (the kbase migration), where a value an earlier firmware
/// accepted must keep working.
fn store_verifier<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: u16,
    pin: &[u8],
    rearmed: Option<&Rearmed>,
) -> Result<(), Sw> {
    let mut rec = Secret::<[u8; 34]>::zeroed();
    rec.expose_mut()[0] = pin.len() as u8;
    rec.expose_mut()[1] = PIN_FORMAT_V1;
    rec.expose_mut()[2..].copy_from_slice(dev.pin_derive_verifier(pin).expose());
    let r = fs
        .put_over(fid, rec.expose(), rearmed)
        .map_err(|_| Sw::MEMORY_FAILURE);
    rec.wipe();
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
    rearmed: &Rearmed,
) -> Result<Secret<[u8; 32]>, Sw> {
    let session = dev.pin_derive_session(pin);
    let mut def = Secret::<[u8; DEK_FILE_SIZE]>::zeroed();
    def.expose_mut()[0] = DEK_FORMAT_V3;
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce);
    dev.encrypt_with_aad(
        session.expose(),
        dek,
        PinKdf::V2,
        &nonce,
        &mut def.expose_mut()[1..],
    )
    .map_err(|_| Sw::EXEC_ERROR)?;
    let r = fs
        .put_key_over(dek_fid, Sealed::wrap(def.expose()), Some(rearmed))
        .map_err(|_| Sw::MEMORY_FAILURE);
    def.wipe();
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
    let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
    if let Err(sw) = load_dek(dev, fs, sess, &mut dek) {
        return sw;
    }
    let new_pin = &data[old_len..];
    // Stage, verifier, commit — see `stage_dek`. Ordering alone cannot fix this:
    // whichever record lands first, the tear leaves the other one describing a
    // different PIN, and the PIN that is missing is the one nobody holds any more.
    let result = (|| {
        let dek_fid = match p2 {
            PW1_MODE81 => EF_DEK_PW1,
            PW3_MODE83 => EF_DEK_PW3,
            _ => return Err(Sw::WRONG_P1P2),
        };
        // Judge the new value BEFORE anything is written: `check_pin_len`'s own
        // doc says a path that re-seals the DEK ahead of the verifier must call
        // it, and staging is exactly that. Otherwise a refused PIN leaves an
        // orphan stage behind, which is a live record nothing ever retires.
        check_pin_len(fid, new_pin.len())?;
        let (session, rearmed) = stage_dek(dev, fs, rng, dek_fid, new_pin, dek.expose())?;
        put_verifier(dev, fs, fid, new_pin, Some(&rearmed))?;
        commit_staged_dek(fs, dek_fid, &rearmed)?;
        match p2 {
            PW1_MODE81 => sess.session_pw1.copy_from_slice(session.expose()),
            _ => sess.session_pw3.copy_from_slice(session.expose()),
        }
        Ok(())
    })();
    dek.wipe();
    match result {
        Ok(()) => Sw::OK,
        Err(sw) => sw,
    }
}

/// RESET RETRY COUNTER (INS 0x2C): reset PW1 to a new value, either via the
/// resetting code (P1=0x00) or via a verified admin PIN (P1=0x02). Both re-seal
/// the DEK under the new PW1 and reset its retry counter.
/// Refines `RSKeyRetryLattice!BudgetRisesOnlyWithItsSecret` — SEC-LAT-003.
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
        sess.session_rc
            .copy_from_slice(dev.pin_derive_session(&data[..rc_len]).expose());
        let new_pin = &data[rc_len..];
        let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
        if let Err(sw) = load_dek(dev, fs, sess, &mut dek) {
            return sw;
        }
        let result = (|| {
            check_pin_len(EF_PW1, new_pin.len())?;
            let (session, rearmed) = stage_dek(dev, fs, rng, EF_DEK_PW1, new_pin, dek.expose())?;
            put_verifier(dev, fs, EF_PW1, new_pin, Some(&rearmed))?;
            commit_staged_dek(fs, EF_DEK_PW1, &rearmed)?;
            sess.session_pw1.copy_from_slice(session.expose());
            pin_reset_retries(fs, EF_PW1, true)
        })();
        dek.wipe();
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
    let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
    if let Err(sw) = load_dek(dev, fs, sess, &mut dek) {
        return sw;
    }
    let result = (|| {
        check_pin_len(EF_PW1, new_pin.len())?;
        let (session, rearmed) = stage_dek(dev, fs, rng, EF_DEK_PW1, new_pin, dek.expose())?;
        put_verifier(dev, fs, EF_PW1, new_pin, Some(&rearmed))?;
        commit_staged_dek(fs, EF_DEK_PW1, &rearmed)?;
        sess.session_pw1.copy_from_slice(session.expose());
        pin_reset_retries(fs, EF_PW1, true)
    })();
    dek.wipe();
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
        return match clear_reset_code(fs, sess) {
            Ok(()) => Sw::OK,
            Err(sw) => sw,
        };
    }
    sess.has_rc = false;
    let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
    if let Err(sw) = load_dek(dev, fs, sess, &mut dek) {
        return sw;
    }
    let result = (|| {
        // The one caller whose refusal is not `6985`: this value arrives in PUT
        // DATA's data field, and a YubiKey 5.7.4 answers `6A80` there (3/3, at 1,
        // 5, 6, 7 and 128) where CHANGE and RESET RETRY both answer `6985`.
        check_pin_len(EF_RC, data.len()).map_err(|_| Sw::WRONG_DATA)?;
        let (_, rearmed) = stage_dek(dev, fs, rng, EF_DEK_RC, data, dek.expose())?;
        put_verifier(dev, fs, EF_RC, data, Some(&rearmed))?;
        commit_staged_dek(fs, EF_DEK_RC, &rearmed)?;
        // Activate the resetting code: it ships deactivated (counter 0), so
        // enable its retry counter now that a real RC exists.
        pin_reset_retries(fs, EF_RC, true)?;
        Ok::<(), Sw>(())
    })();
    dek.wipe();
    match result {
        Ok(()) => Sw::OK,
        Err(sw) => sw,
    }
}

#[cfg(test)]
#[path = "pin_tests.rs"]
mod tests;
