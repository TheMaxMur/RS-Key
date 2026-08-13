// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg_attr(not(test), no_std)]

//! `rsk-openpgp` — the OpenPGP card applet, reached over the CCID transport.
//! Generic over `S: Storage`; the device seed / serial / RNG and the flash file
//! system are threaded in by the caller, so the applet is pure and host-testable.

// The `rsa` crate returns `alloc::vec::Vec` from its sign/decrypt API; the
// firmware provides a heap. Only the RSA path allocates — the rest stays no-alloc.
extern crate alloc;

pub mod consts;
pub mod dobj;
pub mod files;
pub mod getdata;
pub mod importdata;
pub mod info;
pub mod init;
pub mod internalaut;
pub mod keypairgen;
pub mod keys;
pub mod mse;
pub mod origin;
pub mod pin;
pub mod pso;
pub mod putdata;
pub mod rsa_crt;
pub mod select;
pub mod terminate;

#[cfg(test)]
#[path = "bp_kat.rs"]
mod bp_kat;

use core::cell::RefCell;

use rsk_crypto::{Device, FusedKey, read_fused};
use rsk_fs::{Fs, KeyFid, Storage};
pub use rsk_sdk::Confirm;
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};

pub use init::{Error, scan_files};
pub use pin::Session;

/// Random-byte source. `firmware` backs this with the RP2350 TRNG; tests use a
/// deterministic counter.
pub trait Rng {
    fn fill(&mut self, buf: &mut [u8]);
}

/// Outcome of asking for a physical touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    Confirmed,
    Timeout,
    Declined,
}

/// Physical user presence for the UIF (touch-policy) DOs. `firmware` polls the
/// BOOTSEL button; with no button configured it confirms instantly, like
/// [`AlwaysConfirm`] (which tests use). Shared with the FIDO applet — the firmware
/// type implements both `rsk_fido::UserPresence` and this.
pub trait UserPresence {
    /// Ask for presence. `confirm` names the pending operation for a trusted
    /// on-screen Approve/Deny prompt; the BOOTSEL-button backend ignores it.
    fn request(&mut self, confirm: Confirm<'_>) -> Presence;
}

/// A [`UserPresence`] that confirms instantly — the no-button default and the
/// host-test stand-in.
pub struct AlwaysConfirm;

impl UserPresence for AlwaysConfirm {
    fn request(&mut self, _confirm: Confirm<'_>) -> Presence {
        Presence::Confirmed
    }
}

/// If the UIF DO `fid` (`0xD6/D7/D8`) is present with a non-zero first byte,
/// require a touch; a non-confirmation maps to `SECURE_MESSAGE_EXEC_ERROR`
/// (0x6600). With UIF off (or no button) this is a no-op.
pub(crate) fn check_uif<S: Storage>(
    fs: &mut Fs<S>,
    fid: u16,
    presence: &mut dyn UserPresence,
) -> Result<(), Sw> {
    let mut buf = [0u8; 2];
    let on = matches!(fs.read(fid, &mut buf), Some(n) if n >= 1 && buf[0] > 0);
    if on {
        // The trusted screen names which key operation the UIF is gating (the
        // OpenPGP UIF DOs: 0xD6 signature, 0xD7 decryption, 0xD8 authentication).
        let title = match fid {
            consts::EF_UIF_SIG => "Sign data?",
            consts::EF_UIF_DEC => "Decrypt data?",
            consts::EF_UIF_AUT => "Authenticate?",
            _ => "Confirm?",
        };
        if presence.request(Confirm::titled(title)) != Presence::Confirmed {
            return Err(Sw::SECURE_MESSAGE_EXEC_ERROR);
        }
    }
    Ok(())
}

/// Scratch buffer for the SELECT FCI and the PSO results. **Not** for GET DATA,
/// which builds into the caller's response buffer: a stored DO can be as long as
/// DO C0 announces, and giving the applet private RAM that size costs more than
/// the stack floor has. The largest thing built here is the `0xFA` algorithm
/// information at ~370 bytes.
const SCRATCH: usize = 1024;

/// GET CHALLENGE fills the scratch, so what DO C0 announces cannot exceed it —
/// the two used to drift, C0 saying 128 while the command served up to 1024.
const _: () = assert!(files::MAX_CHALLENGE_BYTES <= SCRATCH);

/// The OpenPGP applet. Holds the per-power-cycle session state (`has_pw1/2/3`
/// and the session keys via [`Session`], the currently selected DO); the
/// persistent state lives in flash. The device serial and the shared TRNG
/// (`rng`) are threaded in at construction.
pub struct OpenpgpApplet<'a> {
    serial_id: [u8; 8],
    serial_hash: [u8; 32],
    /// How to read the OTP MKEK, once provisioned — never the key itself, so no
    /// copy of it sits in this applet's memory between operations.
    mkek_source: Option<FusedKey>,
    full_aid: [u8; 16],
    sess: Session,
    current_ef: Option<u16>,
    rng: &'a RefCell<dyn Rng>,
    /// Physical user presence for the UIF DOs, shared with the FIDO applet through
    /// a `RefCell` (the firmware's one BOOTSEL); borrowed only for a touch wait.
    presence: &'a RefCell<dyn UserPresence>,
    scratch: [u8; SCRATCH],
}

impl<'a> OpenpgpApplet<'a> {
    /// `serial_id` is the device chip id (its BCD-encoded 8-digit serial goes into
    /// the full AID); `serial_hash` + `serial_id` form the [`Device`] context for
    /// the PIN KDF; `rng` is the shared hardware TRNG; `presence` the shared BOOTSEL
    /// button. The AID manufacturer defaults to the unmanaged range — see
    /// [`Self::with_manufacturer`].
    pub fn new(
        serial_id: [u8; 8],
        serial_hash: [u8; 32],
        mkek_source: Option<FusedKey>,
        rng: &'a RefCell<dyn Rng>,
        presence: &'a RefCell<dyn UserPresence>,
    ) -> Self {
        Self {
            serial_id,
            serial_hash,
            mkek_source,
            // Default RS-Key identity; firmware calls `with_manufacturer` to swap
            // in the Yubico id when it presents the Yubico VID.
            full_aid: files::aid_for(&serial_id, consts::OPGP_MFR_UNMANAGED),
            sess: Session::new(),
            current_ef: None,
            rng,
            presence,
            scratch: [0u8; SCRATCH],
        }
    }

    /// Set the OpenPGP AID manufacturer id (bytes 8-9). Firmware passes
    /// [`consts::OPGP_MFR_YUBICO`] on the Yubico-VID interop build so hosts show
    /// the same vendor as a real YubiKey; the default is the unmanaged range.
    pub fn with_manufacturer(mut self, manufacturer: u16) -> Self {
        self.full_aid = files::aid_for(&self.serial_id, manufacturer);
        self
    }

    /// Clear the RAM auth state. (File init is done once at boot via
    /// [`scan_files`].)
    fn reset_session(&mut self) {
        self.sess.reset();
        self.current_ef = None;
    }

    /// CCID keepalive path: if this GENERATE (0x47) command targets an RSA slot,
    /// return `(fid, nbits)` so the caller can run the slow keygen asynchronously
    /// (stepping [`keys::RsaKeygen`] + sending time-extensions). `Ok(None)` =
    /// non-RSA generate / read-public → use the synchronous [`Applet::process`].
    pub fn rsa_generate_params<S: Storage>(
        &self,
        fs: &mut Fs<S>,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<Option<(KeyFid, usize)>, Sw> {
        keypairgen::rsa_generate_params(fs, &self.sess, p1, p2, data)
    }

    /// CCID keepalive path: finish an RSA GENERATE after the key has been produced.
    /// Returns `(response_len, status)`; the public-key DO is written to `out`.
    pub fn rsa_generate_finish<S: Storage>(
        &self,
        fs: &mut Fs<S>,
        rng: &mut dyn Rng,
        fid: KeyFid,
        key: &rsa::RsaPrivateKey,
        out: &mut [u8],
    ) -> (usize, Sw) {
        let mkek = read_fused(self.mkek_source);
        let dev = Device {
            serial_hash: &self.serial_hash,
            serial_id: &self.serial_id,
            otp_key: mkek.as_deref(),
        };
        keypairgen::rsa_generate_finish(&dev, fs, &self.sess, rng, fid, key, out)
    }

    /// Read the SELECT-DATA-selected cardholder-certificate occurrence
    /// (`EF_CH_1/2/3`) into `res`. §5's access table gives 7F21 READ = *Always*,
    /// so this is free; an unset occurrence reads as empty.
    fn read_cert_occurrence<S: Storage>(&mut self, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        let room = res.capacity() - res.len();
        let stor = consts::EF_CH_1 + self.sess.cert_occ as u16;
        if let Some(n) = fs.read(stor, res.spare_mut()) {
            // `fs.read` reports the value's FULL stored length while the
            // backend copies only what fit. PUT DATA now bounds every write
            // at MAX_DO_BYTES, so this can only be a value an older build
            // wrote through the chaining path, which delivers one byte more
            // than fits. Say so instead of handing back a short body with
            // `9000`, which is the whole defect this rule exists to end.
            if n > room {
                return Sw::MEMORY_FAILURE;
            }
            res.commit(n);
        }
        Sw::OK
    }

    /// GET DATA (0xCA): the cardholder-certificate occurrence (7F21) is a free
    /// read of the SELECT-DATA-selected slot; every other DO goes through
    /// `getdata::get_data` (PW2/PW3-gated).
    fn handle_get_data<S: Storage>(&mut self, fid: u16, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        // Command data is ignored, not refused: a YubiKey 5.7.4 answers `00 CA
        // 00 5E 01 AA` with the DO, and the tag is in P1/P2 anyway, so there is
        // nothing for a body to say.
        //
        // Both arms build straight into the response buffer. Going via `scratch`
        // and copying meant the applet had to own RAM as large as the biggest DO
        // it could return, and the RP2350's stack floor does not have a spare
        // 2 KiB — that is why the scratch was 1024 while DO C0 announced twice
        // that, and why the announcement was the thing that had to be wrong.
        let room = res.capacity() - res.len();
        if fid == consts::EF_CH_CERT {
            let sw = self.read_cert_occurrence(fs, res);
            if sw.is_ok() {
                // The anchor GET NEXT DATA walks from — set here as well as in
                // `get_data`, which this arm never reaches, and only on a read
                // that produced an occurrence.
                self.current_ef = Some(fid);
            }
            return sw;
        }
        let (n, sw) = getdata::get_data(
            fid,
            self.sess.has_pw2,
            self.sess.has_pw3,
            fs,
            &self.full_aid,
            &mut self.current_ef,
            res.spare_mut(),
        );
        if sw.is_ok() {
            // `get_data` bounds `n` by the buffer it was handed, but commit what
            // was written and not what was reported: `ResBuf::commit` can only
            // clamp to the capacity, and anything past the written bytes is the
            // tail of the previous response in a reused array.
            res.commit(n.min(room));
        }
        sw
    }

    /// PUT DATA (0xDA): the cardholder cert (7F21), reset code (0xD3), AES key
    /// (0xD5) and PW status (0xC4) touch the cert / DEK / key / status files and
    /// route to their own handlers; every other DO is a generic write.
    fn handle_put_data<S: Storage>(&mut self, fid: u16, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        // The password outranks the body's length as well as its tag: a YubiKey
        // 5.7.4 answers `6982` to a PUT DATA it is not authorised for at every
        // tag AND every length (10 to 3000 bytes over ten tags, 3 runs). E81
        // moved the tag below the ACL and left this one above it.
        if !putdata::write_authorized(&self.sess, fid) {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        // One owner for the length DO C0 announces, checked before the routing
        // splits: the cardholder certificate below writes flash without going
        // through `putdata::put_data`, so a check living only there would guard
        // every DO except the one C0's own bytes 5-6 are about.
        //
        // NOT parity, deliberately: the card answers `9000` here and keeps only
        // `n mod 256` bytes, which is the one behaviour AGENTS.md says never to
        // copy.
        if apdu.data.len() > files::MAX_DO_BYTES {
            return consts::WRONG_DATA;
        }
        if fid == consts::EF_CH_CERT {
            // Cardholder certificate write (PW3, held by the gate above — this
            // arm is inline and private, so unlike the routed handlers it has no
            // direct caller to re-state it for): the SELECT-DATA occurrence picks
            // the EF_CH_1/2/3 instance; empty data deletes it.
            let stor = consts::EF_CH_1 + self.sess.cert_occ as u16;
            if apdu.data.is_empty() {
                let _ = fs.delete(stor);
                Sw::OK
            } else if fs.put(stor, apdu.data).is_err() {
                Sw::MEMORY_FAILURE
            } else {
                Sw::OK
            }
        } else if fid == consts::EF_RESET_CODE {
            let mkek = read_fused(self.mkek_source);
            let dev = Device {
                serial_hash: &self.serial_hash,
                serial_id: &self.serial_id,
                otp_key: mkek.as_deref(),
            };
            let mut rng = self.rng.borrow_mut();
            pin::put_reset_code(&dev, fs, &mut self.sess, &mut *rng, apdu.data)
        } else if fid == consts::EF_AES_KEY.get() {
            let mkek = read_fused(self.mkek_source);
            let dev = Device {
                serial_hash: &self.serial_hash,
                serial_id: &self.serial_id,
                otp_key: mkek.as_deref(),
            };
            putdata::put_aes_key(&dev, fs, &self.sess, apdu.data)
        } else if fid == consts::EF_PW_STATUS {
            putdata::put_pw_status(fs, &self.sess, apdu.data)
        } else {
            putdata::put_data(fs, &self.sess, fid, apdu.data)
        }
    }
}

impl<S: Storage> Applet<Fs<S>> for OpenpgpApplet<'_> {
    fn aid(&self) -> &'static [u8] {
        consts::OPENPGP_AID
    }

    /// OpenPGP 3.4 (VERIFY): a verified PW stays valid only "up to a RESET of the
    /// card, a SELECT to a different DF or an internal resetting". Both of the first
    /// two land here, and the `Session` doc already promises zeroization on
    /// deselect — without this the PW1/PW2/PW3 state simply outlived them.
    fn deselect(&mut self, _fs: &mut Fs<S>) {
        self.reset_session();
    }

    /// `gpg`/`scdaemon` read GET DATA with a short `Le` (256) and follow `61xx`
    /// with GET RESPONSE; the application-related-data `6E` template exceeds 256
    /// bytes once keys exist, so opt into the dispatcher's response chaining.
    fn response_chaining(&self) -> bool {
        true
    }

    /// §4.2 spends its one sentence on which SELECT clears the access status —
    /// "a SELECT to a **different** DF" — and §7.2.2 repeats it for PW1 82. A
    /// SELECT that lands back here is not a state transition at all, so nothing
    /// is reset: not the PWs, not the MSE key references, not the SELECT DATA
    /// occurrence. Measured on a YubiKey 5.7.4, 3/3: re-SELECT of the bare AID
    /// and of a 5-byte truncation both keep all three PWs, while a different
    /// valid AID and an ICC power cycle clear them (the dispatcher's `deselect`).
    fn select(&mut self, reselect: bool, _fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if !reselect {
            self.reset_session();
        }
        let n = select::build_fci(&mut self.scratch);
        res.extend(&self.scratch[..n]);
        Sw::OK
    }

    fn process(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        let fid = ((apdu.p1 as u16) << 8) | apdu.p2 as u16;
        match apdu.ins {
            consts::INS_GET_DATA => self.handle_get_data(fid, fs, res),
            consts::INS_GET_NEXT_DATA => {
                if apdu.nc > 0 {
                    return consts::WRONG_DATA;
                }
                // OpenPGP 3.4 §7.2.7 gives GET NEXT DATA exactly one use: walking
                // the 7F21 occurrences after a GET DATA of that DO anchored the
                // walk. Any other tag, no anchor, or a walk past the last
                // occurrence is wrong data — measured on a YubiKey 5.7.4, which
                // answers 6A80 to all three and leaves the occurrence pointer
                // where the walk ended.
                if fid != consts::EF_CH_CERT
                    || self.current_ef != Some(consts::EF_CH_CERT)
                    || self.sess.cert_occ + 1 >= consts::CERT_OCCURRENCES
                {
                    return consts::WRONG_DATA;
                }
                self.sess.cert_occ += 1;
                self.read_cert_occurrence(fs, res)
            }
            consts::INS_SELECT => {
                let (n, sw) = select::cmd_select(apdu, &mut self.scratch);
                if sw.is_ok() && n > 0 {
                    res.extend(&self.scratch[..n]);
                }
                sw
            }
            consts::INS_VERIFY => {
                // Device is built inline (a `&self` helper would borrow all of
                // self and conflict with `&mut self.sess`).
                let mkek = read_fused(self.mkek_source);
                let dev = Device {
                    serial_hash: &self.serial_hash,
                    serial_id: &self.serial_id,
                    otp_key: mkek.as_deref(),
                };
                let mut rng = self.rng.borrow_mut();
                pin::verify(
                    &dev,
                    fs,
                    &mut self.sess,
                    &mut *rng,
                    apdu.p1,
                    apdu.p2,
                    apdu.data,
                )
            }
            consts::INS_CHANGE_PIN => {
                let mkek = read_fused(self.mkek_source);
                let dev = Device {
                    serial_hash: &self.serial_hash,
                    serial_id: &self.serial_id,
                    otp_key: mkek.as_deref(),
                };
                let mut rng = self.rng.borrow_mut();
                pin::change_pin(
                    &dev,
                    fs,
                    &mut self.sess,
                    &mut *rng,
                    apdu.p1,
                    apdu.p2,
                    apdu.data,
                )
            }
            consts::INS_RESET_RETRY => {
                let mkek = read_fused(self.mkek_source);
                let dev = Device {
                    serial_hash: &self.serial_hash,
                    serial_id: &self.serial_id,
                    otp_key: mkek.as_deref(),
                };
                let mut rng = self.rng.borrow_mut();
                pin::reset_retry(
                    &dev,
                    fs,
                    &mut self.sess,
                    &mut *rng,
                    apdu.p1,
                    apdu.p2,
                    apdu.data,
                )
            }
            consts::INS_PUT_DATA => self.handle_put_data(fid, apdu, fs),
            consts::INS_PUT_DATA_ODD => {
                // IMPORT (extended header list). Public-key derivation is
                // deterministic, so no RNG is needed here.
                let mkek = read_fused(self.mkek_source);
                let dev = Device {
                    serial_hash: &self.serial_hash,
                    serial_id: &self.serial_id,
                    otp_key: mkek.as_deref(),
                };
                importdata::import_data(&dev, fs, &self.sess, apdu.p1, apdu.p2, apdu.data)
            }
            consts::INS_PSO => {
                let mkek = read_fused(self.mkek_source);
                let dev = Device {
                    serial_hash: &self.serial_hash,
                    serial_id: &self.serial_id,
                    otp_key: mkek.as_deref(),
                };
                let mut rng = self.rng.borrow_mut();
                let mut presence = self.presence.borrow_mut();
                let (n, sw) = pso::pso(
                    &dev,
                    fs,
                    &mut self.sess,
                    &mut *rng,
                    &mut *presence,
                    apdu,
                    &mut self.scratch,
                );
                drop(presence);
                drop(rng);
                if sw.is_ok() && n > 0 {
                    res.extend(&self.scratch[..n]);
                }
                sw
            }
            consts::INS_INTERNAL_AUT => {
                let mkek = read_fused(self.mkek_source);
                let dev = Device {
                    serial_hash: &self.serial_hash,
                    serial_id: &self.serial_id,
                    otp_key: mkek.as_deref(),
                };
                let mut rng = self.rng.borrow_mut();
                let mut presence = self.presence.borrow_mut();
                let (n, sw) = internalaut::internal_aut(
                    &dev,
                    fs,
                    &self.sess,
                    &mut *rng,
                    &mut *presence,
                    apdu,
                    &mut self.scratch,
                );
                drop(presence);
                drop(rng);
                if sw.is_ok() && n > 0 {
                    res.extend(&self.scratch[..n]);
                }
                sw
            }
            consts::INS_KEYPAIR_GEN => {
                let mkek = read_fused(self.mkek_source);
                let dev = Device {
                    serial_hash: &self.serial_hash,
                    serial_id: &self.serial_id,
                    otp_key: mkek.as_deref(),
                };
                let mut rng = self.rng.borrow_mut();
                let (n, sw) = keypairgen::keypair_gen(
                    &dev,
                    fs,
                    &self.sess,
                    &mut *rng,
                    apdu.p1,
                    apdu.p2,
                    apdu.data,
                    &mut self.scratch,
                );
                drop(rng);
                if sw.is_ok() && n > 0 {
                    res.extend(&self.scratch[..n]);
                }
                sw
            }
            consts::INS_VERSION => {
                // Report the shared device firmware version, like a real YubiKey
                // (whose OpenPGP applet version == its firmware version).
                let (major, minor, patch) = rsk_sdk::FIRMWARE_VERSION;
                res.extend(&[major, minor, patch]);
                Sw::OK
            }
            consts::INS_MSE => mse::mse(&mut self.sess, apdu),
            consts::INS_CHALLENGE => {
                // §7.2.15 fixes P1 = P2 = 00. Stricter than a YubiKey 5.7.4, which
                // refuses only when BOTH are non-zero — so this refuses everything
                // that card refuses and nothing a conformant host sends.
                if apdu.p1 != 0 || apdu.p2 != 0 {
                    return Sw::WRONG_P1P2;
                }
                // GET CHALLENGE: `apdu.ne` random bytes. Bounded by what DO C0
                // announces, not by the buffer that happens to back it: an
                // announcement a host cannot rely on is worth nothing, and
                // truncating to it under `9000` would be worse than refusing.
                let ne = apdu.ne;
                if ne == 0 {
                    // A command carrying Lc and no Le at all — zero random bytes
                    // under 9000 reads as a served challenge. `6A80`, the answer
                    // measured on a YubiKey 5.7.4; ISO case 1 is indistinguishable
                    // here because `Apdu::parse` defaults its Ne to 256.
                    return consts::WRONG_DATA;
                }
                if ne > files::MAX_CHALLENGE_BYTES {
                    // No cell to copy: that card over-announces by ten, corrupts
                    // its own response one byte past what it can serve and wedges
                    // its CCID interface four past that. ISO 7816-4 decides.
                    return Sw::WRONG_LENGTH;
                }
                self.rng.borrow_mut().fill(&mut self.scratch[..ne]);
                res.extend(&self.scratch[..ne]);
                Sw::OK
            }
            consts::INS_ACTIVATE_FILE => Sw::OK,
            consts::INS_TERMINATE_DF => {
                let mkek = read_fused(self.mkek_source);
                let dev = Device {
                    serial_hash: &self.serial_hash,
                    serial_id: &self.serial_id,
                    otp_key: mkek.as_deref(),
                };
                let mut rng = self.rng.borrow_mut();
                terminate::terminate_df(&dev, fs, &mut *rng, self.sess.has_pw3, apdu)
            }
            // SELECT DATA (0xA5): pick the cardholder-certificate occurrence (7F21 →
            // EF_CH_1/2/3) for the following GET / PUT DATA.
            consts::INS_SELECT_DATA => {
                let sw = select::select_data(apdu, &mut self.sess);
                if sw.is_ok() {
                    // SELECT DATA arms the walk as much as GET DATA does — a
                    // YubiKey walks from the selected occurrence with no read in
                    // between, and that is the natural way to start at one.
                    self.current_ef = Some(consts::EF_CH_CERT);
                }
                sw
            }
            // Deliberately unsupported: GET BULK DATA (0xCE, vendor), the management
            // applet, and secure messaging — none used by gpg/scdaemon over USB/PC-SC.
            _ => Sw::INS_NOT_SUPPORTED,
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "serial_identity_tests.rs"]
mod serial_identity_tests;

#[cfg(test)]
#[path = "dying_storage.rs"]
mod dying_storage;

#[cfg(test)]
#[path = "dispatch_getdata_tests.rs"]
mod dispatch_getdata_tests;

#[cfg(test)]
#[path = "reselect_tests.rs"]
mod reselect_tests;
