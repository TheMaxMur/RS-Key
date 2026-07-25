// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg_attr(not(test), no_std)]

//! `rsk-piv` — the PIV card applet: the NIST SP 800-73-4 command subset plus the
//! Yubico extensions `ykman piv` / `yubico-piv-tool` exercise (metadata, serial,
//! attestation, move/delete, set-mgm-key, set-retries, reset), reached over CCID.
//! Pure and host-testable; key machinery comes from `rsk-openpgp`, private keys
//! at rest are GCM-sealed ([`seal`]), and management operations (IMPORT KEY, PUT
//! DATA, SET MGM KEY, MOVE KEY, SET RETRIES) require management-key auth.

extern crate alloc;

mod auth;
mod chuid;
pub mod files;
pub mod info;
mod keygen;
mod seal;
mod x509;

use core::cell::RefCell;

use rsk_crypto::Device;
use rsk_fs::{Fs, Sealed, Storage};
pub use rsk_openpgp::Rng;
use rsk_openpgp::keys::{MAX_RSA_BYTES, MAX_RSA_PUBDO, RSA_PUB_EXP_BE, make_rsa_pub_body};
// PIV reuses the OpenPGP user-presence trait, so the firmware's existing
// `impl rsk_openpgp::UserPresence for ButtonPresence` already drives PIV touch.
use rsa::RsaPrivateKey;
use rsa::traits::PublicKeyParts;
pub use rsk_openpgp::{AlwaysConfirm, Presence, UserPresence};
use rsk_sdk::tlv::{find_tag, format_len};
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};
use zeroize::Zeroize;

use files::*;

/// The PIV AID prefix the dispatcher matches. The full requested AID is
/// `A0 00 00 03 08 00 00 10 00 01 00`.
pub const PIV_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x03, 0x08];

/// Reported PIV application version — the shared [`rsk_sdk::FIRMWARE_VERSION`]
/// (default 5.7.4, `FW_VERSION`-overridable).
pub const VERSION: (u8, u8, u8) = rsk_sdk::FIRMWARE_VERSION;

/// Status 0x6A80 (wrong data).
pub(crate) const WRONG_DATA: Sw = Sw::INCORRECT_PARAMS;

const INS_VERIFY: u8 = 0x20;
const INS_CHANGE_PIN: u8 = 0x24;
const INS_RESET_RETRY: u8 = 0x2C;
/// Shared with the OpenPGP GENERATE INS; PIV uses P1 = 0x00 (OpenPGP: 0x80/0x81).
pub const INS_ASYM_KEYGEN: u8 = 0x47;
const INS_AUTHENTICATE: u8 = 0x87;
const INS_SELECT: u8 = 0xA4;
const INS_GET_DATA: u8 = 0xCB;
const INS_PUT_DATA: u8 = 0xDB;
const INS_MOVE_KEY: u8 = 0xF6;
const INS_GET_METADATA: u8 = 0xF7;
const INS_YK_SERIAL: u8 = 0xF8;
const INS_ATTESTATION: u8 = 0xF9;
const INS_SET_RETRIES: u8 = 0xFA;
const INS_RESET: u8 = 0xFB;
const INS_VERSION: u8 = 0xFD;
const INS_IMPORT_ASYM: u8 = 0xFE;
const INS_SET_MGMKEY: u8 = 0xFF;

/// YubiKey "PRINTED INFORMATION" object — repurposed to hold the PIN-protected
/// management key (readable only after a PIN VERIFY, and only once protection is
/// enabled). The key itself is synthesized from the sealed 0x9B auth slot, never
/// stored a second time.
const PRINTED_ID: u32 = 0x5FC109;
const CHUID_ID: u32 = 0x5FC102;
/// PivmanData (ADMIN DATA) TLV: outer `0x80 { 0x81 = flags, 0x82 = derived-key
/// salt, 0x83 = PIN-change timestamp }`; flag bit `0x02` means the management key
/// is PIN-protected (a host reads it back from PRINTED). ykman writes the salt
/// only for the deprecated PIN-*derived* management key; the timestamp is the
/// last-PIN-change record it displays.
const PIVMAN_TAG: u8 = 0x80;
const PIVMAN_FLAGS_TAG: u8 = 0x81;
// Salt (0x82) is only ever *read* to be dropped, never re-emitted, so it needs no
// named constant in the encoder; tests spell the raw tag with a `// salt` note.
const PIVMAN_TS_TAG: u8 = 0x83;
const PIVMAN_FLAG_MGM_PROTECTED: u8 = 0x02;
/// Upper bound for a PivmanData record we re-emit: outer tag+len, the 3-byte
/// flags TLV, and a preserved timestamp TLV whose value we cap at 16 bytes (a
/// real one is 4). The salt is never re-emitted, so it is not budgeted.
const PIVMAN_TS_MAX: usize = 16;
const PIVMAN_MAX: usize = 2 + 3 + 2 + PIVMAN_TS_MAX;
/// PivmanProtectedData TLV: outer `0x88 { 0x89 = raw management key }`.
const PROTECTED_TAG: u8 = 0x88;
const PROTECTED_MGM_TAG: u8 = 0x89;
// GET/PUT DATA (SP 800-73-4): 5C = the object-id path, 53 = the data object.
const TAG_DATA_PATH: u8 = 0x5C;
const TAG_DATA_OBJECT: u8 = 0x53;

/// Which GENERAL AUTHENTICATE handshake issued the pending `challenge`. The two
/// flows attach opposite confidentiality to that field — mutual auth returns the
/// witness *encrypted* (proof = decrypt it), single auth returns the challenge in
/// *plaintext* (proof = encrypt it) — so a challenge issued by one flow must never
/// be consumed by the other. Without this tag the plaintext single-auth challenge
/// could be replayed as the mutual-auth witness, authenticating with no key.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ChallengeKind {
    #[default]
    None,
    MutualWitness,
    SingleChallenge,
}

/// Volatile per-selection security state.
#[derive(Default)]
pub(crate) struct Session {
    pub(crate) has_pin: bool,
    pub(crate) has_mgm: bool,
    pub(crate) has_challenge: bool,
    pub(crate) chal_kind: ChallengeKind,
    pub(crate) challenge: [u8; 16],
    /// The 9B algorithm the outstanding challenge/witness was issued under. A
    /// step-2 presented under a different algorithm is refused, so an AES-192
    /// witness cannot be answered as 3DES (both are 24-byte keys, so the
    /// length gate alone does not separate them).
    pub(crate) chal_algo: u8,
}

impl Session {
    fn reset(&mut self) {
        self.has_pin = false;
        self.has_mgm = false;
        self.has_challenge = false;
        self.chal_kind = ChallengeKind::None;
        self.chal_algo = 0;
        self.challenge.zeroize();
    }
}

pub struct PivApplet<'a> {
    serial_id: [u8; 8],
    serial_hash: [u8; 32],
    /// The OTP MKEK, once provisioned.
    otp_key: Option<[u8; 32]>,
    rng: &'a RefCell<dyn Rng>,
    presence: &'a RefCell<dyn UserPresence>,
    sess: Session,
    /// Set once `scan_files` has provisioned the default files this power-cycle,
    /// so a re-SELECT skips its five flash probes. Only ever cleared by the fresh
    /// struct a reboot builds — nothing removes those files mid-power-cycle
    /// without a reboot (see `select`).
    files_ensured: bool,
}

impl<'a> PivApplet<'a> {
    /// `presence` is the BOOTSEL button (shared with the FIDO/OpenPGP/OTP
    /// applets) — it gates the slot/management touch policies.
    pub fn new(
        serial_id: [u8; 8],
        serial_hash: [u8; 32],
        otp_key: Option<[u8; 32]>,
        rng: &'a RefCell<dyn Rng>,
        presence: &'a RefCell<dyn UserPresence>,
    ) -> Self {
        PivApplet {
            serial_id,
            serial_hash,
            otp_key,
            rng,
            presence,
            sess: Session::default(),
            files_ensured: false,
        }
    }

    /// Owned copies of the device identifiers, for building a [`Device`] that
    /// does not hold a borrow of `self` across `&mut self` calls.
    fn device_ids(&self) -> ([u8; 32], [u8; 8], Option<[u8; 32]>) {
        (self.serial_hash, self.serial_id, self.otp_key)
    }

    /// If `apdu` is a PIV RSA GENERATE, validate it fully and return the slot,
    /// modulus size and resolved policy bytes so the firmware can run the slow
    /// prime search itself (stepping [`RsaKeygen`] between CCID keepalives).
    /// `None` falls through to normal dispatch — EC generate, or any error
    /// (re-validated there so the right SW is reported).
    pub fn rsa_generate_params<S: Storage>(
        &mut self,
        _fs: &mut Fs<S>,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Option<(u8, usize, [u8; 2])> {
        if p1 != 0x00 || !self.sess.has_mgm || !is_key(p2) {
            return None;
        }
        let req = keygen::parse_gen_template(data).ok()?;
        let nbits = keygen::rsa_size_from_algo(req.algo)? * 8;
        let pol = keygen::resolved_policies(p2, req.pin_policy, req.touch_policy);
        Some((p2, nbits, pol))
    }

    /// Store the firmware-generated RSA key, certificate and metadata and write
    /// the `7F49` response body + SW into `resp`; returns the total length.
    pub fn rsa_generate_finish<S: Storage>(
        &mut self,
        fs: &mut Fs<S>,
        rng: &mut dyn Rng,
        slot: u8,
        pol: [u8; 2],
        key: &RsaPrivateKey,
        resp: &mut [u8],
    ) -> (usize, Sw) {
        let Some(algo) = keygen::rsa_algo_from_size(key.size()) else {
            return (0, Sw::EXEC_ERROR);
        };
        let dev = Device {
            serial_hash: &self.serial_hash,
            serial_id: &self.serial_id,
            otp_key: self.otp_key.as_ref(),
        };
        let mut res = ResBuf::new(resp);
        let sw = keygen::finish_rsa(&dev, fs, rng, slot, algo, pol, key, &mut res);
        (res.len(), sw)
    }
}

/// The SELECT application property template (`61 { … }`); the outer length
/// byte is filled in (some implementations leave it 0).
fn apt(res: &mut ResBuf) -> Sw {
    // NIST SP 800-73-4 §3.1.1: 4F is the PIV AID/PIX and 79 (coexistent tag
    // allocation authority) MUST wrap a nested 4F holding the NIST RID. A flat 79
    // (no inner 4F) makes OpenSC's piv_match_card fall back to the OpenPGP applet.
    const BODY: &[u8] = &[
        0x4F, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, // PIV application AID (PIX)
        0x79, 0x07, 0x4F, 0x05, 0xA0, 0x00, 0x00, 0x03,
        0x08, // tag alloc authority → NIST RID
        0x50, 0x0A, b'R', b'S', b'-', b'K', b'e', b'y', b' ', b'P', b'I',
        b'V', // application label
        0xAC, 0x0C, 0x80, 0x07, 0x07, 0x08, 0x0A, 0x0C, 0x11, 0x14, 0x2E, 0x06, 0x01,
        0x00, // supported algorithms
    ];
    if !res.push(0x61) || !res.push(BODY.len() as u8) || !res.extend(BODY) {
        return Sw::WRONG_LENGTH;
    }
    Sw::OK
}

impl<S: Storage> Applet<Fs<S>> for PivApplet<'_> {
    fn aid(&self) -> &'static [u8] {
        PIV_AID
    }

    /// PIV GET DATA (certificates) routinely exceeds 256 bytes; OpenSC/`ykman`
    /// read it with a short `Le` and standard GET RESPONSE, so opt into the
    /// dispatcher's response chaining.
    fn response_chaining(&self) -> bool {
        true
    }

    fn select(&mut self, _reselect: bool, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        self.sess.reset();
        // The default PIN/PUK/retry/mgmt/attestation files are provisioned once
        // and afterwards only ever removed by a path that recreates them (PIV
        // `reset_files`) or reboots (trusted-display factory wipe → `sys_reset`);
        // `authenticatorReset` leaves them. So past the first SELECT this
        // power-cycle they are present — skip the five flash `has_data` probes
        // scan_files would otherwise repeat on every re-SELECT.
        if !self.files_ensured {
            let (serial_hash, serial_id, otp_key) = self.device_ids();
            let dev = Device {
                serial_hash: &serial_hash,
                serial_id: &serial_id,
                otp_key: otp_key.as_ref(),
            };
            let mut rng = self.rng.borrow_mut();
            if files::scan_files(&dev, fs, &mut *rng).is_err() {
                return Sw::MEMORY_FAILURE;
            }
            self.files_ensured = true;
        }
        apt(res)
    }

    fn deselect(&mut self, _fs: &mut Fs<S>) {
        self.sess.reset();
    }

    fn process(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        let (serial_hash, serial_id, otp_key) = self.device_ids();
        let dev = Device {
            serial_hash: &serial_hash,
            serial_id: &serial_id,
            otp_key: otp_key.as_ref(),
        };
        match apdu.ins {
            INS_VERSION => {
                res.extend(&[VERSION.0, VERSION.1, VERSION.2]);
                Sw::OK
            }
            INS_YK_SERIAL => {
                res.extend(&rsk_mgmt::serial4(self.serial_id));
                Sw::OK
            }
            INS_SELECT => {
                // A re-SELECT addressed at the applet itself.
                if apdu.p2 != 0x01 {
                    return Sw::WRONG_P1P2;
                }
                if apdu.data.len() >= PIV_AID.len() && &apdu.data[..PIV_AID.len()] == PIV_AID {
                    return apt(res);
                }
                Sw::OK
            }
            INS_VERIFY => self.verify(&dev, fs, apdu, res),
            INS_CHANGE_PIN => self.change_pin(&dev, fs, apdu),
            INS_RESET_RETRY => self.reset_retry(&dev, fs, apdu),
            INS_AUTHENTICATE => {
                let mut rng = self.rng.borrow_mut();
                let mut presence = self.presence.borrow_mut();
                auth::general_authenticate(
                    &mut self.sess,
                    &dev,
                    fs,
                    &mut *rng,
                    &mut *presence,
                    apdu.p1,
                    apdu.p2,
                    apdu.data,
                    res,
                )
            }
            INS_ASYM_KEYGEN => self.keygen(&dev, fs, apdu, res),
            INS_GET_DATA => self.get_data(fs, apdu, res),
            INS_PUT_DATA => self.put_data(fs, apdu),
            INS_GET_METADATA => self.get_metadata(&dev, fs, apdu, res),
            INS_SET_MGMKEY => self.set_mgmkey(&dev, fs, apdu),
            INS_MOVE_KEY => self.move_key(fs, apdu),
            INS_SET_RETRIES => self.set_retries(&dev, fs, apdu),
            INS_RESET => self.reset(&dev, fs, apdu),
            INS_ATTESTATION => {
                if apdu.p2 != 0x00 {
                    return Sw::INCORRECT_P1P2;
                }
                let mut rng = self.rng.borrow_mut();
                keygen::attest(
                    &dev,
                    fs,
                    &mut *rng,
                    apdu.p1,
                    rsk_mgmt::serial4(self.serial_id),
                    res,
                )
            }
            INS_IMPORT_ASYM => {
                let mut rng = self.rng.borrow_mut();
                keygen::import(&self.sess, &dev, fs, &mut *rng, apdu.p1, apdu.p2, apdu.data)
            }
            _ => Sw::INS_NOT_SUPPORTED,
        }
    }
}

impl PivApplet<'_> {
    /// VERIFY (INS 0x20): the PIV application PIN, reference 0x80.
    fn verify<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        apdu: &Apdu,
        _res: &mut ResBuf,
    ) -> Sw {
        if apdu.p1 != 0x00 && apdu.p1 != 0xFF {
            return Sw::INCORRECT_P1P2;
        }
        if apdu.p2 != REF_PIN {
            return Sw::REFERENCE_NOT_FOUND;
        }
        if !fs.has_data(EF_PIN) {
            return Sw::REFERENCE_NOT_FOUND;
        }
        if apdu.p1 == 0xFF {
            // SP 800-73: reset the security status of the PIN.
            if apdu.nc != 0 {
                return Sw::WRONG_LENGTH;
            }
            self.sess.has_pin = false;
            return Sw::OK;
        }
        if apdu.nc == 0 {
            let left = match retries_left(fs, RETRY_PIN) {
                Ok(l) => l,
                Err(sw) => return sw,
            };
            if left == 0 {
                return Sw::PIN_BLOCKED;
            }
            if self.sess.has_pin {
                return Sw::OK;
            }
            return Sw::retries(left);
        }
        match check_ref(dev, fs, EF_PIN, RETRY_PIN, apdu.data) {
            Sw::OK => {
                self.sess.has_pin = true;
                Sw::OK
            }
            sw => sw,
        }
    }

    /// CHANGE REFERENCE DATA (INS 0x24): `old ‖ new`, old length taken from
    /// the stored record.
    fn change_pin<S: Storage>(&mut self, dev: &Device, fs: &mut Fs<S>, apdu: &Apdu) -> Sw {
        if apdu.p1 != 0x00 {
            return Sw::INCORRECT_P1P2;
        }
        let which = match apdu.p2 {
            REF_PIN => PinRef::Pin,
            REF_PUK => PinRef::Puk,
            _ => return Sw::INCORRECT_P1P2,
        };
        let (fid, _) = which.fid_retry();
        let old_len = match stored_pin_len(fs, fid) {
            Ok(n) => n,
            Err(sw) => return sw,
        };
        if apdu.nc <= old_len {
            return Sw::WRONG_LENGTH;
        }
        change_reference(dev, fs, which, &apdu.data[..old_len], &apdu.data[old_len..])
    }

    /// RESET RETRY COUNTER (INS 0x2C): unblock/replace the PIN with the PUK.
    fn reset_retry<S: Storage>(&mut self, dev: &Device, fs: &mut Fs<S>, apdu: &Apdu) -> Sw {
        if apdu.p1 != 0x00 || apdu.p2 != REF_PIN {
            return Sw::INCORRECT_P1P2;
        }
        let puk_len = match stored_pin_len(fs, EF_PUK) {
            Ok(n) => n,
            Err(sw) => return sw,
        };
        if apdu.nc <= puk_len {
            return Sw::WRONG_LENGTH;
        }
        unblock_pin_with_puk(dev, fs, &apdu.data[..puk_len], &apdu.data[puk_len..])
    }

    /// SET RETRIES (INS 0xFA): resets both references to their defaults with the
    /// new totals. Requires the management key **and** the current PIN — it wipes
    /// PIN/PUK, so mgmt alone must not reset an unknown PIN (matches YubiKey).
    fn set_retries<S: Storage>(&mut self, dev: &Device, fs: &mut Fs<S>, apdu: &Apdu) -> Sw {
        if !self.sess.has_mgm || !self.sess.has_pin {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        if apdu.p1 == 0 || apdu.p2 == 0 {
            return Sw::INCORRECT_PARAMS;
        }
        if fs
            .put(EF_RETRIES, &[apdu.p1, apdu.p1, apdu.p2, apdu.p2])
            .is_err()
        {
            return Sw::MEMORY_FAILURE;
        }
        if put_pin_verifier(dev, fs, EF_PIN, &DEFAULT_PIN).is_err()
            || put_pin_verifier(dev, fs, EF_PUK, &DEFAULT_PUK).is_err()
        {
            return Sw::MEMORY_FAILURE;
        }
        self.sess.has_pin = false;
        Sw::OK
    }

    /// RESET (INS 0xFB): only with both references blocked.
    fn reset<S: Storage>(&mut self, dev: &Device, fs: &mut Fs<S>, apdu: &Apdu) -> Sw {
        if apdu.p1 != 0x00 || apdu.p2 != 0x00 {
            return Sw::INCORRECT_P1P2;
        }
        let (pin_left, puk_left) = match (retries_left(fs, RETRY_PIN), retries_left(fs, RETRY_PUK))
        {
            (Ok(p), Ok(k)) => (p, k),
            _ => return Sw::REFERENCE_NOT_FOUND,
        };
        if pin_left != 0 || puk_left != 0 {
            return Sw::INCORRECT_PARAMS;
        }
        let mut rng = self.rng.borrow_mut();
        if files::reset_files(dev, fs, &mut *rng).is_err() {
            // A half-swept card may have lost the files SELECT's fast path assumes
            // are there, so re-arm the provisioning instead of trusting it — a
            // retried RESET must not answer 6A88 for the rest of the power cycle.
            self.sess.reset();
            self.files_ensured = false;
            return Sw::MEMORY_FAILURE;
        }
        self.sess.reset();
        // reset_files re-provisions the defaults, so they stay present — keep the
        // SELECT fast-path armed rather than forcing a re-scan next SELECT.
        self.files_ensured = true;
        Sw::OK
    }

    /// GENERATE ASYMMETRIC KEY PAIR (INS 0x47). EC runs inline; RSA normally
    /// arrives via the firmware fast-path, with a blocking fallback for host use.
    fn keygen<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        apdu: &Apdu,
        res: &mut ResBuf,
    ) -> Sw {
        if apdu.p1 != 0x00 {
            return Sw::INCORRECT_P1P2;
        }
        if apdu.nc == 0 {
            return Sw::WRONG_LENGTH;
        }
        if apdu.data[0] != TAG_GEN_TEMPLATE {
            return WRONG_DATA;
        }
        if !self.sess.has_mgm {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        if !is_key(apdu.p2) {
            return Sw::INCORRECT_P1P2;
        }
        let req = match keygen::parse_gen_template(apdu.data) {
            Ok(r) => r,
            Err(sw) => return sw,
        };
        let mut rng = self.rng.borrow_mut();
        match req.algo {
            ALGO_ECCP256 | ALGO_ECCP384 | ALGO_ED25519 | ALGO_X25519 => {
                keygen::generate_ec(dev, fs, &mut *rng, apdu.p2, &req, res)
            }
            ALGO_RSA1024 | ALGO_RSA2048 | ALGO_RSA3072 | ALGO_RSA4096 => {
                keygen::generate_rsa_blocking(dev, fs, &mut *rng, apdu.p2, &req, res)
            }
            _ => WRONG_DATA,
        }
    }

    /// GET DATA (INS 0xCB).
    fn get_data<S: Storage>(&mut self, fs: &mut Fs<S>, apdu: &Apdu, res: &mut ResBuf) -> Sw {
        if apdu.p1 != 0x3F || apdu.p2 != 0xFF {
            return Sw::INCORRECT_P1P2;
        }
        let d = apdu.data;
        if d.len() < 3 || d[0] != TAG_DATA_PATH {
            return WRONG_DATA;
        }
        let l = d[1] as usize;
        if l == 0 || l > 3 || d.len() < 2 + l {
            return WRONG_DATA;
        }
        let mut id: u32 = 0;
        for &b in &d[2..2 + l] {
            id = id << 8 | b as u32;
        }
        if id == DISCOVERY_ID {
            res.extend(DISCOVERY);
            return Sw::OK;
        }
        if id == PRINTED_ID {
            return self.get_protected_mgm(fs, res);
        }
        let Some(fid) = object_fid(id) else {
            return Sw::FILE_NOT_FOUND;
        };
        let mut obj = [0u8; MAX_OBJECT];
        // `Storage::read` returns the value's FULL stored length; clamp to the
        // bytes we actually hold. Host writers cap at MAX_OBJECT (put_data), so
        // this only bites a flash-corrupted over-length record — returning its
        // prefix instead of panicking on the slice.
        let n = match fs.read(fid, &mut obj) {
            Some(n) if n > 0 => n.min(obj.len()),
            // No host-provisioned CHUID: synthesize a default so Windows' PIV
            // minidriver has the card GUID it needs to enumerate the slots (a
            // 6A82 here leaves RSA/EC auth "pending" under CAPI). A real PUT DATA
            // persists at this same fid and wins the read above.
            _ if id == CHUID_ID => {
                let synth = chuid::default_chuid(&self.serial_hash);
                obj[..synth.len()].copy_from_slice(&synth);
                synth.len()
            }
            _ => return Sw::FILE_NOT_FOUND,
        };
        if push_tlv(res, TAG_DATA_OBJECT, &obj[..n]).is_err() {
            return Sw::WRONG_LENGTH;
        }
        Sw::OK
    }

    /// GET DATA for the PRINTED object (`5FC109`) — the PIN-protected management
    /// key. Returns it only when protection is enabled (the ADMIN-DATA flag) AND
    /// the PIN is verified; a default or plain mgmt key reads as absent, so the
    /// key is never PIN-disclosed unless the user opted in. The key is synthesized
    /// from the sealed 0x9B auth slot — there is no second copy at rest.
    fn get_protected_mgm<S: Storage>(&mut self, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if !mgm_is_protected(fs) {
            return Sw::FILE_NOT_FOUND;
        }
        if !self.sess.has_pin {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let dev = Device {
            serial_hash: &self.serial_hash,
            serial_id: &self.serial_id,
            otp_key: self.otp_key.as_ref(),
        };
        let mut key = [0u8; 32];
        let klen = match seal::seal_read(&dev, fs, key_fid(SLOT_CARDMGM), &mut key) {
            Ok(n) => n,
            Err(sw) => return sw,
        };
        // PivmanProtectedData: 88 { 89 <key> }, wrapped in the 53 response object.
        let mut body = [0u8; 4 + 32];
        body[0] = PROTECTED_TAG;
        body[1] = (2 + klen) as u8;
        body[2] = PROTECTED_MGM_TAG;
        body[3] = klen as u8;
        body[4..4 + klen].copy_from_slice(&key[..klen]);
        key.zeroize();
        let r = if push_tlv(res, TAG_DATA_OBJECT, &body[..4 + klen]).is_err() {
            Sw::WRONG_LENGTH
        } else {
            Sw::OK
        };
        body.zeroize();
        r
    }

    /// PUT DATA (INS 0xDB, management-gated).
    fn put_data<S: Storage>(&mut self, fs: &mut Fs<S>, apdu: &Apdu) -> Sw {
        if apdu.p1 != 0x3F || apdu.p2 != 0xFF {
            return Sw::INCORRECT_P1P2;
        }
        if !self.sess.has_mgm {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        // Discovery / biometric writes are acknowledged with a bare OK (not stored).
        if !apdu.data.is_empty() && (apdu.data[0] == 0x7E || apdu.data[0] == 0x7F) {
            return Sw::OK;
        }
        let (Some(path), Some(obj)) = (
            find_tag(apdu.data, TAG_DATA_PATH as u16),
            find_tag(apdu.data, TAG_DATA_OBJECT as u16),
        ) else {
            return WRONG_DATA;
        };
        if path.len() != 3 {
            return WRONG_DATA;
        }
        let fid = match (path[0], path[1], path[2]) {
            // ADMIN DATA (5FFF00): the protection flags. Plaintext (non-secret).
            (0x5F, 0xFF, 0x00) => EF_PIVMAN_DATA,
            // PRINTED (5FC109): the PIN-protected mgmt key is virtual — backed by
            // the sealed 0x9B auth slot (set via SET MANAGEMENT KEY); the host's
            // copy isn't persisted (GET DATA synthesizes it), so acknowledge the
            // write without storing the key plaintext at rest.
            (0x5F, 0xC1, 0x09) => return Sw::OK,
            (0x5F, 0xC1, b) => match data_object_fid(b) {
                Some(fid) => fid,
                None => return WRONG_DATA,
            },
            _ => return WRONG_DATA,
        };
        if obj.is_empty() {
            let _ = fs.delete(fid);
            return Sw::OK;
        }
        if obj.len() > MAX_OBJECT {
            return Sw::WRONG_LENGTH;
        }
        if fs.put(fid, obj).is_err() {
            return Sw::MEMORY_FAILURE;
        }
        Sw::OK
    }

    /// GET METADATA (INS 0xF7, Yubico).
    fn get_metadata<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        apdu: &Apdu,
        res: &mut ResBuf,
    ) -> Sw {
        if apdu.p1 != 0x00 {
            return Sw::INCORRECT_P1P2;
        }
        let key_ref = apdu.p2;
        match key_ref {
            REF_PIN | REF_PUK => {
                let (fid, retry, default) = if key_ref == REF_PIN {
                    (EF_PIN, RETRY_PIN, &DEFAULT_PIN)
                } else {
                    (EF_PUK, RETRY_PUK, &DEFAULT_PUK)
                };
                let mut rec = [0u8; PIN_REC_LEN];
                let Some(PIN_REC_LEN) = fs.read(fid, &mut rec) else {
                    return Sw::REFERENCE_NOT_FOUND;
                };
                let is_default = ct_eq(&rec[2..PIN_REC_LEN], &dev.pin_derive_verifier(default));
                let (total, left) = match retries(fs, retry) {
                    Ok(t) => t,
                    Err(sw) => return sw,
                };
                res.extend(&[0x05, 0x01, is_default as u8]);
                res.extend(&[0x06, 0x02, total, left]);
                Sw::OK
            }
            SLOT_CARDMGM => {
                let mut meta = [0u8; 8];
                let Some(n) = fs.meta_find(key_fid(SLOT_CARDMGM).get(), &mut meta) else {
                    return Sw::REFERENCE_NOT_FOUND;
                };
                if n < 3 {
                    return Sw::REFERENCE_NOT_FOUND;
                }
                let mut key = [0u8; 32];
                let is_default = match seal::seal_read(dev, fs, key_fid(SLOT_CARDMGM), &mut key) {
                    Ok(24) => ct_eq(&key[..24], &DEFAULT_MGM),
                    Ok(_) => false,
                    Err(sw) => return sw,
                };
                key.zeroize();
                res.extend(&[0x01, 0x01, meta[0]]);
                res.extend(&[0x02, 0x02, meta[1], meta[2]]);
                res.extend(&[0x05, 0x01, is_default as u8]);
                Sw::OK
            }
            s if is_key(s) => {
                // meta_find below gates existence (delete clears the meta record
                // unconditionally), so the old separate has_key probe here was a
                // redundant per-slot flash fetch on every GET METADATA — dropped.
                // Sized to hold a cached EC public point trailing the 4-byte
                // [algo, pin_pol, touch_pol, origin] head (see slot_pubkey_tlv).
                let mut meta = [0u8; 4 + MAX_EC_POINT];
                let Some(n) = fs.meta_find(key_fid(s).get(), &mut meta) else {
                    return Sw::REFERENCE_NOT_FOUND;
                };
                let n = n.min(meta.len());
                if n < 4 {
                    return Sw::REFERENCE_NOT_FOUND;
                }
                res.extend(&[0x01, 0x01, meta[0]]);
                res.extend(&[0x02, 0x02, meta[1], meta[2]]);
                res.extend(&[0x03, 0x01, meta[3]]);
                self.slot_pubkey_tlv(dev, fs, s, &meta[..n], res)
            }
            _ => Sw::REFERENCE_NOT_FOUND,
        }
    }

    /// Metadata tag 0x04: the slot public key as `81/82` (RSA) or `86` (EC)
    /// TLVs, the encoding `yubikit` expects.
    fn slot_pubkey_tlv<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        slot: u8,
        meta: &[u8],
        res: &mut ResBuf,
    ) -> Sw {
        let mut body = [0u8; MAX_RSA_PUBDO];
        let n = match meta[0] {
            ALGO_RSA1024 | ALGO_RSA2048 | ALGO_RSA3072 | ALGO_RSA4096 => {
                // Emit the public modulus without rebuilding the private key: GET
                // METADATA needs only N (= p·q) + e (always 65537 for PIV), never
                // `from_p_q`'s ~50 ms CRT precompute. Output byte-identical.
                let mut nbuf = [0u8; MAX_RSA_BYTES];
                let nlen = match seal::load_rsa_modulus(dev, fs, key_fid(slot), &mut nbuf) {
                    Ok(l) => l,
                    Err(_) => return Sw::EXEC_ERROR,
                };
                make_rsa_pub_body(&nbuf[..nlen], RSA_PUB_EXP_BE, &mut body)
            }
            ALGO_ECCP256 | ALGO_ECCP384 | ALGO_ED25519 | ALGO_X25519 => {
                // Emit the slot public point without recomputing the ~tens-of-ms
                // `d·G`. Prefer the per-slot cache file (O(1), works at any slot
                // count); then the legacy in-EF_META cache (older keys that fit);
                // finally derive it from the sealed scalar (pre-cache keys).
                let mut point = [0u8; MAX_EC_POINT];
                let pt: &[u8] = if let Some(pn) = fs.read(pubkey_fid(slot), &mut point) {
                    &point[..pn.min(point.len())]
                } else if meta.len() > 4 {
                    &meta[4..]
                } else {
                    let key = match seal::load_ec_key(dev, fs, key_fid(slot)) {
                        Ok(k) => k,
                        Err(_) => return Sw::EXEC_ERROR,
                    };
                    let plen = match key.public_point(&mut point) {
                        Ok(p) => p,
                        Err(e) => return e,
                    };
                    &point[..plen]
                };
                body[0] = 0x86;
                let ll = format_len(pt.len() as u16, &mut body[1..4]);
                body[1 + ll..1 + ll + pt.len()].copy_from_slice(pt);
                1 + ll + pt.len()
            }
            _ => return Sw::REFERENCE_NOT_FOUND,
        };
        if push_tlv(res, 0x04, &body[..n]).is_err() {
            return Sw::WRONG_LENGTH;
        }
        Sw::OK
    }

    /// SET MGM KEY (INS 0xFF, management-gated).
    fn set_mgmkey<S: Storage>(&mut self, dev: &Device, fs: &mut Fs<S>, apdu: &Apdu) -> Sw {
        if apdu.p1 != 0xFF {
            return Sw::INCORRECT_P1P2;
        }
        let touch = match apdu.p2 {
            0xFF => TOUCHPOLICY_NEVER,
            0xFE => TOUCHPOLICY_ALWAYS,
            _ => return Sw::INCORRECT_P1P2,
        };
        if !self.sess.has_mgm {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        if apdu.nc < 5 {
            return Sw::WRONG_LENGTH;
        }
        let (algo, key_ref, klen) = (apdu.data[0], apdu.data[1], apdu.data[2] as usize);
        // The FIPS-style profile refuses *new* 3DES management keys
        // (SP 800-131A); an existing 3DES key still authenticates, so a
        // reflashed device can migrate itself to AES.
        let tdes = cfg!(not(feature = "fips-profile"));
        let len_ok = mgm_key_len(algo) == Some(klen) && (tdes || algo != ALGO_3DES);
        if key_ref != SLOT_CARDMGM || !len_ok {
            return WRONG_DATA;
        }
        if apdu.nc != 3 + klen {
            return Sw::WRONG_LENGTH;
        }
        let mut rng = self.rng.borrow_mut();
        if seal::seal_put(
            dev,
            fs,
            &mut *rng,
            key_fid(SLOT_CARDMGM),
            &apdu.data[3..3 + klen],
        )
        .is_err()
        {
            return Sw::MEMORY_FAILURE;
        }
        let mut meta = [0u8; 8];
        let Some(n) = fs.meta_find(key_fid(SLOT_CARDMGM).get(), &mut meta) else {
            return Sw::REFERENCE_NOT_FOUND;
        };
        if n < 3 {
            return Sw::REFERENCE_NOT_FOUND;
        }
        if fs
            .meta_add(key_fid(SLOT_CARDMGM).get(), &[algo, meta[1], touch])
            .is_err()
        {
            return Sw::MEMORY_FAILURE;
        }
        // Revoke the one-key escrow LAST, mirroring `protect_mgm_key`'s ordering:
        // clearing the flag before its key is really replaced would strand a
        // PRINTED-only owner whenever the seal write fails. ykman re-sets it.
        if let Err(sw) = mgm_clear_protected(fs) {
            return sw;
        }
        Sw::OK
    }

    /// MOVE KEY (INS 0xF6, Yubico 5.7, management-gated): move (or, to 0xFF,
    /// delete) a key with its certificate object and metadata.
    fn move_key<S: Storage>(&mut self, fs: &mut Fs<S>, apdu: &Apdu) -> Sw {
        if apdu.nc != 0 {
            return Sw::WRONG_LENGTH;
        }
        if !self.sess.has_mgm {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let (to, from) = (apdu.p1, apdu.p2);
        if (!is_key(to) && to != 0xFF) || !is_key(from) {
            return Sw::INCORRECT_P1P2;
        }
        // A self-move would write the key back then delete the source — the same
        // slot — destroying it; reject before any write, as real hardware does.
        if to == from {
            return Sw::INCORRECT_P1P2;
        }
        if is_retired(from) && is_active(to) {
            return Sw::INCORRECT_P1P2;
        }
        // The sealed blob is bound to the device, not the fid, so it moves
        // verbatim. Sized to the largest sealed record (RSA-4096 `P ‖ Q`); a
        // smaller buffer would truncate/overrun-slice a 3072/4096 key's blob.
        let mut blob = [0u8; seal::MAX_BLOB];
        let Some(blob_n) = fs.read_key(key_fid(from), &mut blob) else {
            return Sw::FILE_NOT_FOUND;
        };
        let (cert_from, cert_to) = (cert_fid_for_slot(from), cert_fid_for_slot(to));
        if to != 0xFF {
            // Same power-cut ordering as IMPORT: the destination's own origin
            // record goes before its new key, so a tear can never leave the moved
            // key wearing the destination's provenance.
            if let Err(sw) = keygen::drop_slot_meta(fs, key_fid(to).get()) {
                blob.zeroize();
                return sw;
            }
            if fs
                .put_key(key_fid(to), Sealed::wrap(&blob[..blob_n]))
                .is_err()
            {
                blob.zeroize();
                return Sw::MEMORY_FAILURE;
            }
            let mut obj = [0u8; MAX_OBJECT];
            let cert = cert_from.and_then(|f| fs.read(f, &mut obj));
            // Clamp the full stored length to the buffer (flash-corruption guard,
            // as in get_data); host-written certs are already <= MAX_OBJECT.
            if let (Some(n), Some(tofid)) = (cert, cert_to) {
                if fs.put(tofid, &obj[..n.min(obj.len())]).is_err() {
                    blob.zeroize();
                    return Sw::MEMORY_FAILURE;
                }
            } else if let Some(tofid) = cert_to {
                let _ = fs.delete(tofid);
            }
            // Sized to read the full source record (head + any cached point).
            // The point is carried to the destination best-effort — kept when
            // EF_META has room, else dropped to the head alone (see meta_add_slot).
            let mut meta = [0u8; 4 + MAX_EC_POINT];
            if let Some(n) = fs.meta_find(key_fid(from).get(), &mut meta) {
                let n = n.min(meta.len());
                if let Err(e) = keygen::meta_add_slot(fs, key_fid(to).get(), &meta[..n]) {
                    blob.zeroize();
                    return e;
                }
            }
        }
        // Carry the cached public point to the destination slot (best-effort), then
        // drop the source's — MOVE relocates the whole slot. Skip the carry when
        // `to == 0xFF` (the delete sentinel): there is no destination slot, so a put
        // to `pubkey_fid(0xFF)` would only strand an unread `0xD4FF` orphan file.
        if to != 0xFF {
            let mut pk = [0u8; MAX_EC_POINT];
            if let Some(pn) = fs.read(pubkey_fid(from), &mut pk) {
                let _ = fs.put(pubkey_fid(to), &pk[..pn.min(pk.len())]);
            }
        }
        blob.zeroize();
        let _ = fs.delete_key(key_fid(from));
        let _ = fs.delete(pubkey_fid(from));
        if let Some(f) = cert_from {
            let _ = fs.delete(f);
        }
        let _ = fs.meta_delete(key_fid(from).get());
        Sw::OK
    }
}

/// Largest stored data-object body (certificate objects included); bounded so
/// the `53`-wrapped response fits the 2 KiB CCID response buffer.
const MAX_OBJECT: usize = 1900;

const RETRY_PIN: usize = 0;
const RETRY_PUK: usize = 2;

fn retries<S: Storage>(fs: &mut Fs<S>, idx: usize) -> Result<(u8, u8), Sw> {
    let mut r = [0u8; 4];
    let Some(4) = fs.read(EF_RETRIES, &mut r) else {
        return Err(Sw::REFERENCE_NOT_FOUND);
    };
    Ok((r[idx], r[idx + 1]))
}

fn retries_left<S: Storage>(fs: &mut Fs<S>, idx: usize) -> Result<u8, Sw> {
    retries(fs, idx).map(|(_, l)| l)
}

fn set_retries_left<S: Storage>(fs: &mut Fs<S>, idx: usize, left: u8) -> Result<(), Sw> {
    let mut r = [0u8; 4];
    let Some(4) = fs.read(EF_RETRIES, &mut r) else {
        return Err(Sw::REFERENCE_NOT_FOUND);
    };
    r[idx + 1] = left;
    fs.put(EF_RETRIES, &r).map_err(|_| Sw::MEMORY_FAILURE)
}

fn reset_counter<S: Storage>(fs: &mut Fs<S>, idx: usize) -> Sw {
    match retries(fs, idx) {
        Ok((total, _)) => match set_retries_left(fs, idx, total) {
            Ok(()) => Sw::OK,
            Err(sw) => sw,
        },
        Err(sw) => sw,
    }
}

fn stored_pin_len<S: Storage>(fs: &mut Fs<S>, fid: u16) -> Result<usize, Sw> {
    let mut rec = [0u8; PIN_REC_LEN];
    let Some(PIN_REC_LEN) = fs.read(fid, &mut rec) else {
        return Err(Sw::MEMORY_FAILURE);
    };
    Ok(rec[0] as usize)
}

/// Boot-pass migration: re-seal every sealed PIV key slot under the OTP kbase
/// (no-op without the OTP key). PIN/PUK verifiers migrate lazily at their own
/// verify instead — they are one-way derivations of the PIN.
pub fn migrate_kbase<S: Storage>(dev: &Device, fs: &mut Fs<S>, rng: &mut dyn Rng) {
    seal::migrate_kbase(dev, fs, rng)
}

/// Verify a PIN/PUK against its stored verifier, with the retry dance —
/// decrement on mismatch (`63Cx`, `6983` at zero), reset on success.
fn check_ref<S: Storage>(dev: &Device, fs: &mut Fs<S>, fid: u16, retry: usize, pin: &[u8]) -> Sw {
    let (total, left) = match retries(fs, retry) {
        Ok(t) => t,
        Err(sw) => return sw,
    };
    if left == 0 {
        return Sw::PIN_BLOCKED;
    }
    let mut rec = [0u8; PIN_REC_LEN];
    let Some(PIN_REC_LEN) = fs.read(fid, &mut rec) else {
        return Sw::MEMORY_FAILURE;
    };
    let ver = dev.pin_derive_verifier(pin);
    let mut matched = ct_eq(&ver, &rec[2..PIN_REC_LEN]);
    if !matched
        && dev.otp_key.is_some()
        && ct_eq(
            &dev.without_otp().pin_derive_verifier(pin),
            &rec[2..PIN_REC_LEN],
        )
    {
        // kbase-migration fallback: the correct PIN against a verifier stored
        // before the OTP key was provisioned — re-store it under the OTP arm
        // (sealed key slots migrate in the boot pass, not here).
        if put_pin_verifier(dev, fs, fid, pin).is_err() {
            return Sw::MEMORY_FAILURE;
        }
        matched = true;
    }
    if matched {
        if set_retries_left(fs, retry, total).is_err() {
            return Sw::MEMORY_FAILURE;
        }
        return Sw::OK;
    }
    let left = left - 1;
    if set_retries_left(fs, retry, left).is_err() {
        return Sw::MEMORY_FAILURE;
    }
    if left == 0 {
        Sw::PIN_BLOCKED
    } else {
        Sw::retries(left)
    }
}

/// Which PIV reference a change/verify targets — the application PIN or the PUK.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PinRef {
    Pin,
    Puk,
}

impl PinRef {
    fn fid_retry(self) -> (u16, usize) {
        match self {
            PinRef::Pin => (EF_PIN, RETRY_PIN),
            PinRef::Puk => (EF_PUK, RETRY_PUK),
        }
    }
}

/// Pad a collected numeric PIN/PUK (`1..=8` bytes) to the 8-byte PIV wire form
/// (trailing `0xFF`), matching ykman / yubico-piv-tool. On-device (panel) entry
/// MUST store the verifier over this padded form, or a host `VERIFY` — which
/// always pads — will not match. `None` for empty / over-long input.
pub fn pad_pin(entered: &[u8]) -> Option<[u8; PIN_WIRE_LEN]> {
    if entered.is_empty() || entered.len() > PIN_WIRE_LEN {
        return None;
    }
    let mut out = [0xFFu8; PIN_WIRE_LEN];
    out[..entered.len()].copy_from_slice(entered);
    Some(out)
}

/// Change a PIN or PUK: verify `old` (burns a retry on mismatch, exactly like the
/// CHANGE REFERENCE DATA APDU), then store `new`. Shared by that handler and the
/// on-device panel flow; panel callers pad both via [`pad_pin`] first so the
/// stored verifier matches the host's padded wire form.
pub fn change_reference<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    which: PinRef,
    old: &[u8],
    new: &[u8],
) -> Sw {
    if new.is_empty() || new.len() > PIN_WIRE_LEN {
        return Sw::WRONG_LENGTH;
    }
    let (fid, retry) = which.fid_retry();
    match check_ref(dev, fs, fid, retry, old) {
        Sw::OK => {}
        sw => return sw,
    }
    if put_pin_verifier(dev, fs, fid, new).is_err() {
        return Sw::MEMORY_FAILURE;
    }
    Sw::OK
}

/// Unblock the PIN with the PUK (RESET RETRY COUNTER): verify `puk`, set the PIN to
/// `new`, and reset the PIN retry counter. Shared by the APDU handler and the panel.
pub fn unblock_pin_with_puk<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    puk: &[u8],
    new: &[u8],
) -> Sw {
    if new.is_empty() || new.len() > PIN_WIRE_LEN {
        return Sw::WRONG_LENGTH;
    }
    match check_ref(dev, fs, EF_PUK, RETRY_PUK, puk) {
        Sw::OK => {}
        sw => return sw,
    }
    if put_pin_verifier(dev, fs, EF_PIN, new).is_err() {
        return Sw::MEMORY_FAILURE;
    }
    reset_counter(fs, RETRY_PIN)
}

/// Remaining verify attempts for the PIN or PUK — for on-panel status display.
pub fn reference_retries_left<S: Storage>(fs: &mut Fs<S>, which: PinRef) -> Option<u8> {
    let (_, retry) = which.fid_retry();
    retries_left(fs, retry).ok()
}

/// Verify the PIN or PUK against its stored verifier — the retry dance (burns an attempt on
/// mismatch → `63Cx` / `6983`, resets on success). For the on-panel change/unblock flows to
/// gate on the *current* secret before collecting the new one; the host VERIFY APDU stays
/// its own path. Callers mirroring the host wire pad via [`pad_pin`] first.
pub fn verify_reference<S: Storage>(dev: &Device, fs: &mut Fs<S>, which: PinRef, pin: &[u8]) -> Sw {
    let (fid, retry) = which.fid_retry();
    check_ref(dev, fs, fid, retry, pin)
}

/// Whether the management key is marked PIN-protected (the ADMIN-DATA `0x02`
/// flag). The PRINTED object only yields the key when this is set, so a default
/// or plain management key is never PIN-readable.
fn mgm_is_protected<S: Storage>(fs: &mut Fs<S>) -> bool {
    // Sized to hold a real ykman PivmanData (flags + 16-byte salt + 4-byte timestamp ≈ 29B);
    // `Storage::read` returns the value's FULL stored length, so clamp to the bytes we hold
    // before slicing — a larger record must not panic, and an unparsable one fails closed
    // (read as not protected), the safe direction.
    let mut obj = [0u8; 64];
    let Some(n) = fs.read(EF_PIVMAN_DATA, &mut obj) else {
        return false;
    };
    let body = &obj[..n.min(obj.len())];
    if body.len() < 2 || body[0] != PIVMAN_TAG {
        return false;
    }
    let inner_len = (body[1] as usize).min(body.len() - 2);
    matches!(
        find_tag(&body[2..2 + inner_len], PIVMAN_FLAGS_TAG as u16),
        Some(f) if !f.is_empty() && f[0] & PIVMAN_FLAG_MGM_PROTECTED != 0
    )
}

/// Revoke the PIN-readable escrow: clear the ADMIN-DATA `0x02` flag, carrying
/// the rest of the record forward ([`pivman_set_protected`] with the bit off).
/// A record without the flag is left untouched, so a host's PivmanData is only
/// rewritten when there is an escrow to revoke.
fn mgm_clear_protected<S: Storage>(fs: &mut Fs<S>) -> Result<(), Sw> {
    if !mgm_is_protected(fs) {
        return Ok(());
    }
    // Sized as in `mgm_is_protected`: a real ykman record (flags + salt + timestamp).
    let mut prior = [0u8; 64];
    let Some(n) = fs.read(EF_PIVMAN_DATA, &mut prior) else {
        return Ok(());
    };
    let mut admin = [0u8; PIVMAN_MAX];
    let len = pivman_rebuild(&prior[..n.min(prior.len())], false, &mut admin);
    fs.put(EF_PIVMAN_DATA, &admin[..len])
        .map_err(|_| Sw::MEMORY_FAILURE)
}

/// Replace the PIV management key with a fresh random AES-256 key and mark it
/// PIN-protected (the ykman `--protect` model): the key is sealed in the 0x9B
/// auth slot and the ADMIN-DATA flag is set, so a host reads it back from the
/// PRINTED object (`5FC109`) after a PIN VERIFY. The user never sees the key.
/// Shared by the on-panel "Protect management key" action — physical presence at
/// the trusted panel is the authorisation (no prior management-key auth).
///
/// SECURITY: after this, the PIV PIN **alone** grants management access (it
/// unlocks the random mgmt key), exactly as YubiKey's `--protect`. Caller-gated
/// behind the device PIN + a deliberate hold on the panel.
///
/// Power-cut ordering: the key+meta are written before the ADMIN flag, so a torn
/// write leaves the flag clear → PRINTED reads absent (fail-closed, no half-key
/// disclosure). Re-running this (or a PIV factory reset) recovers — it depends on
/// no prior state, just overwriting the slot.
///
/// The ADMIN-DATA record is rebuilt from any prior host-written one
/// ([`pivman_set_protected`]): the PIN-change timestamp and unrelated flag bits
/// survive, so on-panel protect no longer discards a host's PivmanData.
pub fn protect_mgm_key<S: Storage>(dev: &Device, fs: &mut Fs<S>, rng: &mut dyn Rng) -> Sw {
    // Read any existing PivmanData up front (before the writes below), so the new
    // record can carry its timestamp / flags forward.
    let mut prior_buf = [0u8; 64];
    let prior = match fs.read(EF_PIVMAN_DATA, &mut prior_buf) {
        Some(n) => &prior_buf[..n.min(prior_buf.len())],
        None => &[][..],
    };
    let mut admin = [0u8; PIVMAN_MAX];
    let admin_len = pivman_set_protected(prior, &mut admin);

    let mut key = [0u8; 32];
    rng.fill(&mut key);
    let sealed = seal::seal_put(dev, fs, rng, key_fid(SLOT_CARDMGM), &key);
    key.zeroize();
    if sealed.is_err() {
        return Sw::MEMORY_FAILURE;
    }
    // pin-policy NEVER matches a real YubiKey's protected mgmt key (9B is not
    // PIN-gated at the APDU level; `is_key(0x9B)` is false so auth ignores it).
    if fs
        .meta_add(
            key_fid(SLOT_CARDMGM).get(),
            &[ALGO_AES256, PINPOLICY_NEVER, TOUCHPOLICY_NEVER],
        )
        .is_err()
    {
        return Sw::MEMORY_FAILURE;
    }
    if fs.put(EF_PIVMAN_DATA, &admin[..admin_len]).is_err() {
        return Sw::MEMORY_FAILURE;
    }
    Sw::OK
}

/// Rebuild the PivmanData (ADMIN DATA) record with the MGM_PROTECTED flag forced
/// on. See [`pivman_rebuild`].
pub(crate) fn pivman_set_protected(prior: &[u8], out: &mut [u8; PIVMAN_MAX]) -> usize {
    pivman_rebuild(prior, true, out)
}

/// Rebuild the PivmanData (ADMIN DATA) record for the given PIN-protected-mgmt
/// state from an arbitrary `prior` record, writing the encoded object into `out`
/// and returning its length. The MGM_PROTECTED flag is forced to `protected`; any
/// other flag bits and the PIN-change timestamp (`0x83`) in `prior` are carried
/// forward; the derived-key salt (`0x82`) is deliberately dropped.
///
/// Dropping the salt mirrors ykman's `--protect`: once the management key is a
/// fresh random device-sealed key it is no longer derived from PIN+salt, so a
/// left-over salt would only mislead a host into the derivation path. A malformed
/// `prior` contributes nothing (flags default to 0, no timestamp) and never
/// panics — the record is always a well-formed `80 { 81 .. }`.
fn pivman_rebuild(prior: &[u8], protected: bool, out: &mut [u8; PIVMAN_MAX]) -> usize {
    // Parse the prior record's inner TLV run, if it is a `80 <len> { .. }`.
    let inner = if prior.len() >= 2 && prior[0] == PIVMAN_TAG {
        let l = (prior[1] as usize).min(prior.len() - 2);
        &prior[2..2 + l]
    } else {
        &[][..]
    };
    let prior_flags = find_tag(inner, PIVMAN_FLAGS_TAG as u16)
        .and_then(|f| f.first().copied())
        .unwrap_or(0);
    let flags = if protected {
        prior_flags | PIVMAN_FLAG_MGM_PROTECTED
    } else {
        prior_flags & !PIVMAN_FLAG_MGM_PROTECTED
    };
    let ts = find_tag(inner, PIVMAN_TS_TAG as u16)
        .map(|t| &t[..t.len().min(PIVMAN_TS_MAX)])
        .unwrap_or(&[]);

    // Body = 81 01 <flags> [83 <len> <ts>]; outer = 80 <body_len> <body>.
    let mut body = [0u8; 3 + 2 + PIVMAN_TS_MAX];
    let mut n = 0;
    body[n] = PIVMAN_FLAGS_TAG;
    body[n + 1] = 0x01;
    body[n + 2] = flags;
    n += 3;
    if !ts.is_empty() {
        body[n] = PIVMAN_TS_TAG;
        body[n + 1] = ts.len() as u8;
        body[n + 2..n + 2 + ts.len()].copy_from_slice(ts);
        n += 2 + ts.len();
    }
    out[0] = PIVMAN_TAG;
    out[1] = n as u8;
    out[2..2 + n].copy_from_slice(&body[..n]);
    2 + n
}

/// Constant-time slice equality (length public).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    rsk_crypto::ct_eq(a, b)
}

/// Append `tag { payload }` with a DER length to `res`.
pub(crate) fn push_tlv(res: &mut ResBuf, tag: u8, payload: &[u8]) -> Result<(), Sw> {
    let mut ll = [0u8; 3];
    let n = format_len(payload.len() as u16, &mut ll);
    if !res.push(tag) || !res.extend(&ll[..n]) || !res.extend(payload) {
        return Err(Sw::WRONG_LENGTH);
    }
    Ok(())
}

/// Build the GENERAL AUTHENTICATE response `7C { tag payload }`.
pub(crate) fn dyn_auth_resp(res: &mut ResBuf, tag: u8, payload: &[u8]) -> Result<(), Sw> {
    let mut ll = [0u8; 3];
    let inner = 1 + format_len(payload.len() as u16, &mut ll) as u16 + payload.len() as u16;
    let mut oll = [0u8; 3];
    let on = format_len(inner, &mut oll);
    if !res.push(TAG_DYN_AUTH) || !res.extend(&oll[..on]) {
        return Err(Sw::WRONG_LENGTH);
    }
    push_tlv(res, tag, payload)
}

/// Wrap a DER certificate as the Yubico certificate object
/// `70 { cert } 71 { 0 } FE { }` (uncompressed).
pub fn wrap_cert_object(cert: &[u8], out: &mut [u8]) -> usize {
    let mut p = 0;
    out[p] = 0x70;
    p += 1;
    let mut ll = [0u8; 3];
    let n = format_len(cert.len() as u16, &mut ll);
    out[p..p + n].copy_from_slice(&ll[..n]);
    p += n;
    out[p..p + cert.len()].copy_from_slice(cert);
    p += cert.len();
    out[p..p + 5].copy_from_slice(&[0x71, 0x01, 0x00, 0xFE, 0x00]);
    p + 5
}

/// Kani proof harnesses (`cargo kani -p rsk-piv`): exhaustive over every input up
/// to the stated bound, where the unit tests only sample.
#[cfg(kani)]
#[path = "kani.rs"]
mod proofs;

#[cfg(test)]
mod tests;
