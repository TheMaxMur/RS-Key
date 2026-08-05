// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! YKOATH applet — Yubico's OATH protocol over CCID: a credential store of HMAC
//! keys (SHA-1/SHA-256/SHA-512), CALCULATE / CALCULATE ALL for TOTP/HOTP, an
//! optional access code, and the Nitrokey OTP-PIN / password-safe extensions.

#![cfg_attr(not(test), no_std)]

mod seal;

use core::cell::RefCell;

use rsk_crypto::{Device, hmac_sha1, hmac_sha256, hmac_sha512};
use rsk_fs::{Fs, KeyFid, Storage};
pub use rsk_sdk::Confirm;
use rsk_sdk::tlv::{find_tag, format_len};
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};
use zeroize::Zeroize;

/// YKOATH applet AID.
pub const OATH_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

/// Version reported in the SELECT response — the shared
/// [`rsk_sdk::FIRMWARE_VERSION`]. ykman gates protocol features (rename, touch)
/// on this; the full 5.x set is implemented.
pub const VERSION: (u8, u8, u8) = rsk_sdk::FIRMWARE_VERSION;

/// Random-byte source for the VALIDATE challenge. Same shape as
/// `rsk_openpgp::Rng`; the firmware TRNG wrapper implements both.
pub trait Rng {
    fn fill(&mut self, buf: &mut [u8]);
}

/// Outcome of a touch request (credentials stored with `PROP_TOUCH`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    Confirmed,
    Timeout,
    Declined,
}

/// Physical user presence; the firmware backs this with the BOOTSEL button
/// (same shape as `rsk_openpgp::UserPresence`).
pub trait UserPresence {
    /// Ask for presence. `confirm` names the operation for a trusted on-screen
    /// Approve/Deny prompt; the BOOTSEL-button backend ignores it.
    fn request(&mut self, confirm: Confirm<'_>) -> Presence;
}

/// Test/no-button stand-in: confirms instantly.
pub struct AlwaysConfirm;

impl UserPresence for AlwaysConfirm {
    fn request(&mut self, _confirm: Confirm<'_>) -> Presence {
        Presence::Confirmed
    }
}

// FIDs.
const EF_OATH_CRED: u16 = 0xBA00; // 255 cred slots, 0xBA00..=0xBAFE (each a sealed KeyFid)
const EF_OATH_CODE: KeyFid = KeyFid::new(0xBAFF); // SET CODE validation key, sealed
/// Max stored access-code length. Bounds SET CODE so the code always fits the
/// VALIDATE read buffer — otherwise an over-long code makes `seal_read` fail and
/// (pre-fix) VALIDATE unlocked the applet without the code.
const OATH_CODE_MAX: usize = 128;
const EF_OTP_PIN: u16 = 0x10A0;

const MAX_OATH_CRED: u16 = 255;
const CHALLENGE_LEN: usize = 8;
const MAX_OTP_COUNTER: u8 = 3;
/// OTP-PIN record format tag. v1 = `[counter, 0x01, pin_derive_verifier(pin)]`
/// roots the verifier in the OTP MKEK (identical to the OpenPGP/PIV PINs), so a
/// flash-dump thief can no longer offline-brute-force it once the device is
/// provisioned. The legacy layout `[counter, double_hash_pin(pin)]` (33 B, no
/// tag) is a serial-only fast hash; it is recognised and upgraded to v1 on the
/// next successful VERIFY / CHANGE. See #35/#42 (pico-keys carryover).
const OTP_PIN_FMT_V1: u8 = 0x01;
/// `EF_OTP_PIN` record lengths: legacy `[counter, double_hash(32)]`, v1
/// `[counter, fmt, verifier(32)]`.
const OTP_PIN_REC_LEGACY: usize = 33;
const OTP_PIN_REC_V1: usize = 34;

// Data-object tags.
const TAG_NAME: u8 = 0x71;
const TAG_NAME_LIST: u8 = 0x72;
const TAG_KEY: u8 = 0x73;
const TAG_CHALLENGE: u8 = 0x74;
const TAG_RESPONSE: u8 = 0x75;
const TAG_NO_RESPONSE: u8 = 0x77;
const TAG_PROPERTY: u8 = 0x78;
const TAG_T_VERSION: u8 = 0x79;
const TAG_IMF: u8 = 0x7A;
const TAG_ALGO: u8 = 0x7B;
const TAG_TOUCH_RESPONSE: u8 = 0x7C;
const TAG_PASSWORD: u8 = 0x80;
const TAG_NEW_PASSWORD: u8 = 0x81;
const TAG_PWS_LOGIN: u8 = 0x83;
const TAG_PWS_PASSWORD: u8 = 0x84;
const TAG_PWS_METADATA: u8 = 0x85;

const ALG_HMAC_SHA1: u8 = 0x01;
const ALG_HMAC_SHA256: u8 = 0x02;
const ALG_HMAC_SHA512: u8 = 0x03;
const ALG_MASK: u8 = 0x0F;

const OATH_TYPE_HOTP: u8 = 0x10;
const OATH_TYPE_MASK: u8 = 0xF0;

const PROP_TOUCH: u8 = 0x02;

// Instructions.
const INS_PUT: u8 = 0x01;
const INS_DELETE: u8 = 0x02;
const INS_SET_CODE: u8 = 0x03;
const INS_RESET: u8 = 0x04;
const INS_RENAME: u8 = 0x05;
const INS_LIST: u8 = 0xA1;
const INS_CALCULATE: u8 = 0xA2;
const INS_VALIDATE: u8 = 0xA3;
const INS_CALC_ALL: u8 = 0xA4;
const INS_SEND_REMAINING: u8 = 0xA5;
const INS_VERIFY_CODE: u8 = 0xB1;
const INS_VERIFY_PIN: u8 = 0xB2;
const INS_CHANGE_PIN: u8 = 0xB3;
const INS_SET_PIN: u8 = 0xB4;
const INS_GET_CREDENTIAL: u8 = 0xB5;

/// "Wrong data" in this protocol is reported as `0x6700` (wrong length), which
/// is what clients expect.
const SW_WRONG_DATA: Sw = Sw::WRONG_LENGTH;

/// Max stored credential blob. Bounds the PUT/RENAME rebuild buffers and every
/// slot read; comfortably above anything real clients send (name ≤64, key ≤66,
/// three password-safe fields ≤255 each).
const CRED_MAX: usize = 1024;

/// In-progress LIST / CALCULATE ALL pagination. YKOATH streams a large response
/// via `61xx` + SEND REMAINING (0xA5); this records where to resume the stable
/// sorted present-cred sweep and the context needed to rebuild the next page.
/// Any command other than SEND REMAINING clears it.
#[derive(Clone, Copy)]
enum Chain {
    None,
    List {
        ext: bool,
    },
    CalcAll {
        p2: u8,
        chal: [u8; CHALLENGE_LEN],
        chal_len: u8,
    },
}

pub struct OathApplet<'a> {
    serial_id: [u8; 8],
    serial_hash: [u8; 32],
    /// The OTP MKEK, once provisioned. OATH stores nothing under kbase today;
    /// wired anyway so every applet shares one derivation truth.
    otp_key: Option<[u8; 32]>,
    rng: &'a RefCell<dyn Rng>,
    presence: &'a RefCell<dyn UserPresence>,
    /// Access-code session state. `true` when no code is set (everything
    /// allowed); with a code set, SELECT resets it and VALIDATE/VERIFY PIN
    /// flip it back.
    validated: bool,
    /// Challenge the host must answer in VALIDATE; regenerated on SELECT and
    /// SET CODE.
    challenge: [u8; CHALLENGE_LEN],
    /// LIST / CALCULATE ALL pagination cursor: the command context and the
    /// position in the sorted present-cred sweep to resume on SEND REMAINING.
    chain: Chain,
    chain_at: u16,
}

impl<'a> OathApplet<'a> {
    pub fn new(
        serial_id: [u8; 8],
        serial_hash: [u8; 32],
        otp_key: Option<[u8; 32]>,
        rng: &'a RefCell<dyn Rng>,
        presence: &'a RefCell<dyn UserPresence>,
    ) -> Self {
        Self {
            serial_id,
            serial_hash,
            otp_key,
            rng,
            presence,
            validated: true,
            challenge: [0; CHALLENGE_LEN],
            chain: Chain::None,
            chain_at: 0,
        }
    }

    fn device(&self) -> Device<'_> {
        Device {
            serial_hash: &self.serial_hash,
            serial_id: &self.serial_id,
            otp_key: self.otp_key.as_ref(),
        }
    }

    /// The 8-byte OATH device id — the salt ykman folds into its PBKDF2 access-code
    /// derivation. A one-way hash of `serial_hash` (sha256 of the full chip id), so
    /// it is stable across boots yet opaque like a real YubiKey's: not predictable
    /// from the semi-public device serial, and it does not expose `serial_hash`.
    fn serial_name(&self) -> [u8; 8] {
        let mut input = [0u8; 40];
        input[..8].copy_from_slice(b"rsk-oath");
        input[8..].copy_from_slice(&self.serial_hash);
        let mut out = [0u8; 8];
        out.copy_from_slice(&rsk_crypto::sha256(&input)[..8]);
        out
    }

    fn cmd_put<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        if !self.validated {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let data = &apdu.data[..apdu.nc];
        let (mut name, mut key, mut imf, mut prop) = (None, None, None, None);
        for (t, v) in PutIter::new(data) {
            // The stored-blob walkers (find_tag_range/PutIter) decode 1-byte tags;
            // reject the 2-byte tag form (tag&0x1f==0x1f) so a credential is never
            // re-read differently by the SDK Tlv walker. No OATH tag uses that form.
            if t & 0x1f == 0x1f {
                return Sw::INCORRECT_PARAMS;
            }
            match t {
                TAG_NAME if name.is_none() => name = Some(v),
                TAG_KEY if key.is_none() => key = Some(v),
                TAG_IMF if imf.is_none() => imf = Some(v),
                TAG_PROPERTY if prop.is_none() => prop = v.first().copied(),
                _ => {}
            }
        }
        let Some(key) = key else {
            return Sw::INCORRECT_PARAMS;
        };
        // key = [type|alg, digits, secret…]; must hold at least those 2 bytes.
        if key.len() < 2 {
            return Sw::INCORRECT_PARAMS;
        }
        let Some(name) = name else {
            return Sw::INCORRECT_PARAMS;
        };
        let hotp = key[0] & OATH_TYPE_MASK == OATH_TYPE_HOTP;

        // Rebuild in normalised form: NAME, KEY, PROPERTY as a real TLV, other
        // TLVs verbatim, and (HOTP) the IMF last, zero-padded to 8 bytes.
        let mut blob = [0u8; CRED_MAX];
        let mut n = 0;
        let mut ok = emit_tlv(&mut blob, &mut n, TAG_NAME, name);
        ok &= emit_tlv(&mut blob, &mut n, TAG_KEY, key);
        if let Some(p) = prop {
            ok &= emit_tlv(&mut blob, &mut n, TAG_PROPERTY, &[p]);
        }
        for (t, v) in PutIter::new(data) {
            match t {
                TAG_NAME | TAG_KEY | TAG_IMF | TAG_PROPERTY => {}
                _ => ok &= emit_tlv(&mut blob, &mut n, t, v),
            }
        }
        if hotp {
            let mut counter = [0u8; 8];
            match imf {
                // Short IMF values are left-padded (ykman sends 4 bytes).
                Some(v) if v.len() <= 8 => counter[8 - v.len()..].copy_from_slice(v),
                Some(v) => counter.copy_from_slice(&v[..8]),
                None => {}
            }
            ok &= emit_tlv(&mut blob, &mut n, TAG_IMF, &counter);
        } else if let Some(v) = imf {
            ok &= emit_tlv(&mut blob, &mut n, TAG_IMF, v);
        }
        if !ok {
            return Sw::FILE_FULL;
        }

        let mut scratch = [0u8; CRED_MAX];
        let dev = self.device();
        let fid = match find_cred(&dev, fs, name, &mut scratch) {
            Some((fid, _)) => fid,
            None => match free_slot(fs) {
                Some(fid) => fid,
                None => return Sw::FILE_FULL,
            },
        };
        if seal::seal_put(
            &dev,
            fs,
            &mut *self.rng.borrow_mut(),
            KeyFid::new(fid),
            &blob[..n],
        ) {
            Sw::OK
        } else {
            Sw::MEMORY_FAILURE
        }
    }

    fn cmd_delete<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        if !self.validated {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let Some(name) = find_tag(&apdu.data[..apdu.nc], TAG_NAME as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        let mut scratch = [0u8; CRED_MAX];
        let dev = self.device();
        match find_cred(&dev, fs, name, &mut scratch) {
            Some((fid, _)) => {
                let _ = fs.delete(fid);
                Sw::OK
            }
            None => Sw::DATA_INVALID,
        }
    }

    fn cmd_set_code<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        if !self.validated {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let data = &apdu.data[..apdu.nc];
        if data.is_empty() {
            let _ = fs.delete_key(EF_OATH_CODE);
            self.validated = true;
            return Sw::OK;
        }
        let Some(key) = find_tag(data, TAG_KEY as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        if key.is_empty() {
            let _ = fs.delete_key(EF_OATH_CODE);
            self.validated = true;
            return Sw::OK;
        }
        // The code must fit the VALIDATE read buffer, else it becomes unreadable
        // and (pre-fix) unlocked the applet without the code.
        if key.len() > OATH_CODE_MAX {
            return Sw::WRONG_LENGTH;
        }
        let Some(chal) = find_tag(data, TAG_CHALLENGE as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        let Some(resp) = find_tag(data, TAG_RESPONSE as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        // The host proves it knows the new code: response = HMAC(key, challenge).
        let mut mac = [0u8; 64];
        let Some(size) = oath_hmac(key[0], &key[1..], chal, &mut mac) else {
            return Sw::INCORRECT_PARAMS;
        };
        if !ct_eq(resp, &mac[..size]) {
            return Sw::DATA_INVALID;
        }
        self.rng.borrow_mut().fill(&mut self.challenge);
        let dev = self.device();
        if !seal::seal_put(&dev, fs, &mut *self.rng.borrow_mut(), EF_OATH_CODE, key) {
            return Sw::MEMORY_FAILURE;
        }
        // Installing a new access code drops any OTP-PIN: VERIFY PIN sets the same
        // `validated` flag as VALIDATE, so a PIN minted while the applet was open
        // would survive as a second, invisible unlock path for the store the owner
        // is protecting right now. Re-mint it from a session that knows this code.
        let _ = fs.delete(EF_OTP_PIN);
        self.validated = false;
        Sw::OK
    }

    fn cmd_reset<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        if apdu.p1 != 0xDE || apdu.p2 != 0xAD {
            return Sw::INCORRECT_P1P2;
        }
        // Prove the wipe rather than assume it. `present_creds` reads the in-RAM
        // present bitmap, which a boot scan truncated by a read fault leaves
        // *undecided* — so a live credential was skipped and the host still got
        // `9000` over a store that kept its TOTP secrets, the access code and the
        // OTP-PIN. PIV, OpenPGP and FIDO reset all enumerate through `for_each_key`,
        // honour its `complete` flag and propagate; this was the outlier (run-33).
        if let Err(sw) = wipe_oath(fs) {
            return sw;
        }
        self.validated = true;
        Sw::OK
    }

    fn cmd_list<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if !self.validated {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        // Extended list (nitropy): one data byte 0x01 appends a properties byte.
        let ext = apdu.nc == 1 && apdu.data[0] == 0x01;
        self.chain = Chain::List { ext };
        self.chain_at = 0;
        self.list_page(fs, res)
    }

    /// Emit LIST name entries from `self.chain_at` until the response frame fills.
    /// On overrun, stash the resume position and return `61xx` (SEND REMAINING
    /// continues here); otherwise clear the chain and return OK. The sweep order
    /// is the stable sorted present-cred list, so pages never skip or repeat.
    fn list_page<S: Storage>(&mut self, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        let Chain::List { ext } = self.chain else {
            return Sw::OK;
        };
        let start = self.chain_at as usize;
        let mut resume = None;
        {
            let dev = self.device();
            let mut fids = [0u16; MAX_OATH_CRED as usize];
            let nfids = present_creds(fs, &mut fids);
            let mut scratch = [0u8; CRED_MAX];
            let mut idx = start;
            while idx < nfids {
                let fid = fids[idx];
                idx += 1;
                let Some(n) = seal::seal_read(&dev, fs, KeyFid::new(fid), &mut scratch) else {
                    continue;
                };
                let blob = &scratch[..n.min(CRED_MAX)];
                let (Some(name), Some(key)) = (
                    find_tag(blob, TAG_NAME as u16),
                    find_tag(blob, TAG_KEY as u16),
                ) else {
                    continue;
                };
                if key.is_empty() || name.len() + 2 > 255 {
                    continue;
                }
                let entry = 2 + 1 + name.len() + ext as usize;
                if res.len() + entry > res.capacity() {
                    resume = Some(idx - 1);
                    break;
                }
                res.push(TAG_NAME_LIST);
                res.push((name.len() + 1 + ext as usize) as u8);
                res.push(key[0]);
                res.extend(name);
                if ext {
                    let mut props = 0u8;
                    if find_tag(blob, TAG_PWS_LOGIN as u16).is_some()
                        || find_tag(blob, TAG_PWS_PASSWORD as u16).is_some()
                        || find_tag(blob, TAG_PWS_METADATA as u16).is_some()
                    {
                        props |= 0x4;
                    }
                    if find_tag(blob, TAG_PROPERTY as u16)
                        .and_then(|v| v.first())
                        .is_some_and(|p| p & PROP_TOUCH != 0)
                    {
                        props |= 0x1;
                    }
                    res.push(props);
                }
            }
        }
        match resume {
            Some(at) => {
                self.chain_at = at as u16;
                Sw::BYTES_REMAINING_00
            }
            None => {
                self.chain = Chain::None;
                Sw::OK
            }
        }
    }

    fn cmd_validate<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        let data = &apdu.data[..apdu.nc];
        let Some(chal) = find_tag(data, TAG_CHALLENGE as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        let Some(resp) = find_tag(data, TAG_RESPONSE as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        let mut code = [0u8; OATH_CODE_MAX];
        let dev = self.device();
        // A present-but-unreadable code (over-long or corrupt) must keep the applet
        // LOCKED — a fail-open here unlocked it without the access code. A truly
        // absent code leaves the applet as select() set it (unlocked, no code).
        let Some(n) = seal::seal_read(&dev, fs, EF_OATH_CODE, &mut code) else {
            if fs.has_key(EF_OATH_CODE) {
                self.validated = false;
            }
            return Sw::DATA_INVALID;
        };
        let code = &code[..n.min(OATH_CODE_MAX)];
        if code.is_empty() {
            self.validated = false;
            return Sw::DATA_INVALID;
        }
        let mut mac = [0u8; 64];
        let Some(size) = oath_hmac(code[0], &code[1..], &self.challenge, &mut mac) else {
            return Sw::INCORRECT_PARAMS;
        };
        if !ct_eq(resp, &mac[..size]) {
            return Sw::DATA_INVALID;
        }
        // Mutual authentication: answer the host's challenge with the same key.
        let Some(size) = oath_hmac(code[0], &code[1..], chal, &mut mac) else {
            return Sw::INCORRECT_PARAMS;
        };
        self.validated = true;
        res.push(TAG_RESPONSE);
        res.push(size as u8);
        res.extend(&mac[..size]);
        Sw::OK
    }

    fn cmd_calculate<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if apdu.p2 != 0x00 && apdu.p2 != 0x01 {
            return Sw::INCORRECT_P1P2;
        }
        if !self.validated {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let data = &apdu.data[..apdu.nc];
        let Some(chal) = find_tag(data, TAG_CHALLENGE as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        let Some(name) = find_tag(data, TAG_NAME as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        let mut scratch = [0u8; CRED_MAX];
        let dev = self.device();
        let Some((fid, n)) = find_cred(&dev, fs, name, &mut scratch) else {
            return Sw::DATA_INVALID;
        };
        let blob = &scratch[..n];
        let Some(key) = find_tag(blob, TAG_KEY as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        if key.len() < 2 {
            return Sw::INCORRECT_PARAMS;
        }
        // Touch-flagged credentials compute only after a confirmed press —
        // gated here, before the HOTP counter burns.
        if find_tag(blob, TAG_PROPERTY as u16)
            .and_then(|v| v.first())
            .is_some_and(|p| p & PROP_TOUCH != 0)
            && self
                .presence
                .borrow_mut()
                .request(Confirm::titled("Show OATH code?"))
                != Presence::Confirmed
        {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let hotp = key[0] & OATH_TYPE_MASK == OATH_TYPE_HOTP;
        // HOTP ignores the host challenge: the stored 8-byte counter is the
        // moving factor.
        let imf = if hotp {
            match find_tag_range(blob, TAG_IMF) {
                Some(r) if r.len() >= 8 => Some(r),
                _ => return Sw::INCORRECT_PARAMS,
            }
        } else {
            None
        };
        res.push(TAG_RESPONSE + apdu.p2);
        let chal_eff = match &imf {
            Some(r) => &blob[r.start..r.start + 8],
            None => chal,
        };
        if calculate(apdu.p2 == 0x01, key, chal_eff, res).is_none() {
            return Sw::EXEC_ERROR;
        }
        if let Some(r) = imf {
            // Bump the counter and persist the updated blob.
            let mut counter = [0u8; 8];
            counter.copy_from_slice(&scratch[r.start..r.start + 8]);
            let v = u64::from_be_bytes(counter).wrapping_add(1);
            scratch[r.start..r.start + 8].copy_from_slice(&v.to_be_bytes());
            if !seal::seal_put(
                &dev,
                fs,
                &mut *self.rng.borrow_mut(),
                KeyFid::new(fid),
                &scratch[..n],
            ) {
                return Sw::MEMORY_FAILURE;
            }
        }
        Sw::OK
    }

    fn cmd_calculate_all<S: Storage>(
        &mut self,
        apdu: &Apdu,
        fs: &mut Fs<S>,
        res: &mut ResBuf,
    ) -> Sw {
        if apdu.p2 != 0x00 && apdu.p2 != 0x01 {
            return Sw::INCORRECT_P1P2;
        }
        if !self.validated {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let Some(chal) = find_tag(&apdu.data[..apdu.nc], TAG_CHALLENGE as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        // Stash the (8-byte, per YKOATH) time challenge so SEND REMAINING pages
        // recompute the same codes; a longer challenge is clamped (spec is 8).
        let mut chal_buf = [0u8; CHALLENGE_LEN];
        let chal_len = chal.len().min(CHALLENGE_LEN);
        chal_buf[..chal_len].copy_from_slice(&chal[..chal_len]);
        self.chain = Chain::CalcAll {
            p2: apdu.p2,
            chal: chal_buf,
            chal_len: chal_len as u8,
        };
        self.chain_at = 0;
        self.calc_all_page(fs, res)
    }

    /// Emit CALCULATE ALL entries from `self.chain_at` until the frame fills
    /// (each reserves the 64-byte worst-case response), paging via `61xx` /
    /// SEND REMAINING exactly like [`Self::list_page`].
    fn calc_all_page<S: Storage>(&mut self, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        let Chain::CalcAll {
            p2,
            chal: chal_buf,
            chal_len,
        } = self.chain
        else {
            return Sw::OK;
        };
        let chal = &chal_buf[..chal_len as usize];
        let start = self.chain_at as usize;
        let mut resume = None;
        {
            let dev = self.device();
            let mut fids = [0u16; MAX_OATH_CRED as usize];
            let nfids = present_creds(fs, &mut fids);
            let mut scratch = [0u8; CRED_MAX];
            let mut idx = start;
            while idx < nfids {
                let fid = fids[idx];
                idx += 1;
                let Some(n) = seal::seal_read(&dev, fs, KeyFid::new(fid), &mut scratch) else {
                    continue;
                };
                let blob = &scratch[..n.min(CRED_MAX)];
                let (Some(name), Some(key)) = (
                    find_tag(blob, TAG_NAME as u16),
                    find_tag(blob, TAG_KEY as u16),
                ) else {
                    continue;
                };
                if key.len() < 2 || name.len() > 255 {
                    continue;
                }
                // Worst-case entry: name TLV + full-response TLV (64 + digits).
                if res.len() + 2 + name.len() + 2 + 65 > res.capacity() {
                    resume = Some(idx - 1);
                    break;
                }
                res.push(TAG_NAME);
                res.push(name.len() as u8);
                res.extend(name);
                if key[0] & OATH_TYPE_MASK == OATH_TYPE_HOTP {
                    // HOTP is never computed in bulk (it would burn counters).
                    res.push(TAG_NO_RESPONSE);
                    res.push(1);
                    res.push(key[1]);
                } else if find_tag(blob, TAG_PROPERTY as u16)
                    .and_then(|v| v.first())
                    .is_some_and(|p| p & PROP_TOUCH != 0)
                {
                    res.push(TAG_TOUCH_RESPONSE);
                    res.push(1);
                    res.push(key[1]);
                } else {
                    res.push(TAG_RESPONSE + p2);
                    if calculate(p2 == 0x01, key, chal, res).is_none() {
                        // Unknown algorithm: emit the digits byte only.
                        res.push(1);
                        res.push(key[1]);
                    }
                }
            }
        }
        match resume {
            Some(at) => {
                self.chain_at = at as u16;
                Sw::BYTES_REMAINING_00
            }
            None => {
                self.chain = Chain::None;
                Sw::OK
            }
        }
    }

    fn cmd_verify_code<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        // Same access-code gate as every other stored-data command: a locked applet
        // must not answer VERIFY CODE, which would be a replayable oracle on the
        // primary credential's current OTP across the access-code boundary.
        if !self.validated {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let data = &apdu.data[..apdu.nc];
        if find_tag(data, TAG_NAME as u16).is_none() {
            return Sw::INCORRECT_PARAMS;
        }
        // The named credential is ignored — slot 0 is always the one verified.
        let mut scratch = [0u8; CRED_MAX];
        let dev = self.device();
        let Some(n) = seal::seal_read(&dev, fs, KeyFid::new(EF_OATH_CRED), &mut scratch) else {
            return Sw::DATA_INVALID;
        };
        let blob = &scratch[..n.min(CRED_MAX)];
        let Some(key) = find_tag(blob, TAG_KEY as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        if key.len() < 2 {
            return Sw::INCORRECT_PARAMS;
        }
        if key[0] & OATH_TYPE_MASK != OATH_TYPE_HOTP {
            return Sw::DATA_INVALID;
        }
        // A touch-flagged credential is exercised only after a confirmed press —
        // else VERIFY CODE is a presence-free guessing oracle on its current OTP,
        // the same reason cmd_calculate gates here.
        if find_tag(blob, TAG_PROPERTY as u16)
            .and_then(|v| v.first())
            .is_some_and(|p| p & PROP_TOUCH != 0)
            && self
                .presence
                .borrow_mut()
                .request(Confirm::titled("Verify OATH code?"))
                != Presence::Confirmed
        {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let Some(imf) = find_tag(blob, TAG_IMF as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        if imf.len() < 8 {
            return Sw::INCORRECT_PARAMS;
        }
        let code_int = match find_tag(data, TAG_RESPONSE as u16) {
            Some(v) if v.len() >= 4 => u32::from_be_bytes([v[0], v[1], v[2], v[3]]),
            Some(_) => return Sw::INCORRECT_PARAMS,
            None => 0,
        };
        let mut mac = [0u8; 64];
        let Some(size) = oath_hmac(key[0], &key[2..], &imf[..8], &mut mac) else {
            return Sw::EXEC_ERROR;
        };
        let off = (mac[size - 1] & 0xF) as usize;
        let trunc = u32::from_be_bytes([mac[off] & 0x7F, mac[off + 1], mac[off + 2], mac[off + 3]]);
        let modulus = if key[1] == 6 { 1_000_000 } else { 100_000_000 };
        if trunc % modulus != code_int {
            return SW_WRONG_DATA;
        }
        Sw::OK
    }

    fn cmd_rename<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        if !self.validated {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let data = &apdu.data[..apdu.nc];
        if data.first() != Some(&TAG_NAME) {
            return SW_WRONG_DATA;
        }
        // Two TAG_NAME TLVs back to back: current name, then the new one.
        let mut names = PutIter::new(data).filter(|(t, _)| *t == TAG_NAME);
        let (Some((_, name)), Some((_, new_name))) = (names.next(), names.next()) else {
            return SW_WRONG_DATA;
        };
        if name == new_name {
            return SW_WRONG_DATA;
        }
        let mut scratch = [0u8; CRED_MAX];
        let dev = self.device();
        let Some((fid, n)) = find_cred(&dev, fs, name, &mut scratch) else {
            return Sw::DATA_INVALID;
        };
        // Rebuild the blob with the name TLV replaced in place.
        let mut blob = [0u8; CRED_MAX];
        let mut bn = 0;
        let mut replaced = false;
        let mut ok = true;
        for (t, v) in rsk_sdk::tlv::Tlv::new(&scratch[..n]) {
            if t == TAG_NAME as u16 && !replaced {
                ok &= emit_tlv(&mut blob, &mut bn, TAG_NAME, new_name);
                replaced = true;
            } else {
                ok &= emit_tlv(&mut blob, &mut bn, t as u8, v);
            }
        }
        if !ok {
            return Sw::FILE_FULL;
        }
        if seal::seal_put(
            &dev,
            fs,
            &mut *self.rng.borrow_mut(),
            KeyFid::new(fid),
            &blob[..bn],
        ) {
            Sw::OK
        } else {
            Sw::MEMORY_FAILURE
        }
    }

    fn cmd_get_credential<S: Storage>(
        &mut self,
        apdu: &Apdu,
        fs: &mut Fs<S>,
        res: &mut ResBuf,
    ) -> Sw {
        // Gated on validation: this returns stored password-safe secrets.
        if !self.validated {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let data = &apdu.data[..apdu.nc];
        if data.len() < 3 {
            return Sw::INCORRECT_PARAMS;
        }
        if data[0] != TAG_NAME {
            return SW_WRONG_DATA;
        }
        let Some(name) = find_tag(data, TAG_NAME as u16) else {
            return SW_WRONG_DATA;
        };
        let mut scratch = [0u8; CRED_MAX];
        let dev = self.device();
        let Some((_, n)) = find_cred(&dev, fs, name, &mut scratch) else {
            return Sw::DATA_INVALID;
        };
        let blob = &scratch[..n];
        for tag in [
            TAG_NAME,
            TAG_PWS_LOGIN,
            TAG_PWS_PASSWORD,
            TAG_PWS_METADATA,
            TAG_PROPERTY,
        ] {
            if let Some(v) = find_tag(blob, tag as u16)
                && v.len() <= 255
                && res.len() + 2 + v.len() <= res.capacity()
            {
                res.push(tag);
                res.push(v.len() as u8);
                res.extend(v);
            }
        }
        Sw::OK
    }

    /// Constant-time check of a presented OTP-PIN `pw` against a stored record.
    /// Handles both the v1 OTP-rooted verifier and the legacy serial-only double
    /// hash (which [`Self::cmd_verify_otp_pin`] / [`Self::cmd_change_otp_pin`]
    /// upgrade to v1 on success).
    fn otp_pin_matches(&self, rec: &[u8], pw: &[u8]) -> bool {
        let dev = self.device();
        match rec.len() {
            OTP_PIN_REC_V1 if rec[1] == OTP_PIN_FMT_V1 => {
                let stored = &rec[2..OTP_PIN_REC_V1];
                ct_eq(&dev.pin_derive_verifier(pw), stored)
                    // kbase-migration fallback: a v1 verifier stored before the
                    // OTP key was provisioned. On a match the caller re-stores it
                    // under the OTP arm (verify/change rewrite v1 on success), so
                    // the PIN survives an OTP burn — mirrors the PIV/OpenPGP/FIDO
                    // PIN checks. Without this the legacy double_hash_pin was
                    // serial-only and burn-immune; v1 must not regress that.
                    || (dev.otp_key.is_some()
                        && ct_eq(&dev.without_otp().pin_derive_verifier(pw), stored))
            }
            OTP_PIN_REC_LEGACY => ct_eq(&dev.double_hash_pin(pw), &rec[1..OTP_PIN_REC_LEGACY]),
            _ => false,
        }
    }

    /// A fresh v1 record: `[MAX_OTP_COUNTER, 0x01, pin_derive_verifier(pw)]`.
    fn otp_pin_record_v1(&self, pw: &[u8]) -> [u8; OTP_PIN_REC_V1] {
        let mut rec = [0u8; OTP_PIN_REC_V1];
        rec[0] = MAX_OTP_COUNTER;
        rec[1] = OTP_PIN_FMT_V1;
        rec[2..].copy_from_slice(&self.device().pin_derive_verifier(pw));
        rec
    }

    fn cmd_set_otp_pin<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        // Setting the OTP-PIN mints an unlock secret; a locked (access-code)
        // applet must be validated first, else an unauthenticated host could
        // create the very PIN that unlocks the store.
        if !self.validated {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        // On a code-less applet select() leaves validated=true unconditionally, so
        // it proves nothing and this command is otherwise unauthenticated: a host
        // could plant a PIN on a factory-state key and unlock the store later,
        // through the access code the owner sets afterwards. Require the operator.
        if !fs.has_key(EF_OATH_CODE)
            && self
                .presence
                .borrow_mut()
                .request(Confirm::titled("Set OATH PIN?"))
                != Presence::Confirmed
        {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        if fs.has_data(EF_OTP_PIN) {
            return Sw::CONDITIONS_NOT_SATISFIED;
        }
        let Some(pw) = find_tag(&apdu.data[..apdu.nc], TAG_PASSWORD as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        match fs.put(EF_OTP_PIN, &self.otp_pin_record_v1(pw)) {
            Ok(()) => Sw::OK,
            Err(_) => Sw::MEMORY_FAILURE,
        }
    }

    /// Persist one retry decrement and confirm it stuck before an OTP-PIN compare,
    /// so a glitched or failed flash program can't widen the limiter (mirrors the
    /// FIDO clientPIN spend_and_verify_pin_hash read-back). `false` = fail closed, no compare.
    fn spend_otp_retry<S: Storage>(fs: &mut Fs<S>, rec: &mut [u8], size: usize) -> bool {
        rec[0] = rec[0].saturating_sub(1);
        if fs.put(EF_OTP_PIN, &rec[..size]).is_err() {
            return false;
        }
        let mut back = [0u8; OTP_PIN_REC_V1];
        matches!(
            fs.read(EF_OTP_PIN, &mut back),
            Some(n) if n == size && back[0] == rec[0]
        )
    }

    /// The single OTP-PIN attempt chokepoint shared by VERIFY and CHANGE. Refuses
    /// once the retry counter is exhausted (`rec[0] == 0`) so neither path can turn
    /// the saturating floor into an unlimited guessing oracle (run-3 #2 / run-6);
    /// legitimate recovery after lock-out is RESET, not more guesses. Spends the
    /// retry (persist + read-back) before the constant-time compare so a glitched
    /// or failed flash program can't widen the limiter. Ok(()) only on a real match;
    /// the caller resets the counter on success. This is the sole caller of
    /// `spend_otp_retry`, so a future command cannot reintroduce the gap by forgetting the gate.
    fn spend_and_match_otp_pin<S: Storage>(
        &self,
        fs: &mut Fs<S>,
        rec: &mut [u8],
        size: usize,
        pw: &[u8],
    ) -> Result<(), Sw> {
        if rec[0] == 0 {
            return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        if !Self::spend_otp_retry(fs, rec, size) {
            return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        if !self.otp_pin_matches(&rec[..size], pw) {
            return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        Ok(())
    }

    fn cmd_change_otp_pin<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        let mut rec = [0u8; OTP_PIN_REC_V1];
        let size = match fs.read(EF_OTP_PIN, &mut rec) {
            Some(n) if (OTP_PIN_REC_LEGACY..=OTP_PIN_REC_V1).contains(&n) => n,
            _ => return Sw::CONDITIONS_NOT_SATISFIED,
        };
        let data = &apdu.data[..apdu.nc];
        let Some(pw) = find_tag(data, TAG_PASSWORD as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        let Some(new_pw) = find_tag(data, TAG_NEW_PASSWORD as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        // Same anti-bruteforce gate as VERIFY: refuse at the counter floor. After a
        // lock-out even a correct old-PIN cannot CHANGE (that floor "recovery" was
        // the run-6 unlimited-guessing oracle); recover with RESET instead.
        if let Err(sw) = self.spend_and_match_otp_pin(fs, &mut rec, size, pw) {
            return sw;
        }
        match fs.put(EF_OTP_PIN, &self.otp_pin_record_v1(new_pw)) {
            Ok(()) => Sw::OK,
            Err(_) => Sw::MEMORY_FAILURE,
        }
    }

    fn cmd_verify_otp_pin<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        let mut rec = [0u8; OTP_PIN_REC_V1];
        let size = match fs.read(EF_OTP_PIN, &mut rec) {
            Some(n) if (OTP_PIN_REC_LEGACY..=OTP_PIN_REC_V1).contains(&n) => n,
            _ => return Sw::CONDITIONS_NOT_SATISFIED,
        };
        let Some(pw) = find_tag(&apdu.data[..apdu.nc], TAG_PASSWORD as u16) else {
            return Sw::INCORRECT_PARAMS;
        };
        // Any attempt clears a prior unlock; only a correct PIN re-validates below.
        self.validated = false;
        // Shared anti-bruteforce chokepoint: refuse at the counter floor, spend the
        // retry (persist + read-back), then constant-time compare.
        if let Err(sw) = self.spend_and_match_otp_pin(fs, &mut rec, size, pw) {
            return sw;
        }
        // Success: reset the counter and (lazily) upgrade a legacy record to the
        // OTP-rooted v1 verifier. The OTP PIN doubles as VALIDATE (nitropy flow).
        let _ = fs.put(EF_OTP_PIN, &self.otp_pin_record_v1(pw));
        // The record just superseded may have been keyed under the pre-OTP arm,
        // which the public chip serial derives. Re-arm the one-shot at-rest lap
        // (rsk-fs `EF_HARDENED` invariant; audit run-35).
        rsk_fs::request_rescrub(fs);
        self.validated = true;
        Sw::OK
    }
}

impl<S: Storage> Applet<Fs<S>> for OathApplet<'_> {
    fn aid(&self) -> &'static [u8] {
        OATH_AID
    }

    /// Drop the VALIDATE result on deselect / card reset, so a later session must
    /// present the access code again rather than inheriting an unlocked store.
    /// `select` recomputes `validated` from whether a code is set.
    fn deselect(&mut self, _fs: &mut Fs<S>) {
        self.validated = false;
        self.chain = Chain::None;
    }

    /// SELECT response: version + device id, plus a fresh challenge (and its
    /// algorithm) when an access code is set.
    fn select(&mut self, _reselect: bool, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        let (maj, min, patch) = VERSION;
        res.push(TAG_T_VERSION);
        res.push(3);
        res.push(maj);
        res.push(min);
        res.push(patch);
        res.push(TAG_NAME);
        res.push(8);
        res.extend(&self.serial_name());
        let code_set = fs.has_key(EF_OATH_CODE);
        if code_set {
            self.rng.borrow_mut().fill(&mut self.challenge);
            res.push(TAG_CHALLENGE);
            res.push(CHALLENGE_LEN as u8);
            res.extend(&self.challenge);
            res.push(TAG_ALGO);
            res.push(1);
            res.push(ALG_HMAC_SHA1);
        }
        // A new SELECT abandons any pending LIST / CALCULATE ALL page.
        self.chain = Chain::None;
        // With a code set, every new SELECT must start locked: protected
        // commands work only after VALIDATE (or VERIFY PIN).
        self.validated = !code_set;
        Sw::OK
    }

    fn process(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if apdu.cla != 0x00 {
            return Sw::CLA_NOT_SUPPORTED;
        }
        // A fresh command abandons any half-read LIST / CALCULATE ALL page; only
        // SEND REMAINING continues one.
        if apdu.ins != INS_SEND_REMAINING {
            self.chain = Chain::None;
        }
        match apdu.ins {
            INS_PUT => self.cmd_put(apdu, fs),
            INS_DELETE => self.cmd_delete(apdu, fs),
            INS_SET_CODE => self.cmd_set_code(apdu, fs),
            INS_RESET => self.cmd_reset(apdu, fs),
            INS_RENAME => self.cmd_rename(apdu, fs),
            INS_LIST => self.cmd_list(apdu, fs, res),
            INS_CALCULATE => self.cmd_calculate(apdu, fs, res),
            INS_VALIDATE => self.cmd_validate(apdu, fs, res),
            INS_CALC_ALL => self.cmd_calculate_all(apdu, fs, res),
            // YKOATH response chaining: continue the LIST / CALCULATE ALL page
            // whose previous frame returned 61xx. No pending page => empty OK.
            INS_SEND_REMAINING => match self.chain {
                Chain::List { .. } => self.list_page(fs, res),
                Chain::CalcAll { .. } => self.calc_all_page(fs, res),
                Chain::None => Sw::OK,
            },
            INS_VERIFY_CODE => self.cmd_verify_code(apdu, fs),
            INS_VERIFY_PIN => self.cmd_verify_otp_pin(apdu, fs),
            INS_CHANGE_PIN => self.cmd_change_otp_pin(apdu, fs),
            INS_SET_PIN => self.cmd_set_otp_pin(apdu, fs),
            INS_GET_CREDENTIAL => self.cmd_get_credential(apdu, fs, res),
            _ => Sw::INS_NOT_SUPPORTED,
        }
    }
}

/// HMAC with the credential's algorithm nibble; returns the digest size.
fn oath_hmac(alg: u8, key: &[u8], msg: &[u8], out: &mut [u8; 64]) -> Option<usize> {
    match alg & ALG_MASK {
        ALG_HMAC_SHA1 => {
            out[..20].copy_from_slice(&hmac_sha1(key, msg));
            Some(20)
        }
        ALG_HMAC_SHA256 => {
            out[..32].copy_from_slice(&hmac_sha256(key, msg));
            Some(32)
        }
        ALG_HMAC_SHA512 => {
            out[..64].copy_from_slice(&hmac_sha512(key, msg));
            Some(64)
        }
        _ => None,
    }
}

/// Append `[len][digits][code]` to `res` — the RFC 4226 dynamic truncation
/// when `truncate`, the full HMAC otherwise. The caller has already pushed the
/// response tag. `key` = `[type|alg, digits, secret…]`.
fn calculate(truncate: bool, key: &[u8], chal: &[u8], res: &mut ResBuf) -> Option<()> {
    let mut mac = [0u8; 64];
    let size = oath_hmac(key[0], &key[2..], chal, &mut mac)?;
    if truncate {
        res.push(4 + 1);
        res.push(key[1]);
        let off = (mac[size - 1] & 0xF) as usize;
        res.push(mac[off] & 0x7F);
        res.push(mac[off + 1]);
        res.push(mac[off + 2]);
        res.push(mac[off + 3]);
    } else {
        res.push((size + 1) as u8);
        res.push(key[1]);
        res.extend(&mac[..size]);
    }
    Some(())
}

/// FIDs of every present OATH credential (slots `EF_OATH_CRED..`), in ascending
/// FID order; returns the count written to `out`. Reads occupancy straight from
/// the in-RAM present index via [`rsk_fs::Fs::present_slots`] — O(255) bit tests,
/// no flash access — instead of a whole-partition [`for_each_key`] scan on every
/// LIST / CALCULATE ALL (which cost tens of ms on a busy store: the exact
/// anti-pattern fixed for FIDO's `slot_map`). Occupancy-equivalent — both derive
/// from the boot [`scan`](rsk_fs::Fs::scan) seed kept live by every put/delete —
/// and ascending by construction, so enumeration output stays byte-identical to
/// the old sorted `for_each_key` sweep. A stale present bit at worst costs one
/// skipped `seal_read` at the call site; the absent direction keeps the bulk
/// pass's torn-migration semantics (no new false-absent).
///
/// [`for_each_key`]: rsk_fs::Fs::for_each_key
fn present_creds<S: Storage>(fs: &mut Fs<S>, out: &mut [u16; MAX_OATH_CRED as usize]) -> usize {
    let mut occ = [false; MAX_OATH_CRED as usize];
    fs.present_slots(EF_OATH_CRED, &mut occ);
    let mut n = 0;
    for (i, &present) in occ.iter().enumerate() {
        if present {
            out[n] = EF_OATH_CRED + i as u16;
            n += 1;
        }
    }
    n
}

/// The 255 credential slots — everything the access code exists to protect.
fn is_oath_cred_fid(fid: u16) -> bool {
    (EF_OATH_CRED..EF_OATH_CODE.get()).contains(&fid)
}

/// The two records that gate access: the access-code key and the OTP-PIN. Kept
/// separate from [`is_oath_cred_fid`] so [`wipe_oath`] can delete them last.
fn is_oath_lock_fid(fid: u16) -> bool {
    fid == EF_OATH_CODE.get() || fid == EF_OTP_PIN
}

/// Progress backstop for [`sweep`]: every batched `force_delete` clears one
/// *distinct* live fid and the two predicates span 257 of them between them, so
/// needing more deletes than that means the backend keeps re-yielding what it
/// removed.
const RESET_MAX_DELETES: u32 = 257;

/// Delete every live OATH record, and say so only when the sweep provably
/// completed. Mirrors `rsk_piv::files::wipe_piv`: batched because `for_each_key`
/// cannot delete mid-iteration, de-duped because it yields one entry per stored
/// *version*, and `force_delete` so a present-cache false-absent cannot loop.
fn wipe_oath<S: Storage>(fs: &mut Fs<S>) -> Result<(), Sw> {
    // Two phases, and the order carries the security property. `for_each_key`
    // yields in flash-ring (write) order, not FID order, so one combined sweep can
    // reach the access code before the credentials — and a power cut there leaves
    // the credentials live behind no lock at all, since `select` derives
    // `validated` from `!code_set`. Credentials first, proven empty, then the
    // unlock records.
    sweep(fs, is_oath_cred_fid)?;
    sweep(fs, is_oath_lock_fid)
}

/// One phase of [`wipe_oath`]: delete every live fid matching `pred`, reporting
/// success only when the enumeration provably completed over an empty range.
fn sweep<S: Storage>(fs: &mut Fs<S>, pred: fn(u16) -> bool) -> Result<(), Sw> {
    let mut deleted = 0u32;
    loop {
        let mut fids = [0u16; 32];
        let mut n = 0;
        let complete = fs.for_each_key(&mut |fid| {
            if pred(fid) && n < fids.len() && !fids[..n].contains(&fid) {
                fids[n] = fid;
                n += 1;
            }
        });
        if n == 0 {
            // A truncated walk (flash read fault) can hide a live fid, so an empty
            // batch only proves the range is clear when the enumeration completed.
            return if complete {
                Ok(())
            } else {
                Err(Sw::MEMORY_FAILURE)
            };
        }
        deleted += n as u32;
        if deleted > RESET_MAX_DELETES {
            return Err(Sw::MEMORY_FAILURE);
        }
        for &fid in &fids[..n] {
            fs.force_delete(fid).map_err(|_| Sw::MEMORY_FAILURE)?;
        }
    }
}

/// One stored credential's public metadata, unsealed for the trusted display.
/// The secret HMAC key is never surfaced — only its type/hash byte is decoded.
pub struct OathCredView<'a> {
    /// Credential label (issuer:account), with any `<period>/` prefix stripped;
    /// sanitise before display.
    pub name: &'a [u8],
    /// HOTP (event-based) when set, else TOTP (time-based).
    pub hotp: bool,
    /// HMAC hash algorithm (`ALG_HMAC_SHA1/256/512`, the key byte's low nibble).
    pub algo: u8,
    /// Code length (digits).
    pub digits: u8,
    /// TOTP step in seconds (from the `<period>/` name prefix, default 30); `0`
    /// for HOTP (counter-based, no period).
    pub period: u16,
    /// Whether the credential is touch-gated.
    pub touch: bool,
}

/// Split a Yubico OATH credential id into its optional `<period>/` prefix and the
/// bare `issuer:account` label. A TOTP credential whose step is not the default 30 s
/// is stored as `"<period>/issuer:account"`; the default-30 case carries no prefix.
/// Returns `(period, label)` — `period` is `None` when there is no numeric prefix.
fn split_period(name: &[u8]) -> (Option<u16>, &[u8]) {
    let mut i = 0;
    while i < name.len() && i < 4 && name[i].is_ascii_digit() {
        i += 1;
    }
    if i > 0 && name.get(i) == Some(&b'/') {
        let period = name[..i]
            .iter()
            .fold(0u16, |p, &d| p * 10 + (d - b'0') as u16);
        (Some(period), &name[i + 1..])
    } else {
        (None, name)
    }
}

/// A short ASCII label for an OATH hash algorithm (the key byte's low nibble).
pub fn algo_name(algo: u8) -> &'static str {
    match algo {
        ALG_HMAC_SHA1 => "SHA1",
        ALG_HMAC_SHA256 => "SHA256",
        ALG_HMAC_SHA512 => "SHA512",
        _ => "?",
    }
}

/// Visit every stored credential's public metadata for the trusted display,
/// returning the count. Each credential is device-unsealed (no PIN, no SET-CODE
/// gate) into a scratch buffer the callback borrows for the call; the scratch —
/// which holds the secret key bytes — is zeroized before returning, and the view
/// exposes only name / type / algorithm / digits / touch. No code is computed
/// (the device has no clock for TOTP, and HOTP would mutate a counter).
pub fn for_each_cred<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    mut f: impl FnMut(OathCredView<'_>),
) -> usize {
    let mut fids = [0u16; MAX_OATH_CRED as usize];
    let nfids = present_creds(fs, &mut fids);
    let mut scratch = [0u8; CRED_MAX];
    let mut count = 0;
    for &fid in &fids[..nfids] {
        let Some(n) = seal::seal_read(dev, fs, KeyFid::new(fid), &mut scratch) else {
            continue;
        };
        let blob = &scratch[..n.min(CRED_MAX)];
        let (Some(name), Some(key)) = (
            find_tag(blob, TAG_NAME as u16),
            find_tag(blob, TAG_KEY as u16),
        ) else {
            continue;
        };
        if key.is_empty() {
            continue;
        }
        let hotp = key[0] & OATH_TYPE_MASK == OATH_TYPE_HOTP;
        let algo = key[0] & ALG_MASK;
        let digits = key.get(1).copied().unwrap_or(0);
        let touch = find_tag(blob, TAG_PROPERTY as u16)
            .and_then(|v| v.first().copied())
            .is_some_and(|p| p & PROP_TOUCH != 0);
        let (period_prefix, label) = split_period(name);
        let period = if hotp { 0 } else { period_prefix.unwrap_or(30) };
        f(OathCredView {
            name: label,
            hotp,
            algo,
            digits,
            period,
            touch,
        });
        count += 1;
    }
    scratch.zeroize();
    count
}

/// Find a present credential whose `TAG_NAME` equals `name`; the blob is left in
/// `buf`. Only present slots are read (see [`present_creds`]).
fn find_cred<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    name: &[u8],
    buf: &mut [u8],
) -> Option<(u16, usize)> {
    let mut fids = [0u16; MAX_OATH_CRED as usize];
    let nfids = present_creds(fs, &mut fids);
    for &fid in &fids[..nfids] {
        if let Some(n) = seal::seal_read(dev, fs, KeyFid::new(fid), buf)
            && find_tag(&buf[..n], TAG_NAME as u16) == Some(name)
        {
            return Some((fid, n));
        }
    }
    None
}

/// Boot pass: seal any OATH secret slot still stored as legacy plaintext. A blob
/// that already unseals is left alone; one that does not is taken to be a
/// pre-seal plaintext credential and re-sealed in place. Covers every present
/// credential and the SET CODE key. Idempotent and crash-safe per slot — GCM
/// authentication tells the sealed and plaintext generations apart — so it can
/// run unconditionally at every boot (see `firmware/src/main.rs`), before any
/// host command touches a credential. Closes the one applet that historically
/// stored its secrets in the clear (FIDO / PIV / OpenPGP always sealed theirs).
pub fn migrate_seal<S: Storage>(dev: &Device, fs: &mut Fs<S>, rng: &mut dyn Rng) {
    let mut fids = [0u16; MAX_OATH_CRED as usize];
    let n = present_creds(fs, &mut fids);
    let mut out = [0u8; CRED_MAX];
    let mut raw = [0u8; CRED_MAX];
    for &fid in &fids[..n] {
        reseal_if_plaintext(dev, fs, rng, KeyFid::new(fid), &mut out, &mut raw);
    }
    reseal_if_plaintext(dev, fs, rng, EF_OATH_CODE, &mut out, &mut raw);
    out.zeroize();
    raw.zeroize();
}

/// Bring `fid` to a seal under the current kbase arm. No-op if it already
/// authenticates there. A secret sealed under the pre-OTP (NO-OTP) arm is
/// recovered and re-sealed under the OTP arm; otherwise the stored bytes are
/// taken to be legacy plaintext and sealed in place. No-op when the slot is
/// absent.
fn reseal_if_plaintext<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    fid: KeyFid,
    out: &mut [u8],
    raw: &mut [u8],
) {
    if seal::seal_read(dev, fs, fid, out).is_some() {
        return; // already sealed under the current arm
    }
    // A credential sealed before the OTP MKEK was burned is under the NO-OTP
    // kbase. Recover it via the pre-OTP arm and re-seal under the current (OTP)
    // arm — else the fall-through below would re-seal the *ciphertext* as if it
    // were plaintext (double-encrypting and destroying the secret). Plaintext and
    // sealed OATH blobs overlap in length (a cred TLV is variable-length), so
    // unlike the OTP applet this cannot be a size guard — it must be the AEAD
    // trial-decrypt. Mirrors keydev/PIV/seed.
    if dev.otp_key.is_some()
        && let Some(n) = seal::seal_read(&dev.without_otp(), fs, fid, out)
    {
        let _ = seal::seal_put(dev, fs, rng, fid, &out[..n]);
        return;
    }
    if let Some(n) = fs.read_key(fid, raw) {
        let n = n.min(raw.len());
        let _ = seal::seal_put(dev, fs, rng, fid, &raw[..n]);
    }
}

/// Lowest unused credential slot for a new PUT, or `None` if all 255 are taken.
/// Reads occupancy from the in-RAM present index (see [`present_creds`]) — no flash
/// scan on the PUT path. A live slot always carries a set present bit after the boot
/// scan, so this cannot hand out an occupied slot in normal operation.
fn free_slot<S: Storage>(fs: &mut Fs<S>) -> Option<u16> {
    let mut used = [false; MAX_OATH_CRED as usize];
    fs.present_slots(EF_OATH_CRED, &mut used);
    used.iter()
        .position(|&u| !u)
        .map(|i| EF_OATH_CRED + i as u16)
}

/// Byte range of the first `tag` value inside `blob` (so callers can mutate it
/// in place — the HOTP counter bump).
fn find_tag_range(blob: &[u8], tag: u8) -> Option<core::ops::Range<usize>> {
    let mut i = 0;
    while i < blob.len() {
        let t = *blob.get(i)?;
        i += 1;
        let l0 = *blob.get(i)?;
        i += 1;
        let len = match l0 {
            0x82 => {
                let v = ((*blob.get(i)? as usize) << 8) | *blob.get(i + 1)? as usize;
                i += 2;
                v
            }
            0x81 => {
                let v = *blob.get(i)? as usize;
                i += 1;
                v
            }
            n => n as usize,
        };
        let end = i.checked_add(len)?;
        if end > blob.len() {
            return None;
        }
        if t == tag {
            return Some(i..end);
        }
        i = end;
    }
    None
}

/// TLV walk over PUT data. `TAG_PROPERTY` is special-cased per the YKOATH spec:
/// a bare `(tag, value)` byte pair with no length octet (ykman sends exactly
/// that). Everything else is a normal BER-TLV. Malformed input ends iteration.
struct PutIter<'d> {
    rest: &'d [u8],
}

impl<'d> PutIter<'d> {
    fn new(data: &'d [u8]) -> Self {
        Self { rest: data }
    }
}

impl<'d> Iterator for PutIter<'d> {
    type Item = (u8, &'d [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let b = self.rest;
        let t = *b.first()?;
        if t == TAG_PROPERTY {
            let v = b.get(1..2)?;
            self.rest = &b[2..];
            return Some((t, v));
        }
        let mut p = 1;
        let l0 = *b.get(p)?;
        p += 1;
        let len = match l0 {
            0x82 => {
                let v = ((*b.get(p)? as usize) << 8) | *b.get(p + 1)? as usize;
                p += 2;
                v
            }
            0x81 => {
                let v = *b.get(p)? as usize;
                p += 1;
                v
            }
            n => n as usize,
        };
        let end = p.checked_add(len)?;
        if end > b.len() {
            return None;
        }
        let v = &b[p..end];
        self.rest = &b[end..];
        Some((t, v))
    }
}

/// Append a BER-TLV to `buf`; `false` on overflow.
fn emit_tlv(buf: &mut [u8], n: &mut usize, tag: u8, val: &[u8]) -> bool {
    if val.len() > u16::MAX as usize {
        return false;
    }
    let mut lenb = [0u8; 3];
    let ln = format_len(val.len() as u16, &mut lenb);
    if *n + 1 + ln + val.len() > buf.len() {
        return false;
    }
    buf[*n] = tag;
    buf[*n + 1..*n + 1 + ln].copy_from_slice(&lenb[..ln]);
    buf[*n + 1 + ln..*n + 1 + ln + val.len()].copy_from_slice(val);
    *n += 1 + ln + val.len();
    true
}

/// Constant-time equality — the access-code MAC compare must not be a timing
/// oracle, and short responses must never match.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    rsk_crypto::ct_eq(a, b)
}

/// Kani proof harnesses (`cargo kani -p rsk-oath`): exhaustive over every input
/// up to the stated bound, where the unit tests only sample.
#[cfg(kani)]
#[path = "kani.rs"]
mod proofs;

#[cfg(test)]
mod tests;
