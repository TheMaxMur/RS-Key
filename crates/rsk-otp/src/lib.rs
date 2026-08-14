// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Yubico OTP applet — the YubiKey slot protocol over CCID: slot configure /
//! update / swap / delete, status, GET SERIAL / GET CONFIG, and HMAC-SHA1 /
//! Yubico-mode challenge-response. [`ticket`] and [`hid`] serve the keyboard side.

#![cfg_attr(not(test), no_std)]

use core::cell::RefCell;

use rsk_crypto::{Device, FusedKey, FusedRead, aes128_encrypt_block, ct_eq, hmac_sha1, read_fused};
use rsk_fs::{Fs, KeyFid, Storage};
pub use rsk_sdk::Confirm;
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};
use zeroize::Zeroize;

mod counter;
pub mod hid;
pub mod seal;
pub mod ticket;

/// Randomness source for at-rest seal nonces (the firmware backs it with the
/// hardware TRNG). Mirrors the sibling applets' `Rng` traits.
pub trait Rng {
    fn fill(&mut self, buf: &mut [u8]);
}

#[cfg(test)]
mod tests_support;

/// OTP applet AID.
pub const OTP_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01];

/// Version reported in the status record — the shared
/// [`rsk_sdk::FIRMWARE_VERSION`].
pub const VERSION: (u8, u8, u8) = rsk_sdk::FIRMWARE_VERSION;

/// Outcome of a touch request (CHAL_BTN_TRIG slots).
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

// FIDs: four contiguous slots — 1/2 (the classic short/long press) plus 3/4
// (0xBB02/0xBB03), addressed everywhere as `EF_OTP_SLOT1 + (slot - 1)`. Slots 3/4
// are reached over CCID via the P2 slot offset and typed by three/four BOOTSEL clicks.
pub(crate) const EF_OTP_SLOT1: u16 = 0xBB00;
const EF_OTP_SLOT2: u16 = 0xBB01;
/// Number of OTP slots (1/2 classic short/long press, 3/4 via CCID P2 offset).
pub(crate) const SLOT_COUNT: usize = 4;
/// Highest addressable slot FID. Only slots 1..=4 (0xBB00..=0xBB03) are ever read
/// back (button_ticket, status, migrate_seal, power_up_bump); every command that
/// derives a FID from a host offset must reject anything past this, or a slot can
/// be written/relocated to an FID no code ever reaches again.
const EF_OTP_SLOT_LAST: u16 = EF_OTP_SLOT1 + SLOT_COUNT as u16 - 1;

// ykman OTP-HID admin-slot storage (DEFAULT build only). Above the slot range
// (0xBB00..=0xBB03) and outside every applet-reset scope; read back
// forward-compatibly, so an already-provisioned device survives the upgrade.
#[cfg(not(feature = "strict-config"))]
const EF_OTP_SCANMAP: u16 = 0xBB10;
#[cfg(not(feature = "strict-config"))]
const EF_OTP_NDEF1: u16 = 0xBB11;
#[cfg(not(feature = "strict-config"))]
const EF_OTP_NDEF2: u16 = 0xBB12;
#[cfg(not(feature = "strict-config"))]
const EF_OTP_DEVCFG: u16 = 0xBB13;
#[cfg(not(feature = "strict-config"))]
const EF_OTP_NDEF_MAX: usize = 64;
#[cfg(not(feature = "strict-config"))]
const EF_OTP_DEVCFG_MAX: usize = 32;

/// Slot-config field offsets (packed, 52 bytes).
pub(crate) const FIXED_SIZE: usize = 16;
pub(crate) const UID_SIZE: usize = 6;
pub(crate) const KEY_SIZE: usize = 16;
const ACC_CODE_SIZE: usize = 6;
pub(crate) const OFF_UID: usize = FIXED_SIZE;
pub(crate) const OFF_AES_KEY: usize = OFF_UID + UID_SIZE;
const OFF_ACC_CODE: usize = OFF_AES_KEY + KEY_SIZE;
const OFF_FIXED_SIZE: usize = OFF_ACC_CODE + ACC_CODE_SIZE;
const OFF_EXT_FLAGS: usize = OFF_FIXED_SIZE + 1;
pub(crate) const OFF_TKT_FLAGS: usize = OFF_EXT_FLAGS + 1;
pub(crate) const OFF_CFG_FLAGS: usize = OFF_TKT_FLAGS + 1;
const OFF_RFU: usize = OFF_CFG_FLAGS + 1;
pub(crate) const CONFIG_SIZE: usize = OFF_RFU + 2 + 2; // rfu[2] + crc16 = 52

/// Slot files carry the 52-byte config plus an 8-byte counter tail (the dynamic
/// use counter for typed Yubico-OTP / the 64-bit HOTP moving factor).
pub(crate) const SLOT_SIZE: usize = CONFIG_SIZE + 8;

// Status `opts` bits.
const CONFIG1_VALID: u8 = 0x01;
const CONFIG2_VALID: u8 = 0x02;
const CONFIG1_TOUCH: u8 = 0x04;
const CONFIG2_TOUCH: u8 = 0x08;

// EXT flags.
const EXTFLAG_UPDATE_MASK: u8 = 0xFF; // SERIAL_* | USE_NUMERIC | FAST_TRIG | ALLOW_UPDATE | DORMANT | LED_INV

// TKT flags.
pub(crate) const TKT_OATH_HOTP: u8 = 0x40;
const TKT_CHAL_RESP: u8 = 0x40;
/// Append a carriage return after the typed ticket (`APPEND_CR`).
pub(crate) const TKT_APPEND_CR: u8 = 0x20;
const TKTFLAG_UPDATE_MASK: u8 = 0x3F; // TAB/DELAY/CR bits

// CFG flags.
pub(crate) const CFG_SHORT_TICKET: u8 = 0x02;
const CFG_HMAC_LT64: u8 = 0x04;
const CFG_CHAL_BTN_TRIG: u8 = 0x08;
pub(crate) const CFG_STATIC_TICKET: u8 = 0x20;
const CFG_CHAL_YUBICO: u8 = 0x20;
const CFG_CHAL_HMAC: u8 = 0x22;
/// Generate 8-digit HOTP rather than 6 (`OATH_HOTP8`).
pub(crate) const CFG_OATH_HOTP8: u8 = 0x02;

/// Whether a programmed slot answers host challenges rather than typing a ticket
/// on a button press.
///
/// `TKT_OATH_HOTP` and `TKT_CHAL_RESP` are the SAME bit in Yubico's layout, so the
/// ticket flag alone cannot tell the two apart — the cfgFlags mode bits decide, and
/// `CFG_CHAL_HMAC` is a two-bit value for exactly that reason. An OATH-HOTP slot
/// carries `CFG_OATH_HOTP8` without `CFG_CHAL_YUBICO`, so it is a typing slot.
fn is_chal_resp_slot(tkt: u8, cfg: u8) -> bool {
    tkt & TKT_CHAL_RESP != 0
        && (cfg & CFG_CHAL_HMAC == CFG_CHAL_HMAC
            || (cfg & CFG_CHAL_YUBICO != 0 && cfg & CFG_OATH_HOTP8 == 0))
}

/// Whether the slot demands a press: a typing slot always does, a
/// challenge-response slot only when it was programmed with `CFG_CHAL_BTN_TRIG`.
fn slot_needs_touch(tkt: u8, cfg: u8) -> bool {
    !is_chal_resp_slot(tkt, cfg) || cfg & CFG_CHAL_BTN_TRIG != 0
}
const CFGFLAG_UPDATE_MASK: u8 = 0x0C; // PACING_10MS | PACING_20MS

/// Yubico OTP use-counter ceiling — the counter is 15-bit, high bit reserved.
pub(crate) const USE_COUNTER_MAX: u16 = 0x7FFF;

const INS_OTP: u8 = 0x01;

// Slot-command P1 codes (ykman's SLOT.* vocabulary).
const P1_CONFIG_SLOT1: u8 = 0x01;
const P1_CONFIG_SLOT2: u8 = 0x03;
const P1_UPDATE_SLOT1: u8 = 0x04;
const P1_UPDATE_SLOT2: u8 = 0x05;
const P1_SWAP: u8 = 0x06;
const P1_CHAL_OTP_SLOT1: u8 = 0x20;
const P1_CHAL_OTP_SLOT2: u8 = 0x28;
const P1_CHAL_HMAC_SLOT1: u8 = 0x30;
const P1_CHAL_HMAC_SLOT2: u8 = 0x38;
// ykman DeviceInfo write over the OTP transport (SLOT_YK4_SET_DEVICE_INFO).
// Served only on the DEFAULT (permissive) build; `strict-config` swallows it as
// a no-op like a config write it does not honour.
#[cfg(not(feature = "strict-config"))]
const P1_SET_DEVICE_INFO: u8 = 0x15;
// The remaining ykman OTP-HID admin slots, DEFAULT-build only. SCAN_MAP is
// functional (button_ticket remaps typed output through it); DEVICE_CONFIG
// (legacy set-mode) and NDEF are inert on this USB-only board (no NFC radio; the
// interface set lives in EF_PHY), so they are accept+store for ykman parity.
#[cfg(not(feature = "strict-config"))]
const P1_NDEF1: u8 = 0x08;
#[cfg(not(feature = "strict-config"))]
const P1_NDEF2: u8 = 0x09;
#[cfg(not(feature = "strict-config"))]
const P1_DEVICE_CONFIG: u8 = 0x11;
#[cfg(not(feature = "strict-config"))]
const P1_SCAN_MAP: u8 = 0x12;
/// The 45-character YubiKey set a custom scan map covers, in scan-map index
/// order: modhex lowercase, modhex uppercase, digits, then `!` `\t` `\r`.
#[cfg(not(feature = "strict-config"))]
const YUBICO_CHARSET: &[u8; 45] = b"cbdefghijklnrtuvCBDEFGHIJKLNRTUV0123456789!\t\r";
#[cfg(not(feature = "strict-config"))]
const SCANMAP_LEN: usize = 45;

/// Whether a keyboard-HID slot P1 is an OTP *function* — programming a slot
/// (configure/update/swap) or a challenge-response — as opposed to an
/// identify/config slot (GET SERIAL, READ/WRITE CONFIG, status, admin). When the
/// OTP application is disabled via `ykman config usb`, the firmware takes the
/// former inert while keeping the latter live, so the host can still read the
/// DeviceInfo and re-enable OTP.
pub fn is_function_slot(slot_id: u8) -> bool {
    // SCAN_MAP is functional too — it decides what a slot types — so it goes inert
    // with the rest when the OTP application is disabled (audit run-34 #22). Under
    // `strict-config` it is unhandled anyway and falls to the bare-OK swallow.
    #[cfg(not(feature = "strict-config"))]
    if matches!(slot_id, P1_SCAN_MAP | P1_NDEF1 | P1_NDEF2) {
        return true;
    }
    matches!(
        slot_id,
        P1_CONFIG_SLOT1
            | P1_CONFIG_SLOT2
            | P1_UPDATE_SLOT1
            | P1_UPDATE_SLOT2
            | P1_SWAP
            | P1_CHAL_OTP_SLOT1
            | P1_CHAL_OTP_SLOT2
            | P1_CHAL_HMAC_SLOT1
            | P1_CHAL_HMAC_SLOT2
    )
}

/// "Wrong data" in this protocol is reported as `0x6700` (wrong length).
const SW_WRONG_DATA: Sw = Sw::WRONG_LENGTH;

pub struct OtpApplet<'a> {
    serial_id: [u8; 8],
    serial_hash: [u8; 32],
    /// How to read the OTP MKEK that roots the slot seal — never the key itself,
    /// so no copy of it sits in this applet's memory between operations.
    mkek_source: Option<FusedKey>,
    rng: &'a RefCell<dyn Rng>,
    presence: &'a RefCell<dyn UserPresence>,
    /// Status-record sequence number; bumped on every config write, reset on
    /// SELECT to 1/0 depending on whether any slot is programmed.
    config_seq: u8,
    /// Per-slot RAM session-use counter mixed into a typed Yubico-OTP token;
    /// resets each power cycle. One entry per slot (1–4).
    session_counter: [u8; SLOT_COUNT],
}

impl<'a> OtpApplet<'a> {
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
            rng,
            presence,
            config_seq: 1,
            session_counter: [0; SLOT_COUNT],
        }
    }

    fn device<'k>(&'k self, mkek: &'k FusedRead) -> Device<'k> {
        Device {
            serial_hash: &self.serial_hash,
            serial_id: &self.serial_id,
            otp_key: mkek.as_deref(),
        }
    }

    /// Read+unseal a slot into `buf`; `Some(len)` only when it holds at least a
    /// full config. A `&self` helper so the `&mut self` command handlers read a
    /// slot without pinning a device borrow across their own mutations.
    fn read_slot_m<S: Storage>(
        &self,
        fs: &mut Fs<S>,
        fid: u16,
        buf: &mut [u8; SLOT_SIZE],
    ) -> Option<usize> {
        let mkek = read_fused(self.mkek_source);
        read_slot(&self.device(&mkek), fs, fid, buf)
    }

    /// Seal+write a slot record. `false` on a storage failure.
    fn put_slot<S: Storage>(&self, fs: &mut Fs<S>, fid: u16, data: &[u8]) -> bool {
        let mkek = read_fused(self.mkek_source);
        seal::seal_put(
            &self.device(&mkek),
            fs,
            &mut *self.rng.borrow_mut(),
            KeyFid::new(fid),
            data,
        )
    }

    /// Generate the typed ticket for a physical button press on `slot` (1–4: one
    /// or two clicks for the classic slots, three or four for slots 3/4). Builds
    /// the ticket via [`ticket::build`], persists any bumped use counter and
    /// writes the bytes to type into `out`. Returns `None` for an empty or
    /// challenge-response slot (nothing is typed). The `bool` is `true` when the
    /// bytes are ASCII to be keycode-mapped, `false` for raw scancodes.
    pub fn button_ticket<S: Storage>(
        &mut self,
        slot: u8,
        ts_secs: u32,
        rnd: [u8; 2],
        fs: &mut Fs<S>,
        out: &mut [u8; ticket::MAX_TICKET],
    ) -> Option<(usize, bool)> {
        if !(1..=SLOT_COUNT as u8).contains(&slot) {
            return None;
        }
        let fid = EF_OTP_SLOT1 + (slot as u16 - 1);
        let mut buf = [0u8; SLOT_SIZE];
        let n = self.read_slot_m(fs, fid, &mut buf)?;
        if n < SLOT_SIZE {
            buf[CONFIG_SIZE..].fill(0);
        }
        // A Yubico challenge-response slot types nothing on a press.
        let tkt = buf[OFF_TKT_FLAGS];
        let cfg = buf[OFF_CFG_FLAGS];
        if cfg & CFG_CHAL_YUBICO != 0 && tkt & TKT_CHAL_RESP != 0 {
            return None;
        }
        let idx = (slot - 1) as usize;
        let t = ticket::build(&buf, self.session_counter[idx], ts_secs, rnd, out)?;
        self.session_counter[idx] = t.new_session;
        if let Some(tail) = t.new_tail {
            let mut rec = buf;
            rec[CONFIG_SIZE..].copy_from_slice(&tail);
            let _ = self.put_slot(fs, fid, &rec);
        }
        let (len, encode) = (t.len, t.encode);
        // Functional custom scancode map (0x12): if one is stored and the whole
        // typed output is within the covered 45-char set, emit raw scancodes so a
        // non-US host types the intended characters. Absent under strict-config.
        #[cfg(not(feature = "strict-config"))]
        if encode && self.apply_scanmap(fs, &mut out[..len]) {
            return Some((len, false));
        }
        Some((len, encode))
    }

    /// First 10 chars of the serial hex string — mixed into the Yubico-mode
    /// challenge block.
    fn serial_str10(&self) -> [u8; 10] {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut out = [0u8; 10];
        for i in 0..5 {
            out[2 * i] = HEX[(self.serial_id[i] >> 4) as usize];
            out[2 * i + 1] = HEX[(self.serial_id[i] & 0xF) as usize];
        }
        out
    }

    /// The 7-byte status record body — version, sequence, valid/touch bits, a
    /// zero pad and the (idle) status byte. Shared by the CCID status response
    /// and the keyboard interface's status frame ([`Self::hid_status_frame`]).
    fn status_bytes<S: Storage>(&mut self, fs: &mut Fs<S>) -> [u8; 7] {
        let (maj, min, patch) = VERSION;
        let mut opts = 0u8;
        let mut slot = [0u8; SLOT_SIZE];
        if self.read_slot_m(fs, EF_OTP_SLOT1, &mut slot).is_some() {
            opts |= CONFIG1_VALID;
            if slot_needs_touch(slot[OFF_TKT_FLAGS], slot[OFF_CFG_FLAGS]) {
                opts |= CONFIG1_TOUCH;
            }
        }
        if self.read_slot_m(fs, EF_OTP_SLOT2, &mut slot).is_some() {
            opts |= CONFIG2_VALID;
            if slot_needs_touch(slot[OFF_TKT_FLAGS], slot[OFF_CFG_FLAGS]) {
                opts |= CONFIG2_TOUCH;
            }
        }
        // [maj, min, patch, config_seq, opts, pad, status_byte]; status_byte is
        // always idle here — the touch wait is signalled to the host through the
        // keyboard frame protocol's keepalive (see firmware `otp_kbd`).
        [maj, min, patch, self.config_seq, opts, 0, 0]
    }

    /// Push the status record onto the CCID response. The Yubico OTP status is
    /// 6 bytes — version(3), program sequence(1), 2-byte touch/valid level — so the
    /// 7th byte of [`Self::status_bytes`] (the keyboard-frame-only idle status byte)
    /// is dropped here to match a real YubiKey.
    fn status<S: Storage>(&mut self, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        res.extend(&self.status_bytes(fs)[..6]);
        Sw::OK
    }

    /// The 8-byte status frame returned by a keyboard-interface GET_REPORT poll:
    /// a leading reserved byte then the status record, so the host reads version
    /// at `[1..4]`, the program sequence at `[4]` and the slot valid/touch bits
    /// at `[5]`.
    pub fn hid_status_frame<S: Storage>(&mut self, fs: &mut Fs<S>) -> [u8; 8] {
        hid::status_frame(self.status_bytes(fs))
    }

    /// Run one keyboard-interface frame command: the 64-byte payload becomes the
    /// APDU data and `slot_id` its P1. The response body (CRC framing is the
    /// transport's job) lands in `res`; an empty body means the host should read
    /// the status frame instead (a configure/swap that only bumps the seq).
    pub fn process_hid<S: Storage>(
        &mut self,
        slot_id: u8,
        payload: &[u8; hid::PAYLOAD_SIZE],
        fs: &mut Fs<S>,
        res: &mut ResBuf,
    ) -> Sw {
        let mut raw = [0u8; 5 + hid::PAYLOAD_SIZE];
        raw[..5].copy_from_slice(&[0x00, INS_OTP, slot_id, 0x00, hid::PAYLOAD_SIZE as u8]);
        raw[5..].copy_from_slice(payload);
        match Apdu::parse(&raw) {
            Ok(apdu) => self.process(&apdu, fs, res),
            Err(_) => Sw::WRONG_LENGTH,
        }
    }

    /// P1 = 0x01/0x03: write or delete a slot config.
    fn cmd_configure<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if apdu.p1 == P1_CONFIG_SLOT2 && apdu.p2 != 0 {
            return Sw::INCORRECT_P1P2;
        }
        let base = if apdu.p1 == P1_CONFIG_SLOT1 {
            EF_OTP_SLOT1
        } else {
            EF_OTP_SLOT2
        };
        let fid = base + apdu.p2 as u16;
        if fid > EF_OTP_SLOT_LAST {
            return Sw::INCORRECT_P1P2;
        }
        if apdu.nc < CONFIG_SIZE {
            return Sw::WRONG_LENGTH;
        }
        let data = &apdu.data[..apdu.nc];
        let mut stored = [0u8; SLOT_SIZE];
        if self.read_slot_m(fs, fid, &mut stored).is_some() {
            // Existing config: the host must present its access code.
            if data.len() < CONFIG_SIZE + ACC_CODE_SIZE {
                return Sw::WRONG_LENGTH;
            }
            if !ct_eq(
                &data[CONFIG_SIZE..CONFIG_SIZE + ACC_CODE_SIZE],
                &stored[OFF_ACC_CODE..OFF_ACC_CODE + ACC_CODE_SIZE],
            ) {
                return Sw::SECURITY_STATUS_NOT_SATISFIED;
            }
        }
        if data[..CONFIG_SIZE].iter().any(|&b| b != 0) {
            if data[OFF_RFU] != 0 || data[OFF_RFU + 1] != 0 || !check_crc(&data[..CONFIG_SIZE]) {
                return SW_WRONG_DATA;
            }
            let mut rec = [0u8; SLOT_SIZE];
            rec[..CONFIG_SIZE].copy_from_slice(&data[..CONFIG_SIZE]);
            if !self.put_slot(fs, fid, &rec) {
                return Sw::MEMORY_FAILURE;
            }
        } else {
            // An all-zero config deletes the slot.
            let _ = fs.delete(fid);
        }
        self.config_seq = self.config_seq.wrapping_add(1);
        self.status(fs, res)
    }

    /// P1 = 0x04/0x05: update the flag bytes of an existing config, keeping its
    /// fixed part / UID / key.
    fn cmd_update<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if apdu.p1 == P1_UPDATE_SLOT2 && apdu.p2 != 0 {
            return Sw::INCORRECT_P1P2;
        }
        let base = if apdu.p1 == P1_UPDATE_SLOT1 {
            EF_OTP_SLOT1
        } else {
            EF_OTP_SLOT2
        };
        let fid = base + apdu.p2 as u16;
        if fid > EF_OTP_SLOT_LAST {
            return Sw::INCORRECT_P1P2;
        }
        if apdu.nc < CONFIG_SIZE {
            return Sw::WRONG_LENGTH;
        }
        let data = &apdu.data[..apdu.nc];
        if data[OFF_RFU] != 0 || data[OFF_RFU + 1] != 0 || !check_crc(&data[..CONFIG_SIZE]) {
            return SW_WRONG_DATA;
        }
        let mut stored = [0u8; SLOT_SIZE];
        if self.read_slot_m(fs, fid, &mut stored).is_some() {
            if data.len() < CONFIG_SIZE + ACC_CODE_SIZE {
                return Sw::WRONG_LENGTH;
            }
            if !ct_eq(
                &data[CONFIG_SIZE..CONFIG_SIZE + ACC_CODE_SIZE],
                &stored[OFF_ACC_CODE..OFF_ACC_CODE + ACC_CODE_SIZE],
            ) {
                return Sw::SECURITY_STATUS_NOT_SATISFIED;
            }
            let mut merged = [0u8; SLOT_SIZE];
            merged[..CONFIG_SIZE].copy_from_slice(&data[..CONFIG_SIZE]);
            // The 8-byte tail is the Yubico-OTP use counter / HOTP moving factor:
            // non-volatile anti-replay state that must only ever advance. Carry it
            // forward — only a full re-CONFIGURE resets it, exactly as on a YubiKey.
            // (A CONFIG_SIZE `merged` here truncated it, silently rolling the counter
            // back on the next read — audit run-30.)
            merged[CONFIG_SIZE..].copy_from_slice(&stored[CONFIG_SIZE..]);
            // Keep the secret material and fixed part; merge only the
            // updateable flag bits.
            merged[..OFF_ACC_CODE].copy_from_slice(&stored[..OFF_ACC_CODE]);
            merged[OFF_FIXED_SIZE] = stored[OFF_FIXED_SIZE];
            merged[OFF_EXT_FLAGS] = (stored[OFF_EXT_FLAGS] & !EXTFLAG_UPDATE_MASK)
                | (data[OFF_EXT_FLAGS] & EXTFLAG_UPDATE_MASK);
            merged[OFF_TKT_FLAGS] = (stored[OFF_TKT_FLAGS] & !TKTFLAG_UPDATE_MASK)
                | (data[OFF_TKT_FLAGS] & TKTFLAG_UPDATE_MASK);
            merged[OFF_CFG_FLAGS] = if stored[OFF_TKT_FLAGS] & TKT_CHAL_RESP == 0 {
                (stored[OFF_CFG_FLAGS] & !CFGFLAG_UPDATE_MASK)
                    | (data[OFF_CFG_FLAGS] & CFGFLAG_UPDATE_MASK)
            } else {
                stored[OFF_CFG_FLAGS]
            };
            if !self.put_slot(fs, fid, &merged) {
                return Sw::MEMORY_FAILURE;
            }
            self.config_seq = self.config_seq.wrapping_add(1);
        }
        self.status(fs, res)
    }

    /// P1 = 0x06: swap the two slots. Body layouts: empty = slots 1↔2, no code;
    /// `[code0..code5]` (6 bytes) = slots 1↔2 with an access code — the frame
    /// `ykman`/yubikit actually send for `otp swap`; `[a,b]` = slots (1+a)↔(2+b);
    /// `[a,b,code0..code5]` = that pair with a 6-byte access code. Swapping
    /// moves/deletes stored configs, so — like cmd_configure/cmd_update/delete
    /// (docs/guides/otp.md) — a programmed slot is only touched when the presented
    /// code matches its stored access code; an unprotected slot's all-zero code is
    /// satisfied by the default, so a plain `ykman otp swap` of unprotected slots
    /// is unchanged. Out-of-range offsets are rejected so a swap can never orphan a
    /// slot outside the 4-slot range.
    fn cmd_swap<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        let (mut fid1, mut fid2) = (EF_OTP_SLOT1, EF_OTP_SLOT2);
        let mut code = [0u8; ACC_CODE_SIZE];
        if apdu.nc == ACC_CODE_SIZE {
            // The standard `ykman otp swap` frame: a bare 6-byte access code, no
            // slot-offset bytes → swap the default slots 1↔2 with it. Missing this
            // arm rejected the real swap as WRONG_LENGTH (ykman: "Failed to write").
            code.copy_from_slice(&apdu.data[..ACC_CODE_SIZE]);
        } else if apdu.nc == 2 || apdu.nc == 2 + ACC_CODE_SIZE {
            // RS-Key's 4-slot extension: [a,b] offsets, optionally + a 6-byte code.
            fid1 += apdu.data[0] as u16;
            fid2 += apdu.data[1] as u16;
            if apdu.nc == 2 + ACC_CODE_SIZE {
                code.copy_from_slice(&apdu.data[2..2 + ACC_CODE_SIZE]);
            }
        } else if apdu.nc != 0 {
            return Sw::WRONG_LENGTH;
        }
        if fid1 > EF_OTP_SLOT_LAST || fid2 > EF_OTP_SLOT_LAST {
            return Sw::INCORRECT_P1P2;
        }
        let mut a = [0u8; SLOT_SIZE];
        let mut b = [0u8; SLOT_SIZE];
        let na = self.read_slot_m(fs, fid1, &mut a);
        let nb = self.read_slot_m(fs, fid2, &mut b);
        // The access code gates a swap's move/delete just as it gates
        // overwrite/update/delete: a programmed slot may not be relocated or
        // deleted without its code (an unprotected slot's stored code is zero).
        let unmatched =
            |rec: &[u8; SLOT_SIZE]| !ct_eq(&code, &rec[OFF_ACC_CODE..OFF_ACC_CODE + ACC_CODE_SIZE]);
        if (na.is_some() && unmatched(&a)) || (nb.is_some() && unmatched(&b)) {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        match nb {
            Some(n) => {
                if !self.put_slot(fs, fid1, &b[..n]) {
                    return Sw::MEMORY_FAILURE;
                }
            }
            None => {
                let _ = fs.delete(fid1);
            }
        }
        match na {
            Some(n) => {
                if !self.put_slot(fs, fid2, &a[..n]) {
                    return Sw::MEMORY_FAILURE;
                }
            }
            None => {
                let _ = fs.delete(fid2);
            }
        }
        self.config_seq = self.config_seq.wrapping_add(1);
        self.status(fs, res)
    }

    /// P1 = 0x14: per-slot flag/fixed-part TLVs (extended status).
    fn cmd_status_ext<S: Storage>(&mut self, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        let mut slot = [0u8; SLOT_SIZE];
        for i in 0..SLOT_COUNT as u16 {
            if self.read_slot_m(fs, EF_OTP_SLOT1 + i, &mut slot).is_none() {
                continue;
            }
            let tkt = slot[OFF_TKT_FLAGS];
            let cfg = slot[OFF_CFG_FLAGS];
            // A plain (typed) Yubico-OTP slot also reports its public id.
            let plain_otp = !(cfg & CFG_CHAL_YUBICO != 0 && tkt & TKT_CHAL_RESP != 0)
                && tkt & TKT_OATH_HOTP == 0
                && cfg & (CFG_SHORT_TICKET | CFG_STATIC_TICKET) == 0;
            res.push(0xB0 + i as u8);
            res.push(if plain_otp { 4 + 8 } else { 4 });
            res.push(0xA0);
            res.push(2);
            res.push(tkt);
            res.push(cfg);
            if plain_otp {
                res.push(0xC0);
                res.push(6);
                res.extend(&slot[..6]);
            }
        }
        Sw::OK
    }

    /// P1 = 0x20/0x28 (Yubico mode) / 0x30/0x38 (HMAC-SHA1): challenge-response.
    /// Challenge lengths are required up front — never overread the body.
    fn cmd_calculate<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if (apdu.p1 == P1_CHAL_HMAC_SLOT2 || apdu.p1 == P1_CHAL_OTP_SLOT2) && apdu.p2 != 0 {
            return Sw::INCORRECT_P1P2;
        }
        let base = if apdu.p1 == P1_CHAL_HMAC_SLOT1 || apdu.p1 == P1_CHAL_OTP_SLOT1 {
            EF_OTP_SLOT1
        } else {
            EF_OTP_SLOT2
        };
        let fid = base + apdu.p2 as u16;
        if fid > EF_OTP_SLOT_LAST {
            return Sw::INCORRECT_P1P2;
        }
        let mut slot = [0u8; SLOT_SIZE];
        if self.read_slot_m(fs, fid, &mut slot).is_none() {
            // Protocol quirk: an empty slot answers 9000 with no body.
            return Sw::OK;
        }
        let tkt = slot[OFF_TKT_FLAGS];
        let cfg = slot[OFF_CFG_FLAGS];
        if !is_chal_resp_slot(tkt, cfg) {
            return SW_WRONG_DATA;
        }
        if cfg & CFG_CHAL_BTN_TRIG != 0
            && self
                .presence
                .borrow_mut()
                .request(Confirm::titled("Challenge-response?"))
                != Presence::Confirmed
        {
            return Sw::CONDITIONS_NOT_SATISFIED;
        }
        let data = &apdu.data[..apdu.nc];
        if apdu.p1 == P1_CHAL_HMAC_SLOT1 || apdu.p1 == P1_CHAL_HMAC_SLOT2 {
            // CFG_CHAL_HMAC is a TWO-bit mask (CHAL_YUBICO | 0x02) — Yubico decides
            // the mode with both bits because TKT_OATH_HOTP and TKT_CHAL_RESP are
            // the same bit and the check above cannot separate them. An any-bit test
            // let CFG_OATH_HOTP8 (0x02) alone enter this arm, so an OATH-HOTP slot —
            // which never carries CFG_CHAL_BTN_TRIG — answered HMAC challenges over
            // its HOTP seed with no touch. Match the whole mask.
            if cfg & CFG_CHAL_HMAC != CFG_CHAL_HMAC {
                return SW_WRONG_DATA;
            }
            if data.len() < hid::PAYLOAD_SIZE {
                return Sw::WRONG_LENGTH;
            }
            // HMAC key = AES field + all 6 UID bytes (22 total). HMAC zero-pads
            // keys, so with the zero UID tail this equals the 20-byte-key HMAC.
            let mut key = [0u8; KEY_SIZE + UID_SIZE];
            key[..KEY_SIZE].copy_from_slice(&slot[OFF_AES_KEY..OFF_AES_KEY + KEY_SIZE]);
            key[KEY_SIZE..].copy_from_slice(&slot[OFF_UID..OFF_UID + UID_SIZE]);
            // Variable-length challenges are padded by repeating the final
            // byte; trim that padding back off.
            let mut chal_len = hid::PAYLOAD_SIZE;
            if cfg & CFG_HMAC_LT64 != 0 {
                while chal_len > 0 && data[chal_len - 1] == data[hid::PAYLOAD_SIZE - 1] {
                    chal_len -= 1;
                }
            }
            res.extend(&hmac_sha1(&key, &data[..chal_len]));
        } else {
            // Mirror of the mask above: an OATH-HOTP slot sets 0x02 without
            // CHAL_YUBICO's 0x20, but a chal-resp slot in HMAC mode sets both — so
            // the Yubico arm must reject anything carrying the HMAC discriminator.
            if cfg & CFG_CHAL_YUBICO == 0 || cfg & CFG_OATH_HOTP8 != 0 {
                return SW_WRONG_DATA;
            }
            if data.len() < 6 {
                return Sw::WRONG_LENGTH;
            }
            // Challenge block = 6 host bytes + 10 chars of the serial string.
            let mut block = [0u8; 16];
            block[..6].copy_from_slice(&data[..6]);
            block[6..].copy_from_slice(&self.serial_str10());
            let mut key = [0u8; KEY_SIZE];
            key.copy_from_slice(&slot[OFF_AES_KEY..OFF_AES_KEY + KEY_SIZE]);
            aes128_encrypt_block(&key, &mut block);
            res.extend(&block);
        }
        Sw::OK
    }

    fn cmd_otp<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        match apdu.p1 {
            P1_CONFIG_SLOT1 | P1_CONFIG_SLOT2 => self.cmd_configure(apdu, fs, res),
            P1_UPDATE_SLOT1 | P1_UPDATE_SLOT2 => self.cmd_update(apdu, fs, res),
            P1_SWAP => self.cmd_swap(apdu, fs, res),
            0x10 => {
                res.extend(&rsk_mgmt::serial4(self.serial_id));
                Sw::OK
            }
            0x13 => rsk_mgmt::config_tlv(&rsk_mgmt::serial4(self.serial_id), fs, res),
            0x14 => self.cmd_status_ext(fs, res),
            P1_CHAL_OTP_SLOT1 | P1_CHAL_OTP_SLOT2 | P1_CHAL_HMAC_SLOT1 | P1_CHAL_HMAC_SLOT2 => {
                self.cmd_calculate(apdu, fs, res)
            }
            #[cfg(not(feature = "strict-config"))]
            P1_SET_DEVICE_INFO => self.cmd_set_device_info(apdu, fs),
            #[cfg(not(feature = "strict-config"))]
            P1_DEVICE_CONFIG => self.cmd_device_config(apdu, fs),
            #[cfg(not(feature = "strict-config"))]
            P1_SCAN_MAP => self.cmd_scan_map(apdu, fs),
            #[cfg(not(feature = "strict-config"))]
            P1_NDEF1 => self.cmd_ndef(apdu, fs, false),
            #[cfg(not(feature = "strict-config"))]
            P1_NDEF2 => self.cmd_ndef(apdu, fs, true),
            // Unknown P1 values (and, under `strict-config`, the admin-write
            // slots) fall through to a bare OK — the deliberate silent no-op the
            // host reads as "not implemented".
            _ => Sw::OK,
        }
    }

    /// SLOT_YK4_SET_DEVICE_INFO (`0x15`): ykman's DeviceInfo write over the OTP
    /// transport. The body is `[len][DeviceConfig TLV]` (yubikit
    /// `DeviceConfig.get_bytes()`) — the SAME blob CCID WRITE CONFIG persists, so a
    /// write here round-trips into the `0x13` / CCID READ CONFIG / CTAPHID `0x42`
    /// reads. Over the keyboard-HID transport the APDU body is a fixed 64 bytes, so
    /// trust the inner length byte, not `nc`. Ungated (parity); an empty inner
    /// blob is a no-op. Absent under `strict-config` (falls to the bare-OK swallow).
    #[cfg(not(feature = "strict-config"))]
    fn cmd_set_device_info<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        let data = apdu.data;
        if data.is_empty() {
            return Sw::OK;
        }
        let len = data[0] as usize;
        if len == 0 {
            return Sw::OK; // no config bytes → nothing to persist (status frame only)
        }
        if 1 + len > data.len() {
            return Sw::WRONG_DATA;
        }
        match rsk_mgmt::persist_dev_conf(fs, &data[1..1 + len]) {
            Ok(()) => {
                // ykman/yubikit confirm an OTP-transport write by the program-
                // sequence byte in the status frame advancing (`_is_sequence_updated`),
                // not by any response body. Bump it like a slot configure/update/swap
                // or `ykman config usb` fails with `CommandRejectedError: No data`.
                self.config_seq = self.config_seq.wrapping_add(1);
                Sw::OK
            }
            Err(rsk_mgmt::DevConfError::TooLong | rsk_mgmt::DevConfError::BadTlv) => Sw::WRONG_DATA,
            Err(rsk_mgmt::DevConfError::Store) => Sw::MEMORY_FAILURE,
        }
    }

    /// Legacy set-mode (`0x11`): the enabled-interface set lives in EF_PHY and is
    /// applied only at boot, so this is accept+store for ykman parity — inert on
    /// this USB-only board. Absent under `strict-config`.
    #[cfg(not(feature = "strict-config"))]
    fn cmd_device_config<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        let n = apdu.data.len().min(EF_OTP_DEVCFG_MAX);
        if n != 0 {
            let _ = fs.put(EF_OTP_DEVCFG, &apdu.data[..n]);
            self.config_seq = self.config_seq.wrapping_add(1); // pgmSeq bump (see cmd_set_device_info)
        }
        Sw::OK
    }

    /// NDEF program (`0x08`/`0x09`): no NFC radio, so accept+store only — the
    /// stored record is never emitted over any transport. Absent under
    /// `strict-config`.
    #[cfg(not(feature = "strict-config"))]
    fn cmd_ndef<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>, slot2: bool) -> Sw {
        let n = apdu.data.len().min(EF_OTP_NDEF_MAX);
        if n == 0 {
            return Sw::OK;
        }
        // Same gate as SCAN_MAP, and for the same reason (audit run-34 #22, swept to
        // this sibling by run-35): yubikit puts the access code after the payload,
        // and a device-global write must satisfy EVERY programmed slot's code — it
        // is otherwise only as protected as the least-protected slot.
        let mut code = [0u8; ACC_CODE_SIZE];
        if apdu.data.len() >= n + ACC_CODE_SIZE {
            code.copy_from_slice(&apdu.data[n..n + ACC_CODE_SIZE]);
        }
        if !self.code_clears_every_slot(fs, &code) {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let fid = if slot2 { EF_OTP_NDEF2 } else { EF_OTP_NDEF1 };
        let _ = fs.put(fid, &apdu.data[..n]);
        self.config_seq = self.config_seq.wrapping_add(1); // pgmSeq bump (see cmd_set_device_info)
        Sw::OK
    }

    /// SCAN_MAP (`0x12`): store the 45-byte custom HID-scancode table (yubikit
    /// `write_scan_map` puts it at the head of the frame, followed by the access
    /// code). `button_ticket` then remaps typed output through it. Absent under
    /// `strict-config`. (Exact HID framing is HW-unverified.)
    ///
    /// Gated like the slot writes: the map is global, so an all-zero one silences a
    /// protected slot's OTP and an all-`0x28` one makes it type Enters — changing
    /// what that slot emits without ever presenting its code (audit run-34 #22).
    #[cfg(not(feature = "strict-config"))]
    fn cmd_scan_map<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        let data = apdu.data;
        if data.len() < SCANMAP_LEN {
            return Sw::OK;
        }
        let mut code = [0u8; ACC_CODE_SIZE];
        if data.len() >= SCANMAP_LEN + ACC_CODE_SIZE {
            code.copy_from_slice(&data[SCANMAP_LEN..SCANMAP_LEN + ACC_CODE_SIZE]);
        }
        if !self.code_clears_every_slot(fs, &code) {
            return Sw::SECURITY_STATUS_NOT_SATISFIED;
        }
        let _ = fs.put(EF_OTP_SCANMAP, &data[..SCANMAP_LEN]);
        self.config_seq = self.config_seq.wrapping_add(1); // pgmSeq bump (see cmd_set_device_info)
        Sw::OK
    }

    /// Whether `code` satisfies *every* programmed slot's access code — the gate a
    /// device-global write needs, since it is otherwise only as protected as the
    /// least-protected slot. An unprotected slot's stored code is all-zero, so a
    /// plain `ykman otp set-scan-map` on an unprotected key is unchanged.
    #[cfg(not(feature = "strict-config"))]
    fn code_clears_every_slot<S: Storage>(
        &self,
        fs: &mut Fs<S>,
        code: &[u8; ACC_CODE_SIZE],
    ) -> bool {
        for i in 0..SLOT_COUNT as u16 {
            let mut rec = [0u8; SLOT_SIZE];
            if self.read_slot_m(fs, EF_OTP_SLOT1 + i, &mut rec).is_some()
                && !ct_eq(code, &rec[OFF_ACC_CODE..OFF_ACC_CODE + ACC_CODE_SIZE])
            {
                return false;
            }
        }
        true
    }

    /// If a complete custom scan map is stored AND every byte of `buf` (the typed
    /// output) is in the covered 45-char set, rewrite `buf` to the mapped raw HID
    /// scancodes (high bit = LeftShift) and return true; otherwise leave `buf`
    /// untouched (the caller keeps the ASCII path). All-or-nothing.
    #[cfg(not(feature = "strict-config"))]
    fn apply_scanmap<S: Storage>(&self, fs: &mut Fs<S>, buf: &mut [u8]) -> bool {
        let mut map = [0u8; SCANMAP_LEN];
        if fs
            .read(EF_OTP_SCANMAP, &mut map)
            .is_none_or(|n| n < SCANMAP_LEN)
        {
            return false;
        }
        if buf.iter().any(|&c| scanmap_scancode(&map, c).is_none()) {
            return false;
        }
        for c in buf.iter_mut() {
            *c = scanmap_scancode(&map, *c).unwrap();
        }
        true
    }
}

/// The raw HID scancode (high bit = LeftShift) a custom scan map assigns to `ch`,
/// or None if `ch` is outside the 45-char YubiKey set the map covers.
#[cfg(not(feature = "strict-config"))]
fn scanmap_scancode(map: &[u8], ch: u8) -> Option<u8> {
    if map.len() < SCANMAP_LEN {
        return None;
    }
    YUBICO_CHARSET.iter().position(|&c| c == ch).map(|i| map[i])
}

impl<S: Storage> Applet<Fs<S>> for OtpApplet<'_> {
    fn aid(&self) -> &'static [u8] {
        OTP_AID
    }

    /// SELECT returns the status record.
    fn select(&mut self, _reselect: bool, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        self.config_seq = u8::from(fs.has_data(EF_OTP_SLOT1) || fs.has_data(EF_OTP_SLOT2));
        self.status(fs, res)
    }

    fn process(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if apdu.cla != 0x00 {
            return Sw::CLA_NOT_SUPPORTED;
        }
        match apdu.ins {
            INS_OTP => self.cmd_otp(apdu, fs, res),
            _ => Sw::INS_NOT_SUPPORTED,
        }
    }
}

/// Read+unseal a slot file; `Some(len)` only when it holds at least a full
/// config. Legacy plaintext (pre-seal) fails GCM authentication and reads as
/// `None` until [`migrate_seal`] re-seals it at boot.
pub(crate) fn read_slot<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: u16,
    buf: &mut [u8; SLOT_SIZE],
) -> Option<usize> {
    let n = seal::seal_read(dev, fs, KeyFid::new(fid), buf)?;
    (n >= CONFIG_SIZE).then_some(n)
}

/// Boot pass: bring every slot to a seal under the current kbase arm. A blob that
/// already unseals is left alone; a slot sealed under the pre-OTP (NO-OTP) arm is
/// recovered and re-sealed under the OTP arm once the fuse key is present; a
/// legacy plaintext config is sealed in place. Idempotent and crash-safe per slot
/// — GCM authentication tells the generations apart — so it runs unconditionally
/// at every boot (see `firmware/src/main.rs`), before any host command or
/// [`power_up_bump`] touches a slot. Closes the one applet that historically
/// stored its secrets in the clear, and (via the pre-OTP arm, mirroring
/// keydev/PIV/seed) keeps an OTP burn from orphaning a slot provisioned before it.
pub fn migrate_seal<S: Storage>(dev: &Device, fs: &mut Fs<S>, rng: &mut dyn Rng) {
    let mut out = [0u8; SLOT_SIZE];
    // Sized to hold a full sealed blob so a sealed-but-unauthenticating slot
    // (e.g. a foreign serial) reads back at its true length and is skipped
    // rather than truncated and mis-resealed.
    let mut raw = [0u8; seal::MAX_BLOB];
    for i in 0..SLOT_COUNT as u16 {
        let fid = KeyFid::new(EF_OTP_SLOT1 + i);
        if seal::seal_read(dev, fs, fid, &mut out).is_some() {
            continue; // already sealed under the current arm
        }
        // A slot sealed before the OTP MKEK was burned is under the NO-OTP kbase;
        // recover it via the pre-OTP arm and re-seal under the current (OTP) arm,
        // so a burn never silently orphans an existing slot.
        if dev.otp_key.is_some()
            && let Some(n) = seal::seal_read(&dev.without_otp(), fs, fid, &mut out)
        {
            let _ = seal::seal_put(dev, fs, rng, fid, &out[..n]);
            continue;
        }
        if let Some(n) = fs.read_key(fid, &mut raw) {
            // Only re-seal a genuine plaintext config; anything longer is not a
            // legacy record — the smallest sealed blob is already > SLOT_SIZE,
            // asserted at compile time in `seal.rs`.
            if (CONFIG_SIZE..=SLOT_SIZE).contains(&n) {
                let _ = seal::seal_put(dev, fs, rng, fid, &raw[..n]);
            }
        }
    }
    out.zeroize();
    raw.zeroize();
}

/// Boot-time use-counter bump: on power-up, advance the 16-bit use counter of
/// every plain Yubico-OTP slot (skipping HOTP / short / static slots), so a
/// counter never repeats across reboots — the YubiKey replay defence. Runs once
/// at startup.
pub fn power_up_bump<S: Storage>(dev: &Device, fs: &mut Fs<S>, rng: &mut dyn Rng) {
    let mut slot = [0u8; SLOT_SIZE];
    for i in 0..SLOT_COUNT as u16 {
        let fid = EF_OTP_SLOT1 + i;
        let Some(n) = read_slot(dev, fs, fid, &mut slot) else {
            continue;
        };
        let tkt = slot[OFF_TKT_FLAGS];
        let cfg = slot[OFF_CFG_FLAGS];
        if tkt & TKT_OATH_HOTP != 0 || cfg & (CFG_SHORT_TICKET | CFG_STATIC_TICKET) != 0 {
            continue;
        }
        // The counter lives in the first two tail bytes (big-endian).
        let mut rec = slot;
        if n < SLOT_SIZE {
            rec[CONFIG_SIZE..].fill(0);
        }
        let stored = u16::from_be_bytes([rec[CONFIG_SIZE], rec[CONFIG_SIZE + 1]]);
        if let Some(counter) = counter::boot_use_counter(stored) {
            rec[CONFIG_SIZE..CONFIG_SIZE + 2].copy_from_slice(&counter.to_be_bytes());
            let _ = seal::seal_put(dev, fs, rng, KeyFid::new(fid), &rec);
        }
    }
}

/// CRC16 X.25 / CRC-CCITT reflected, poly 0x8408.
pub(crate) fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            let lsb = crc & 1;
            crc >>= 1;
            if lsb == 1 {
                crc ^= 0x8408;
            }
        }
    }
    crc
}

/// A valid config CRCs (over all 52 bytes, the stored ~CRC included) to the
/// X.25 residual.
fn check_crc(config: &[u8]) -> bool {
    crc16(config) == 0xF0B8
}

#[cfg(test)]
mod tests;
