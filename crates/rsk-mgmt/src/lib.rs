// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Yubico management applet: reports device capabilities, serial and firmware
//! version — what `ykman` / Yubico Authenticator SELECT first to identify the key.
//! READ CONFIG (0x1D) returns the DeviceInfo TLV; WRITE CONFIG (0x1C) persists it.
#![cfg_attr(not(test), no_std)]

use core::cell::RefCell;
use rsk_devconf::{DEV_CONF_WRITE_MAX, DevConfError, config_tlv, persist_dev_conf};
use rsk_fs::{Fs, Storage};
// The user-presence seam gating WRITE CONFIG against a hostile USB host is
// `rsk-sdk`'s, shared with every sibling applet — the board has one button.
pub use rsk_sdk::{AlwaysConfirm, Confirm, Presence, UserPresence};
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};

/// Management applet AID.
pub const MANAGEMENT_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

/// Reported firmware version `(major, minor, patch)` — the shared
/// [`rsk_sdk::FIRMWARE_VERSION`] so CTAP getInfo, the DeviceInfo TLV and `ykman`
/// all agree.
pub const VERSION: (u8, u8, u8) = rsk_sdk::FIRMWARE_VERSION;

/// What a YubiKey 5.8.0's SELECT answers ahead of its version, byte for byte.
const SELECT_PREFIX: &[u8] = b"Virtual mgr - FW version ";

const INS_WRITE_CONFIG: u8 = 0x1C;
const INS_READ_CONFIG: u8 = 0x1D;
/// Answered `9000` with nothing done, whatever the P1-P2 or body, as a YubiKey 5.8.0
/// answers it. It and `1F` were a factory reset here, which the rescue and vendor
/// applets' `1E`/`1F`, sent while this applet was selected, could reach.
const INS_ACKNOWLEDGED: u8 = 0x1E;

pub struct ManagementApplet<'a> {
    /// First 4 bytes of the chip id → the 8-digit serial.
    serial: [u8; 4],
    /// Touch/approval gate for the privileged WRITE CONFIG.
    presence: &'a RefCell<dyn UserPresence>,
}

impl<'a> ManagementApplet<'a> {
    /// `serial_id` is the device chip id; its first 4 bytes form the serial.
    pub fn new(serial_id: [u8; 8], presence: &'a RefCell<dyn UserPresence>) -> Self {
        Self {
            serial: rsk_sdk::serial4(serial_id),
            presence,
        }
    }

    /// Require a physical user-presence confirmation before a privileged op.
    /// `true` only on Confirmed — a hostile USB host cannot drive it alone.
    fn require_presence(&self, confirm: Confirm<'_>) -> bool {
        self.presence.borrow_mut().request(confirm) == Presence::Confirmed
    }

    /// Serve READ CONFIG to a non-CCID transport — the same DeviceInfo TLV as the
    /// CCID path. The OTP keyboard interface and the CTAPHID Management vendor
    /// command both answer it (a YubiKey replies on every transport).
    pub fn read_config<S: Storage>(&self, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        config_tlv(&self.serial, fs, res)
    }

    /// Serve WRITE CONFIG to a non-CCID transport (the CTAPHID vendor command): the
    /// same record under the same configuration lock, without the presence gate —
    /// a `strict-config` build does not route that command here at all.
    pub fn persist_config<S: Storage>(
        &self,
        fs: &mut Fs<S>,
        blob: &[u8],
    ) -> Result<(), DevConfError> {
        persist_dev_conf(&self.serial, fs, blob)
    }

    /// WRITE CONFIG: the first data byte is the length of the rest; persist that
    /// TLV blob as `EF_DEV_CONF`.
    fn write_config<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        if apdu.nc == 0 || apdu.data[0] as usize != apdu.nc - 1 {
            return Sw::WRONG_DATA;
        }
        // Request-side bound only. What actually reaches flash is bounded by
        // `persist_dev_conf` against `EF_DEV_CONF_MAX` *after* the lock tags are
        // stripped, so a legitimate `set-lock-code` (two 16-byte codes in one
        // request, neither stored) is not refused for the size of its request.
        if apdu.nc - 1 > DEV_CONF_WRITE_MAX {
            return Sw::WRONG_DATA;
        }
        // Rewriting the reported DeviceInfo is a privileged, sticky change. Under
        // `strict-config` gate it on operator presence as well as the lock. The
        // DEFAULT build has the lock alone, as a YubiKey does: with no code set, any
        // USB host can rewrite DeviceInfo (docs/threat-model.md).
        if cfg!(feature = "strict-config")
            && !self.require_presence(Confirm::titled("Write device config?"))
        {
            return Sw::CONDITIONS_NOT_SATISFIED;
        }
        match persist_dev_conf(&self.serial, fs, &apdu.data[1..apdu.nc]) {
            Ok(()) => Sw::OK,
            Err(e) => e.sw(),
        }
    }
}

impl<S: Storage> Applet<Fs<S>> for ManagementApplet<'_> {
    fn aid(&self) -> &'static [u8] {
        MANAGEMENT_AID
    }

    /// SELECT answers `Virtual mgr - FW version X.Y.Z` in ASCII, as a YubiKey 5.8.0
    /// does; yubikit reads the version out of the words around it.
    fn select(&mut self, _reselect: bool, _fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        let (maj, min, patch) = VERSION;
        res.extend(SELECT_PREFIX);
        push_dec(res, maj);
        res.push(b'.');
        push_dec(res, min);
        res.push(b'.');
        push_dec(res, patch);
        Sw::OK
    }

    fn process(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if !apdu.is_basic_class() {
            return Sw::CLA_NOT_SUPPORTED;
        }
        match apdu.ins {
            INS_READ_CONFIG => config_tlv(&self.serial, fs, res),
            INS_WRITE_CONFIG => self.write_config(apdu, fs),
            INS_ACKNOWLEDGED => Sw::OK,
            _ => Sw::INS_NOT_SUPPORTED,
        }
    }
}

/// Append a `u8` as 1-3 ASCII decimal digits.
fn push_dec(res: &mut ResBuf, v: u8) {
    if v >= 100 {
        res.push(b'0' + v / 100);
    }
    if v >= 10 {
        res.push(b'0' + (v / 10) % 10);
    }
    res.push(b'0' + v % 10);
}

#[cfg(test)]
mod tests;
