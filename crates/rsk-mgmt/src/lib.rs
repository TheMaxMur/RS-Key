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

const INS_WRITE_CONFIG: u8 = 0x1C;
const INS_READ_CONFIG: u8 = 0x1D;
const INS_RESET: u8 = 0x1E;
// ykman's device-wide reset (ManagementSession.device_reset) is INS 0x1F; RS-Key's
// own placeholder was 0x1E. The DEFAULT build honours BOTH as a factory reset;
// strict-config keeps them unsupported. DEFAULT-build only.
#[cfg(not(feature = "strict-config"))]
const INS_DEVICE_RESET: u8 = 0x1F;

/// Pending device-wide factory-reset request, set by the Management RESET command
/// and drained by the firmware after the command's SW_OK. DEFAULT build only.
#[cfg(not(feature = "strict-config"))]
static DEVICE_RESET: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Take (and clear) a pending device-wide factory-reset request. The firmware
/// polls this after the RESET SW_OK, then wipes all flash (keeping attestation)
/// and reboots. `strict-config` never sets it (RESET stays `6D00`).
#[cfg(not(feature = "strict-config"))]
pub fn take_device_reset() -> bool {
    DEVICE_RESET.swap(false, core::sync::atomic::Ordering::Relaxed)
}

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
        // `strict-config` gate it on operator presence (the CONFIG_LOCK byte is
        // only reported, never enforced, so presence is the authentication of
        // record). The DEFAULT build is ungated for full YubiKey/ykman parity —
        // any USB host can rewrite DeviceInfo (docs/threat-model.md).
        if cfg!(feature = "strict-config")
            && !self.require_presence(Confirm::titled("Write device config?"))
        {
            return Sw::CONDITIONS_NOT_SATISFIED;
        }
        match persist_dev_conf(fs, &apdu.data[1..apdu.nc]) {
            Ok(()) => Sw::OK,
            Err(DevConfError::TooLong | DevConfError::BadTlv) => Sw::WRONG_DATA,
            Err(DevConfError::Store) => Sw::MEMORY_FAILURE,
        }
    }

    /// Management RESET (INS 0x1E / ykman's 0x1F): request a device-wide factory
    /// reset. Even on the permissive default this is presence-gated — an
    /// unauthenticated one-APDU wipe from any USB host would be a silent-brick
    /// footgun. The firmware does the flash wipe + reboot after this SW_OK.
    #[cfg(not(feature = "strict-config"))]
    fn request_device_reset(&mut self) -> Sw {
        if !self.require_presence(Confirm::titled("Factory reset device?")) {
            return Sw::CONDITIONS_NOT_SATISFIED;
        }
        DEVICE_RESET.store(true, core::sync::atomic::Ordering::Relaxed);
        Sw::OK
    }
}

impl<S: Storage> Applet<Fs<S>> for ManagementApplet<'_> {
    fn aid(&self) -> &'static [u8] {
        MANAGEMENT_AID
    }

    /// SELECT returns the firmware version as an ASCII string.
    fn select(&mut self, _reselect: bool, _fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        let (maj, min, patch) = VERSION;
        push_dec(res, maj);
        res.push(b'.');
        push_dec(res, min);
        res.push(b'.');
        push_dec(res, patch);
        Sw::OK
    }

    fn process(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if apdu.cla != 0x00 {
            return Sw::CLA_NOT_SUPPORTED;
        }
        match apdu.ins {
            INS_READ_CONFIG => config_tlv(&self.serial, fs, res),
            INS_WRITE_CONFIG => self.write_config(apdu, fs),
            // DEFAULT build: a presence-gated device-wide factory reset (ykman
            // parity), serviced by the firmware after this SW_OK. strict-config
            // keeps it unsupported (ykman resets FIDO over CTAP instead).
            #[cfg(not(feature = "strict-config"))]
            INS_RESET | INS_DEVICE_RESET => self.request_device_reset(),
            #[cfg(feature = "strict-config")]
            INS_RESET => Sw::INS_NOT_SUPPORTED,
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
