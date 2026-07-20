// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Yubico management applet: reports device capabilities, serial and firmware
//! version — what `ykman` / Yubico Authenticator SELECT first to identify the key.
//! READ CONFIG (0x1D) returns the DeviceInfo TLV; WRITE CONFIG (0x1C) persists it.
#![cfg_attr(not(test), no_std)]

use core::cell::RefCell;
use rsk_fs::{Fs, Storage};
pub use rsk_sdk::Confirm;
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};

/// Management applet AID.
pub const MANAGEMENT_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

/// Reported firmware version `(major, minor, patch)` — the shared
/// [`rsk_sdk::FIRMWARE_VERSION`] so CTAP getInfo, the DeviceInfo TLV and `ykman`
/// all agree.
pub const VERSION: (u8, u8, u8) = rsk_sdk::FIRMWARE_VERSION;

// Capability bits.
const CAP_OTP: u16 = 0x01;
const CAP_U2F: u16 = 0x02;
const CAP_OPENPGP: u16 = 0x08;
const CAP_OATH: u16 = 0x20;
const CAP_FIDO2: u16 = 0x200;
const CAP_PIV: u16 = 0x10;

/// Capabilities this firmware actually implements. Reporting only what exists
/// keeps Yubico Authenticator from showing tabs that would error on SELECT.
const SUPPORTED_CAPS: u16 = CAP_FIDO2 | CAP_U2F | CAP_OPENPGP | CAP_OATH | CAP_OTP | CAP_PIV;

// DeviceInfo TLV tags.
const TAG_USB_SUPPORTED: u8 = 0x01;
const TAG_SERIAL: u8 = 0x02;
const TAG_USB_ENABLED: u8 = 0x03;
const TAG_FORM_FACTOR: u8 = 0x04;
const TAG_VERSION: u8 = 0x05;
const TAG_DEVICE_FLAGS: u8 = 0x08;
const TAG_CONFIG_LOCK: u8 = 0x0A;

const FLAG_EJECT: u8 = 0x80;
const FORM_FACTOR_USB_A_KEYCHAIN: u8 = 0x01;

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

/// EF holding the persisted enabled-applications TLV. Outside both the FIDO and
/// OpenPGP reset scopes, so the capability config is sticky.
const EF_DEV_CONF: u16 = 0x1122;

/// Bytes of `EF_DEV_CONF` that READ CONFIG can echo back — the size of the fixed
/// buffer it reads into. WRITE CONFIG refuses to persist more (a host config is
/// a handful of small TLVs), so a read can never slice past the buffer.
const EF_DEV_CONF_MAX: usize = 64;

/// Outcome of a user-presence request for a privileged management operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    Confirmed,
    Timeout,
    Declined,
}

/// Physical user presence, gating WRITE CONFIG against a hostile USB host —
/// same shape as the sibling applets' `UserPresence`. On the trusted-display
/// build the `confirm` names the operation; the BOOTSEL backend waits for a press.
pub trait UserPresence {
    fn request(&mut self, confirm: Confirm<'_>) -> Presence;
}

/// A [`UserPresence`] that confirms instantly — the host-test / fuzz stand-in.
pub struct AlwaysConfirm;

impl UserPresence for AlwaysConfirm {
    fn request(&mut self, _confirm: Confirm<'_>) -> Presence {
        Presence::Confirmed
    }
}

pub struct ManagementApplet<'a> {
    /// First 4 bytes of the chip id → the 8-digit serial.
    serial: [u8; 4],
    /// Touch/approval gate for the privileged WRITE CONFIG.
    presence: &'a RefCell<dyn UserPresence>,
}

/// First 4 bytes of the chip id with the top 6 bits cleared (`&= ~0xFC`) — the
/// 8-digit Yubico serial. Shared with the OTP applet's GET SERIAL.
pub fn serial4(serial_id: [u8; 8]) -> [u8; 4] {
    let mut serial = [0u8; 4];
    serial.copy_from_slice(&serial_id[..4]);
    serial[0] &= 0x03;
    serial
}

/// Build the READ CONFIG TLV: a leading overall-length byte, then
/// USB_SUPPORTED / SERIAL / FORM_FACTOR / VERSION, then either the persisted
/// `EF_DEV_CONF` blob or the default USB_ENABLED / DEVICE_FLAGS / CONFIG_LOCK
/// tail. Public because the OTP applet serves the same TLV (P1=0x13).
pub fn config_tlv<S: Storage>(serial: &[u8; 4], fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
    let mut buf = [0u8; 128];
    let mut n = 1; // byte 0 = overall length, filled at the end.

    push_tlv(
        &mut buf,
        &mut n,
        TAG_USB_SUPPORTED,
        &SUPPORTED_CAPS.to_be_bytes(),
    );
    push_tlv(&mut buf, &mut n, TAG_SERIAL, serial);
    push_tlv(
        &mut buf,
        &mut n,
        TAG_FORM_FACTOR,
        &[FORM_FACTOR_USB_A_KEYCHAIN],
    );
    let (maj, min, patch) = VERSION;
    push_tlv(&mut buf, &mut n, TAG_VERSION, &[maj, min, patch]);

    let mut conf = [0u8; EF_DEV_CONF_MAX];
    match fs.read(EF_DEV_CONF, &mut conf) {
        Some(full) if full > 0 => {
            // A host wrote an enabled-applications config — echo it back. Two
            // clamps: (1) `Storage::read` reports the value's *full* length even
            // when it exceeds the buffer, so bound `len` before slicing — WRITE
            // CONFIG caps new writes, but a blob from an older build or corrupt
            // flash could be over-length and must not slice past `conf`/`buf`;
            // (2) mask any USB_ENABLED bits down to what this firmware actually
            // supports, so READ CONFIG never reports enabled ⊄ supported.
            let len = full.min(conf.len()).min(buf.len().saturating_sub(n));
            buf[n..n + len].copy_from_slice(&conf[..len]);
            clamp_usb_enabled(&mut buf[n..n + len]);
            n += len;
        }
        _ => {
            // Defaults: everything supported is enabled, removable, unlocked.
            push_tlv(
                &mut buf,
                &mut n,
                TAG_USB_ENABLED,
                &SUPPORTED_CAPS.to_be_bytes(),
            );
            push_tlv(&mut buf, &mut n, TAG_DEVICE_FLAGS, &[FLAG_EJECT]);
            push_tlv(&mut buf, &mut n, TAG_CONFIG_LOCK, &[0x00]);
        }
    }

    buf[0] = (n - 1) as u8;
    res.extend(&buf[..n]);
    Sw::OK
}

/// Failure to persist a device-config blob — shared by the CCID WRITE CONFIG and
/// the FIDO vendor config-write, which map it to their own status/error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevConfError {
    /// Over `EF_DEV_CONF_MAX` — refused so READ CONFIG can never slice past its
    /// fixed buffer (an over-length blob in flash is a sticky DoS).
    TooLong,
    /// The flash write failed.
    Store,
}

/// Validate and persist the device-config TLV to `EF_DEV_CONF` — the
/// transport-agnostic core of WRITE CONFIG, shared by the CCID applet and the
/// FIDO vendor config-write ([`crate::ManagementApplet`] / `rsk-fido`). `blob` is
/// the enabled-applications TLV *without* any transport length prefix; the caller
/// applies its own auth gate (CCID presence, FIDO PIN + touch) before this.
pub fn persist_dev_conf<S: Storage>(fs: &mut Fs<S>, blob: &[u8]) -> Result<(), DevConfError> {
    if blob.len() > EF_DEV_CONF_MAX {
        return Err(DevConfError::TooLong);
    }
    fs.put(EF_DEV_CONF, blob).map_err(|_| DevConfError::Store)
}

impl<'a> ManagementApplet<'a> {
    /// `serial_id` is the device chip id; its first 4 bytes form the serial.
    pub fn new(serial_id: [u8; 8], presence: &'a RefCell<dyn UserPresence>) -> Self {
        Self {
            serial: serial4(serial_id),
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
            return Sw::INCORRECT_PARAMS;
        }
        // READ CONFIG echoes this blob back through a fixed `EF_DEV_CONF_MAX`
        // buffer; refuse to persist more than fits so a read can never slice out
        // of bounds (an over-length blob would otherwise be a sticky DoS — it
        // lives in flash and crashes every DeviceInfo query until wiped).
        if apdu.nc - 1 > EF_DEV_CONF_MAX {
            return Sw::INCORRECT_PARAMS;
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
            Err(DevConfError::TooLong) => Sw::INCORRECT_PARAMS,
            Err(DevConfError::Store) => Sw::MEMORY_FAILURE,
        }
    }

    /// Management RESET (INS 0x1E / ykman's 0x1F): request a device-wide factory
    /// reset. Even on the permissive default this is presence-gated — an
    /// unauthenticated one-APDU wipe from any USB host would be a silent-brick
    /// footgun. The firmware does the flash wipe + reboot after this SW_OK.
    #[cfg(not(feature = "strict-config"))]
    fn request_device_reset(&mut self) -> Sw {
        if !self.require_presence(Confirm::titled("Factory reset the device?")) {
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

/// Clamp any USB_ENABLED (`0x03`) TLV in a persisted config blob to
/// `SUPPORTED_CAPS`, so READ CONFIG never reports an enabled capability this
/// firmware does not implement. A real YubiKey guarantees enabled ⊆ supported;
/// RS-Key echoes the host-written `EF_DEV_CONF` blob, which could carry a wider
/// mask (a newer host that knows capability bits we lack). Walks short-form
/// TLVs in place; a malformed length stops the walk, leaving the rest untouched.
fn clamp_usb_enabled(blob: &mut [u8]) {
    let mut i = 0;
    while i + 2 <= blob.len() {
        let len = blob[i + 1] as usize;
        if i + 2 + len > blob.len() {
            break;
        }
        if blob[i] == TAG_USB_ENABLED && len == 2 {
            let masked =
                (u16::from_be_bytes([blob[i + 2], blob[i + 3]]) & SUPPORTED_CAPS).to_be_bytes();
            blob[i + 2..i + 4].copy_from_slice(&masked);
        }
        i += 2 + len;
    }
}

/// Append a `tag, len, value` TLV; silently truncated by the fixed `read_config`
/// buffer (sized for the largest config, so this never actually overflows).
fn push_tlv(buf: &mut [u8], n: &mut usize, tag: u8, val: &[u8]) {
    if *n + 2 + val.len() > buf.len() {
        return;
    }
    buf[*n] = tag;
    buf[*n + 1] = val.len() as u8;
    buf[*n + 2..*n + 2 + val.len()].copy_from_slice(val);
    *n += 2 + val.len();
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
