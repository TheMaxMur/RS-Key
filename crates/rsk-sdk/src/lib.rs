// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg_attr(not(test), no_std)]

//! `rsk-sdk` — core smartcard machinery: ISO-7816 APDU parsing ([`apdu`]),
//! status words ([`sw`]), BER-TLV ([`tlv`]), the `Applet` trait with AID
//! registry/dispatch ([`applet`]), internal error codes ([`error`]), and the
//! two seams a composition root hands every applet: randomness ([`rng`]) and
//! user presence ([`presence`]).
//!
//! Plus the device identity every applet echoes but none owns —
//! [`FIRMWARE_VERSION`] and [`serial4`]. They are here for the same reason the
//! seams are: four applets report each of them for four unrelated reasons, so
//! whichever applet reported it first is the wrong home.

pub mod apdu;
pub mod applet;
pub mod confirm;
pub mod error;
pub mod presence;
pub mod rng;
pub mod sw;
pub mod tlv;

pub use apdu::Apdu;
pub use applet::{Applet, Dispatcher, ResBuf};
pub use confirm::{Confirm, ConfirmKind};
pub use error::{Error, Result};
pub use presence::{AlwaysConfirm, PinEntry, Presence, UserPresence};
pub use rng::Rng;
pub use sw::Sw;

/// Parse a clean decimal env string to `u8` in const context (build.rs has
/// already validated the range, so this stays minimal).
const fn env_u8(s: &str) -> u8 {
    let b = s.as_bytes();
    let mut acc = 0u8;
    let mut i = 0;
    while i < b.len() {
        acc = acc * 10 + (b[i] - b'0');
        i += 1;
    }
    acc
}

/// Reported device firmware version `(major, minor, patch)` — the single source
/// for the management DeviceInfo, FIDO getInfo (0x0E) and the OATH/OTP/PIV
/// version fields. Defaults to 5.7.4 (a current YubiKey 5); override at build
/// time with `FW_VERSION=X.Y.Z`. The OpenPGP card/applet versions are separate
/// protocol numbers and are unaffected.
pub const FIRMWARE_VERSION: (u8, u8, u8) = (
    env_u8(env!("PK_FW_VERSION_MAJOR")),
    env_u8(env!("PK_FW_VERSION_MINOR")),
    env_u8(env!("PK_FW_VERSION_PATCH")),
);

/// [`FIRMWARE_VERSION`] packed as the FIDO getInfo 0x0E `u32` (`0xMM_mm_pp`).
pub const FIRMWARE_VERSION_U32: u32 = ((FIRMWARE_VERSION.0 as u32) << 16)
    | ((FIRMWARE_VERSION.1 as u32) << 8)
    | (FIRMWARE_VERSION.2 as u32);

/// First 4 bytes of the chip id with the top 6 bits cleared (`&= ~0xFC`) — the
/// 8-digit Yubico serial. The same device identity four applets report for four
/// unrelated reasons (the OpenPGP AID, PIV `INS 0xF8`, OTP GET SERIAL, the
/// management DeviceInfo `SERIAL` tag), so it is declared once here beside
/// [`FIRMWARE_VERSION`] rather than owned by whichever applet reports it first.
pub fn serial4(serial_id: [u8; 8]) -> [u8; 4] {
    let mut serial = [0u8; 4];
    serial.copy_from_slice(&serial_id[..4]);
    serial[0] &= 0x03;
    serial
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
