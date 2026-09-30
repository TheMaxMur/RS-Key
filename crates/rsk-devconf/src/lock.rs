// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The configuration lock, `ykman config set-lock-code`: while a code is set, a
//! DeviceInfo write lands only if it carries that code in `UNLOCK`, whichever of
//! the four transports sends it. The code itself is never stored — `EF_DEV_LOCK`
//! holds a salted SHA-256 verifier of it — and READ CONFIG reports only whether
//! one is set.

use rsk_crypto::{ct_eq, sha256};
use rsk_fs::{Fs, Storage};
use rsk_secret::Secret;

use crate::{DevConfError, TAG_CONFIG_LOCK, TAG_CONFIG_UNLOCK, tag_value};

/// EF holding the lock's verifier; absent is unlocked, as every device upgrades, since
/// no earlier build wrote this FID. It survives `authenticatorReset` like
/// `EF_DEV_CONF`: a factory wipe or a flash erase is what clears a lost code.
pub(crate) const EF_DEV_LOCK: u16 = 0x1124;

/// A lock code's width in either tag; yubikit sends no other.
pub(crate) const LOCK_CODE_LEN: usize = 16;

/// `EF_DEV_LOCK` is `[LOCK_FORMAT, verifier]`, the verifier SHA-256 over
/// [`LOCK_DOMAIN`], the DeviceInfo serial and the code. The serial salts it, so one
/// precomputed table does not serve every device.
const LOCK_FORMAT: u8 = 0x01;
const LOCK_VERIFIER_LEN: usize = 32;
const LOCK_RECORD_LEN: usize = 1 + LOCK_VERIFIER_LEN;
const LOCK_DOMAIN: &[u8] = b"RS-Key/CONFIG-LOCK";
const LOCK_INPUT_LEN: usize = LOCK_DOMAIN.len() + 4 + LOCK_CODE_LEN;

/// The lock as `EF_DEV_LOCK` records it.
#[derive(Clone, Copy)]
enum Lock {
    Unlocked,
    /// Set. `None` is a record no code can be checked against — a later format or
    /// a damaged one — which stays locked rather than opening.
    Locked(Option<[u8; LOCK_VERIFIER_LEN]>),
}

/// What a write the lock lets through does to it.
pub(crate) enum LockChange {
    Keep,
    /// A new code over a set one: the write carried the current code.
    Set([u8; LOCK_VERIFIER_LEN]),
    /// A code where none is set, which no code stands behind: it takes a touch.
    Arm([u8; LOCK_VERIFIER_LEN]),
    Clear,
}

fn read_lock<S: Storage>(fs: &mut Fs<S>) -> Result<Lock, DevConfError> {
    let mut rec = [0u8; LOCK_RECORD_LEN];
    match fs.try_read(EF_DEV_LOCK, &mut rec) {
        Ok(None) => Ok(Lock::Unlocked),
        Ok(Some(n)) => Ok(Lock::Locked(match rec {
            [LOCK_FORMAT, verifier @ ..] if n == LOCK_RECORD_LEN => Some(verifier),
            _ => None,
        })),
        Err(_) => Err(DevConfError::Store),
    }
}

/// The DeviceInfo `CONFIG_LOCK` byte: `01` while a code is set. A record that cannot
/// be read reports locked, the one answer that promises no write it would refuse.
pub(crate) fn lock_reported<S: Storage>(fs: &mut Fs<S>) -> u8 {
    match read_lock(fs) {
        Ok(Lock::Unlocked) => 0x00,
        _ => 0x01,
    }
}

/// The lock covers the phy and LED records too, where no code opens it: a host write
/// of either is refused while a code is set, as a DeviceInfo write without one is,
/// and a record that cannot be read refuses as well.
pub fn ensure_unlocked<S: Storage>(fs: &mut Fs<S>) -> Result<(), DevConfError> {
    match read_lock(fs)? {
        Lock::Unlocked => Ok(()),
        Lock::Locked(_) => Err(DevConfError::Locked),
    }
}

/// Whether `blob` may pass the lock, and what it does to it. Locked, a write needs the
/// code in `UNLOCK` — `6986` without, `63C0` wrong, no retry counter, as on a YubiKey
/// 5.8.0. A `CONFIG_LOCK` of sixteen zero bytes clears the lock; any other sets it.
pub(crate) fn lock_change<S: Storage>(
    serial: &[u8; 4],
    fs: &mut Fs<S>,
    blob: &[u8],
) -> Result<LockChange, DevConfError> {
    let lock = read_lock(fs)?;
    if let Lock::Locked(stored) = lock {
        let code = tag_value(blob, TAG_CONFIG_UNLOCK).ok_or(DevConfError::Locked)?;
        let opens = match (stored, <&[u8; LOCK_CODE_LEN]>::try_from(code)) {
            (Some(stored), Ok(code)) => ct_eq(&verifier(serial, code), &stored),
            _ => false,
        };
        if !opens {
            return Err(DevConfError::WrongCode);
        }
    }
    let Some(code) = tag_value(blob, TAG_CONFIG_LOCK) else {
        return Ok(LockChange::Keep);
    };
    let code = <&[u8; LOCK_CODE_LEN]>::try_from(code).map_err(|_| DevConfError::BadTlv)?;
    if code.iter().all(|&b| b == 0) {
        return Ok(match lock {
            Lock::Unlocked => LockChange::Keep,
            Lock::Locked(_) => LockChange::Clear,
        });
    }
    let new = verifier(serial, code);
    Ok(match lock {
        Lock::Locked(Some(stored)) if ct_eq(&new, &stored) => LockChange::Keep,
        Lock::Locked(_) => LockChange::Set(new),
        Lock::Unlocked => LockChange::Arm(new),
    })
}

impl LockChange {
    /// Store what the change leaves: the new verifier, or no record at all.
    pub(crate) fn apply<S: Storage>(self, fs: &mut Fs<S>) -> Result<(), DevConfError> {
        let stored = match self {
            Self::Keep => return Ok(()),
            Self::Set(verifier) | Self::Arm(verifier) => {
                let mut rec = [LOCK_FORMAT; LOCK_RECORD_LEN];
                for (dst, src) in rec.iter_mut().skip(1).zip(verifier) {
                    *dst = src;
                }
                fs.put(EF_DEV_LOCK, &rec)
            }
            Self::Clear => fs.delete(EF_DEV_LOCK),
        };
        stored.map_err(|_| DevConfError::Store)
    }
}

/// The verifier `EF_DEV_LOCK` keeps for `code`.
fn verifier(serial: &[u8; 4], code: &[u8; LOCK_CODE_LEN]) -> [u8; LOCK_VERIFIER_LEN] {
    let mut input = Secret::<[u8; LOCK_INPUT_LEN]>::zeroed();
    let parts = LOCK_DOMAIN.iter().chain(serial).chain(code);
    for (dst, &src) in input.expose_mut().iter_mut().zip(parts) {
        *dst = src;
    }
    sha256(input.expose())
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    reason = "a test's fixture is its own bound, and a panic is its failure report"
)]
#[path = "lock_tests.rs"]
mod tests;
