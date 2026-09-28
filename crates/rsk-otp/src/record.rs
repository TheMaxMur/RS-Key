// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! A slot record — the 52-byte config, then the 8-byte tail holding the use counter
//! or the HOTP moving factor — whose bytes only its own methods write, so
//! [`seal_put`](crate::seal::seal_put) takes no tail a caller chose (this must NOT build):
//!
//! ```compile_fail,E0308
//! # fn f<S: rsk_fs::Storage>(dev: &rsk_crypto::Device, fs: &mut rsk_fs::Fs<S>, rng: &mut dyn rsk_otp::Rng) {
//! let rec = [0u8; 60];
//! rsk_otp::seal::seal_put(dev, fs, rng, rsk_fs::KeyFid::new(0xBB00), &rec);
//! # }
//! ```
//!
//! and its twin does:
//!
//! ```
//! # fn f<S: rsk_fs::Storage>(dev: &rsk_crypto::Device, fs: &mut rsk_fs::Fs<S>, rng: &mut dyn rsk_otp::Rng, rec: &rsk_otp::SlotRecord) {
//! rsk_otp::seal::seal_put(dev, fs, rng, rsk_fs::KeyFid::new(0xBB00), rec);
//! # }
//! ```

use rsk_crypto::Device;
use rsk_fs::{Fs, KeyFid, Storage};
use rsk_sdk::error::Result;
use rsk_secret::Secret;

use crate::{CONFIG_SIZE, EF_OTP_SLOT_LAST, EF_OTP_SLOT1, OFF_UID, SLOT_SIZE, counter, seal};

/// A slot record, read from a slot or made by a CONFIGURE. What a read did not fill
/// is zero, so a legacy record (a bare config) reads with a zero tail.
pub struct SlotRecord {
    bytes: Secret<[u8; SLOT_SIZE]>,
    /// The stored length: a verbatim move keeps a legacy record at 52 bytes.
    len: usize,
}

/// Where the tail — the use counter or the HOTP moving factor — starts.
const TAIL: usize = CONFIG_SIZE;

/// Whether `fid` is a slot's: only a slot's bytes may become a record.
fn is_slot(fid: u16) -> bool {
    (EF_OTP_SLOT1..=EF_OTP_SLOT_LAST).contains(&fid)
}

impl SlotRecord {
    /// No record: all zero, nothing stored. What a read fills.
    pub(crate) fn vacant() -> Self {
        Self {
            bytes: Secret::zeroed(),
            len: 0,
        }
    }

    /// The record, config then tail.
    pub(crate) fn expose(&self) -> &[u8; SLOT_SIZE] {
        self.bytes.expose()
    }

    /// What [`seal_put`](crate::seal::seal_put) seals: the record at its length.
    pub(crate) fn stored(&self) -> &[u8] {
        self.bytes.expose().get(..self.len).unwrap_or_default()
    }

    /// Read+unseal slot `fid` under `dev`'s arm, at whatever length it was stored —
    /// [`seal::try_seal_read`]'s answer. A FID outside the slots reads as absent.
    pub(crate) fn try_read<S: Storage>(
        &mut self,
        dev: &Device,
        fs: &mut Fs<S>,
        fid: u16,
    ) -> Result<Option<usize>> {
        self.bytes.wipe();
        self.len = 0;
        if !is_slot(fid) {
            return Ok(None);
        }
        let n = seal::try_seal_read(dev, fs, KeyFid::new(fid), &mut self.bytes)?;
        self.len = n.unwrap_or(0);
        Ok(n)
    }

    /// A legacy slot stored in the clear: `Some` at a config's length up to a full
    /// record's. The scratch holds a whole sealed blob, so one that does not
    /// authenticate reads at its true length and is refused, not truncated. `Err`
    /// is a read the medium could not complete.
    pub(crate) fn try_read_plaintext<S: Storage>(
        &mut self,
        fs: &mut Fs<S>,
        fid: u16,
    ) -> Result<Option<usize>> {
        self.bytes.wipe();
        self.len = 0;
        if !is_slot(fid) {
            return Ok(None);
        }
        let mut raw = Secret::<[u8; seal::MAX_BLOB]>::zeroed();
        let Some(n) = fs.try_read_key(KeyFid::new(fid), raw.expose_mut())? else {
            return Ok(None);
        };
        if !(CONFIG_SIZE..=SLOT_SIZE).contains(&n) {
            return Ok(None);
        }
        let (Some(dst), Some(src)) = (self.bytes.expose_mut().get_mut(..n), raw.expose().get(..n))
        else {
            return Ok(None);
        };
        dst.copy_from_slice(src);
        self.len = n;
        Ok(Some(n))
    }

    /// CONFIGURE: a fresh config, so the tail restarts at zero — as on a YubiKey.
    pub(crate) fn configure(&mut self, cfg: &[u8; CONFIG_SIZE]) {
        self.bytes.wipe();
        self.bytes.expose_mut()[..CONFIG_SIZE].copy_from_slice(cfg);
        self.len = SLOT_SIZE;
    }

    /// UPDATE: `cfg` replaces the config and the tail carries over; only a
    /// re-CONFIGURE resets it. (A 52-byte record here once dropped the tail and
    /// rolled the counter back on the next read — audit run-30.)
    pub(crate) fn reconfigure(&mut self, cfg: &[u8; CONFIG_SIZE]) {
        self.bytes.expose_mut()[..CONFIG_SIZE].copy_from_slice(cfg);
        self.len = SLOT_SIZE;
    }

    /// A Yubico-OTP press: the counter the ticket carries (an unused one promoted
    /// from 0 to 1, the Yubico convention) and the session after it. The tail takes
    /// [`counter::next_use_counter`]'s step; `true` when it moved.
    pub(crate) fn press_yubico(&mut self, session: u8) -> (u16, u8, bool) {
        let rec = self.tail_to_move();
        let stored = u16::from_be_bytes([rec[TAIL], rec[TAIL + 1]]);
        let (typed, promoted) = match stored {
            0 => (1, true),
            n => (n, false),
        };
        let (counter, new_session, bumped) = counter::next_use_counter(typed, session);
        let moved = promoted || bumped;
        if moved {
            rec[TAIL..TAIL + 2].copy_from_slice(&counter.to_be_bytes());
            self.len = SLOT_SIZE;
        }
        (typed, new_session, moved)
    }

    /// An OATH-HOTP press: the moving factor this code is computed over — the tail,
    /// or while that is zero the initial factor in the last two UID bytes — and the
    /// tail takes the next one.
    pub(crate) fn press_hotp(&mut self) -> u64 {
        let rec = self.bytes.expose();
        let programmed = u64::from(u16::from_be_bytes([rec[OFF_UID + 4], rec[OFF_UID + 5]]));
        let rec = self.tail_to_move();
        let mut factor = [0u8; SLOT_SIZE - TAIL];
        factor.copy_from_slice(&rec[TAIL..]);
        let imf = match u64::from_be_bytes(factor) {
            0 => programmed,
            n => n,
        };
        // `wrapping_add` matches the sibling config_seq bumps and removes a debug-panic /
        // release-wrap asymmetry at the (unreachable) u64::MAX factor.
        rec[TAIL..].copy_from_slice(&imf.wrapping_add(1).to_be_bytes());
        self.len = SLOT_SIZE;
        imf
    }

    /// A power cycle's first press, [`counter::cycle_use_counter`]'s: `true` when the
    /// use counter moved; at the ceiling it stays where it is.
    pub(crate) fn cycle_bump(&mut self) -> bool {
        let rec = self.tail_to_move();
        let stored = u16::from_be_bytes([rec[TAIL], rec[TAIL + 1]]);
        let Some(counter) = counter::cycle_use_counter(stored) else {
            return false;
        };
        rec[TAIL..TAIL + 2].copy_from_slice(&counter.to_be_bytes());
        self.len = SLOT_SIZE;
        true
    }

    /// The record whose tail (from [`TAIL`]) a press or a cycle's first press moves. A record
    /// shorter than a full one holds no counter, so the move starts from zero — as
    /// it always has.
    fn tail_to_move(&mut self) -> &mut [u8; SLOT_SIZE] {
        let short = self.len < SLOT_SIZE;
        let rec = self.bytes.expose_mut();
        if short {
            rec[TAIL..].fill(0);
        }
        rec
    }

    /// A record from its stored bytes, `None` past a full record's length: the
    /// tests, the fuzz targets and the emulator seed a slot as it was stored.
    #[cfg(any(test, feature = "test-util"))]
    pub fn from_bytes(stored: &[u8]) -> Option<Self> {
        let mut rec = Self::vacant();
        rec.bytes
            .expose_mut()
            .get_mut(..stored.len())?
            .copy_from_slice(stored);
        rec.len = stored.len();
        Some(rec)
    }
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
#[path = "record_tests.rs"]
mod tests;
