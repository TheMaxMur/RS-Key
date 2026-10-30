// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Boot-only completion of page-58 provisioning, after migration and scrubbing.

use rsk_secret::Secret;

use crate::otp_lock::{
    LockDecision, PAGE58_LATCH_VALUE, PAGE58_LOCK_VALUE, PAGE58_LOCK1_ROW, arms_closed,
    lock_decision,
};

pub const DEVK_ROW: usize = 0xE80;
pub const MKEK_ROW: usize = 0xE90;
pub const KEY_ROWS: usize = 16;
pub const CHAFF_OFFSET: usize = 0x20;
const RAW_MASK: u32 = 0x00FF_FFFF;

/// READ 1E/09's boot result. No key material is exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Unchecked = 0,
    Unprovisioned = 1,
    Sealed = 2,
    MigrationPending = 3,
    ScrubPending = 4,
    Incomplete = 5,
    ReadFailed = 6,
    ForeignLock = 7,
    WriteFailed = 8,
    TestKeys = 9,
    PartialLatch = 10,
    IncompleteLock = 11,
}

/// Only page 58's access bits and latch can be written through this boot seam.
pub trait Otp {
    fn test_keys(&self) -> bool;
    fn read_raw(&mut self, row: usize) -> Option<u32>;
    fn read_ecc(&mut self, row: usize) -> Option<u16>;
    fn burn_lock(&mut self, value: u32) -> bool;
}

fn read_key(otp: &mut impl Otp, row: usize, key: &mut [u8; 32]) -> Result<bool, Status> {
    let mut any = false;
    for (i, bytes) in key.as_chunks_mut::<2>().0.iter_mut().enumerate() {
        let raw = otp.read_raw(row + i).ok_or(Status::ReadFailed)? & RAW_MASK;
        any |= raw != 0;
        let word = otp.read_ecc(row + i).ok_or(Status::ReadFailed)?;
        let encoded = ecc_encode(word);
        let distance = (raw ^ encoded)
            .count_ones()
            .min((raw ^ encoded ^ RAW_MASK).count_ones());
        if distance > 1 {
            return Err(Status::Incomplete);
        }
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    Ok(any)
}

fn verify_chaff(otp: &mut impl Otp) -> Result<(), Status> {
    for base in [DEVK_ROW, MKEK_ROW] {
        for i in 0..KEY_ROWS {
            let raw = otp.read_raw(base + i).ok_or(Status::ReadFailed)?;
            let chaff = otp
                .read_raw(base + CHAFF_OFFSET + i)
                .ok_or(Status::ReadFailed)?;
            if (raw ^ chaff) & RAW_MASK != RAW_MASK {
                return Err(Status::Incomplete);
            }
        }
    }
    Ok(())
}

/// RP2350 ROM's 16-bit data / 6-bit parity code, before optional polarity repair.
fn ecc_encode(word: u16) -> u32 {
    let mut raw = u32::from(word);
    for (i, parity) in [0xAD5B, 0x366D, 0xC78E, 0x07F0, 0xF800, 0x1FFFFF]
        .iter()
        .enumerate()
    {
        raw |= ((raw & parity).count_ones() & 1) << (16 + i);
    }
    raw
}

/// Validate the real keys before storage can migrate under their root. Chaff is
/// the completion evidence for an unlocked page; a finished latch is immutable.
pub fn check_provisioning(otp: &mut impl Otp) -> Result<Option<u32>, Status> {
    if otp.test_keys() {
        return Err(Status::TestKeys);
    }
    let raw = otp.read_raw(PAGE58_LOCK1_ROW).ok_or(Status::ReadFailed)?;
    let mut mkek = Secret::<[u8; 32]>::zeroed();
    let mut devk = Secret::<[u8; 32]>::zeroed();
    let mkek_present = read_key(otp, MKEK_ROW, mkek.expose_mut())?;
    let devk_present = read_key(otp, DEVK_ROW, devk.expose_mut())?;
    if !mkek_present && !devk_present && raw == 0 {
        return Ok(None);
    }
    if !mkek_present || !devk_present || k256::SecretKey::from_slice(devk.expose()).is_err() {
        return Err(Status::Incomplete);
    }
    mkek.wipe();
    devk.wipe();
    validate_lock(raw)?;
    if raw != PAGE58_LATCH_VALUE {
        verify_chaff(otp)?;
    }
    Ok(Some(raw))
}

fn validate_lock(raw: u32) -> Result<(), Status> {
    if lock_decision(raw) == LockDecision::Unexpected {
        return Err(Status::ForeignLock);
    }
    let secure_read_only = PAGE58_LATCH_VALUE ^ PAGE58_LOCK_VALUE;
    if (raw & secure_read_only).count_ones() >= 2 && !arms_closed(raw) {
        return Err(Status::IncompleteLock);
    }
    Ok(())
}

/// A prior marker can outlive a best-effort wipe whose re-arm failed. Before
/// the irreversible latch, force a fresh successful scrub after all boot passes.
pub fn scrub_before_seal<S: rsk_fs::Storage>(fs: &mut rsk_fs::Fs<S>) -> bool {
    if rsk_fs::request_rescrub(fs).is_err() {
        return false;
    }
    rsk_fs::run_at_rest_lap(fs);
    let mut marker = [0; 1];
    fs.read(rsk_fs::EF_HARDENED, &mut marker) == Some(1) && marker == [1]
}

/// A successful or partial burn may close the fuse before its readback fails.
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    pub status: Status,
    pub restart: bool,
    pub quarantine: bool,
}

/// Runs before serving commands. Unknown post-write state fences root reads;
/// a newly closed latch requires a scrubbed reboot to refresh all RAM bindings.
pub fn seal_at_boot(
    otp: &mut impl Otp,
    left: Option<u16>,
    scrubbed: bool,
    was_latched: bool,
) -> Outcome {
    let result = finish(otp, left, scrubbed);
    match result {
        Ok((status, raw)) => Outcome {
            status,
            restart: !was_latched && arms_closed(raw),
            quarantine: false,
        },
        Err(status) => Outcome {
            status,
            restart: false,
            quarantine: matches!(
                status,
                Status::ReadFailed
                    | Status::ForeignLock
                    | Status::Incomplete
                    | Status::IncompleteLock
            ),
        },
    }
}

fn finish(otp: &mut impl Otp, left: Option<u16>, scrubbed: bool) -> Result<(Status, u32), Status> {
    let Some(before) = check_provisioning(otp)? else {
        return Ok((Status::Unprovisioned, 0));
    };
    // ROM checks a lock-row write against the page it protects. Once the
    // majority sets Secure read-only, it cannot complete a torn third copy.
    if before != PAGE58_LATCH_VALUE && arms_closed(before) {
        return Ok((Status::PartialLatch, before));
    }
    match lock_decision(before) {
        LockDecision::AlreadyLocked => return Ok((Status::Sealed, before)),
        LockDecision::Unexpected => return Err(Status::ForeignLock),
        LockDecision::Write | LockDecision::Latch => {}
    }
    if left != Some(0) {
        return Err(Status::MigrationPending);
    }
    if !scrubbed {
        return Err(Status::ScrubPending);
    }
    // Complete every access-lock copy before setting Secure read-only: ROM
    // cannot repair missing BOOTSEL/Non-secure bits after that majority lands.
    let mut current = before;
    let access = before | PAGE58_LOCK_VALUE;
    if before != access {
        let written = otp.burn_lock(access);
        current = read_after_burn(otp, before)?;
        if !written || current != access {
            return Ok((Status::WriteFailed, current));
        }
    }
    let written = otp.burn_lock(PAGE58_LATCH_VALUE);
    let after = read_after_burn(otp, current)?;
    let status = if written && after == PAGE58_LATCH_VALUE {
        Status::Sealed
    } else {
        Status::WriteFailed
    };
    Ok((status, after))
}

fn read_after_burn(otp: &mut impl Otp, before: u32) -> Result<u32, Status> {
    let after = otp.read_raw(PAGE58_LOCK1_ROW).ok_or(Status::ReadFailed)?;
    validate_lock(after)?;
    if after & before != before {
        return Err(Status::ForeignLock);
    }
    Ok(after)
}

#[cfg(test)]
#[path = "seal_tests.rs"]
mod tests;
