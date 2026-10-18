// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Volatile Quad Enable and continuous-read sequencing for the Puya P25Q32H.

pub const QUAD_READ: u8 = 0xeb;
pub const CONTINUOUS_SUFFIX: u8 = 0xa0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadStep {
    Prepare,
    Prime,
    OmitPrefix,
    Probe,
    Release,
    Restore,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadMode {
    Unchanged,
    Continuous,
    Restored,
    Fatal,
}

/// Prime exactly one word, then omit EBh; never return through an unproven mode.
#[inline(always)]
pub fn continuous_read(mut step: impl FnMut(ReadStep) -> bool) -> ReadMode {
    if !step(ReadStep::Prepare) {
        return ReadMode::Unchanged;
    }
    let primed = step(ReadStep::Prime);
    if !step(ReadStep::OmitPrefix) {
        return ReadMode::Fatal;
    }
    if primed && step(ReadStep::Probe) {
        return ReadMode::Continuous;
    }
    if !step(ReadStep::Release) || !step(ReadStep::Restore) || !step(ReadStep::Probe) {
        return ReadMode::Fatal;
    }
    ReadMode::Restored
}

const PUYA_ID: [u8; 3] = [0x85, 0x60, 0x16];
const QE: u8 = 2;
const READ_ID: u8 = 0x9f;
const READ_STATUS: u8 = 0x05;
const READ_STATUS1: u8 = 0x35;
const VOLATILE_ENABLE: u8 = 0x50;
const WRITE_STATUS1: u8 = 0x31;

pub trait Commands {
    fn transfer(&mut self, command: u8, payload: Option<u8>, output: &mut [u8]) -> bool;
}

/// Refuse unknown chips, active writes and protected/unsupported status layouts.
#[inline(always)]
pub fn enable(commands: &mut impl Commands) -> bool {
    let mut id = [0; 3];
    let mut status = [0; 1];
    let mut extended = [0; 1];
    if !commands.transfer(READ_ID, None, &mut id)
        || id != PUYA_ID
        || !commands.transfer(READ_STATUS, None, &mut status)
        || status != [0]
        || !commands.transfer(READ_STATUS1, None, &mut extended)
        || extended[0] & !QE != 0
    {
        return false;
    }
    if extended == [QE] {
        return true;
    }
    // P25Q32H §10.4: 50h selects volatile SR writes without setting WEL.
    if !commands.transfer(VOLATILE_ENABLE, None, &mut [])
        || !commands.transfer(WRITE_STATUS1, Some(QE), &mut [])
    {
        return false;
    }
    commands.transfer(READ_STATUS1, None, &mut extended)
        && extended == [QE]
        && commands.transfer(READ_STATUS, None, &mut status)
        && status == [0]
}

#[cfg(test)]
#[path = "flash_quad_tests.rs"]
mod tests;
