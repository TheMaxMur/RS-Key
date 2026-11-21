// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! IO_QSPI as far as the BOOTSEL button: embassy-rp stops driving the flash's CS,
//! lets the button's 1K pull it, and reads the pad back from QSPI_SS's STATUS.
//! Everything else in the block is plain storage.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rp2350_emu::{MmioCtx, MmioDevice};

use super::Regs;

pub const IO_QSPI_BASE: u32 = 0x4003_0000;
const QSPI_SS_STATUS: u32 = 0x018;
const QSPI_SS_CTRL: u32 = 0x01C;
const CTRL_OEOVER_SHIFT: u32 = 14;
const OEOVER_DISABLE: u32 = 2;
const STATUS_INFROMPAD: u32 = 1 << 17;

pub struct IoQspi {
    regs: Regs,
    /// The BOOTSEL button, held down.
    pressed: Arc<AtomicBool>,
}

impl IoQspi {
    pub fn new(pressed: Arc<AtomicBool>) -> Self {
        Self {
            regs: Regs::default(),
            pressed,
        }
    }

    /// CS reads high while the QMI drives it idle; with the drive off, the pad
    /// is what the button makes it.
    fn ss_status(&self) -> u32 {
        let oeover = (self.regs.read(QSPI_SS_CTRL) >> CTRL_OEOVER_SHIFT) & 3;
        let low = oeover == OEOVER_DISABLE && self.pressed.load(Ordering::Relaxed);
        if low { 0 } else { STATUS_INFROMPAD }
    }
}

impl MmioDevice for IoQspi {
    fn read(&mut self, offset: u32, _size: u8, _ctx: &mut MmioCtx) -> u32 {
        let word = match offset & !3 {
            QSPI_SS_STATUS => self.ss_status(),
            o => self.regs.read(o),
        };
        word >> ((offset & 3) * 8)
    }

    fn write(&mut self, offset: u32, value: u32, _size: u8, alias: u32, _ctx: &mut MmioCtx) {
        self.regs
            .write(offset & !3, value << ((offset & 3) * 8), alias);
    }
}

#[cfg(test)]
#[path = "ioqspi_tests.rs"]
mod tests;
