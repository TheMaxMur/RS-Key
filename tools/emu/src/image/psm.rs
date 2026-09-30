// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The PSM as far as FRCE_OFF.PROC1: embassy-rp pulses it to put core 1 back
//! into the bootrom's launch wait. The chip watches `core1_off` and
//! `core1_released` and resets the core itself; a device cannot reach one.

use std::sync::Arc;

use rp2350_emu::threaded::CoreAtomics;
use rp2350_emu::{MmioCtx, MmioDevice};

use super::Regs;

pub const PSM_BASE: u32 = 0x4001_8000;
const PSM_FRCE_OFF: u32 = 0x4;
const PSM_DONE: u32 = 0xC;
const PSM_PROC1: u32 = 1 << 24;
const PSM_ALL: u32 = 0x01FF_FFFF;

pub struct Psm {
    regs: Regs,
    /// Core 1 is held from FRCE_OFF.PROC1 until the chip has reset it: a core
    /// running past the release would answer the launch with stale state.
    atomics: Arc<CoreAtomics>,
    pub core1_off: bool,
    pub core1_released: u32,
}

impl Psm {
    pub fn new(atomics: Arc<CoreAtomics>) -> Self {
        Self {
            regs: Regs::default(),
            atomics,
            core1_off: false,
            core1_released: 0,
        }
    }
}

impl MmioDevice for Psm {
    fn read(&mut self, offset: u32, _size: u8, _ctx: &mut MmioCtx) -> u32 {
        let word = match offset & !3 {
            PSM_DONE => PSM_ALL & !self.regs.read(PSM_FRCE_OFF),
            o => self.regs.read(o),
        };
        word >> ((offset & 3) * 8)
    }

    fn write(&mut self, offset: u32, value: u32, _size: u8, alias: u32, _ctx: &mut MmioCtx) {
        let word = offset & !3;
        self.regs.write(word, value << ((offset & 3) * 8), alias);
        if word == PSM_FRCE_OFF {
            let off = self.regs.read(PSM_FRCE_OFF) & PSM_PROC1 != 0;
            if off != self.core1_off {
                self.core1_off = off;
                if off {
                    self.atomics.set_halted(1);
                } else {
                    self.core1_released += 1;
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "psm_tests.rs"]
mod tests;
