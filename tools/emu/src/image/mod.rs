// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `--image`: the firmware's own ELF on an emulated RP2350, behind the ports the
//! applet stack serves. picoem runs the two Cortex-M33 cores and the bus; the
//! chip models here are what the bootrom and the image lean on beyond it.

mod board;
mod bootram;
mod chip;
mod desc;
mod elf;
mod flash;
mod hc;
mod inspect;
mod ioqspi;
mod otp;
mod psm;
mod qspi;
mod sha256;
mod sockets;
mod trng;
mod usb;
mod watchdog;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rp2350_emu::peripherals::apply_alias_rmw;

pub use board::{Options, run};

/// What the chip models noticed, stamped with the cycle: printed under `--trace`.
pub type Log = Arc<Mutex<Vec<(u64, String)>>>;

/// Plain read/write registers for the parts of a block nothing depends on.
#[derive(Default)]
struct Regs(HashMap<u32, u32>);

impl Regs {
    fn read(&self, offset: u32) -> u32 {
        self.0.get(&(offset & !3)).copied().unwrap_or(0)
    }

    fn write(&mut self, offset: u32, value: u32, alias: u32) {
        apply_alias_rmw(self.0.entry(offset & !3).or_insert(0), value, alias);
    }
}
