// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Functional CPU streaming reads; XIP cache misses and QSPI timing are not modelled.

use std::sync::{Arc, Mutex};

use rp2350_emu::peripherals::apply_alias_rmw;
use rp2350_emu::{MmioCtx, MmioDevice};

pub const XIP_CTRL_BASE: u32 = 0x400C_8000;
pub const XIP_AUX_BASE: u32 = 0x5050_0000;
const CTRL: u32 = 0;
const STAT: u32 = 8;
const ADDR: u32 = 0x14;
const COUNT: u32 = 0x18;
const FIFO: u32 = 0x1C;
const COUNT_MASK: u32 = 0x003F_FFFF;
const ADDRESS_MASK: u32 = 0x03FF_FFFC;

pub struct Xip {
    control: u32,
    address: u32,
    remaining: u32,
    fifo: [u32; 2],
    len: usize,
}

impl Default for Xip {
    fn default() -> Self {
        Self {
            control: 0x83,
            address: 0,
            remaining: 0,
            fifo: [0; 2],
            len: 0,
        }
    }
}

impl Xip {
    fn fill(&mut self, ctx: &mut MmioCtx) {
        while self.remaining != 0 && self.len < self.fifo.len() {
            let offset = self.address as usize;
            let Some(bytes) = ctx.flash().get(offset..offset + 4) else {
                ctx.bus_fault();
                return;
            };
            let Ok(word) = bytes.try_into() else {
                ctx.bus_fault();
                return;
            };
            self.fifo[self.len] = u32::from_le_bytes(word);
            self.len += 1;
            self.address = self.address.wrapping_add(4) & ADDRESS_MASK;
            self.remaining -= 1;
        }
    }
}

impl MmioDevice for Xip {
    fn read(&mut self, offset: u32, size: u8, ctx: &mut MmioCtx) -> u32 {
        if size != 4 || !offset.is_multiple_of(4) {
            ctx.bus_fault();
            return 0;
        }
        match offset {
            CTRL => self.control,
            STAT => {
                self.fill(ctx);
                (u32::from(self.len == 0) << 1) | (u32::from(self.len == self.fifo.len()) << 2)
            }
            ADDR => self.address,
            COUNT => self.remaining,
            FIFO if self.len != 0 => {
                let word = self.fifo[0];
                self.fifo[0] = self.fifo[1];
                self.len -= 1;
                word
            }
            FIFO => {
                ctx.bus_fault();
                0
            }
            _ => 0,
        }
    }
    fn write(&mut self, offset: u32, value: u32, size: u8, alias: u32, ctx: &mut MmioCtx) {
        if size != 4 || !offset.is_multiple_of(4) {
            ctx.bus_fault();
            return;
        }
        match offset {
            CTRL => apply_alias_rmw(&mut self.control, value, alias),
            ADDR => {
                apply_alias_rmw(&mut self.address, value, alias);
                self.address &= ADDRESS_MASK;
            }
            COUNT => {
                apply_alias_rmw(&mut self.remaining, value, alias);
                self.remaining &= COUNT_MASK;
            }
            _ => {}
        }
    }
    fn tick(&mut self, _clocks: u32, ctx: &mut MmioCtx) {
        self.fill(ctx);
    }
}

#[derive(Clone, Default)]
pub struct SharedXip(Arc<Mutex<Xip>>);

impl SharedXip {
    pub fn aux(&self) -> XipAux {
        XipAux(self.0.clone())
    }
}

impl MmioDevice for SharedXip {
    fn read(&mut self, offset: u32, size: u8, ctx: &mut MmioCtx) -> u32 {
        let Ok(mut state) = self.0.lock() else {
            ctx.bus_fault();
            return 0;
        };
        state.read(offset, size, ctx)
    }
    fn write(&mut self, offset: u32, value: u32, size: u8, alias: u32, ctx: &mut MmioCtx) {
        let Ok(mut state) = self.0.lock() else {
            ctx.bus_fault();
            return;
        };
        state.write(offset, value, size, alias, ctx);
    }
    fn tick(&mut self, clocks: u32, ctx: &mut MmioCtx) {
        let Ok(mut state) = self.0.lock() else {
            ctx.bus_fault();
            return;
        };
        state.tick(clocks, ctx);
    }
}

pub struct XipAux(Arc<Mutex<Xip>>);
impl MmioDevice for XipAux {
    fn read(&mut self, offset: u32, size: u8, ctx: &mut MmioCtx) -> u32 {
        if offset != 0 {
            return 0;
        }
        let Ok(mut state) = self.0.lock() else {
            ctx.bus_fault();
            return 0;
        };
        state.read(FIFO, size, ctx)
    }
    fn write(&mut self, _offset: u32, _value: u32, _size: u8, _alias: u32, _ctx: &mut MmioCtx) {}
}

#[cfg(test)]
#[path = "xip_tests.rs"]
mod tests;
