// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The ROM's 1 MHz watchdog tick, independent of the CPU's step quantum.

use rp2350_emu::peripherals::watchdog::WatchdogRegs;
use rp2350_emu::{MmioCtx, MmioDevice};

pub use rp2350_emu::peripherals::watchdog::WATCHDOG_BASE;

const CTRL: u32 = 0;
const LOAD: u32 = 4;
const ENABLE: u32 = 1 << 30;
const PAUSE: u32 = 7 << 24;
const TIME: u32 = 0x00FF_FFFF;
const TICKS_PER_SECOND: u64 = 1_000_000;

pub struct Watchdog {
    regs: WatchdogRegs,
    phase: u64,
    clock_hz: u32,
    pub reset_requested: bool,
}

impl Watchdog {
    pub fn new() -> Self {
        Self {
            regs: WatchdogRegs::new(),
            phase: 0,
            clock_hz: 1,
            reset_requested: false,
        }
    }
}

impl MmioDevice for Watchdog {
    fn read(&mut self, offset: u32, _size: u8, _ctx: &mut MmioCtx) -> u32 {
        self.regs.read32(offset)
    }

    fn write(&mut self, offset: u32, value: u32, _size: u8, alias: u32, _ctx: &mut MmioCtx) {
        self.reset_requested |= self.regs.write32(offset, value, alias);
        if offset == LOAD {
            self.phase = 0;
        }
    }

    fn tick(&mut self, sys_clks: u32, ctx: &mut MmioCtx) {
        let ctrl = self.regs.read32(CTRL);
        if ctrl & ENABLE == 0 || self.reset_requested {
            return;
        }
        let hz = ctx.sys_clk_hz.max(1);
        if hz != self.clock_hz {
            self.phase = self.phase * u64::from(hz) / u64::from(self.clock_hz);
            self.clock_hz = hz;
        }
        self.phase += u64::from(sys_clks) * TICKS_PER_SECOND;
        let ticks = self.phase / u64::from(hz);
        self.phase %= u64::from(hz);
        if ticks > 0 && ctrl & TIME == 0 {
            self.reset_requested = true;
        }
        // PAUSE bits preserve their readback; no core is held by a debugger here.
        let _ = self.regs.write32(CTRL, ctrl & !PAUSE, 0);
        for _ in 0..ticks.min(u64::from(ctrl & TIME)) {
            self.reset_requested |= self.regs.tick();
        }
        let _ = self.regs.write32(CTRL, ctrl, 0);
    }
}

#[cfg(test)]
#[path = "watchdog_tests.rs"]
mod tests;
