// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The blocking I2C1 driver subset and the board's CST328 and CST3530 reports.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use rp2350_emu::{MmioCtx, MmioDevice};

use super::Regs;

pub const I2C1_BASE: u32 = 0x4009_8000;
const CST328: u32 = 0x1A;
const CST3530: u32 = 0x58;
const TARGET: u32 = 0x04;
const DATA_CMD: u32 = 0x10;
const INTR_STAT: u32 = 0x2C;
const INTR_MASK: u32 = 0x30;
const RAW_INTR_STAT: u32 = 0x34;
const RX_TL: u32 = 0x38;
const CLR_INTR: u32 = 0x40;
const CLR_RX_UNDER: u32 = 0x44;
const CLR_RX_OVER: u32 = 0x48;
const CLR_TX_ABRT: u32 = 0x54;
const CLR_STOP_DET: u32 = 0x60;
const ENABLE: u32 = 0x6C;
const STATUS: u32 = 0x70;
const TXFLR: u32 = 0x74;
const RXFLR: u32 = 0x78;
const TX_ABRT_SOURCE: u32 = 0x80;
const ENABLE_STATUS: u32 = 0x9C;
const FIFO_DEPTH: usize = 16;
const IRQ: u32 = 37;
const TOUCH_RESET: u64 = 1 << 17;
const READ: u32 = 1 << 8;
const STOP: u32 = 1 << 9;
const RX_UNDER: u32 = 1;
const RX_OVER: u32 = 1 << 1;
const TX_ABORT: u32 = 1 << 6;
const STOP_DET: u32 = 1 << 9;
const TX_EMPTY: u32 = 1 << 4;
const RX_FULL: u32 = 1 << 2;
const CST328_REPORT: [u8; 2] = [0xD0, 0x00];
const CST328_ACK: [u8; 3] = [0xD0, 0x05, 0x00];
const CST328_NORMAL: [u8; 2] = [0xD1, 0x09];
const CST3530_REPORT: [u8; 4] = 0xD007_0000u32.to_be_bytes();
const CST3530_ACK: [u8; 4] = 0xD000_02ABu32.to_be_bytes();
const CST328_LEN: usize = 7;
const CST3530_LEN: usize = 9;

#[derive(Default)]
pub struct Touch {
    pub pad: Option<super::taps::Pad>,
    pub point: Option<(u16, u16)>,
    pub until_ns: u64,
    pub now_ns: u64,
    pub reports: u64,
    pub normal: bool,
    pub reset: bool,
    latched: Option<Option<(u16, u16)>>,
}

impl Touch {
    pub fn sample(&mut self, pins: u64) {
        let reset = pins & TOUCH_RESET == 0;
        if reset && !self.reset {
            self.normal = false;
            self.latched = None;
        }
        self.reset = reset;
    }

    fn report(&mut self, target: u32) -> Option<(u16, u16)> {
        if (target == CST328 && !self.normal) || self.reset {
            return None;
        }
        if let Some(report) = self.latched {
            return report;
        }
        self.reports += 1;
        let point = if let Some(pad) = &mut self.pad {
            pad.read(self.now_ns)
                .filter(|p| {
                    usize::from(p.x) < super::panel::WIDTH
                        && usize::from(p.y) < super::panel::HEIGHT
                })
                .map(|p| (p.x, p.y))
        } else if self.now_ns < self.until_ns {
            self.point
        } else {
            None
        };
        self.latched = Some(point);
        point
    }

    pub fn reboot(&mut self, now: u64) {
        self.until_ns = self.until_ns.saturating_sub(now);
        self.now_ns = 0;
        self.normal = false;
        self.reset = true;
        self.latched = None;
        if let Some(pad) = &mut self.pad {
            pad.reboot(now);
        }
    }
}

fn encode_report(target: u32, point: Option<(u16, u16)>) -> [u8; CST3530_LEN] {
    let Some((x, y)) = point else {
        return [0; CST3530_LEN];
    };
    if target == CST328 {
        [
            6,
            (x >> 4) as u8,
            (y >> 4) as u8,
            ((x & 15) << 4 | (y & 15)) as u8,
            0,
            1,
            0,
            0,
            0,
        ]
    } else {
        [
            0,
            0,
            0,
            1,
            x as u8,
            y as u8,
            0,
            ((x >> 8) | ((y >> 8) << 4)) as u8,
            0x20,
        ]
    }
}

pub type SharedTouch = Arc<Mutex<Touch>>;

pub struct I2c {
    pub touch: SharedTouch,
    regs: Regs,
    rx: VecDeque<u8>,
    address: Vec<u8>,
    report: [u8; CST3530_LEN],
    index: usize,
    ended: bool,
    raw: u32,
}

impl I2c {
    pub fn new(touch: SharedTouch) -> Self {
        Self {
            touch,
            regs: Regs::default(),
            rx: VecDeque::new(),
            address: Vec::new(),
            report: [0; CST3530_LEN],
            index: 0,
            ended: true,
            raw: 0,
        }
    }

    fn command(&mut self, word: u32) {
        if self.regs.read(ENABLE) & 1 == 0 {
            return;
        }
        let target = self.regs.read(TARGET);
        let (report, len) = match target {
            CST328 => (CST328_REPORT.as_slice(), CST328_LEN),
            CST3530 => (CST3530_REPORT.as_slice(), CST3530_LEN),
            _ => {
                self.raw |= TX_ABORT | STOP_DET;
                return;
            }
        };
        if self.touch.lock().unwrap().reset {
            self.raw |= TX_ABORT | STOP_DET;
            return;
        }
        if word & READ != 0 {
            if self.address != report || self.index >= len {
                self.raw |= TX_ABORT | STOP_DET;
                return;
            }
            if self.index == 0 {
                self.report = encode_report(target, self.touch.lock().unwrap().report(target));
            }
            if self.rx.len() < FIFO_DEPTH {
                self.rx.push_back(self.report[self.index]);
            } else {
                self.raw |= RX_OVER;
            }
            self.index += 1;
        } else {
            if self.ended {
                self.address.clear();
                self.index = 0;
            }
            if self.address.len() == if target == CST328 { 3 } else { 4 } {
                self.raw |= TX_ABORT | STOP_DET;
                return;
            }
            self.address.push(word as u8);
            let address = self.address.as_slice();
            if target == CST328 && address == CST328_NORMAL {
                self.touch.lock().unwrap().normal = true;
            }
            if (target == CST328 && address == CST328_ACK)
                || (target == CST3530 && address == CST3530_ACK)
            {
                self.touch.lock().unwrap().latched = None;
            }
        }
        self.ended = word & STOP != 0;
        if self.ended {
            self.raw |= STOP_DET;
        }
    }

    fn raw(&self) -> u32 {
        self.raw
            | if self.regs.read(ENABLE) & 1 != 0 {
                TX_EMPTY
            } else {
                0
            }
            | if self.rx.len() as u32 > self.regs.read(RX_TL) {
                RX_FULL
            } else {
                0
            }
    }

    fn irq(&self, ctx: &mut MmioCtx) {
        if self.raw() & self.regs.read(INTR_MASK) != 0 {
            ctx.raise_irqs |= 1 << IRQ;
        }
    }
}

impl MmioDevice for I2c {
    fn read(&mut self, offset: u32, _size: u8, _ctx: &mut MmioCtx) -> u32 {
        match offset {
            DATA_CMD => match self.rx.pop_front() {
                Some(byte) => u32::from(byte),
                None => {
                    self.raw |= RX_UNDER;
                    0
                }
            },
            INTR_STAT => self.raw() & self.regs.read(INTR_MASK),
            RAW_INTR_STAT => self.raw(),
            CLR_INTR => {
                self.raw = 0;
                0
            }
            CLR_RX_UNDER | CLR_RX_OVER | CLR_TX_ABRT | CLR_STOP_DET => {
                self.raw &= !match offset {
                    CLR_RX_UNDER => RX_UNDER,
                    CLR_RX_OVER => RX_OVER,
                    CLR_TX_ABRT => TX_ABORT,
                    _ => STOP_DET,
                };
                0
            }
            STATUS => 6 | if self.rx.is_empty() { 0 } else { 8 },
            TXFLR => 0,
            RXFLR => self.rx.len() as u32,
            TX_ABRT_SOURCE => u32::from(self.raw & TX_ABORT != 0),
            ENABLE_STATUS => self.regs.read(ENABLE) & 1,
            _ => self.regs.read(offset),
        }
    }

    fn write(&mut self, offset: u32, value: u32, _size: u8, alias: u32, ctx: &mut MmioCtx) {
        if offset == DATA_CMD {
            self.command(value);
        } else {
            self.regs.write(offset, value, alias);
            if offset == ENABLE && self.regs.read(ENABLE) & 1 == 0 {
                self.rx.clear();
                self.ended = true;
            }
        }
        self.irq(ctx);
    }

    fn tick(&mut self, _sys_clks: u32, ctx: &mut MmioCtx) {
        self.irq(ctx);
    }
}

#[cfg(test)]
#[path = "touch_tests.rs"]
mod tests;
