// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The TRNG as the bootrom and embassy-rp drive it: a block of 192 samples takes
//! simulated time, EHR_VALID then rises, and reading EHR_DATA5 starts the next
//! block. The bits are SHA-256(seed ‖ counter), so a seeded run is reproducible.

use rp2350_emu::peripherals::apply_alias_rmw;
use rp2350_emu::{MmioCtx, MmioDevice};
use sha2::{Digest, Sha256};

use super::Regs;

pub const TRNG_BASE: u32 = 0x400F_0000;
const TRNG_IRQ: u32 = 39;
const RNG_IMR: u32 = 0x100;
const RNG_ISR: u32 = 0x104;
const RNG_ICR: u32 = 0x108;
const TRNG_VALID: u32 = 0x110;
const EHR_DATA0: u32 = 0x114;
const EHR_DATA5: u32 = 0x128;
const RND_SOURCE_ENABLE: u32 = 0x12C;
const SAMPLE_CNT1: u32 = 0x130;
const TRNG_DEBUG_CONTROL: u32 = 0x138;
const TRNG_SW_RESET: u32 = 0x140;
const TRNG_BUSY: u32 = 0x1B8;
const ISR_EHR_VALID: u32 = 1 << 0;
const DEBUG_VNC_BYPASS: u32 = 1 << 1;

pub struct Trng {
    seed: [u8; 32],
    counter: u64,
    ehr: [u32; 6],
    valid: bool,
    source: bool,
    /// Cycle at which the block being sampled completes.
    sampling_until: Option<u64>,
    isr: u32,
    regs: Regs,
}

impl Trng {
    pub fn new(seed: &[u8]) -> Self {
        let mut s = Sha256::new();
        s.update(b"rsk-emu --image TRNG");
        s.update(seed);
        Self {
            seed: s.finalize().into(),
            counter: 0,
            ehr: [0; 6],
            valid: false,
            source: false,
            sampling_until: None,
            isr: 0,
            regs: Regs::default(),
        }
    }

    /// ~235 cycles per 192 raw samples with SAMPLE_CNT1 = 0 (the ROM's own
    /// figure); the von Neumann balancer roughly quadruples it.
    fn sample_cycles(&self) -> u64 {
        let per_sample = self.regs.read(SAMPLE_CNT1).max(1) as u64;
        let vnc = if self.regs.read(TRNG_DEBUG_CONTROL) & DEBUG_VNC_BYPASS != 0 {
            1
        } else {
            4
        };
        192 * per_sample * vnc + 40
    }

    fn start(&mut self, now: u64) {
        if self.source && !self.valid && self.sampling_until.is_none() {
            self.sampling_until = Some(now + self.sample_cycles());
        }
    }

    fn update(&mut self, now: u64) {
        if let Some(t) = self.sampling_until
            && now >= t
        {
            self.sampling_until = None;
            let mut h = Sha256::new();
            h.update(self.seed);
            h.update(self.counter.to_le_bytes());
            self.counter += 1;
            let d = h.finalize();
            for (w, b) in self.ehr.iter_mut().zip(d.chunks(4)) {
                *w = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            }
            self.valid = true;
            self.isr |= ISR_EHR_VALID;
        }
    }
}

impl MmioDevice for Trng {
    fn read(&mut self, offset: u32, _size: u8, ctx: &mut MmioCtx) -> u32 {
        self.update(ctx.cycle);
        match offset & !3 {
            RNG_ISR => self.isr,
            TRNG_VALID => self.valid as u32,
            TRNG_BUSY => self.sampling_until.is_some() as u32,
            RND_SOURCE_ENABLE => self.source as u32,
            o @ EHR_DATA0..=EHR_DATA5 => {
                let v = if self.valid {
                    self.ehr[((o - EHR_DATA0) / 4) as usize]
                } else {
                    0
                };
                if o == EHR_DATA5 && self.valid {
                    self.valid = false;
                    self.start(ctx.cycle);
                }
                v
            }
            // The ROM uses this read as a delay and as its loop counter's start.
            TRNG_SW_RESET => 0,
            o => self.regs.read(o),
        }
    }

    fn write(&mut self, offset: u32, value: u32, _size: u8, alias: u32, ctx: &mut MmioCtx) {
        self.update(ctx.cycle);
        match offset & !3 {
            RND_SOURCE_ENABLE => {
                let mut v = self.source as u32;
                apply_alias_rmw(&mut v, value, alias);
                self.source = v & 1 != 0;
                if self.source {
                    self.start(ctx.cycle);
                } else {
                    self.sampling_until = None;
                }
            }
            RNG_ICR => self.isr &= !value,
            TRNG_SW_RESET if value & 1 != 0 => {
                self.valid = false;
                self.isr = 0;
                self.source = false;
                self.sampling_until = None;
            }
            o => self.regs.write(o, value, alias),
        }
    }

    fn tick(&mut self, _sys_clks: u32, ctx: &mut MmioCtx) {
        self.update(ctx.cycle);
        if self.isr & !self.regs.read(RNG_IMR) & 0xF != 0 {
            ctx.raise_irqs |= 1 << TRNG_IRQ;
        }
    }
}

#[cfg(test)]
#[path = "trng_tests.rs"]
mod tests;
