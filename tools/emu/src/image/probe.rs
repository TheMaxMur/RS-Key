// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Laboratory access to the running cores and their SRAM, outside the USB path.

use super::Chip;
use crate::image::inspect::{PAINT, SRAM_BASE, SRAM_LEN, Stack};
use crate::image::qspi::Qmi;

impl Chip {
    pub fn measuring(&self) -> bool {
        self.stacks.is_some()
    }

    pub fn arm_cycles(&mut self) {
        self.emu
            .bus
            .mmio_device_mut::<Qmi>(self.h_qmi)
            .unwrap()
            .flash
            .arm_cycles();
    }

    pub fn programmed_bytes(&self) -> u64 {
        self.emu
            .bus
            .mmio_device::<Qmi>(self.h_qmi)
            .map_or(0, |q| q.flash.stats.programmed_bytes)
    }

    pub fn begin_measurement(&mut self) -> Result<String, String> {
        let exact = |name: &str| {
            self.elf
                .symbols
                .iter()
                .find(|s| s.name == name)
                .map(|s| s.value)
                .ok_or_else(|| format!("ELF has no {name}"))
        };
        let core1 = self
            .elf
            .symbol(&["core1", "CORE1_STACK"])
            .ok_or("ELF has no core1 stack symbol")?;
        let bounds = [
            (exact("_stack_end")?, exact("_stack_start")?),
            (core1.value, core1.value + core1.size),
        ];
        let mut stacks = Vec::new();
        for (c, (symbol_low, top)) in bounds.into_iter().enumerate() {
            let low = self.emu.core(c).regs.msplim;
            let sp = self.emu.core(c).regs.sp();
            if !(SRAM_BASE..SRAM_BASE + SRAM_LEN).contains(&low)
                || low < symbol_low
                || top > SRAM_BASE + SRAM_LEN
                || !(low..=top).contains(&sp)
            {
                return Err(format!("core {c} is outside its ELF stack: {sp:#x}"));
            }
            stacks.push(Stack {
                low,
                top,
                initial_sp: sp,
                min_sp: sp,
            });
        }
        for stack in &stacks {
            for a in stack.low..stack.initial_sp {
                self.emu.bus.memory.sram_write8(a - SRAM_BASE, PAINT);
            }
        }
        self.stacks = Some([stacks[0].clone(), stacks[1].clone()]);
        Ok(format!("cycle={}", self.cycles()))
    }

    pub fn end_measurement(&mut self) -> Result<String, String> {
        let stacks = self.stacks.take().ok_or("no measurement is active")?;
        let mut report = vec![format!("cycle={}", self.cycles())];
        for (c, stack) in stacks.iter().enumerate() {
            let touched = (stack.low..stack.initial_sp)
                .find(|a| self.emu.bus.memory.sram_read8(*a - SRAM_BASE) != PAINT);
            report.push(format!(
                "core{c}_low={} core{c}_top={} core{c}_min={} core{c}_used={} core{c}_painted={}",
                stack.low,
                stack.top,
                stack.min_sp,
                stack.top.saturating_sub(stack.min_sp),
                touched.map_or(0, |a| stack.top - a)
            ));
        }
        Ok(report.join(" "))
    }

    pub fn scan_sram(&self, pattern: &[u8]) -> String {
        let bytes: Vec<_> = (0..SRAM_LEN)
            .map(|a| self.emu.bus.memory.sram_read8(a))
            .collect();
        let hits: Vec<_> = bytes
            .windows(pattern.len())
            .enumerate()
            .filter(|(_, w)| *w == pattern)
            .map(|(i, _)| format!("{:08x}", SRAM_BASE + i as u32))
            .collect();
        format!("count={} addresses={}", hits.len(), hits.join(","))
    }

    pub fn plant_sram(&mut self, address: u32, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            self.emu
                .bus
                .memory
                .sram_write8(address - SRAM_BASE + i as u32, b);
        }
    }

    pub fn arm_program_cut(&mut self, bytes: u64) {
        self.emu
            .bus
            .mmio_device_mut::<Qmi>(self.h_qmi)
            .unwrap()
            .flash
            .arm_cut(bytes);
    }

    pub fn program_cut(&self) -> Option<u64> {
        self.emu.bus.mmio_device::<Qmi>(self.h_qmi).and_then(|q| {
            q.flash
                .cut_cycle
                .or(q.flash.cut_at.filter(|&at| self.cycles() >= at))
        })
    }

    pub fn arm_program_cycles(&mut self, cycles: u64) {
        self.emu
            .bus
            .mmio_device_mut::<Qmi>(self.h_qmi)
            .unwrap()
            .flash
            .arm_program_cycles(cycles);
    }

    pub fn program_cut_armed(&self) -> bool {
        self.emu
            .bus
            .mmio_device::<Qmi>(self.h_qmi)
            .is_some_and(|q| q.flash.cut_armed())
    }

    pub fn cut_flash(&mut self) -> String {
        let cycle = self.cycles();
        let pending = self
            .emu
            .bus
            .mmio_device_mut::<Qmi>(self.h_qmi)
            .unwrap()
            .flash
            .tear(cycle);
        if let Some((off, bytes, description)) = pending {
            self.emu.bus.memory.xip_write(off, &bytes);
            self.qmi_ops_seen = u64::MAX;
            description
        } else {
            "idle".into()
        }
    }
}
