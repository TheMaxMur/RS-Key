// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Laboratory access to the running cores and their SRAM, outside the USB path.

use super::Chip;
use crate::image::inspect::{PAINT, SRAM_BASE, SRAM_LEN, Stack, Stacks};
use crate::image::qspi::Qmi;

pub(super) fn stack_registers(
    core: &rp2350_emu::CortexM33,
    secure: bool,
) -> Result<(u32, u32), String> {
    // picoem swaps the pairs on each transition; *_ns holds the inactive bank.
    let active = core.is_secure() == secure;
    let control = if active {
        core.regs.control
    } else {
        core.regs.control_ns
    };
    if control & 2 != 0 {
        return Err("process-stack measurement is unsupported".into());
    }
    Ok(if active {
        (core.regs.sp(), core.regs.msplim)
    } else {
        (core.regs.msp_ns, core.regs.msplim_ns)
    })
}

fn nonsecure_region(core: &rp2350_emu::CortexM33, start: u32, end: u32) -> Option<u32> {
    if core.ppb.sau_ctrl & 1 == 0 {
        return None;
    }
    let mut matches =
        core.ppb.sau_regions.iter().filter(|&&(base, limit)| {
            limit & 1 != 0 && (base & !31) <= end && start <= (limit | 31)
        });
    let &(base, limit) = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    let base = base & !31;
    (limit & 3 == 1 && base <= start && end <= (limit | 31)).then_some(base)
}

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
        if !self.emu.core(1).is_secure() {
            return Err("Non-secure core1 stack measurement is unsupported".into());
        }
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
            let (sp, low) = stack_registers(self.emu.core(c), true)?;
            stacks.push(Stack::checked(
                low,
                top,
                sp,
                symbol_low,
                &format!("core {c}"),
            )?);
        }
        let stacks = Stacks {
            secure: [stacks[0].clone(), stacks[1].clone()],
            nonsecure: self.nonsecure_stack()?,
        };
        let measured: Vec<_> = stacks
            .secure
            .iter()
            .chain(stacks.nonsecure.iter())
            .collect();
        for (index, stack) in measured.iter().enumerate() {
            if measured[..index]
                .iter()
                .any(|other| stack.low < other.top && other.low < stack.top)
            {
                return Err("ELF stack ranges overlap".into());
            }
        }
        for stack in measured {
            for a in stack.low..stack.initial_sp {
                self.emu.bus.memory.sram_write8(a - SRAM_BASE, PAINT);
            }
        }
        self.stacks = Some(stacks);
        Ok(format!("cycle={}", self.cycles()))
    }

    pub fn end_measurement(&mut self) -> Result<String, String> {
        let stacks = self.stacks.take().ok_or("no measurement is active")?;
        let mut report = vec![format!("cycle={}", self.cycles())];
        let mut measured: Vec<_> = stacks
            .secure
            .iter()
            .enumerate()
            .map(|(c, stack)| (format!("core{c}"), stack))
            .collect();
        if let Some(stack) = &stacks.nonsecure {
            measured.push(("ns0".into(), stack));
        }
        for (name, stack) in measured {
            let touched = (stack.low..stack.initial_sp)
                .find(|a| self.emu.bus.memory.sram_read8(*a - SRAM_BASE) != PAINT);
            report.push(format!(
                "{name}_low={} {name}_top={} {name}_min={} {name}_used={} {name}_painted={}",
                stack.low,
                stack.top,
                stack.min_sp,
                stack.top.saturating_sub(stack.min_sp),
                touched.map_or(0, |a| stack.top - a)
            ));
        }
        Ok(report.join(" "))
    }

    fn nonsecure_stack(&self) -> Result<Option<Stack>, String> {
        let core = self.emu.core(0);
        let vector = core.ppb.ns.vtor;
        let bytes = self.elf.segments.iter().find_map(|segment| {
            let offset = vector.checked_sub(segment.paddr)? as usize;
            segment.data.get(offset..offset + 8)
        });
        let Some(bytes) = bytes else {
            return if core.is_secure() && self.fault_stop.is_none() {
                Ok(None)
            } else {
                Err("ELF has no Non-secure vectors".into())
            };
        };
        if nonsecure_region(core, vector, vector.saturating_add(7)).is_none() {
            return Err("ELF vectors are outside Non-secure SAU memory".into());
        }
        let top = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let last = top.checked_sub(1).ok_or("invalid Non-secure stack top")?;
        let base =
            nonsecure_region(core, last, last).ok_or("Non-secure stack has no SAU region")?;
        let (sp, low) = stack_registers(core, false)?;
        if !top.is_multiple_of(8) {
            return Err("Non-secure stack top is not aligned".into());
        }
        let stack = Stack::checked(low, top, sp, base, "ns0")?;
        if nonsecure_region(core, low, last).is_none() {
            return Err("Non-secure stack is outside unambiguous SAU memory".into());
        }
        Ok(Some(stack))
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

    pub fn read_sram(&self, address: u32, length: u32) -> String {
        use std::fmt::Write;

        let mut hex = String::with_capacity(length as usize * 2);
        for offset in address - SRAM_BASE..address - SRAM_BASE + length {
            write!(hex, "{:02x}", self.emu.bus.memory.sram_read8(offset)).unwrap();
        }
        hex
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
