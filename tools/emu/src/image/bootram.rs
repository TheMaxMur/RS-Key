// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! BOOTRAM: 1 KB of RAM (the bootrom's stack, its `always` state, the XIP setup
//! code it leaves an image) and the registers at +0x800 — WRITE_ONCE0/1, whose
//! bits only set, and eight BOOTLOCKs that behave like SIO spinlocks.

use rp2350_emu::peripherals::apply_alias_rmw;
use rp2350_emu::{MmioCtx, MmioDevice};

pub const BOOTRAM_BASE: u32 = 0x400E_0000;
pub const BOOTRAM_SIZE: usize = 0x400;
const WRITE_ONCE0: u32 = 0x800;
const WRITE_ONCE1: u32 = 0x804;
const BOOTLOCK_STAT: u32 = 0x808;
const BOOTLOCK0: u32 = 0x80C;
const BOOTLOCK7: u32 = 0x828;

pub struct BootRam {
    ram: Vec<u8>,
    write_once: [u32; 2],
    /// Bit n set = lock n claimed.
    claimed: u8,
}

impl BootRam {
    pub fn new() -> Self {
        Self {
            ram: vec![0u8; BOOTRAM_SIZE],
            write_once: [0; 2],
            claimed: 0,
        }
    }

    fn read32(&self, offset: usize) -> u32 {
        u32::from_le_bytes([
            self.ram[offset],
            self.ram[offset + 1],
            self.ram[offset + 2],
            self.ram[offset + 3],
        ])
    }

    /// The bootrom's `bootram->always` record (src/main/native/bootram.h; at
    /// +0x328 on A2 and A4 alike), decoded for a refusal's diagnosis.
    pub fn describe_always(&self) -> String {
        const ALWAYS: usize = 0x328;
        let b = |o: usize| self.ram[ALWAYS + o];
        let boot_type = b(0x31);
        let type_name = match boot_type & 0x7F {
            0 => "NORMAL",
            2 => "BOOTSEL",
            3 => "RAM_IMAGE",
            4 => "FLASH_UPDATE",
            0xd => "PC_SP",
            _ => "?",
        };
        let diag = self.read32(ALWAYS + 0x34);
        let flags = |d: u32| {
            const NAMES: [&str; 16] = [
                "WINDOW_SEARCHED",
                "INVALID_BLOCK_LOOP",
                "VALID_BLOCK_LOOP",
                "VALID_IMAGE_DEF",
                "HAS_PARTITION_TABLE",
                "CONSIDERED",
                "CHOSEN",
                "PT_MATCHING_KEY_FOR_VERIFY",
                "PT_HASH_FOR_VERIFY",
                "PT_VERIFIED_OK",
                "IMAGE_DEF_MATCHING_KEY_FOR_VERIFY",
                "IMAGE_DEF_HASH_FOR_VERIFY",
                "IMAGE_DEF_VERIFIED_OK",
                "LOAD_MAP_ENTRIES_LOADED",
                "IMAGE_LAUNCHED",
                "IMAGE_CONDITION_FAILURE",
            ];
            let v: Vec<&str> = (0..16)
                .filter(|i| d & (1 << i) != 0)
                .map(|i| NAMES[i])
                .collect();
            if v.is_empty() {
                "-".to_string()
            } else {
                v.join("|")
            }
        };
        format!(
            "boot_type {boot_type:#04x} ({type_name}{}), recent partition {}, diagnostic partition {}, \
             diagnostic lo [{}] hi [{}], partition table loaded {} ({} partitions), flash_devinfo {:#06x}, \
             pending rollback otp {:#010x}",
            if boot_type & 0x80 != 0 {
                ", chained"
            } else {
                ""
            },
            b(0x32) as i8,
            b(0x30) as i8,
            flags(diag & 0xFFFF),
            flags(diag >> 16),
            self.ram[0x360 + 2] != 0,
            self.ram[0x360],
            u16::from_le_bytes([b(0x14), b(0x15)]),
            self.read32(ALWAYS + 0x24),
        )
    }
}

impl MmioDevice for BootRam {
    fn read(&mut self, offset: u32, size: u8, _ctx: &mut MmioCtx) -> u32 {
        let o = offset as usize;
        if o + size as usize <= BOOTRAM_SIZE {
            let mut b = [0u8; 4];
            b[..size as usize].copy_from_slice(&self.ram[o..o + size as usize]);
            return u32::from_le_bytes(b);
        }
        let word = match offset & !3 {
            WRITE_ONCE0 => self.write_once[0],
            WRITE_ONCE1 => self.write_once[1],
            BOOTLOCK_STAT => (!self.claimed) as u32,
            w @ BOOTLOCK0..=BOOTLOCK7 => {
                let bit = 1u8 << ((w - BOOTLOCK0) / 4);
                if self.claimed & bit != 0 {
                    0
                } else {
                    self.claimed |= bit;
                    bit as u32
                }
            }
            _ => 0,
        };
        word >> ((offset & 3) * 8)
    }

    fn write(&mut self, offset: u32, value: u32, size: u8, alias: u32, _ctx: &mut MmioCtx) {
        let o = offset as usize;
        if o + size as usize <= BOOTRAM_SIZE {
            let mut old = [0u8; 4];
            old[..size as usize].copy_from_slice(&self.ram[o..o + size as usize]);
            let mut v = u32::from_le_bytes(old);
            apply_alias_rmw(&mut v, value, alias);
            self.ram[o..o + size as usize].copy_from_slice(&v.to_le_bytes()[..size as usize]);
            return;
        }
        let value = value << ((offset & 3) * 8);
        match offset & !3 {
            w @ (WRITE_ONCE0 | WRITE_ONCE1) => {
                let i = ((w - WRITE_ONCE0) / 4) as usize;
                let mut v = self.write_once[i];
                apply_alias_rmw(&mut v, value, alias);
                self.write_once[i] |= v; // bits only ever set
            }
            w @ BOOTLOCK0..=BOOTLOCK7 => self.claimed &= !(1u8 << ((w - BOOTLOCK0) / 4)),
            _ => {}
        }
    }
}

#[cfg(test)]
#[path = "bootram_tests.rs"]
mod tests;
