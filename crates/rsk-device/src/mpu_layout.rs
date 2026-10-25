// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Non-overlapping SRAM permissions, including the HAL's temporary boot2 code.

pub const SRAM_START: u32 = 0x2000_0000;
pub const SRAM_END: u32 = 0x2008_2000;
pub const MAIN_SRAM_END: u32 = 0x2008_0000;
pub const FLASH_STACK_BYTES: u32 = 4096;
const ALIGNMENT: u32 = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    Data,
    Code,
    FlashStackCode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub start: u32,
    pub end: u32,
    pub permission: Permission,
}

#[derive(Clone, Copy)]
pub struct RamCode {
    start: u32,
    end: u32,
    scratch_start: u32,
}

impl RamCode {
    pub fn new(start: u32, end: u32, scratch_start: u32) -> Option<Self> {
        if start <= SRAM_START
            || end >= MAIN_SRAM_END
            || start >= end
            || !start.is_multiple_of(ALIGNMENT)
            || !end.is_multiple_of(ALIGNMENT)
            || !(MAIN_SRAM_END..SRAM_END).contains(&scratch_start)
            || !scratch_start.is_multiple_of(ALIGNMENT)
        {
            return None;
        }
        Some(Self {
            start,
            end,
            scratch_start,
        })
    }

    fn scratch_region(self) -> Region {
        Region {
            start: self.scratch_start,
            end: SRAM_END,
            permission: Permission::Code,
        }
    }

    pub fn regions(self) -> [Region; 4] {
        [
            Region {
                start: SRAM_START,
                end: self.start,
                permission: Permission::Data,
            },
            Region {
                start: self.start,
                end: self.end,
                permission: Permission::Code,
            },
            Region {
                start: self.end,
                end: self.scratch_start,
                permission: Permission::Data,
            },
            self.scratch_region(),
        ]
    }

    pub fn flash_stack_regions(self, stack: u32) -> Option<[Region; 6]> {
        let start = stack.checked_sub(FLASH_STACK_BYTES)? & !(ALIGNMENT - 1);
        let end = stack.checked_add(ALIGNMENT - 1)? & !(ALIGNMENT - 1);
        if start <= SRAM_START || end >= MAIN_SRAM_END || start >= end {
            return None;
        }
        let code = Region {
            start: self.start,
            end: self.end,
            permission: Permission::Code,
        };
        let flash = Region {
            start,
            end,
            permission: Permission::FlashStackCode,
        };
        if end < self.start {
            Some([
                Region {
                    start: SRAM_START,
                    end: start,
                    permission: Permission::Data,
                },
                flash,
                Region {
                    start: end,
                    end: self.start,
                    permission: Permission::Data,
                },
                code,
                Region {
                    start: self.end,
                    end: self.scratch_start,
                    permission: Permission::Data,
                },
                self.scratch_region(),
            ])
        } else if start > self.end {
            Some([
                Region {
                    start: SRAM_START,
                    end: self.start,
                    permission: Permission::Data,
                },
                code,
                Region {
                    start: self.end,
                    end: start,
                    permission: Permission::Data,
                },
                flash,
                Region {
                    start: end,
                    end: self.scratch_start,
                    permission: Permission::Data,
                },
                self.scratch_region(),
            ])
        } else {
            None
        }
    }
}

#[cfg(test)]
#[path = "mpu_layout_tests.rs"]
mod tests;

#[cfg(kani)]
#[path = "mpu_layout_kani.rs"]
mod proofs;
