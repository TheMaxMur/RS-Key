// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use embassy_rp::flash::Error;
use rsk_store::flash_stream::{self, Stream};

const FLASH_BASE: u32 = 0x1000_0000;
const FLASH_UNCACHED_BASE: u32 = 0x1400_0000;
const FLASH_UNCACHED_BYTES: usize = 64 * 1024 * 1024;
const TIMEOUT_US: u32 = 100_000;

#[inline(always)]
pub(super) fn read_byte(offset: u32) -> Result<u8, Error> {
    const {
        assert!(super::FLASH_SIZE <= FLASH_UNCACHED_BYTES);
    }
    flash_stream::read_byte(super::FLASH_SIZE, offset, |offset| {
        // SAFETY: SharedFlash holds its exclusive borrow; the checked offset is
        // inside this chip's capacity and the translated uncached XIP window.
        // A u8 read permits every alignment and every initialized flash value.
        unsafe { core::ptr::read_volatile((FLASH_UNCACHED_BASE + offset) as *const u8) }
    })
    .map_err(|_| Error::OutOfBounds)
}

struct Cpu {
    started: u32,
}
impl Stream for Cpu {
    #[inline(always)]
    fn stop(&mut self) {
        rp_pac::XIP_CTRL
            .stream_ctr()
            .write_value(Default::default());
    }
    #[inline(always)]
    fn readable(&mut self) -> Result<bool, flash_stream::Error> {
        let status = rp_pac::XIP_CTRL.stat().read();
        flash_stream::fifo_readable(status.fifo_empty(), status.fifo_full())
    }
    #[inline(always)]
    fn start(&mut self, offset: u32, words: u32) {
        rp_pac::XIP_CTRL
            .stream_addr()
            .write_value(rp_pac::xip_ctrl::regs::StreamAddr(FLASH_BASE + offset));
        self.started = rp_pac::TIMER0.timerawl().read();
        rp_pac::XIP_CTRL
            .stream_ctr()
            .write_value(rp_pac::xip_ctrl::regs::StreamCtr(words));
    }
    #[inline(always)]
    fn read_word(&mut self) -> u32 {
        rp_pac::XIP_AUX.stream().read()
    }
    #[inline(always)]
    fn remaining(&mut self) -> u32 {
        rp_pac::XIP_CTRL.stream_ctr().read().stream_ctr()
    }
    #[inline(always)]
    fn address(&mut self) -> u32 {
        rp_pac::XIP_CTRL.stream_addr().read().0
    }
    #[inline(always)]
    fn expired(&mut self) -> bool {
        rp_pac::TIMER0.timerawl().read().wrapping_sub(self.started) >= TIMEOUT_US
    }
}

// SAFETY: startup copies .data.ram_func before use; the existing linker/MPU
// places it in read-only executable SRAM, outside mutable data and the stack.
#[unsafe(link_section = ".data.ram_func")]
#[inline(never)]
pub(super) fn read(offset: u32, bytes: &mut [u8]) -> Result<(), Error> {
    flash_stream::read(&mut Cpu { started: 0 }, super::FLASH_SIZE, offset, bytes).map_err(|error| {
        match error {
            flash_stream::Error::Unaligned => Error::Unaligned,
            flash_stream::Error::OutOfBounds => Error::OutOfBounds,
            flash_stream::Error::Transfer => Error::Other,
        }
    })
}
