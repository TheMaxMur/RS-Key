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
    flash_stream::read_byte(super::FLASH_SIZE, offset, read_uncached)
        .map_err(|_| Error::OutOfBounds)
}

#[inline(always)]
pub(super) fn read_pair(offset: u32) -> Result<[u8; 2], Error> {
    flash_stream::read_pair(super::FLASH_SIZE, offset, read_uncached)
        .map_err(|_| Error::OutOfBounds)
}

#[inline(always)]
fn read_uncached(offset: u32) -> u8 {
    const {
        assert!(super::FLASH_SIZE <= FLASH_UNCACHED_BYTES);
    }
    // SAFETY: SharedFlash holds its exclusive borrow; both callers check every
    // callback offset against this chip's capacity before this translated load.
    // A u8 read permits every alignment and every initialized flash value.
    unsafe { core::ptr::read_volatile((FLASH_UNCACHED_BASE + offset) as *const u8) }
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

// SAFETY: startup copies .data.ram_func into the existing read-only executable
// SRAM range; this routine runs under the same exclusive flash borrow as read.
#[unsafe(link_section = ".data.ram_func")]
#[inline(never)]
pub(super) fn read_erased(offset: u32, length: usize) -> Result<bool, Error> {
    flash_stream::read_erased(&mut Cpu { started: 0 }, super::FLASH_SIZE, offset, length).map_err(
        |error| match error {
            flash_stream::Error::Unaligned => Error::Unaligned,
            flash_stream::Error::OutOfBounds => Error::OutOfBounds,
            flash_stream::Error::Transfer => Error::Other,
        },
    )
}
