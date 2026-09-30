// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The SHA-256 accelerator as the bootrom drives it: narrow WDATA writes build
//! little-endian words, CSR.BSWAP swaps each, and every 16 words compress with
//! no new START — picoem's built-in model gets BSWAP and narrow writes wrong.

use rp2350_emu::peripherals::apply_alias_rmw;
use rp2350_emu::{MmioCtx, MmioDevice};
use sha2::compress256;

pub const SHA256_BASE: u32 = 0x400F_8000;

const CSR: u32 = 0x00;
const WDATA: u32 = 0x04;
const SUM0: u32 = 0x08;
const SUM7: u32 = 0x24;

const CSR_START: u32 = 1 << 0;
const CSR_WDATA_RDY: u32 = 1 << 1;
const CSR_SUM_VLD: u32 = 1 << 2;
const CSR_ERR_WDATA_NOT_RDY: u32 = 1 << 4;
const CSR_DMA_SIZE: u32 = 3 << 8;
const CSR_BSWAP: u32 = 1 << 12;
/// SHA256_CSR_RESET: BSWAP=1, DMA_SIZE=2 (32-bit), WDATA_RDY, SUM_VLD.
const CSR_RESET_RW: u32 = CSR_BSWAP | (2 << 8);

const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

pub struct Sha256 {
    /// The RW CSR fields (DMA_SIZE, BSWAP).
    ctrl: u32,
    state: [u32; 8],
    block: [u32; 16],
    words: usize,
    /// Bytes of a word still being assembled from narrow writes.
    pending: u32,
    pending_bytes: u32,
    pub blocks: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            ctrl: CSR_RESET_RW,
            state: IV,
            block: [0; 16],
            words: 0,
            pending: 0,
            pending_bytes: 0,
            blocks: 0,
        }
    }

    fn start(&mut self) {
        self.state = IV;
        self.words = 0;
        self.pending = 0;
        self.pending_bytes = 0;
    }

    fn push_byte(&mut self, b: u8) {
        self.pending |= (b as u32) << (8 * self.pending_bytes);
        self.pending_bytes += 1;
        if self.pending_bytes == 4 {
            let w = if self.ctrl & CSR_BSWAP != 0 {
                self.pending.swap_bytes()
            } else {
                self.pending
            };
            self.pending = 0;
            self.pending_bytes = 0;
            self.block[self.words] = w;
            self.words += 1;
            if self.words == 16 {
                let mut bytes = [0u8; 64];
                for (i, w) in self.block.iter().enumerate() {
                    bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
                }
                compress256(&mut self.state, &[bytes.into()]);
                self.words = 0;
                self.blocks += 1;
            }
        }
    }
}

impl MmioDevice for Sha256 {
    fn read(&mut self, offset: u32, _size: u8, _ctx: &mut MmioCtx) -> u32 {
        let word = match offset & !3 {
            CSR => {
                let busy = self.words != 0 || self.pending_bytes != 0;
                self.ctrl | CSR_WDATA_RDY | if busy { 0 } else { CSR_SUM_VLD }
            }
            o @ SUM0..=SUM7 => self.state[((o - SUM0) / 4) as usize],
            _ => 0,
        };
        word >> ((offset & 3) * 8)
    }

    fn write(&mut self, offset: u32, value: u32, size: u8, alias: u32, _ctx: &mut MmioCtx) {
        match offset & !3 {
            CSR => {
                let mut v = self.ctrl;
                apply_alias_rmw(&mut v, value << ((offset & 3) * 8), alias);
                self.ctrl = v & (CSR_DMA_SIZE | CSR_BSWAP);
                if v & CSR_START != 0 {
                    self.start();
                }
                let _ = CSR_ERR_WDATA_NOT_RDY;
            }
            WDATA => {
                for i in 0..size as u32 {
                    self.push_byte((value >> (8 * i)) as u8);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
#[path = "sha256_tests.rs"]
mod tests;
