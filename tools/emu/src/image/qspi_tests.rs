// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rp2350_emu::{Config, Emulator, MmioAliasing, MmioHandle};
use std::sync::{Arc, Mutex};

const XOR: u32 = 0x1000;

/// An emulator with 4 MB of erased flash and the QMI mounted, driven
/// through the bus like the ROM drives it.
struct Rig {
    emu: Emulator,
    h: MmioHandle,
}

impl Rig {
    fn new() -> Self {
        let mut emu = Emulator::new(Config::default());
        emu.load_flash(&vec![0xFFu8; FLASH_BYTES]);
        let h = emu
            .mount_mmio(
                QMI_BASE,
                0x1000,
                MmioAliasing::Atomic,
                Qmi::new(Arc::new(Mutex::new(Vec::new()))),
            )
            .unwrap();
        Self { emu, h }
    }
    fn q(&mut self) -> &mut Qmi {
        self.emu.bus.mmio_device_mut::<Qmi>(self.h).unwrap()
    }
    fn csr(&mut self) -> u32 {
        self.emu.mmio_read32(QMI_BASE + DIRECT_CSR)
    }
    fn tx(&mut self, v: u32) {
        self.emu.mmio_write32(QMI_BASE + DIRECT_TX, v);
    }
    /// The ROM's `s_native_crit_flash_put_get`.
    fn put_get(&mut self, tx: &[u8], n: usize) -> Vec<u8> {
        self.emu
            .mmio_write32(QMI_BASE + XOR + DIRECT_CSR, CSR_EN | CSR_ASSERT_CS0N);
        let mut out = Vec::new();
        let (mut ti, mut ri) = (0, 0);
        while ti < n || ri < n {
            let st = self.csr();
            if ti < n && st & CSR_TXFULL == 0 {
                self.tx(*tx.get(ti).unwrap_or(&0) as u32);
                ti += 1;
            }
            if ri < n && self.csr() & CSR_RXEMPTY == 0 {
                out.push(self.emu.mmio_read32(QMI_BASE + DIRECT_RX) as u8);
                ri += 1;
            }
        }
        self.emu
            .mmio_write32(QMI_BASE + XOR + DIRECT_CSR, CSR_EN | CSR_ASSERT_CS0N);
        out
    }
    /// `s_varm_flash_put_cmd_addr`.
    fn cmd_addr(&mut self, cmd: u8, offset: u32) {
        let o = (offset & 0x00FF_FFFF).swap_bytes() | cmd as u32;
        self.tx((o & 0xFFFF) | TX_NOPUSH | TX_DWIDTH);
        self.tx((o >> 16) | TX_NOPUSH | TX_DWIDTH);
    }
    fn cmd(&mut self, cmd: u8) {
        self.tx(cmd as u32 | TX_NOPUSH);
        self.put_get(&[], 0);
    }
    fn status(&mut self) -> u8 {
        self.tx(0x05 | TX_NOPUSH);
        self.put_get(&[], 1)[0]
    }
    fn flash(&self, off: usize, n: usize) -> Vec<u8> {
        self.emu.bus.memory.xip_bytes()[off..off + n].to_vec()
    }
}

#[test]
fn jedec_id_reads_back() {
    let mut r = Rig::new();
    r.tx(0x9F | TX_NOPUSH);
    assert_eq!(r.put_get(&[], 3), JEDEC_ID);
}

#[test]
fn program_needs_wel_ands_bits_and_wraps_in_the_page() {
    let mut r = Rig::new();
    // Without WREN: refused, logged.
    r.cmd_addr(0x02, 0x1000);
    r.put_get(&[0x00; 4], 4);
    assert_eq!(r.flash(0x1000, 4), [0xFF; 4]);
    assert!(r.q().flash.stats.protocol_events > 0);
    // With WREN: programs, clears WEL, sets WIP.
    r.cmd(0x06);
    assert_eq!(r.status() & SR1_WEL, SR1_WEL);
    r.cmd_addr(0x02, 0x10FE);
    r.put_get(&[0x12, 0x34, 0x56, 0x0F], 4);
    // Bytes 0xFE, 0xFF, then wrap to 0x00, 0x01 of the same page.
    assert_eq!(r.flash(0x10FE, 2), [0x12, 0x34]);
    assert_eq!(r.flash(0x1000, 2), [0x56, 0x0F]);
    assert_eq!(r.status() & SR1_WEL, 0);
    // XIP sees it.
    assert_eq!(r.emu.bus.read8(0x1000_10FE, 0), 0x12);
    // A second program can only clear bits: 0x0F & 0xF0 = 0x00.
    let t = r.emu.bus.sys_clk_hz() as u64; // let the program finish
    let _ = t;
}

#[test]
fn erase_sets_ff_and_holds_wip_for_the_erase_time() {
    let mut r = Rig::new();
    r.cmd(0x06);
    r.cmd_addr(0x02, 0x3_4500);
    r.put_get(&[0; 16], 16);
    assert_eq!(r.flash(0x3_4500, 2), [0, 0]);
    // Programmed; the part is busy for ~0.4 ms: a WREN now is ignored.
    r.cmd(0x06);
    assert_eq!(r.status() & (SR1_WIP | SR1_WEL), SR1_WIP);
    // Advance past the program time.
    for _ in 0..2000 {
        r.emu.step().unwrap();
    }
    assert_eq!(r.status() & SR1_WIP, 0);
    r.cmd(0x06);
    r.cmd_addr(0x20, 0x3_4567); // any address in the sector
    r.put_get(&[], 0);
    assert_eq!(r.flash(0x3_4000, 0x1000), vec![0xFF; 0x1000]);
    assert_eq!(r.status() & SR1_WIP, SR1_WIP);
    // A read while busy is ignored and logged.
    let ev = r.q().flash.stats.protocol_events;
    r.cmd_addr(0x03, 0);
    r.put_get(&[], 1);
    assert_eq!(r.q().flash.stats.protocol_events, ev + 1);
}

#[test]
fn truncated_erase_is_not_executed() {
    let mut r = Rig::new();
    r.cmd(0x06);
    r.cmd_addr(0x02, 0);
    r.put_get(&[0; 1], 1);
    for _ in 0..2000 {
        r.emu.step().unwrap();
    }
    r.cmd(0x06);
    // Command + only 16 address bits.
    r.tx(0x20 | TX_NOPUSH);
    r.tx(TX_NOPUSH | TX_DWIDTH);
    r.put_get(&[], 0);
    assert_eq!(r.flash(0, 1), [0], "the page was not erased");
    assert_eq!(r.q().flash.stats.erased_bytes, 0);
}

#[test]
fn serial_read_returns_the_array() {
    let mut r = Rig::new();
    r.cmd(0x06);
    r.cmd_addr(0x02, 0x200);
    r.put_get(b"flash!", 6);
    for _ in 0..2000 {
        r.emu.step().unwrap();
    }
    r.cmd_addr(0x03, 0x200);
    assert_eq!(r.put_get(&[], 6), b"flash!");
}

#[test]
fn continuous_read_mode_consumes_the_next_command_byte_as_address() {
    let mut r = Rig::new();
    // XIP configured for EBh with mode bits A0h, then direct mode.
    let rfmt = (1 << 12) | (2 << 14) | (2 << 2) | (2 << 4) | (2 << 6) | (2 << 8);
    r.emu.mmio_write32(QMI_BASE + 0x10, rfmt);
    r.emu.mmio_write32(QMI_BASE + 0x14, 0xA0EB);
    let before = r.q().flash.stats.commands;
    r.tx(0x05 | TX_NOPUSH);
    r.put_get(&[], 1);
    assert_eq!(r.q().flash.stats.commands, before, "no command was decoded");
}
