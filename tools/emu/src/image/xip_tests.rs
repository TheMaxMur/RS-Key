// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rp2350_emu::{Config, Emulator, MmioAliasing};

fn chip() -> Emulator {
    let mut emu = Emulator::new(Config::default());
    emu.load_flash(&(0..64u8).collect::<Vec<_>>());
    let xip = SharedXip::default();
    emu.mount_mmio(XIP_AUX_BASE, 0x1000, MmioAliasing::Atomic, xip.aux())
        .unwrap();
    emu.mount_mmio(XIP_CTRL_BASE, 0x1000, MmioAliasing::Atomic, xip)
        .unwrap();
    emu
}
fn write(emu: &mut Emulator, offset: u32, value: u32) {
    emu.bus.write32(XIP_CTRL_BASE + offset, value, 0);
}
fn read(emu: &mut Emulator, offset: u32) -> u32 {
    emu.bus.read32(XIP_CTRL_BASE + offset, 0)
}

#[test]
fn stream_returns_real_flash_words_with_two_entry_backpressure_and_a_draining_zero_count() {
    let mut e = chip();
    write(&mut e, ADDR, 0x1000_0000);
    write(&mut e, COUNT, 3);
    assert_eq!(read(&mut e, STAT), 4);
    assert_eq!(read(&mut e, COUNT), 1);
    assert_eq!(read(&mut e, ADDR), 0x0000_0008);
    assert_eq!(read(&mut e, STAT), 4);
    assert_eq!(read(&mut e, COUNT), 1);
    assert_eq!(read(&mut e, FIFO), 0x0302_0100);
    assert_eq!(read(&mut e, STAT), 4);
    assert_eq!(read(&mut e, COUNT), 0);
    assert_eq!(read(&mut e, FIFO), 0x0706_0504);
    assert_eq!(read(&mut e, FIFO), 0x0B0A_0908);
    assert_eq!(read(&mut e, STAT), 2);
    assert_eq!(read(&mut e, ADDR), 0x0000_000C);
    assert!(!e.bus.bus_fault(0));
}

#[test]
fn abort_preserves_fifo_and_restart_reads_current_flash_instead_of_an_old_snapshot() {
    let mut e = chip();
    write(&mut e, ADDR, 0x1000_0000);
    write(&mut e, COUNT, 6);
    assert_eq!(read(&mut e, STAT), 4);
    write(&mut e, COUNT, 0);
    assert_eq!(read(&mut e, STAT), 4);
    assert_eq!(read(&mut e, COUNT), 0);
    assert_eq!(read(&mut e, FIFO), 0x0302_0100);
    assert_eq!(read(&mut e, FIFO), 0x0706_0504);
    assert_eq!(read(&mut e, STAT), 2);
    e.load_flash(&[0xA5; 64]);
    write(&mut e, ADDR, 0x1000_0010);
    write(&mut e, COUNT, 1);
    assert_eq!(read(&mut e, STAT), 0);
    assert_eq!(read(&mut e, FIFO), 0xA5A5_A5A5);
    assert_eq!(read(&mut e, STAT), 2);
    assert_eq!(read(&mut e, ADDR), 0x0000_0014);
}

#[test]
fn aliases_mask_addresses_and_counts_and_invalid_reads_fault() {
    let mut e = chip();
    write(&mut e, ADDR, 0x1000_0003);
    assert_eq!(read(&mut e, ADDR), 0);
    write(&mut e, COUNT, !COUNT_MASK);
    assert_eq!(read(&mut e, COUNT), 0);
    write(&mut e, 0x2000 + COUNT, 1);
    assert_eq!(read(&mut e, COUNT), 1);
    assert_eq!(read(&mut e, STAT), 0);
    assert_eq!(read(&mut e, FIFO), 0x0302_0100);
    read(&mut e, FIFO);
    assert!(e.bus.bus_fault(0));
    e.bus.clear_bus_fault(0);
    write(&mut e, ADDR, 0x1000_0040);
    write(&mut e, COUNT, 1);
    read(&mut e, STAT);
    assert!(e.bus.bus_fault(0));
}

#[test]
fn reset_and_internal_addresses_match_the_cpu_stream_port() {
    let mut e = chip();
    assert_eq!(read(&mut e, CTRL), 0x83);
    assert_eq!(read(&mut e, STAT), 2);
    write(&mut e, ADDR, 0x1400_0013);
    assert_eq!(read(&mut e, ADDR), 0x10);
    write(&mut e, COUNT, 1);
    read(&mut e, STAT);
    assert_eq!(read(&mut e, FIFO), 0x1312_1110);
    assert_eq!(read(&mut e, ADDR), 0x14);
}

#[test]
fn auxiliary_cpu_reads_consume_the_same_fifo_and_refuse_narrow_accesses() {
    let mut e = chip();
    write(&mut e, ADDR, 0x1000_0000);
    write(&mut e, COUNT, 3);
    assert_eq!(read(&mut e, STAT), 4);
    assert_eq!(e.bus.read32(XIP_AUX_BASE, 0), 0x0302_0100);
    assert_eq!(read(&mut e, STAT), 4);
    assert_eq!(read(&mut e, COUNT), 0);
    assert_eq!(e.bus.read32(XIP_AUX_BASE, 0), 0x0706_0504);
    assert_eq!(read(&mut e, FIFO), 0x0B0A_0908);
    assert_eq!(read(&mut e, STAT), 2);
    assert!(!e.bus.bus_fault(0));
    e.bus.read8(XIP_AUX_BASE, 0);
    assert!(e.bus.bus_fault(0));
    e.bus.clear_bus_fault(0);
    e.bus.read16(XIP_CTRL_BASE + STAT, 0);
    assert!(e.bus.bus_fault(0));
}
