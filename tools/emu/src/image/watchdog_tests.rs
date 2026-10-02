// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn countdown(load: u32) -> (Watchdog, MmioCtx<'static>) {
    let mut device = Watchdog::new();
    let mut ctx = MmioCtx::default();
    ctx.sys_clk_hz = 12_000_000;
    device.write(LOAD, load, 4, 0, &mut ctx);
    device.write(CTRL, ENABLE | PAUSE, 4, 0, &mut ctx);
    (device, ctx)
}

#[test]
fn a_rom_delay_counts_microseconds_at_any_step_quantum() {
    for quantum in [1, 12, 1200, 12_000] {
        let (mut device, mut ctx) = countdown(500_000);
        for _ in 0..6_000_000 / quantum - 1 {
            device.tick(quantum, &mut ctx);
        }
        assert!(!device.reset_requested, "watchdog fired before 500 ms");
        device.tick(quantum, &mut ctx);
        assert!(device.reset_requested, "watchdog ignored elapsed clocks");
        assert_eq!(device.read(CTRL, 4, &mut ctx) & PAUSE, PAUSE);
    }
}

#[test]
fn disabled_time_reload_clock_changes_trigger_and_scratch() {
    let (mut device, mut ctx) = countdown(1000);
    device.write(CTRL, ENABLE, 4, 3, &mut ctx);
    device.tick(12_000, &mut ctx);
    assert_eq!(device.read(CTRL, 4, &mut ctx) & TIME, 1000);
    device.write(CTRL, ENABLE, 4, 2, &mut ctx);
    device.tick(6000, &mut ctx);
    assert_eq!(device.read(CTRL, 4, &mut ctx) & TIME, 500);
    ctx.sys_clk_hz = 48_000_000;
    device.tick(12_000, &mut ctx);
    assert_eq!(device.read(CTRL, 4, &mut ctx) & TIME, 250);
    device.write(LOAD, 1000, 4, 0, &mut ctx);
    device.write(0x0C, 0x12345678, 4, 0, &mut ctx);
    device.tick(12_000, &mut ctx);
    assert!(!device.reset_requested);
    assert_eq!(device.read(CTRL, 4, &mut ctx) & TIME, 750);
    device.write(CTRL, 1 << 31, 4, 2, &mut ctx);
    assert!(device.reset_requested);
    assert_eq!(device.read(0x0C, 4, &mut ctx), 0x12345678);
}

#[test]
fn partial_ticks_survive_a_clock_change_and_a_zero_load_fires() {
    let (mut device, mut ctx) = countdown(1);
    device.tick(6, &mut ctx);
    ctx.sys_clk_hz = 48_000_000;
    device.tick(23, &mut ctx);
    assert!(!device.reset_requested);
    device.tick(1, &mut ctx);
    assert!(device.reset_requested);
    let (mut device, mut ctx) = countdown(0);
    device.tick(11, &mut ctx);
    assert!(!device.reset_requested);
    device.tick(1, &mut ctx);
    assert!(device.reset_requested);
}
