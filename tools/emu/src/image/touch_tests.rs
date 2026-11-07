// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn register_read_encodes_a_held_finger_then_releases_on_image_time() {
    let touch = SharedTouch::default();
    {
        let mut t = touch.lock().unwrap();
        t.point = Some((239, 319));
        t.until_ns = 800_000_000;
    }
    let mut bus = I2c::new(touch.clone());
    let ctx = &mut MmioCtx::default();
    bus.write(TARGET, ADDRESS, 4, 0, ctx);
    bus.write(ENABLE, 1, 4, 0, ctx);
    for byte in [0xD1, 0x09 | STOP] {
        bus.write(DATA_CMD, byte, 4, 0, ctx);
    }
    for now in [0, 799_999_999, 800_000_000] {
        touch.lock().unwrap().now_ns = now;
        for byte in [0xD0, 0] {
            bus.write(DATA_CMD, byte, 4, 0, ctx);
        }
        for index in 0..7 {
            bus.write(
                DATA_CMD,
                READ | if index == 6 { STOP } else { 0 },
                4,
                0,
                ctx,
            );
        }
        let report: Vec<_> = (0..7).map(|_| bus.read(DATA_CMD, 4, ctx) as u8).collect();
        assert_eq!(
            rsk_ui::touch::parse_cst328(&report),
            if now < 800_000_000 {
                Some(rsk_ui::Point::new(239, 319))
            } else {
                None
            }
        );
        for byte in [0xD0, 0x05, STOP] {
            bus.write(DATA_CMD, byte, 4, 0, ctx);
        }
        assert_ne!(bus.read(RAW_INTR_STAT, 4, ctx) & STOP_DET, 0);
        bus.read(CLR_STOP_DET, 4, ctx);
        assert_eq!(bus.read(RAW_INTR_STAT, 4, ctx) & STOP_DET, 0);
    }
    bus.write(TARGET, 0x19, 4, 0, ctx);
    bus.write(DATA_CMD, READ | STOP, 4, 0, ctx);
    assert_ne!(bus.read(RAW_INTR_STAT, 4, ctx) & TX_ABORT, 0);
    bus.read(CLR_TX_ABRT, 4, ctx);
    assert_eq!(bus.read(RAW_INTR_STAT, 4, ctx) & TX_ABORT, 0);
}

#[test]
fn controller_reports_are_latched_until_ack_and_reset_is_not_a_finger_lift() {
    let touch = SharedTouch::default();
    let mut bus = I2c::new(touch.clone());
    let ctx = &mut MmioCtx::default();
    bus.write(ENABLE, 1, 4, 0, ctx);
    bus.write(TARGET, ADDRESS, 4, 0, ctx);
    touch.lock().unwrap().normal = true;
    touch.lock().unwrap().point = Some((170, 272));
    touch.lock().unwrap().until_ns = 800_000_000;
    let mut read = |now| {
        touch.lock().unwrap().now_ns = now;
        for word in [0xD0, 0, READ | STOP] {
            bus.write(DATA_CMD, word, 4, 0, ctx);
        }
        bus.read(DATA_CMD, 4, ctx)
    };
    assert_eq!(read(0), 6);
    assert_eq!(read(900_000_000), 6);
    for word in [0xD0, 0x05, STOP] {
        bus.write(DATA_CMD, word, 4, 0, ctx);
    }
    for word in [0xD0, 0, READ | STOP] {
        bus.write(DATA_CMD, word, 4, 0, ctx);
    }
    assert_eq!(bus.read(DATA_CMD, 4, ctx), 0);
    let mut state = touch.lock().unwrap();
    state.sample(0);
    assert!(!state.normal && state.reset);
    assert_eq!(state.point, Some((170, 272)));
    state.sample(TOUCH_RESET);
    assert!(!state.normal && !state.reset);
    state.reboot(700_000_000);
    assert_eq!(state.until_ns, 100_000_000);
    assert_eq!(state.point, Some((170, 272)));
}

#[test]
fn fifo_thresholds_enable_abort_clears_and_level_irq_are_observable() {
    let touch = SharedTouch::default();
    touch.lock().unwrap().normal = true;
    let mut bus = I2c::new(touch.clone());
    let ctx = &mut MmioCtx::default();
    bus.write(TARGET, ADDRESS, 4, 0, ctx);
    bus.write(DATA_CMD, READ, 4, 0, ctx);
    assert_eq!(bus.read(RXFLR, 4, ctx), 0);
    bus.write(ENABLE, 1, 4, 0, ctx);
    bus.write(INTR_MASK, RX_FULL | RX_OVER | TX_ABORT, 4, 0, ctx);
    bus.write(RX_TL, 6, 4, 0, ctx);
    for _ in 0..3 {
        for word in [0xD0, 0] {
            bus.write(DATA_CMD, word, 4, 0, ctx);
        }
        for index in 0..7 {
            bus.write(
                DATA_CMD,
                READ | if index == 6 { STOP } else { 0 },
                4,
                0,
                ctx,
            );
        }
    }
    assert_eq!(bus.read(RXFLR, 4, ctx), FIFO_DEPTH as u32);
    assert_eq!(bus.read(INTR_STAT, 4, ctx), RX_FULL | RX_OVER);
    assert_eq!(ctx.raise_irqs, 1 << IRQ);
    ctx.raise_irqs = 0;
    bus.tick(64, ctx);
    assert_eq!(ctx.raise_irqs, 1 << IRQ);
    bus.read(CLR_RX_OVER, 4, ctx);
    for _ in 0..FIFO_DEPTH {
        bus.read(DATA_CMD, 4, ctx);
    }
    assert_eq!(bus.read(INTR_STAT, 4, ctx), 0);
    bus.read(DATA_CMD, 4, ctx);
    assert_ne!(bus.read(RAW_INTR_STAT, 4, ctx) & RX_UNDER, 0);
    bus.read(CLR_RX_UNDER, 4, ctx);
    assert_eq!(bus.read(RAW_INTR_STAT, 4, ctx) & RX_UNDER, 0);
    bus.write(TARGET, ADDRESS, 4, 1, ctx);
    bus.write(DATA_CMD, READ | STOP, 4, 0, ctx);
    assert_ne!(bus.read(TX_ABRT_SOURCE, 4, ctx), 0);
    bus.read(CLR_INTR, 4, ctx);
    assert_eq!(bus.read(TX_ABRT_SOURCE, 4, ctx), 0);
    bus.write(ENABLE, 0, 4, 0, ctx);
    assert_eq!(bus.read(ENABLE_STATUS, 4, ctx), 0);
    assert_eq!(bus.read(RXFLR, 4, ctx), 0);
    touch.lock().unwrap().sample(0);
    bus.write(ENABLE, 1, 4, 0, ctx);
    bus.write(TARGET, ADDRESS, 4, 0, ctx);
    bus.write(DATA_CMD, READ | STOP, 4, 0, ctx);
    assert_ne!(bus.read(TX_ABRT_SOURCE, 4, ctx), 0);
}
