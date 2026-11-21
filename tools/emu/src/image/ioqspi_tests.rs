// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// What embassy-rp's `is_bootsel_pressed` does: drive off, read the pad back.
fn sample(io: &mut IoQspi, ctx: &mut MmioCtx) -> bool {
    let normal = io.read(QSPI_SS_CTRL, 4, ctx);
    io.write(QSPI_SS_CTRL, OEOVER_DISABLE << CTRL_OEOVER_SHIFT, 4, 0, ctx);
    let status = io.read(QSPI_SS_STATUS, 4, ctx);
    io.write(QSPI_SS_CTRL, normal, 4, 0, ctx);
    status & STATUS_INFROMPAD == 0
}

#[test]
fn the_button_reads_through_the_undriven_cs_pad() {
    let pressed = Arc::new(AtomicBool::new(false));
    let mut io = IoQspi::new(pressed.clone());
    let mut ctx = MmioCtx::default();
    assert!(!sample(&mut io, &mut ctx));
    pressed.store(true, Ordering::Relaxed);
    assert!(sample(&mut io, &mut ctx));
    pressed.store(false, Ordering::Relaxed);
    assert!(!sample(&mut io, &mut ctx));
}

#[test]
fn a_driven_cs_reads_high_whatever_the_button() {
    let mut io = IoQspi::new(Arc::new(AtomicBool::new(true)));
    let mut ctx = MmioCtx::default();
    assert_eq!(
        io.read(QSPI_SS_STATUS, 4, &mut ctx) & STATUS_INFROMPAD,
        STATUS_INFROMPAD
    );
    io.write(QSPI_SS_CTRL + 4, 0x55, 4, 0, &mut ctx);
    assert_eq!(
        io.read(QSPI_SS_CTRL + 4, 4, &mut ctx),
        0x55,
        "plain storage"
    );
}
