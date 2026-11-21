// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const CLR: u32 = 3;

#[test]
fn ram_is_byte_addressable_and_takes_the_atomic_aliases() {
    let mut b = BootRam::new();
    let mut ctx = MmioCtx::default();
    b.write(0x10, 0xAABB_CCDD, 4, 0, &mut ctx);
    b.write(0x11, 0x11, 1, 0, &mut ctx);
    assert_eq!(b.read(0x10, 4, &mut ctx), 0xAABB_11DD);
    b.write(0x10, 0xFF, 4, CLR, &mut ctx);
    assert_eq!(b.read(0x10, 4, &mut ctx), 0xAABB_1100);
}

#[test]
fn write_once_bits_only_ever_set() {
    let mut b = BootRam::new();
    let mut ctx = MmioCtx::default();
    b.write(WRITE_ONCE0, 0b101, 4, 0, &mut ctx);
    b.write(WRITE_ONCE0, 0b010, 4, 0, &mut ctx);
    b.write(WRITE_ONCE0, 0b111, 4, CLR, &mut ctx);
    assert_eq!(b.read(WRITE_ONCE0, 4, &mut ctx), 0b111);
    assert_eq!(b.read(WRITE_ONCE1, 4, &mut ctx), 0);
}

#[test]
fn a_bootlock_is_claimed_by_the_first_read_until_written() {
    let mut b = BootRam::new();
    let mut ctx = MmioCtx::default();
    let lock3 = BOOTLOCK0 + 3 * 4;
    assert_eq!(b.read(lock3, 4, &mut ctx), 1 << 3);
    assert_eq!(b.read(lock3, 4, &mut ctx), 0, "taken");
    assert_eq!(b.read(BOOTLOCK0, 4, &mut ctx), 1, "the others are not");
    b.write(lock3, 0, 4, 0, &mut ctx);
    assert_eq!(
        b.read(lock3, 4, &mut ctx),
        1 << 3,
        "released, claimed again"
    );
}
