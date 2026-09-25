// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use core::cell::Cell;

use super::*;

/// Records that it was wiped, so a test can see `Drop` reach `zeroize`.
struct Probe<'a>(&'a Cell<bool>);

impl Zeroize for Probe<'_> {
    fn zeroize(&mut self) {
        self.0.set(true);
    }
}

fn wipes_on_drop<T: ZeroizeOnDrop>(_: &T) {}

/// Fails, the way a flash write or a parse does on the path a wipe used to miss.
fn refuse() -> Result<(), ()> {
    Err(())
}

#[test]
fn a_secret_is_wiped_when_it_drops() {
    let wiped = Cell::new(false);
    let s = Secret::new(Probe(&wiped));
    wipes_on_drop(&s);
    assert!(!wiped.get());
    drop(s);
    assert!(wiped.get());
}

fn early_exit(wiped: &Cell<bool>) -> Result<(), ()> {
    let _held = Secret::new(Probe(wiped));
    refuse()?;
    Ok(())
}

#[test]
fn a_secret_is_wiped_on_an_early_return() {
    let wiped = Cell::new(false);
    assert!(early_exit(&wiped).is_err());
    assert!(wiped.get());
}

#[test]
fn a_guard_wipes_the_whole_buffer_on_an_early_return() {
    fn fill_then_fail(buf: &mut [u8]) -> Result<(), ()> {
        let mut g = WipeGuard::new(buf);
        g[..2].copy_from_slice(&[0xAA, 0xBB]);
        refuse()?;
        Ok(())
    }
    let mut buf = [0x55u8; 8];
    assert!(fill_then_fail(&mut buf).is_err());
    assert_eq!(buf, [0; 8]);
}

#[test]
fn zeroed_is_zero_and_writes_land() {
    let mut s = Secret::<[u8; 4]>::zeroed();
    assert_eq!(s.expose(), &[0; 4]);
    s.expose_mut()[3] = 7;
    assert_eq!(s.expose(), &[0, 0, 0, 7]);
}

#[test]
fn a_static_can_hold_one() {
    static HELD: Secret<[u32; 2]> = Secret::new([1, 2]);
    assert_eq!(HELD.expose(), &[1, 2]);
}
