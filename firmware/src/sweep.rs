// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Zeroing a core's dead stack once its work is done. What a request's crypto
//! leaves below the stack pointer — a RustCrypto `Copy` temporary, the `hmac`
//! crate's padded key block, a SHAKE reader's state — no `Drop` or `Secret` can
//! reach, and it stays until a later frame overwrites it. Core0 is swept after
//! every request, keyboard OTP frame, typed ticket and panel flow, core1 after
//! every prime search.

#[cfg(feature = "bench")]
use core::sync::atomic::{AtomicBool, Ordering};

use cortex_m::register::{msp, msplim};

const WORD: usize = size_of::<u32>();

/// This core's dead stack, `[floor, top)`: from the floor its `MSPLIM` holds up to
/// the stack pointer. Empty while `MSPLIM` is unarmed (it reads 0).
fn dead_region() -> (usize, usize) {
    let floor = msplim::read() as usize;
    let top = msp::read() as usize & !(WORD - 1);
    if floor == 0 {
        (0, 0)
    } else {
        (floor, top.max(floor))
    }
}

/// Zero this core's dead stack.
#[inline(never)]
pub fn dead_stack() {
    #[cfg(feature = "bench")]
    if PAUSED.load(Ordering::Relaxed) {
        return;
    }
    let (floor, top) = dead_region();
    let zero = |word: usize| {
        // SAFETY: callers pass a 4-aligned `word` in `[floor, top)`, this core's
        // stack under its live frames: no value lives there, the frames that held
        // one have returned. Volatile, so no dead-store elimination drops it.
        unsafe { core::ptr::with_exposed_provenance_mut::<u32>(word).write_volatile(0) };
    };
    let mut word = floor;
    // Eight stores a pass, written out: at `opt-level = "s"` a loop stays a loop,
    // and its compare and branch cost more than the store they repeat.
    while top - word >= 8 * WORD {
        zero(word);
        zero(word + WORD);
        zero(word + 2 * WORD);
        zero(word + 3 * WORD);
        zero(word + 4 * WORD);
        zero(word + 5 * WORD);
        zero(word + 6 * WORD);
        zero(word + 7 * WORD);
        word += 8 * WORD;
    }
    while word < top {
        zero(word);
        word += WORD;
    }
}

/// What the measurement build's residue probe reports about the dead stack.
#[cfg(feature = "bench")]
pub struct Residue {
    /// Occurrences of the probe's pattern, at any byte offset.
    pub matches: u32,
    /// Bytes that are not zero.
    pub nonzero: u32,
    /// Bytes read.
    pub scanned: u32,
}

/// Search this core's dead stack for `pattern` without writing it.
#[cfg(feature = "bench")]
pub fn residue(pattern: &[u8]) -> Residue {
    let (floor, top) = dead_region();
    let at = |addr: usize| {
        // SAFETY: callers pass `addr` in `[floor, top)`, this core's dead stack as
        // `dead_stack` reads it; a volatile read assumes nothing of what is there.
        unsafe { core::ptr::with_exposed_provenance::<u8>(addr).read_volatile() }
    };
    let (mut matches, mut nonzero) = (0, 0);
    for addr in floor..top {
        if at(addr) != 0 {
            nonzero += 1;
        }
        if addr + pattern.len() <= top
            && pattern.iter().enumerate().all(|(i, &b)| at(addr + i) == b)
        {
            matches += 1;
        }
    }
    Residue {
        matches,
        nonzero,
        scanned: (top - floor) as u32,
    }
}

/// Stop or restart the sweep on both cores, on a measurement build only: a request
/// answered while it is stopped is the positive control that shows the probe can
/// see what the sweep removes.
#[cfg(feature = "bench")]
pub fn pause(paused: bool) {
    PAUSED.store(paused, Ordering::Relaxed);
}

#[cfg(feature = "bench")]
static PAUSED: AtomicBool = AtomicBool::new(false);
