// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `bcdDevice`, read out of the firmware's own source at compile time.
//!
//! A host reads it before anything else, so an emulator claiming a build it is
//! not running lies in the very first descriptor it serves — and it was a
//! hand-copied number, 172 releases behind the firmware by the time anyone
//! looked. Copying it again only resets that clock: the counter moves on every
//! firmware-behaviour change, several times a day here.
//!
//! So it is derived from the one place that binds it, which is the same place
//! `scripts/bcd_gate.py` reads and the same rule: comment lines first, then the
//! binding. `tools/emu` is a detached workspace and cannot depend on `firmware`
//! (thumbv8m-only), so the source is the interface — and a firmware that stops
//! binding it fails this build with a message saying so, rather than serving a
//! number nobody has checked since.

/// The binding, character for character as `scripts/bcd_gate.py` writes it —
/// same name there, so a `git grep RELEASE_TEXT` lands on both readers and a
/// rename breaks both at once instead of leaving one quietly reading a stale tree.
const RELEASE_TEXT: &[u8] = b"let device_release: u16 = 0x";

/// The counter the firmware in this checkout carries.
pub const BCD_DEVICE: u16 = parse(include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../firmware/src/main.rs"
)));

/// The first non-comment `let device_release: u16 = 0x…` in `src`.
///
/// Comment lines are dropped as `bcd_gate.py`'s `release()` drops them: one line
/// of prose quoting the binding — a `// next release: … = 0xFFFF` note — would
/// otherwise be the value, and the two readers would disagree about the same
/// file.
const fn parse(src: &str) -> u16 {
    let b = src.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let mut j = i;
        // Everything `str::strip` would take off a line but the newline itself:
        // `bcd_gate.py` strips before it looks for a `//`, and a decoy indented
        // with a form feed would otherwise be read here and dropped there.
        while j < b.len() && b[j] != b'\n' && b[j].is_ascii_whitespace() {
            j += 1;
        }
        let comment = j + 1 < b.len() && b[j] == b'/' && b[j + 1] == b'/';
        while j < b.len() && b[j] != b'\n' {
            if !comment && at(b, j, RELEASE_TEXT) {
                return hex(b, j + RELEASE_TEXT.len());
            }
            j += 1;
        }
        i = j + 1;
    }
    panic!("firmware/src/main.rs no longer binds `let device_release: u16 = 0x…`");
}

/// Whether `want` sits at `from`.
const fn at(b: &[u8], from: usize, want: &[u8]) -> bool {
    if from + want.len() > b.len() {
        return false;
    }
    let mut k = 0;
    while k < want.len() {
        if b[from + k] != want[k] {
            return false;
        }
        k += 1;
    }
    true
}

/// The hex digits at `from`, which the anchor has already eaten the `0x` of.
const fn hex(b: &[u8], from: usize) -> u16 {
    let (mut v, mut n, mut i) = (0u32, 0usize, from);
    while i < b.len() {
        let d = match b[i] {
            c @ b'0'..=b'9' => (c - b'0') as u32,
            c @ b'a'..=b'f' => (c - b'a') as u32 + 10,
            c @ b'A'..=b'F' => (c - b'A') as u32 + 10,
            _ => break,
        };
        v = v * 16 + d;
        n += 1;
        i += 1;
    }
    assert!(
        n > 0,
        "the binding in firmware/src/main.rs carries no digits"
    );
    assert!(
        v <= u16::MAX as u32,
        "the binding in firmware/src/main.rs does not fit a bcdDevice"
    );
    v as u16
}

#[cfg(test)]
#[path = "bcd_tests.rs"]
mod tests;
