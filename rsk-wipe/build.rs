// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Makes `memory.x` available to the linker and resolves the target flash size
//! so the wiper erases the whole chip (not a fixed 4 MB).
use std::env;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

const DEFAULT_FLASH_SIZE: u32 = 4 * 1024 * 1024;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    File::create(out.join("memory.x"))
        .unwrap()
        .write_all(include_bytes!("memory.x"))
        .unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=build.rs");

    // Erase the whole target flash, not a fixed 4 MB — a larger board (e.g. the
    // 16 MiB display board) must not keep sealed secrets above the assumed size.
    // Same `FLASH_SIZE` knob and the same `BOARD` file the firmware build reads.
    println!("cargo:rustc-env=PK_FLASH_SIZE={}", resolve_flash_size());
    println!("cargo:rerun-if-env-changed=FLASH_SIZE");
    println!("cargo:rerun-if-env-changed=BOARD");
}

/// Resolve `FLASH_SIZE` to a byte count. Accepts a decimal byte count, `0xHEX`,
/// or a `<n>K`/`<n>KB`/`<n>M`/`<n>MB` suffix; falls back to `BOARD`'s
/// `[flash] size_mb`, then to 4 MB. Must be sector-aligned and within the
/// supported 16 MB. Mirrors `firmware/build.rs`.
///
/// `BOARD` matters as much as the explicit knob: `docs/build.md` presents it as
/// *the* board mechanism, but `firmware/build.rs` resolves it inside its own build
/// script process, so it never reached this one. Building the documented way for a
/// 16 MB board therefore produced a 4 MB wiper — and since the KV store sits at the
/// *top* of flash, that erased the code and left every sealed secret intact while
/// the LED still signalled success (audit run-33).
fn resolve_flash_size() -> u32 {
    let raw = env::var("FLASH_SIZE")
        .ok()
        .or_else(board_flash_size)
        .unwrap_or_else(|| DEFAULT_FLASH_SIZE.to_string());
    let bytes = parse_size(raw.trim())
        .unwrap_or_else(|| panic!("FLASH_SIZE={raw:?} — use a byte count, 0xHEX, or <n>K / <n>M"));
    assert!(
        bytes.is_multiple_of(4096),
        "FLASH_SIZE={bytes} must be a multiple of 4096 (the QSPI erase sector)"
    );
    // Lower bound: `0` (and `0x0`/`0K`/`0M`) passes the other asserts and makes
    // flash_range_erase a count-0 no-op — a "successful" wipe that erases nothing
    // and leaves sealed secrets on the chip. Reject any degenerate sub-chip size.
    assert!(
        bytes >= 64 * 1024,
        "FLASH_SIZE={bytes} too small — a 0/degenerate value would erase nothing"
    );
    assert!(
        bytes <= 16 * 1024 * 1024,
        "FLASH_SIZE={bytes} exceeds the supported 16 MiB"
    );
    bytes
}

/// `[flash] size_mb` from `firmware/boards/<BOARD>.toml`, as `"<n>M"`. The board
/// file is the shared definition; only this one key is read here, because the
/// firmware's full parser lives in its own build script. An unreadable or
/// size-less board file is a hard error, never a silent fall back to the default —
/// that is exactly how an under-sized wipe would slip through again.
fn board_flash_size() -> Option<String> {
    let name = env::var("BOARD").ok()?;
    let path = format!("../firmware/boards/{name}.toml");
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|_| panic!("BOARD={name:?}: cannot read {path}"));
    println!("cargo:rerun-if-changed={path}");
    let mb = raw
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("size_mb"))
        .and_then(|v| v.trim_start().strip_prefix('='))
        .and_then(|v| v.split('#').next())
        .map(str::trim)
        .unwrap_or_else(|| panic!("BOARD={name:?}: {path} has no [flash] size_mb"));
    Some(format!("{mb}M"))
}

/// Parse `123`, `0x10000`, `512K`, `4M`, `4MB`, … into a byte count.
fn parse_size(s: &str) -> Option<u32> {
    let lower = s.to_ascii_lowercase();
    let (digits, mult) = if let Some(n) = lower.strip_suffix("mb").or(lower.strip_suffix('m')) {
        (n, 1024 * 1024)
    } else if let Some(n) = lower.strip_suffix("kb").or(lower.strip_suffix('k')) {
        (n, 1024)
    } else {
        (lower.as_str(), 1)
    };
    let digits = digits.trim();
    let base = match digits.strip_prefix("0x") {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => digits.parse::<u32>().ok()?,
    };
    base.checked_mul(mult)
}
