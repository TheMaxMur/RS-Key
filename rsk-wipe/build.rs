// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Makes `memory.x` available to the linker and resolves the target flash size
//! so the wiper erases the whole chip (not a fixed 4 MB).
use std::env;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

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

    // The wiper's LED is its only progress signal, and the README tells the
    // operator that a dark board means the image never launched — so a wiper that
    // drives the wrong pin makes a *successful* wipe read as a failed one. GPIO16
    // was hard-coded: on `tenstar-usb`/`seeed-xiao` nothing is wired there, and on
    // `waveshare-touch-lcd` it is the panel backlight (audit run-34 #31).
    let (kind, pin, order) = resolve_led();
    println!("cargo:rustc-env=PK_LED_KIND={kind}");
    println!("cargo:rustc-env=PK_LED_PIN={pin}");
    println!("cargo:rustc-env=PK_LED_RGB={}", u8::from(order == "rgb"));
    println!("cargo:rerun-if-env-changed=LED_KIND");
    println!("cargo:rerun-if-env-changed=LED_PIN");
    println!("cargo:rerun-if-env-changed=LED_ORDER");
}

/// `[led] kind/pin/order`, from the env knobs first and the `BOARD` file second.
/// Defaults match `firmware/build.rs`: a WS2812 on GPIO16 in RGB order.
fn resolve_led() -> (String, u8, String) {
    let kind = env::var("LED_KIND")
        .ok()
        .or_else(|| board_value("led", "kind"))
        .unwrap_or_else(|| "ws2812".into());
    let pin = env::var("LED_PIN")
        .ok()
        .or_else(|| board_value("led", "pin"))
        .unwrap_or_else(|| "16".into())
        .parse::<u8>()
        .expect("LED_PIN must be a GPIO number");
    assert!(pin <= 29, "LED_PIN={pin} is not a GPIO on the RP2350");
    let order = env::var("LED_ORDER")
        .ok()
        .or_else(|| board_value("led", "order"))
        .unwrap_or_else(|| "rgb".into())
        .to_ascii_lowercase();
    assert!(
        matches!(order.as_str(), "rgb" | "grb"),
        "LED_ORDER={order:?} — expected rgb or grb"
    );
    (kind, pin, order)
}

/// Resolve `FLASH_SIZE` to a byte count. Accepts a decimal byte count, `0xHEX`,
/// or a `<n>K`/`<n>KB`/`<n>M`/`<n>MB` suffix; falls back to `BOARD`'s
/// `[flash] size_mb`. Must be sector-aligned and within the supported 16 MB.
/// Mirrors `firmware/build.rs`.
///
/// `BOARD` matters as much as the explicit knob: `docs/build.md` presents it as
/// *the* board mechanism, but `firmware/build.rs` resolves it inside its own build
/// script process, so it never reached this one. Building the documented way for a
/// 16 MB board therefore produced a 4 MB wiper — and since the KV store sits at the
/// *top* of flash, that erased the code and left every sealed secret intact while
/// the LED still signalled success (audit run-33).
///
/// **There is no default.** A 4 MB fallback meant a build with neither knob still
/// linked, and produced exactly that under-sized wiper on a bigger board — the
/// failure above, one forgotten environment variable away, with no diagnostic
/// (audit run-34 #30). Guessing the erase length of a recovery tool is not a
/// default anyone can check, so not knowing is a build error.
fn resolve_flash_size() -> u32 {
    let raw = env::var("FLASH_SIZE")
        .ok()
        .or_else(board_flash_size)
        .expect(
            "rsk-wipe needs the target flash size: set BOARD=<firmware/boards/*.toml> \
         (preferred) or FLASH_SIZE=<n>M. It bakes the erase length in at build time, \
         and an under-sized wiper leaves sealed secrets on the chip.",
        );
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

/// `[flash] size_mb` from `firmware/boards/<BOARD>.toml`, as `"<n>M"`. An
/// unreadable or size-less board file is a hard error, never a silent fall back —
/// that is exactly how an under-sized wipe would slip through again.
fn board_flash_size() -> Option<String> {
    let name = env::var("BOARD").ok()?;
    let mb = board_value("flash", "size_mb")
        .unwrap_or_else(|| panic!("BOARD={name:?}: no [flash] size_mb"));
    Some(format!("{mb}M"))
}

/// One `key` from one `[section]` of the `BOARD` file.
///
/// Section-aware on purpose. The old lookup took the first line anywhere in the
/// file starting with the key name, so a same-named key under another section won
/// — and every such disagreement with `firmware/build.rs`'s real parser resolved
/// *smaller* here, which for the erase length is the unsafe direction (run-34 #31).
fn board_value(section: &str, key: &str) -> Option<String> {
    let name = env::var("BOARD").ok()?;
    let path = format!("../firmware/boards/{name}.toml");
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|_| panic!("BOARD={name:?}: cannot read {path}"));
    println!("cargo:rerun-if-changed={path}");
    let mut here = false;
    for line in raw.lines().map(str::trim) {
        let line = line.split('#').next().unwrap_or("").trim();
        if let Some(s) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            here = s.trim() == section;
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if here && k.trim() == key {
            return Some(v.trim().trim_matches('"').to_string());
        }
    }
    None
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
