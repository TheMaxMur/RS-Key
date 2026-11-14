// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Assemble the vendored rsa-armv7 primitives for the device target.

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "none" {
        return; // host build — pure-Rust fallback, no C/asm
    }

    for f in ["csrc/bignum_asm.S", "csrc/bignum_config.h"] {
        println!("cargo:rerun-if-changed={f}");
    }

    // Explicit flags (no_default_flags): cortex-m33 enables the DSP extension the
    // assembly requires; hardfloat matches the firmware's eabihf ABI so the object
    // links cleanly.
    cc::Build::new()
        .compiler("arm-none-eabi-gcc")
        .no_default_flags(true)
        .file("csrc/bignum_asm.S")
        .include("csrc")
        .flag("-mcpu=cortex-m33")
        .flag("-mthumb")
        .flag("-mfloat-abi=hard")
        .flag("-mfpu=fpv5-sp-d16")
        .compile("bignum_armv7");
}
