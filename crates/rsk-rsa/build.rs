// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Build the vendored rsa-armv7 C + ARM assembly, but only when targeting the
//! embedded device (`target_os = "none"`). On the host there is no ARM assembler
//! and the crate uses a num-bigint-dig modexp fallback instead, so nothing is
//! compiled here.

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "none" {
        return; // host build — pure-Rust fallback, no C/asm
    }

    for f in [
        "csrc/bignum_asm.S",
        "csrc/bignum_high_level.c",
        "csrc/bignum_high_level.h",
        "csrc/bignum_config.h",
    ] {
        println!("cargo:rerun-if-changed={f}");
    }

    // Force the ARM cross-compiler. The nix dev shell exports CC=clang (a wrapped
    // host compiler that can't target bare-metal ARM); the target-specific
    // CC_<target> var takes precedence over CC in cc-rs.
    // SAFETY: build scripts run single-threaded at this point; no concurrent
    // env access.
    unsafe { std::env::set_var("CC_thumbv8m_main_none_eabihf", "arm-none-eabi-gcc") };

    // Explicit flags (no_default_flags): cortex-m33 enables the DSP extension the
    // assembly requires; hardfloat matches the firmware's eabihf ABI so the object
    // links cleanly.
    cc::Build::new()
        .compiler("arm-none-eabi-gcc")
        .no_default_flags(true)
        .file("csrc/bignum_high_level.c")
        .file("csrc/bignum_asm.S")
        .include("csrc")
        .flag("-mcpu=cortex-m33")
        .flag("-mthumb")
        .flag("-mfloat-abi=hard")
        .flag("-mfpu=fpv5-sp-d16")
        .flag("-O2")
        .flag("-ffreestanding")
        .flag("-ffunction-sections")
        .flag("-fdata-sections")
        .compile("bignum_armv7");
}
