// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use std::{env, path::Path, process::Command};

fn run(command: &mut Command) {
    assert!(
        command
            .status()
            .expect("run TrustZone build tool")
            .success()
    );
}

pub fn configure(out: &Path, memory: &mut String, code_size: u32, flash_size: u32) {
    const FLASH_BASE: u32 = 0x1000_0000;
    const NS_BYTES: u32 = 64 * 1024;
    const NSC_BYTES: u32 = 4096;
    let ns_start = FLASH_BASE + code_size - NS_BYTES;
    let ns_end = ns_start + NS_BYTES;
    let nsc_start = ns_start - NSC_BYTES;
    let begin = memory.find("MEMORY {").unwrap();
    let end = begin + memory[begin..].find('}').unwrap();
    let block = memory[begin..=end]
        .replace(
            &format!(
                "FLASH  : ORIGIN = 0x10000000, LENGTH = {}K",
                code_size / 1024
            ),
            &format!(
                "FLASH  : ORIGIN = 0x10000000, LENGTH = {}K",
                (code_size - NS_BYTES) / 1024
            ),
        )
        .replace(
            "RAM    : ORIGIN = 0x20000000, LENGTH = 512K",
            "RAM    : ORIGIN = 0x20000000, LENGTH = 448K",
        )
        .replace(
            "    KVMAIN :",
            &format!("    NSFLASH : ORIGIN = {ns_start:#010x}, LENGTH = 64K\n    KVMAIN :"),
        );
    memory.replace_range(begin..=end, &block);
    let ns_memory = env::var("RSK_TZ_NS_MEMORY").expect("RSK_TZ_NS_MEMORY");
    std::fs::write(&ns_memory, format!(
        "/* SPDX-License-Identifier: AGPL-3.0-only */\n/* Copyright (C) 2026 RS-Key contributors */\nMEMORY {{\n FLASH : ORIGIN = {ns_start:#010x}, LENGTH = 64K\n RAM : ORIGIN = 0x20070000, LENGTH = 64K\n}}\n"
    )).unwrap();
    for (name, value) in [
        ("PK_TZ_NS_FLASH", ns_start),
        ("PK_TZ_NS_FLASH_END", ns_end),
        ("PK_TZ_NSC_FLASH", nsc_start),
        ("PK_TZ_FLASH_END", FLASH_BASE + flash_size),
    ] {
        println!("cargo:rustc-env={name}={value}");
    }
    println!("cargo:rerun-if-env-changed=RSK_TZ_NS_MEMORY");
    memory.push_str(
        "\nSECTIONS { .nonsecure : { KEEP(*(.nonsecure)) } > NSFLASH } INSERT AFTER .end_block;\n",
    );
    memory.push_str(&format!(
        "ASSERT(LOADADDR(.data) + SIZEOF(.data) <= {nsc_start:#010x}, \"Secure image overlaps NSC\")\n",
    ));
    // Keep the shared verifier instructions off the XIP path.
    memory.push_str(
        "SECTIONS {\n\
         .rsk_exec : ALIGN(32) {\n\
         __rsk_exec_start = .;\n\
         __rsk_sha256_initial_start = .;\n\
         KEEP(*(.rodata._ZN10rsk_sha2567INITIAL17h????????????????E))\n\
         __rsk_sha256_initial_end = .;\n\
         KEEP(*(.text.*rsk_sha256* .text._ZN10rsk_crypto3mac10HmacSha256* .text._ZN10rsk_crypto3mac11hkdf_sha256* .text._ZN10rsk_crypto4drbg8HmacDrbg*)) KEEP(*(.data.bignum_hl .data.bignum_asm .data.sieve_step .data.ram_func))\n\
         . = ALIGN(32); __rsk_exec_end = .;\n\
         } > RAM AT> FLASH\n\
         } INSERT BEFORE .data;\n\
         SECTIONS { .rsk_init_anchor (NOLOAD) : { __sdata = ADDR(.rsk_exec); __sidata = LOADADDR(.rsk_exec); } > RAM } INSERT AFTER .uninit;\n\
         ASSERT(__rsk_sha256_initial_end - __rsk_sha256_initial_start == 32, \"SHA-256 initial vector is not 32 bytes\")\n\
         ASSERT(LOADADDR(.data) - LOADADDR(.rsk_exec) == ADDR(.data) - ADDR(.rsk_exec), \"RAM initialization is not contiguous\")\n",
    );
    let object = out.join("gateway.o");
    run(Command::new("arm-none-eabi-gcc")
        .args([
            "-mcpu=cortex-m33",
            "-mthumb",
            "-mcmse",
            "-mfloat-abi=hard",
            "-mfpu=fpv5-sp-d16",
            "-O2",
            "-ffunction-sections",
            "-fdata-sections",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-c",
            "src/trustzone/gateway.c",
            "-o",
        ])
        .arg(&object));
    println!("cargo:rustc-link-arg={}", object.display());
    println!("cargo:rustc-link-arg=--cmse-implib");
    let import = env::var("RSK_TZ_IMPLIB").expect("RSK_TZ_IMPLIB");
    std::fs::create_dir_all(
        Path::new(&import)
            .parent()
            .expect("import library directory"),
    )
    .unwrap();
    println!("cargo:rustc-link-arg=--out-implib={import}");
    println!("cargo:rustc-link-arg=--section-start=.gnu.sgstubs={nsc_start:#010x}");
    if let Ok(image) = env::var("RSK_TZ_NS_IMAGE") {
        let embedded = out.join("nonsecure.o");
        run(Command::new("arm-none-eabi-objcopy")
            .args([
                "-I",
                "binary",
                "-O",
                "elf32-littlearm",
                "-B",
                "arm",
                // Binary symbols encode the random Nix build directory.
                "--strip-all",
                "--rename-section",
                ".data=.nonsecure,alloc,load,readonly,data,contents",
            ])
            .arg(&image)
            .arg(&embedded));
        println!("cargo:rustc-link-arg={}", embedded.display());
        println!("cargo:rerun-if-changed={image}");
    }
    println!("cargo:rerun-if-changed=src/trustzone/gateway.c");
    println!("cargo:rerun-if-env-changed=RSK_TZ_IMPLIB");
    println!("cargo:rerun-if-env-changed=RSK_TZ_NS_IMAGE");
}
