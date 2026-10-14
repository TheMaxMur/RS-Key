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

pub fn configure(out: &Path, memory: &mut String) {
    assert_eq!(env::var("FLASH_SIZE").unwrap_or_else(|_| "4M".into()), "4M");
    *memory = memory.replace("LENGTH = 2560K", "LENGTH = 2048K");
    *memory = memory.replace("LENGTH = 512K", "LENGTH = 448K");
    *memory = memory.replace(
        "    KVMAIN :",
        "    NSFLASH : ORIGIN = 0x10200000, LENGTH = 512K\n    KVMAIN :",
    );
    memory.push_str(
        "\nSECTIONS { .nonsecure : { KEEP(*(.nonsecure)) } > NSFLASH } INSERT AFTER .end_block;\n",
    );
    memory.push_str(
        "ASSERT(LOADADDR(.data) + SIZEOF(.data) <= 0x101ff000, \"Secure image overlaps NSC\")\n",
    );
    memory.push_str(
        "SECTIONS {\n\
         .rsk_exec : ALIGN(32) {\n\
         __rsk_exec_start = .;\n\
         KEEP(*(.data.bignum_hl .data.bignum_asm .data.sieve_step .data.ram_func))\n\
         . = ALIGN(32); __rsk_exec_end = .;\n\
         } > RAM AT> FLASH\n\
         } INSERT BEFORE .data;\n\
         SECTIONS { .rsk_init_anchor (NOLOAD) : { __sdata = ADDR(.rsk_exec); __sidata = LOADADDR(.rsk_exec); } > RAM } INSERT AFTER .uninit;\n\
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
    println!("cargo:rustc-link-arg=--section-start=.gnu.sgstubs=0x101ff000");
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
