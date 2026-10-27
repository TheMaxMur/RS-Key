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
    const SCRATCH_START: u32 = 0x2008_0100;
    const SCRATCH_END: u32 = 0x2008_2000;
    const XIP_WAY_BYTES: u32 = 8 * 1024;
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
    memory.push_str(&format!(
        "\nMEMORY {{ SCRATCH : ORIGIN = {SCRATCH_START:#010x}, LENGTH = {} }}\n",
        SCRATCH_END - SCRATCH_START
    ));
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
    // Keep the Montgomery ladder and field arithmetic within one XIP cache way.
    memory.push_str(&format!(
        "SECTIONS {{ .rsk_curve25519 : ALIGN({XIP_WAY_BYTES}) {{\n\
         __rsk_curve25519_start = .;\n\
         KEEP(*(.text.*FieldElement2625*Mul* .text.*FieldElement2625*Sub* .text.*FieldElement262512square_inner* .text._ZN12x25519_dalek6x255196x2551917h????????????????E))\n\
         __rsk_curve25519_end = .;\n\
         }} > FLASH }} INSERT BEFORE .rodata;\n\
         ASSERT(SIZEOF(.rsk_curve25519) > 0, \"Curve25519 code is missing\")\n\
         ASSERT(SIZEOF(.rsk_curve25519) <= {XIP_WAY_BYTES}, \"Curve25519 code exceeds one XIP cache way\")\n",
    ));
    // Keep the shared verifier and its memory helpers off the XIP path.
    memory.push_str(
        "SECTIONS {\n\
         .rsk_exec : ALIGN(32) {\n\
         __rsk_exec_start = .;\n\
         __rsk_sha256_initial_start = .;\n\
         KEEP(*(.rodata._ZN10rsk_sha2567INITIAL17h????????????????E))\n\
         __rsk_sha256_initial_end = .;\n\
         KEEP(*(.text.*rsk_sha256* .text._ZN10rsk_crypto3mac10HmacSha256* .text._ZN10rsk_crypto3mac11hkdf_sha256* .text._ZN10rsk_crypto4drbg8HmacDrbg*)) KEEP(*(.data.bignum_hl .data.bignum_asm .data.sieve_step .data.ram_func))\n\
         KEEP(*(.text._ZN9rsk_store13authenticated6record5Entry15verify_with_mac17h????????????????E))\n\
         KEEP(*(.text._ZN10rsk_crypto4hash6sha25617h????????????????E))\n\
         __rsk_memory_start = .;\n\
         KEEP(*(.text.__aeabi_mem* .text.memcpy .text.memmove .text.memset .text.*compiler_builtins3mem6memcpy .text.*compiler_builtins3mem7memmove))\n\
         __rsk_memory_end = .;\n\
         KEEP(*(.text._ZN3aes4soft8fixslice14aes256_encrypt17h????????????????E))\n\
         KEEP(*(.text._ZN3aes4soft8fixslice9sub_bytes17h????????????????E))\n\
         KEEP(*(.text._ZN3aes4soft8fixslice13mix_columns_117h????????????????E))\n\
         KEEP(*(.text._ZN3aes4soft8fixslice13mix_columns_317h????????????????E))\n\
         KEEP(*(.text._ZN65_$LT$aes..soft..Aes256$u20$as$u20$cipher..block..BlockEncrypt$GT$20encrypt_with_backend17h????????????????E))\n\
         KEEP(*(.text._ZN75_$LT$ghash..GHashBackend$LT$B$GT$$u20$as$u20$universal_hash..UhfBackend$GT$10proc_block17h????????????????E))\n\
         KEEP(*(.text._ZN7aes_gcm39AesGcm$LT$Aes$C$NonceSize$C$TagSize$GT$11compute_tag17h????????????????E))\n\
         KEEP(*(.text._ZN4p25610arithmetic5field10field_impl3add17h????????????????E))\n\
         KEEP(*(.text._ZN4p25610arithmetic5field10field_impl17montgomery_reduce17h????????????????E))\n\
         KEEP(*(.text._ZN4p25610arithmetic5field10field_impl3sub17h????????????????E))\n\
         KEEP(*(.text._ZN13crypto_bigint4uint3mul9karatsuba18widening_mul_fixed17h????????????????E))\n\
         KEEP(*(.text._ZN14num_bigint_dig10algorithms3mac4long17h????????????????E))\n\
         KEEP(*(.text._ZN74_$LT$firmware..ZeroingHeap$u20$as$u20$core..alloc..global..GlobalAlloc$GT$7dealloc17h????????????????E))\n\
         KEEP(*(.text._ZN13crypto_bigint4limb2ct97_$LT$impl$u20$ctutils..traits..ct_assign..CtAssignSlice$u20$for$u20$crypto_bigint..limb..Limb$GT$15ct_assign_slice17h????????????????E))\n\
         KEEP(*(.text._ZN124_$LT$num_bigint_dig..biguint..BigUint$u20$as$u20$core..ops..arith..SubAssign$LT$$RF$num_bigint_dig..biguint..BigUint$GT$$GT$10sub_assign17h????????????????E))\n\
         KEEP(*(.text._ZN6rsk_ec3key16ecdh_p256_shared17h????????????????E))\n\
         KEEP(*(.text._ZN14elliptic_curve4ecdh14diffie_hellman17h????????????????E))\n\
         KEEP(*(.text._ZN10primeorder6tables6lookup24LookupTable$LT$Point$GT$6select17h????????????????E))\n\
         KEEP(*(.text._ZN67_$LT$p256..arithmetic..field..FieldElement$u20$as$u20$ff..Field$GT$6square17h????????????????E))\n\
         KEEP(*(.text._ZN4p38410arithmetic5field12montgomery328multiply17h????????????????E))\n\
         KEEP(*(.text._ZN14num_bigint_dig10algorithms3div7div_rem17h????????????????E))\n\
         KEEP(*(.text._ZN14num_bigint_dig10algorithms3mul4mul317h????????????????E))\n\
         KEEP(*(.text._ZN14num_bigint_dig10algorithms3mac9karatsuba17h????????????????E))\n\
         KEEP(*(.text._ZN14num_bigint_dig10algorithms3sub8sub_sign17h????????????????E))\n\
         . = ALIGN(32); __rsk_exec_end = .;\n\
         } > RAM AT> FLASH\n\
         } INSERT BEFORE .data;\n\
         SECTIONS { .rsk_init_anchor (NOLOAD) : { __sdata = ADDR(.rsk_exec); __sidata = LOADADDR(.rsk_exec); } > RAM } INSERT AFTER .uninit;\n\
         ASSERT(__rsk_sha256_initial_end - __rsk_sha256_initial_start == 32, \"SHA-256 initial vector is not 32 bytes\")\n\
         ASSERT(__rsk_memory_end > __rsk_memory_start, \"Memory helpers are missing from Secure SRAM\")\n\
         ASSERT(LOADADDR(.data) - LOADADDR(.rsk_exec) == ADDR(.data) - ADDR(.rsk_exec), \"RAM initialization is not contiguous\")\n",
    );
    // The first 256 bytes remain outside code for SRAM residue positive controls.
    memory.push_str(
        "SECTIONS {\n\
         .rsk_scratch_exec : ALIGN(32) {\n\
         __rsk_scratch_exec_start = .;\n\
         KEEP(*(.text._ZN4p52110arithmetic5field10field_impl19fiat_p521_carry_mul17h????????????????E*))\n\
         KEEP(*(.text._ZN4p52110arithmetic5field10field_impl22fiat_p521_carry_square17h????????????????E*))\n\
         __rsk_scratch_payload_end = .;\n\
         . = ORIGIN(SCRATCH) + LENGTH(SCRATCH);\n\
         __rsk_scratch_exec_end = .;\n\
         } > SCRATCH AT> FLASH = 0\n\
         __rsk_scratch_exec_load = LOADADDR(.rsk_scratch_exec);\n\
         } INSERT BEFORE .rsk_exec;\n\
         ASSERT(__rsk_scratch_payload_end > __rsk_scratch_exec_start, \"P-521 field code is missing from scratch SRAM\")\n\
         ASSERT(__rsk_scratch_payload_end <= __rsk_scratch_exec_end, \"P-521 field code exceeds scratch SRAM\")\n",
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
