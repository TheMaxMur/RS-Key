// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use std::{env, path::Path, process::Command};

pub fn validate_stage() {
    println!("cargo:rerun-if-env-changed=RSK_TZ_STAGE");
    println!("cargo:rerun-if-env-changed=RSK_TZ_NS_IMAGE");
    match env::var("RSK_TZ_STAGE").as_deref() {
        Ok("import") => assert!(
            env::var_os("RSK_TZ_NS_IMAGE").is_none(),
            "the import-library stage must not embed a Non-secure image"
        ),
        Ok("final") => {
            let image = env::var("RSK_TZ_NS_IMAGE")
                .expect("the final TrustZone stage requires RSK_TZ_NS_IMAGE");
            let length = std::fs::metadata(image)
                .expect("read the Non-secure image")
                .len();
            assert!(
                (8..=64 * 1024).contains(&length),
                "invalid Non-secure image size"
            );
        }
        _ => panic!(
            "RS-Key requires Secure + Non-secure firmware; build with \
             `bash firmware/trustzone/build.sh` or `nix build .#firmware`"
        ),
    }
}

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
    const XIP_LINE_BYTES: u32 = 8;
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
        "\nMEMORY {{\n SCRATCH : ORIGIN = {SCRATCH_START:#010x}, LENGTH = {}\n}}\n",
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
        "\nSECTIONS { .nonsecure : { KEEP(*(.nonsecure)) } > NSFLASH } INSERT AFTER .end_block;\n\
         __rsk_ns_image_len = SIZEOF(.nonsecure);\n",
    );
    if env::var("RSK_TZ_STAGE").as_deref() == Ok("final") {
        memory.push_str("ASSERT(SIZEOF(.nonsecure) >= 8, \"Non-secure image is missing\")\n");
    }
    memory.push_str(&format!(
        "ASSERT(LOADADDR(.data) + SIZEOF(.data) <= {nsc_start:#010x}, \"Secure image overlaps NSC\")\n",
    ));
    // Keep the Montgomery ladder and field arithmetic within one XIP cache way.
    // Rust 1.99 folds APLUS2_OVER_FOUR into immediate multiplication by 121666;
    // guard the reviewed ladder body instead of the eliminated 40-byte constant.
    memory.push_str(&format!(
        "SECTIONS {{ .rsk_curve25519 : ALIGN({XIP_WAY_BYTES}) {{\n\
         __rsk_curve25519_start = .;\n\
         KEEP(*(.text.*FieldElement2625*Mul* .text.*FieldElement2625*Sub* .text.*FieldElement262512square_inner*))\n\
         . = ALIGN(4); __rsk_curve25519_barrier_start = .;\n\
         KEEP(*(.text._RINvCs*_6subtle9black_boxhE*))\n\
         __rsk_curve25519_barrier_end = .;\n\
         __rsk_curve25519_field_end = .;\n\
         . = ALIGN(4); __rsk_x25519_start = .;\n\
         KEEP(*(.text._RNvNtCs*_12x25519_dalek6x255196x25519*))\n\
         __rsk_x25519_end = .;\n\
         __rsk_curve25519_end = .;\n\
         }} > FLASH }} INSERT BEFORE .rodata;\n\
         ASSERT(SIZEOF(.rsk_curve25519) > 0, \"Curve25519 code is missing\")\n\
         ASSERT(__rsk_curve25519_barrier_start > __rsk_curve25519_start, \"Curve25519 field code is missing\")\n\
         ASSERT(__rsk_curve25519_barrier_end - __rsk_curve25519_barrier_start == 18, \"Constant-time barrier changed; review grouping\")\n\
         ASSERT(__rsk_x25519_end - __rsk_x25519_start == 4900, \"X25519 ladder changed; review grouping\")\n\
         ASSERT(SIZEOF(.rsk_curve25519) <= {XIP_WAY_BYTES}, \"Curve25519 code exceeds one XIP cache way\")\n",
    ));
    // Keep the Edwards loop off the field core's cache indices, leaving a way
    // for its public basepoint table (RP2350 datasheet section 4.4.1).
    memory.push_str(&format!(
        "__rsk_ed25519_offset = ALIGN(__rsk_curve25519_field_end - __rsk_curve25519_start, {XIP_LINE_BYTES});\n\
         SECTIONS {{ .rsk_ed25519 : ALIGN({XIP_WAY_BYTES}) {{\n\
         . += __rsk_ed25519_offset;\n\
         __rsk_ed25519_code_start = .;\n\
         KEEP(*(.text._RNvX*16curve25519_dalek7backend6serial12curve_models*12EdwardsPoint*3Add*16AffineNielsPointE3add*))\n\
         KEEP(*(.text._RNvM*16curve25519_dalek7edwards*12EdwardsPoint8mul_base*))\n\
         KEEP(*(.text._RNvM*16curve25519_dalek6window*11LookupTable*16AffineNielsPointE6select*))\n\
         KEEP(*(.text._RNvX*16curve25519_dalek7backend6serial12curve_models*16AffineNielsPoint*6subtle23ConditionallySelectable18conditional_assign*))\n\
         }} > FLASH }} INSERT BEFORE .rodata;\n\
         ASSERT(SIZEOF(.rsk_ed25519) > __rsk_ed25519_offset, \"Ed25519 code is missing\")\n\
         ASSERT(__rsk_ed25519_offset > 0 && __rsk_ed25519_code_start % {XIP_WAY_BYTES} == __rsk_ed25519_offset, \"Ed25519 cache offset differs from field span\")\n\
         ASSERT(SIZEOF(.rsk_ed25519) <= {XIP_WAY_BYTES}, \"Ed25519 code overlaps field cache indices\")\n",
    ));
    // Group the hot callees so the comb loop cannot introduce a third cache tag.
    memory.push_str(&format!(
        "SECTIONS {{ .rsk_k256_field : ALIGN({XIP_WAY_BYTES}) {{\n\
         KEEP(*(.text._R*4k25610arithmetic5field*))\n\
         KEEP(*(.text._RNvM*4k25610arithmetic10projective*15ProjectivePoint10add_assign*))\n\
         KEEP(*(.text._RNvX*4k25610arithmetic6affine*11AffinePoint*6subtle23ConditionallySelectable18conditional_select*))\n\
         }} > FLASH }} INSERT BEFORE .rodata;\n\
         ASSERT(SIZEOF(.rsk_k256_field) > 0, \"secp256k1 field code is missing\")\n\
         ASSERT(SIZEOF(.rsk_k256_field) <= {XIP_WAY_BYTES}, \"secp256k1 field code exceeds one XIP cache way\")\n",
    ));
    // The signed P-384 comb's tables are in RAM; its hot flash callees fit in
    // one cache way without competing with each other for cache indices.
    memory.push_str(&format!(
        "SECTIONS {{ .rsk_p384_comb : ALIGN({XIP_WAY_BYTES}) {{\n\
         KEEP(*(.text._RNvM*4p38410arithmetic5field*12FieldElement3add*))\n\
         KEEP(*(.text._RNvM*4p38410arithmetic5field*12FieldElement3sub*))\n\
         KEEP(*(.text._RNvM*4p38410arithmetic5field*12FieldElement6double*))\n\
         KEEP(*(.text._RNvNtNtNtCs*_4p38410arithmetic5field12montgomery326square*))\n\
         KEEP(*(.text._RNvNtCs*_6rsk_ec9comb_p38413comb_mul_p384*))\n\
         __rsk_p384_mixed_start = .;\n\
         KEEP(*(.text._RNvX*10primeorder16point_arithmetic*21EquationAIsMinusThree*15PointArithmetic*4p3848NistP384E16add_assign_mixed*))\n\
         __rsk_p384_mixed_end = .;\n\
         }} > FLASH }} INSERT BEFORE .rodata;\n\
         ASSERT(__rsk_p384_mixed_end - __rsk_p384_mixed_start == 634, \"P-384 mixed addition monomorph changed; review placement\")\n\
         ASSERT(SIZEOF(.rsk_p384_comb) <= {XIP_WAY_BYTES}, \"P-384 comb code exceeds one XIP cache way\")\n",
    ));
    // Keep the shared verifier and its memory helpers off the XIP path.
    // The P-256 addition monomorph's size check makes dependency drift explicit.
    memory.push_str(
        "SECTIONS {\n\
         .rsk_exec : ALIGN(32) {\n\
         __rsk_exec_start = .;\n\
         __rsk_sha256_initial_start = .;\n\
         KEEP(*(.rodata._RNvCs*_10rsk_sha2567INITIAL))\n\
         __rsk_sha256_initial_end = .;\n\
         KEEP(*(.text.*rsk_sha256* .text._RNvM*10rsk_crypto3mac*10HmacSha256* .text._RNvNtCs*_10rsk_crypto3mac11hkdf_sha256* .text._RNvM*10rsk_crypto4drbg*8HmacDrbg*)) KEEP(*(.data.bignum_hl .data.bignum_asm .data.sieve_step .data.ram_func))\n\
         KEEP(*(.text._RNvM*9rsk_store13authenticated6record*5Entry15verify_with_mac*))\n\
         KEEP(*(.text._RNvNtCs*_10rsk_crypto4hash6sha256*))\n\
         __rsk_memory_start = .;\n\
         KEEP(*(.text.__aeabi_mem* .text.memcpy .text.memmove .text.memset .text.*compiler_builtins3mem6memcpy .text.*compiler_builtins3mem7memmove))\n\
         __rsk_memory_end = .;\n\
         KEEP(*(.text._RNvNtNtCs*_3aes4soft8fixslice14aes256_encrypt*))\n\
         KEEP(*(.text._RNvNtNtCs*_3aes4soft8fixslice9sub_bytes*))\n\
         KEEP(*(.text._RNvNtNtCs*_3aes4soft8fixslice13mix_columns_1*))\n\
         KEEP(*(.text._RNvNtNtCs*_3aes4soft8fixslice13mix_columns_3*))\n\
         KEEP(*(.text._RINvX*3aes4soft*6Aes256*6cipher5block12BlockEncrypt20encrypt_with_backend*))\n\
         KEEP(*(.text._RNvX*5ghash*12GHashBackend*14universal_hash10UhfBackend10proc_block*))\n\
         KEEP(*(.text._RNvM*7aes_gcm*6AesGcm*11compute_tag*))\n\
         KEEP(*(.text._RNvNtNtNtCs*_4p25610arithmetic5field10field_impl3add*))\n\
         KEEP(*(.text._RNvNtNtNtCs*_4p25610arithmetic5field10field_impl17montgomery_reduce*))\n\
         KEEP(*(.text._RNvNtNtNtCs*_4p25610arithmetic5field10field_impl3sub*))\n\
         KEEP(*(.text._RINvNtNtNtCs*_13crypto_bigint4uint3mul9karatsuba18widening_mul_fixed*))\n\
         KEEP(*(.text._RNvNtNtCs*_14num_bigint_dig10algorithms3mac4long*))\n\
         KEEP(*(.text._RNvX*8firmware*11ZeroingHeap*4core5alloc6global11GlobalAlloc7dealloc*))\n\
         KEEP(*(.text._RNvX*13crypto_bigint4limb2ct*4Limb*7ctutils6traits9ct_assign13CtAssignSlice15ct_assign_slice*))\n\
         KEEP(*(.text._RNvX*14num_bigint_dig7biguint*7BigUint*4core3ops5arith9SubAssign*10sub_assign*))\n\
         __rsk_p256_add_start = .;\n\
         KEEP(*(.text._RNvX*10primeorder16point_arithmetic*21EquationAIsMinusThree*15PointArithmetic*4p2568NistP256E10add_assign*))\n\
         __rsk_p256_add_end = .;\n\
         KEEP(*(.text._RNvX*4p25610arithmetic5field*12FieldElement*2ff5Field6invert*))\n\
         KEEP(*(.text._RNvNtCs*_6rsk_ec3key16ecdh_p256_shared*))\n\
         KEEP(*(.text._RINvNtCs*_14elliptic_curve4ecdh14diffie_hellman*))\n\
         KEEP(*(.text._RNvM*10primeorder6tables6lookup*11LookupTable*6select*))\n\
         KEEP(*(.text._RNvX*4p25610arithmetic5field*12FieldElement*2ff5Field6square*))\n\
         KEEP(*(.text._RNvNtNtNtCs*_4p38410arithmetic5field12montgomery328multiply*))\n\
         KEEP(*(.text._RNvNtNtCs*_14num_bigint_dig10algorithms3div7div_rem*))\n\
         KEEP(*(.text._RNvNtNtCs*_14num_bigint_dig10algorithms3mul4mul3*))\n\
         KEEP(*(.text._RNvNtNtCs*_14num_bigint_dig10algorithms3mac9karatsuba*))\n\
         KEEP(*(.text._RNvNtNtCs*_14num_bigint_dig10algorithms3sub8sub_sign*))\n\
         __rsk_flash_read_start = .;\n\
         KEEP(*(.text._RNCNvXs_NtCs*_8firmware13flash_storageNtB*_11SharedFlashNtNtCs*_22embedded_storage_async9nor_flash12ReadNorFlash4read0*))\n\
         __rsk_flash_read_end = .;\n\
         . = ALIGN(32); __rsk_exec_end = .;\n\
         } > RAM AT> FLASH\n\
         } INSERT BEFORE .data;\n\
         SECTIONS { .rsk_init_anchor (NOLOAD) : { __sdata = ADDR(.rsk_exec); __sidata = LOADADDR(.rsk_exec); } > RAM } INSERT AFTER .uninit;\n\
         ASSERT(__rsk_sha256_initial_end - __rsk_sha256_initial_start == 32, \"SHA-256 initial vector is not 32 bytes\")\n\
         ASSERT(__rsk_p256_add_end - __rsk_p256_add_start == 798, \"P-256 addition monomorph changed; review relocation\")\n\
         ASSERT(__rsk_memory_end > __rsk_memory_start, \"Memory helpers are missing from Secure SRAM\")\n\
         ASSERT(__rsk_flash_read_end > __rsk_flash_read_start, \"Shared flash reader is missing from Secure SRAM\")\n\
         ASSERT(LOADADDR(.data) - LOADADDR(.rsk_exec) == ADDR(.data) - ADDR(.rsk_exec), \"RAM initialization is not contiguous\")\n",
    );
    // The first 256 bytes remain outside code for SRAM residue positive controls.
    memory.push_str(
        "SECTIONS {\n\
         .rsk_scratch_exec : ALIGN(32) {\n\
         __rsk_scratch_exec_start = .;\n\
         KEEP(*(.text._RNvNtNtNtCs*_4p52110arithmetic5field10field_impl19fiat_p521_carry_mul*))\n\
         KEEP(*(.text._RNvNtNtNtCs*_4p52110arithmetic5field10field_impl22fiat_p521_carry_square*))\n\
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
    let secure_memory = env::var("RSK_TZ_SECURE_MEMORY").expect("RSK_TZ_SECURE_MEMORY");
    std::fs::write(secure_memory, memory).expect("write the Secure memory map");
    println!("cargo:rerun-if-env-changed=RSK_TZ_SECURE_MEMORY");
}
