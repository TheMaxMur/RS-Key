/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

/* M3 memory map: region-for-region with firmware/memory.x's default 4 MB
 * layout (Waveshare RP2350-One), so the store fence the asm build emits
 * bounds exactly the flash the shipping image fences.
 *
 * Security classification:
 *   FLASH  rx  XIP code + const data; the only region the image's own
 *             sections occupy.
 *   KVMAIN r   the rsk-fs credential store; no linker section ever lands
 *             here. Bootrom access is denied by the partition table
 *             scripts/pt.sh embeds (bootloader: ""), not by this map —
 *             the running firmware keeps full access.
 *   KVCNT  r   the per-operation counter partition, same discipline.
 *   RAM   rwx  statics + the descending stack behind a 32-byte MPU guard.
 */

ENTRY(reset_handler)

MEMORY
{
    FLASH  (rx)  : ORIGIN = 0x10000000, LENGTH = 2560K
    KVMAIN (r)   : ORIGIN = 0x10280000, LENGTH = 1408K
    KVCNT  (r)   : ORIGIN = 0x103E0000, LENGTH = 128K
    RAM    (rwx) : ORIGIN = 0x20000000, LENGTH = 512K
}

/* KV bounds as flash-relative offsets, the exact spellings pt.sh reads out
 * of the ELF — the same ones flash_storage.rs uses on the shipping side,
 * so the fence cannot drift from what it fences. */
__kvmain_start = ORIGIN(KVMAIN) - ORIGIN(FLASH);
__kvmain_end   = __kvmain_start + LENGTH(KVMAIN);
__kvcnt_start  = ORIGIN(KVCNT) - ORIGIN(FLASH);
__kvcnt_end    = __kvcnt_start + LENGTH(KVCNT);

SECTIONS
{
    .vectors   : { KEEP(*(.vectors)) } > FLASH
    .image_def : { KEEP(*(.image_def)) } > FLASH
    .text      : { *(.text*) } > FLASH
    .rodata  : { *(.rodata*) } > FLASH

    .data : {
        __data_start = .;
        *(.data*)
        __data_end = .;
    } > RAM AT > FLASH
    __data_load = LOADADDR(.data);

    .bss (NOLOAD) : {
        __bss_start = .;
        *(.bss*) *(COMMON)
        __bss_end = .;
    } > RAM

    /* MPU-granularity guard between statics and the descending stack. */
    .stack_guard (NOLOAD) : {
        . = ALIGN(32);
        __stack_guard = .;
        . += 32;
        __stack_bottom = .;
    } > RAM

    __stack_top = ORIGIN(RAM) + LENGTH(RAM);

    ASSERT(SIZEOF(.vectors) == 64, "vector table must be 16 words")
    ASSERT(SIZEOF(.image_def) == 40, "image_def must be two blocks")
    ASSERT(ADDR(.text) == ADDR(.image_def) + SIZEOF(.image_def),
           "code must directly follow the image def")
    ASSERT(__stack_top - __stack_bottom >= 0x800, "stack must be at least 2 KiB")
    /* the map must be one contiguous 4 MB so the fence covers exactly the
     * tail: code ends where the store begins, the store ends at the top */
    ASSERT(ORIGIN(KVMAIN) == ORIGIN(FLASH) + LENGTH(FLASH),
           "KVMAIN must directly follow the code region")
    ASSERT(ORIGIN(KVCNT) == ORIGIN(KVMAIN) + LENGTH(KVMAIN),
           "KVCNT must directly follow KVMAIN")
    ASSERT(__kvcnt_end == 0x400000, "the store must end at the 4 MB top")
    /* the image's own flash footprint (last LMA: .data's load image) must
     * stay out of the store a table that misses would fence off */
    ASSERT(__data_load + SIZEOF(.data) <= ORIGIN(KVMAIN),
           "image spills into the KV store")
}
