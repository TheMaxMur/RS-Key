/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

/* RP2350A (Waveshare RP2350-One): 4 MB external QSPI flash, 520 KB on-chip SRAM.
   Layout follows the canonical rp235x linker script: the bootrom requires an
   IMAGE_DEF block in `.start_block` right after the vector table, and a matching
   `.end_block`.

   This is the default 4 MB / 1408K-KVMAIN MEMORY block; for any other FLASH_SIZE
   or KVMAIN, build.rs splices in a recomputed one (code = usable − KVMAIN − KVCNT,
   where a 16 MB part stops one sector short of the RP2350-E10 absolute block)
   and keeps everything below it verbatim. KVMAIN is baked as PK_KVMAIN_LEN and read
   back by flash_storage.rs (MAIN_LEN), so build.rs keeps the two in step; KVCNT is
   fixed. Change these defaults here AND in build.rs (DEFAULT_KVMAIN) together. */

/* The top 1.5 MB is reserved for the rsk-fs KV store, split into two partitions so
   the hot per-operation counters can't churn the credential pages (see
   flash_storage.rs): KVMAIN (1408 KB default, creds/keys/DOs) + KVCNT (128 KB,
   counters). FLASH (code) shrinks to 2560 KB — ~1.1 MB headroom over the current
   image. A small-flash build shrinks KVMAIN (e.g. FLASH_SIZE=2M KVMAIN=896K) to keep
   code room. None of the KV regions hold a linker section. */
MEMORY {
    FLASH  : ORIGIN = 0x10000000, LENGTH = 2560K
    KVMAIN : ORIGIN = 0x10280000, LENGTH = 1408K
    KVCNT  : ORIGIN = 0x103E0000, LENGTH = 128K
    RAM    : ORIGIN = 0x20000000, LENGTH = 512K
}

/* KV bounds as flash-relative offsets (what embassy-rp NorFlash takes). */
__kvmain_start = ORIGIN(KVMAIN) - ORIGIN(FLASH);
__kvmain_end   = __kvmain_start + LENGTH(KVMAIN);
__kvcnt_start  = ORIGIN(KVCNT) - ORIGIN(FLASH);
__kvcnt_end    = __kvcnt_start + LENGTH(KVCNT);

SECTIONS {
    .start_block : ALIGN(4)
    {
        __start_block_addr = .;
        KEEP(*(.start_block));
        KEEP(*(.boot_info));
    } > FLASH
} INSERT AFTER .vector_table;

/* Move .text after the boot block so the entry point sits past the IMAGE_DEF. */
_stext = ADDR(.start_block) + SIZEOF(.start_block);

SECTIONS {
    /* Picotool 'Binary Info' entries (program name, etc.). */
    .bi_entries : ALIGN(4)
    {
        __bi_entries_start = .;
        KEEP(*(.bi_entries));
        . = ALIGN(4);
        __bi_entries_end = .;
    } > FLASH
} INSERT AFTER .text;

SECTIONS {
    .end_block : ALIGN(4)
    {
        __end_block_addr = .;
        KEEP(*(.end_block));
    } > FLASH
} INSERT AFTER .uninit;

PROVIDE(start_to_end = __end_block_addr - __start_block_addr);
PROVIDE(end_to_start = __start_block_addr - __end_block_addr);
