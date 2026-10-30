/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

/* rsk-wipe is a RAM-ONLY image. The whole program runs from SRAM so it can
   erase ALL of flash — including offset 0, where a flash-resident image would
   be executing from — and then reboot cleanly to BOOTSEL.

   There is no real FLASH region: the cortex-m-rt `FLASH` region is just the part
   of SRAM that holds code/rodata/.data-init; `RAM` holds .data/.bss/stack. The
   two together fill the 512 KB of contiguous main SRAM on the RP2350.

   The bootrom still needs an IMAGE_DEF block in `.start_block` after the vector
   table and a matching `.end_block`; the SECTIONS below mirror the canonical
   rp235x layout, only retargeted into SRAM. Build + flash: see README.md. */
MEMORY {
    FLASH : ORIGIN = 0x20000000, LENGTH = 256K   /* code + rodata + .data init image */
    RAM   : ORIGIN = 0x20040000, LENGTH = 256K   /* .data + .bss + stack            */
}

SECTIONS {
    .start_block : ALIGN(4)
    {
        __start_block_addr = .;
        KEEP(*(.start_block));
        KEEP(*(.boot_info));
    } > FLASH
} INSERT AFTER .vector_table;

/* Move .text after the boot block so the entry point sits past the IMAGE_DEF. */
_stext = ALIGN(ADDR(.start_block) + SIZEOF(.start_block), ALIGNOF(.text));

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
