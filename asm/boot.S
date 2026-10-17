/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

/* M2 skeleton: vector table + reset + GPIO wiggle. No USB, no crypto, no
 * CTAP — the authenticator stays in firmware/; this boots standalone from UF2. */

/* Register facts, cross-checked against the shipping firmware image
 * (target/asm/ref.disasm is dumped by build.sh for the audit trail):
 *   SIO 0xd0000000; OUT_SET +0x14, OUT_CLR +0x18, OE_SET +0x24 (SIO layout
 *   shared with RP2040). PADS_BANK0 0x40028000, pad n at +0x4+4*n (observed:
 *   0x400280cc = pad 50, written 6 = PIO0). FUNCSEL 5 = SIO, whole-register
 *   write, as the shipping image does for pad setup. */

.equ SIO_BASE,         0xd0000000
.equ SIO_GPIO_OUT_SET, SIO_BASE + 0x14
.equ SIO_GPIO_OUT_CLR, SIO_BASE + 0x18
.equ SIO_GPIO_OE_SET,  SIO_BASE + 0x24
.equ PADS_BANK0_BASE,  0x40028000
.equ PADS_PAD_OFF,     0x4
.equ FUNCSEL_SIO,      5
.equ LED_GPIO,         16    /* firmware build.rs default; board-dependent */
.equ DELAY_COUNT,      0x400000  /* ROSC-relative pacing, not a timer */

.syntax unified
.cpu cortex-m33
.thumb

.section .vectors, "a"
.global __vectors
__vectors:
        .word __stack_top
        .word reset_handler
        .rept 14
        .word default_halt
        .endr

/* picobin IMAGE_DEF, byte-identical to the shipping firmware's block at
 * 0x10000114 (picotool parses it as "image def / RP2350 / ARM Secure");
 * w3 = 0 = no next block: the unpartitioned, pre-pt.sh form. Duplicated,
 * as in the shipping image. */
.section .image_def, "a"
__image_def:
        .word 0xffffded3          /* PICOBIN_BLOCK_MARKER_START */
        .word 0x10210142          /* items {next_block, image_type}; EXE|SEC_S|ARM|RP2350 */
        .word 0x000001ff
        .word 0x00000000          /* next block offset: 0 = self = chain end */
        .word 0xab123579          /* PICOBIN_BLOCK_MARKER_END */
        .word 0xffffded3
        .word 0x10210142
        .word 0x000001ff
        .word 0x00000000
        .word 0xab123579

.section .text
.thumb_func
default_halt:
        wfi
        b default_halt

.thumb_func
.global reset_handler
reset_handler:
        ldr r0, =__stack_top
        mov sp, r0
        ldr r0, =__vectors
        ldr r1, =0xe000ed08          /* SCB_VTOR */
        str r0, [r1]

        ldr r0, =__data_load
        ldr r1, =__data_start
        ldr r2, =__data_end
1:      cmp r1, r2
        bcs 2f
        ldr r3, [r0], #4
        str r3, [r1], #4
        b 1b
2:      ldr r1, =__bss_start
        ldr r2, =__bss_end
3:      cmp r1, r2
        bcs 4f
        movs r3, #0
        str r3, [r1], #4
        b 3b
4:
        ldr r1, =PADS_BANK0_BASE
        movs r2, #LED_GPIO
        lsls r2, r2, #2
        adds r1, r1, r2
        adds r1, #PADS_PAD_OFF
        movs r2, #FUNCSEL_SIO
        str r2, [r1]

        movs r4, #1
        lsls r4, r4, #LED_GPIO
        ldr r5, =SIO_GPIO_OE_SET
        str r4, [r5]
blink:
        ldr r5, =SIO_GPIO_OUT_SET
        str r4, [r5]
        bl delay
        ldr r5, =SIO_GPIO_OUT_CLR
        str r4, [r5]
        bl delay
        b blink

.thumb_func
delay:
        ldr r3, =DELAY_COUNT
1:      subs r3, #1
        bne 1b
        bx lr
