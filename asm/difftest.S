/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

/* Linux user-mode entry for the differential harness: the kernel supplies
 * the stack; raw EABI syscalls keep the binary free of any libc. */

.equ SYS_EXIT,  1
.equ SYS_READ,  3
.equ SYS_WRITE, 4

.syntax unified
.cpu cortex-m33
.thumb

.section .text
.thumb_func
.global _start
_start:
        bl   harness_main
        mov  r7, #SYS_EXIT
        svc  0

.thumb_func
.global sys_mmap2
/* r0 addr, r1 len, r2 prot, r3 flags, [sp] fd, [sp+4] pgoffset -> r0.
 * The kernel syscall ABI passes args 5-6 in r4/r5, not on the stack. */
sys_mmap2:
        push {r4, r5, r7, lr}
        ldr  r4, [sp, #16]
        ldr  r5, [sp, #20]
        mov  r7, #192
        svc  0
        pop  {r4, r5, r7, pc}

.thumb_func
.global sys_read
/* r0 fd, r1 buf, r2 len -> r0. r7 is the EABI syscall register but
 * callee-saved per AAPCS — save it or the caller's locals corrupt. */
sys_read:
        push {r7}
        mov  r7, #SYS_READ
        svc  0
        pop  {r7}
        bx   lr

.thumb_func
.global sys_write
/* r0 fd, r1 buf, r2 len -> r0 */
sys_write:
        push {r7}
        mov  r7, #SYS_WRITE
        svc  0
        pop  {r7}
        bx   lr
