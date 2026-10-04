/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

/* CTAPHID INIT (allocation) kernel (CTAP2.1 §11.2.9.1.3 / §11.2.9.4): maps a
 * broadcast INIT demand into a fresh channel id and composes the 17-byte
 * reply body. Pure, like asm/ctaphid.S / asm/ctaphid_tx.S: no hardware, no
 * allocator of its own — the caller owns the state (persistent next_cid
 * counter plus the small buffer the payload is composed straight into).
 * Differentially tested against rsk-usb's CidAllocator + init_capabilities
 * by asm/difftest.sh.
 *
 * The kernel does NOT frame the response: the caller passes the 17-byte
 * buffer to ctaphid_tx_init(0xffffffff, 0x86, out17, 17) — the reply to a
 * broadcast INIT is itself broadcast. */

/* caller-owned state:
 *   +0 next_cid */
.equ IN_CID,      0

/* interface version reported in the INIT reply (CTAPHID_IF_VERSION) */
.equ IFACE_VERSION, 2

/* build-time firmware version (matches rsk_sdk::FIRMWARE_VERSION default
 * 5.8.0); the oracle cross-checks these against it, so they are the one
 * value this kernel must not drift from */
.equ CI_VERSION_MAJOR, 5
.equ CI_VERSION_MINOR, 8
.equ CI_VERSION_BUILD, 0

/* capability bits (§11.2.9.3): NMSG (0x08) is always clear */
.equ CAP_WINK, 0x01
.equ CAP_LOCK, 0x02
.equ CAP_CBOR, 0x04

/* reply layout (§11.2.9.4, pinned by the shipping ctaphid.rs:646):
 * nonce[8] || newcid[4 LE] || iface(1) || major(1) || minor(1) ||
 * build(1) || caps(1) */
.equ INIT_NONCE_LEN, 8
.equ INIT_CID_OFF,  8
.equ INIT_IFACE_OFF, 12
.equ INIT_VER_OFF,   13
.equ INIT_CAPS_OFF,  16
.equ INIT_RESP_LEN,  17

/* the first id handed out; a wrap past the two reserved values (0 and the
 * broadcast CID) lands back here. Pinned by the shipping tests: allocating
 * from 0xfffffffe yields 0xfffffffe then FIRST_CID; from 0xffffffff yields
 * 0xffffffff then FIRST_CID. */
.equ INIT_FIRST_CID, 0x01000000

.syntax unified
.cpu cortex-m33
.thumb

.section .text

/* r0 = state; sets next_cid = FIRST_CID */
.thumb_func
.global ctaphid_init_init
ctaphid_init_init:
        movw r1, #0x0000
        movt r1, #0x0100          /* INIT_FIRST_CID */
        str  r1, [r0, #IN_CID]
        bx   lr

/* r0 = state, r1 = nonce ptr, r2 = nonce len, r3 = can_wink, and out17 as
 * the 5th argument on the stack; returns 1 on success. The payload is
 * composed directly into the caller's out buffer, so the allocator counter
 * is the only persistent state here. A degenerate nonce_len 0 still
 * succeeds (clamped, zero-filled tail). */
.thumb_func
.global ctaphid_init_run
ctaphid_init_run:
        push {r4, r5, r6, r7, r8, lr}
        mov  r4, r0               /* state */
        mov  r5, r1               /* nonce ptr */
        mov  r6, r2               /* nonce len */
        mov  r7, r3               /* can_wink */
        ldr  r8, [sp, #24]        /* 5th argument: out17 */

        /* allocate: cid = next_cid, next = cid + 1, wrap the reserved Cs */
        ldr  r0, [r4, #IN_CID]
        adds r1, r0, #1
        beq  1f                   /* next == 0 (cid was 0xffffffff) */
        mvn  r3, r1
        cbz  r3, 1f               /* next == 0xffffffff (cid was 0xfffffffe) */
        b    2f
1:      movw r1, #0x0000
        movt r1, #0x0100          /* back to INIT_FIRST_CID */
2:      str  r1, [r4, #IN_CID]

        /* nonce copy, clamped to 8 with a zero-filled tail */
        movs r3, #INIT_NONCE_LEN
        cmp  r6, r3
        bls  3f
        movs r6, #INIT_NONCE_LEN
3:      movs r3, #0
4:      cmp  r3, r6
        bcs  5f
        ldrb r2, [r5, r3]
        strb r2, [r8, r3]
        adds r3, #1
        b    4b
5:      movs r2, #0
6:      cmp  r3, #INIT_NONCE_LEN
        bcs  7f
        strb r2, [r8, r3]
        adds r3, #1
        b    6b
7:
        /* newcid[4 LE] */
        strb r0, [r8, #INIT_CID_OFF]
        lsrs r0, r0, #8
        strb r0, [r8, #INIT_CID_OFF+1]
        lsrs r0, r0, #8
        strb r0, [r8, #INIT_CID_OFF+2]
        lsrs r0, r0, #8
        strb r0, [r8, #INIT_CID_OFF+3]

        movs r0, #IFACE_VERSION
        strb r0, [r8, #INIT_IFACE_OFF]
        movs r0, #CI_VERSION_MAJOR
        strb r0, [r8, #INIT_VER_OFF]
        movs r0, #CI_VERSION_MINOR
        strb r0, [r8, #INIT_VER_OFF+1]
        movs r0, #CI_VERSION_BUILD
        strb r0, [r8, #INIT_VER_OFF+2]

        /* caps = LOCK|CBOR, plus WINK only when the build can wink */
        movs r0, #CAP_LOCK
        orrs r0, r0, #CAP_CBOR
        cbz  r7, 9f
        orrs r0, r0, #CAP_WINK
9:      strb r0, [r8, #INIT_CAPS_OFF]

        movs r0, #1
        pop  {r4, r5, r6, r7, r8, pc}