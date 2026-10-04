/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

/* CTAPHID transmission framing kernel (CTAP2.1 11.2.9.2), the pure mirror
 * of asm/ctaphid.S: splits one outgoing message into 64-byte HID reports
 * (an INIT then CONT frames), always at least the INIT even for an empty
 * payload. Differentially tested against rsk-usb's TxFrames by
 * asm/difftest.sh — the frame stream over identical vectors must match
 * byte-for-byte. */

/* caller-owned state:
 *   +0 cid, +4 cmd, +8 data address, +12 len, +16 off, +20 seq,
 *   +24 started */
.equ TX_CID,     0
.equ TX_CMD,     4
.equ TX_DATA,    8
.equ TX_LEN,     12
.equ TX_OFF,     16
.equ TX_SEQ,     20
.equ TX_STARTED, 24

/* report layout mirrors asm/ctaphid.S (kept in sync by hand) */
.equ F_CID,      0
.equ F_TYPE,     4
.equ F_BCNT_HI,  5
.equ F_BCNT_LO,  6
.equ INIT_DATA,  7
.equ INIT_LEN,   57
.equ CONT_DATA,  5
.equ CONT_LEN,   59

.syntax unified
.cpu cortex-m33
.thumb

.section .text

/* r0 = state, r1 = cid, r2 = cmd (stored verbatim — callers pass the wire
 * type byte, bit 7 already set, matching rsk-usb's TxFrames), r3 = data,
 * len as the 5th argument on the stack */
.thumb_func
.global ctaphid_tx_init
ctaphid_tx_init:
        push {r4, lr}
        ldr  r4, [sp, #8]              /* 5th argument */
        str  r1, [r0, #TX_CID]
        str  r2, [r0, #TX_CMD]
        str  r3, [r0, #TX_DATA]
        str  r4, [r0, #TX_LEN]
        movs r1, #0
        str  r1, [r0, #TX_OFF]
        str  r1, [r0, #TX_SEQ]
        str  r1, [r0, #TX_STARTED]
        pop  {r4, pc}

/* r0 = state, r1 = out[64]; returns 1 if a frame was written, 0 if done */
.thumb_func
.global ctaphid_tx_next
ctaphid_tx_next:
        push {r4, r5, r6, r7, lr}
        mov  r4, r0
        mov  r5, r1
        /* the tail of every report is zero-padded */
        movs r2, #0
        movs r3, #0
1:      str  r3, [r5, r2, lsl #2]
        adds r2, #1
        cmp  r2, #16
        bcc  1b

        ldr  r6, [r4, #TX_STARTED]
        cmp  r6, #0
        bne  cont_path

        /* INIT: cid LE, cmd verbatim, bcnt BE, up to 57 payload bytes */
        movs r6, #1
        str  r6, [r4, #TX_STARTED]
        ldr  r0, [r4, #TX_CID]
        strb r0, [r5, #F_CID]
        lsrs r0, r0, #8
        strb r0, [r5, #F_CID+1]
        lsrs r0, r0, #8
        strb r0, [r5, #F_CID+2]
        lsrs r0, r0, #8
        strb r0, [r5, #F_CID+3]
        ldr  r0, [r4, #TX_CMD]
        strb r0, [r5, #F_TYPE]         /* verbatim — no bit forcing */
        ldr  r0, [r4, #TX_LEN]
        lsrs r6, r0, #8
        strb r6, [r5, #F_BCNT_HI]
        strb r0, [r5, #F_BCNT_LO]
        cmp  r0, #INIT_LEN            /* n = min(len, 57) */
        bls  2f
        movs r0, #INIT_LEN
2:      str  r0, [r4, #TX_OFF]
        adds r7, r5, #INIT_DATA
        ldr  r2, [r4, #TX_DATA]
        movs r3, #0
3:      cmp  r3, r0
        bcs  4f
        ldrb r6, [r2, r3]
        strb r6, [r7, r3]
        adds r3, #1
        b    3b
4:      movs r0, #1
        b    tx_done

cont_path:
        ldr  r6, [r4, #TX_OFF]
        ldr  r0, [r4, #TX_LEN]
        cmp  r6, r0
        bcs  tx_end                    /* message fully sent */
        subs r6, r0, r6                /* n = len - off, before cid clobbers */
        cmp  r6, #CONT_LEN
        bls  5f
        movs r6, #CONT_LEN
5:      ldr  r0, [r4, #TX_CID]
        strb r0, [r5, #F_CID]
        lsrs r0, r0, #8
        strb r0, [r5, #F_CID+1]
        lsrs r0, r0, #8
        strb r0, [r5, #F_CID+2]
        lsrs r0, r0, #8
        strb r0, [r5, #F_CID+3]
        ldr  r0, [r4, #TX_SEQ]
        strb r0, [r5, #F_TYPE]
        adds r7, r5, #CONT_DATA
        ldr  r2, [r4, #TX_DATA]
        ldr  r3, [r4, #TX_OFF]
        movs r1, #0
6:      cmp  r1, r6
        bcs  7f
        ldrb r0, [r2, r3]
        strb r0, [r7, r1]
        adds r1, #1
        adds r3, #1
        b    6b
7:      str  r3, [r4, #TX_OFF]         /* r3 advanced with the copy */
        ldr  r0, [r4, #TX_SEQ]
        adds r0, #1
        str  r0, [r4, #TX_SEQ]
        movs r0, #1
        b    tx_done
tx_end: movs r0, #0
tx_done:
        pop  {r4, r5, r6, r7, pc}
