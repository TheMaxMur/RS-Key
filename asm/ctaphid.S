/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

/* CTAPHID reassembly kernel (CTAP2.1 §11.2.9). Pure: no hardware, no
 * allocator; parses host-controlled framing only. Differentially tested
 * against rsk-usb's Reassembler by asm/difftest.sh — the observable
 * contract (event stream over identical vectors) must match byte-for-byte. */

/* caller-owned state, zeroed before the first feed:
 *   +0 cid, +4 cmd, +8 bcnt, +12 cur, +16 seq, +20 in_tx,
 *   +24 buf_max, +28 buf address, +32.. event out (tag/val/cid/cmd) */
.equ ST_CID,     0
.equ ST_CMD,     4
.equ ST_BCNT,    8
.equ ST_CUR,     12
.equ ST_SEQ,     16
.equ ST_IN_TX,   20
.equ ST_BUF_MAX, 24
.equ ST_BUF,     28
.equ ST_EV_TAG,  32
.equ ST_EV_VAL,  36
.equ ST_EV_CID,  40
.equ ST_EV_CMD,  44

/* CTAPHID framing (§11.2.9.2): INIT = cid[4 LE], cmd|0x80, bcnt[2 BE],
 * data[57]; CONT = cid[4 LE], seq, data[59]. */
.equ F_CID,      0
.equ F_TYPE,     4
.equ F_BCNT_HI,  5
.equ F_BCNT_LO,  6
.equ INIT_DATA,  7
.equ INIT_LEN,   57
.equ CONT_DATA,  5
.equ CONT_LEN,   59
.equ TYPE_INIT,  0x80

.equ CTAPHID_INIT_CMD, 0x86
.equ CID_BROADCAST,    0xffffffff

/* CTAPHID error codes (§11.2.9.1.3) */
.equ ERR_INVALID_LEN,     0x03
.equ ERR_INVALID_SEQ,     0x04
.equ ERR_CHANNEL_BUSY,    0x06
.equ ERR_INVALID_CHANNEL, 0x0b

/* events: 0 busy, 1 done, 2 error, 3 ignored */
.equ EV_BUSY,    0
.equ EV_DONE,    1
.equ EV_ERROR,   2
.equ EV_IGNORED, 3

.syntax unified
.cpu cortex-m33
.thumb

.section .text
.thumb_func
.global ctaphid_feed
/* r0 = state*, r1 = frame*; event lands at state+32 */
ctaphid_feed:
        push {r4, r5, r6, r7, lr}
        mov  r4, r0
        mov  r5, r1

        ldrb r6, [r5, #F_CID]            /* cid: little-endian on the wire */
        ldrb r3, [r5, #F_CID+1]
        orr  r6, r6, r3, lsl #8
        ldrb r3, [r5, #F_CID+2]
        orr  r6, r6, r3, lsl #16
        ldrb r3, [r5, #F_CID+3]
        orr  r6, r6, r3, lsl #24

        ldrb r2, [r5, #F_TYPE]

        /* cid 0 is never valid; broadcast only carries the INIT command */
        cmp  r6, #0
        beq  chan_error
        mvn  r7, #0
        cmp  r6, r7
        bne  chan_ok
        cmp  r2, #CTAPHID_INIT_CMD
        beq  chan_ok
chan_error:
        movs r1, #ERR_INVALID_CHANNEL
        b    emit_error
chan_ok:
        tst  r2, #TYPE_INIT
        beq  cont_path

init_path:
        /* mid-transaction INIT that is not the allocation command */
        ldr  r3, [r4, #ST_IN_TX]
        cmp  r3, #0
        beq  init_fresh
        cmp  r2, #CTAPHID_INIT_CMD
        beq  init_fresh
        ldr  r3, [r4, #ST_CID]
        cmp  r6, r3
        bne  busy_error                  /* other channel cannot interrupt */
        b    seq_error                   /* same channel: abort, out of seq */

init_fresh:
        ldrb r7, [r5, #F_BCNT_HI]        /* bcnt is big-endian on the wire */
        ldrb r3, [r5, #F_BCNT_LO]
        orr  r7, r3, r7, lsl #8
        ldr  r3, [r4, #ST_BUF_MAX]
        cmp  r7, r3
        bhi  len_error                   /* tx state untouched */

        str  r6, [r4, #ST_CID]
        str  r2, [r4, #ST_CMD]
        str  r7, [r4, #ST_BCNT]
        movs r3, #0
        str  r3, [r4, #ST_SEQ]
        cmp  r7, #INIT_LEN              /* n = min(bcnt, 57) */
        bls  1f
        movs r7, #INIT_LEN
1:      ldr  r0, [r4, #ST_BUF]
        adds r1, r5, #INIT_DATA
        movs r2, #0
2:      cmp  r2, r7
        bcs  3f
        ldrb r3, [r1, r2]
        strb r3, [r0, r2]
        adds r2, #1
        b    2b
3:      str  r7, [r4, #ST_CUR]
        ldr  r3, [r4, #ST_BCNT]
        movs r0, #0
        cmp  r3, #INIT_LEN              /* in_tx = bcnt > 57 */
        bls  4f
        movs r0, #1
4:      str  r0, [r4, #ST_IN_TX]
        b    finish_check

cont_path:
        ldr  r3, [r4, #ST_IN_TX]
        cmp  r3, #0
        beq  ignored_out
        ldr  r3, [r4, #ST_CID]
        cmp  r6, r3
        bne  busy_error
        bic  r2, r2, #TYPE_INIT          /* seq = type with the INIT bit off */
        ldr  r3, [r4, #ST_SEQ]
        cmp  r2, r3
        bne  seq_error

        ldr  r7, [r4, #ST_BCNT]
        ldr  r0, [r4, #ST_CUR]
        subs r1, r7, r0
        cmp  r1, #CONT_LEN              /* n = min(remaining, 59) */
        bls  5f
        movs r1, #CONT_LEN
5:      ldr  r3, [r4, #ST_BUF]
        adds r3, r3, r0
        adds r2, r5, #CONT_DATA
        movs r0, #0
6:      cmp  r0, r1
        bcs  7f
        ldrb r7, [r2, r0]
        strb r7, [r3, r0]
        adds r0, #1
        b    6b
7:      ldr  r7, [r4, #ST_CUR]
        adds r7, r7, r1
        str  r7, [r4, #ST_CUR]
        ldr  r3, [r4, #ST_SEQ]
        adds r3, #1
        str  r3, [r4, #ST_SEQ]

finish_check:
        ldr  r7, [r4, #ST_CUR]
        ldr  r3, [r4, #ST_BCNT]
        cmp  r7, r3
        bcs  done_out

busy_out:
        movs r0, #EV_BUSY
        str  r0, [r4, #ST_EV_TAG]
        movs r0, #0
        str  r0, [r4, #ST_EV_VAL]
        str  r0, [r4, #ST_EV_CID]
        str  r0, [r4, #ST_EV_CMD]
        pop  {r4, r5, r6, r7, pc}

ignored_out:
        movs r0, #EV_IGNORED
        str  r0, [r4, #ST_EV_TAG]
        movs r0, #0
        str  r0, [r4, #ST_EV_VAL]
        str  r0, [r4, #ST_EV_CID]
        str  r0, [r4, #ST_EV_CMD]
        pop  {r4, r5, r6, r7, pc}

done_out:
        movs r3, #0
        str  r3, [r4, #ST_IN_TX]
        movs r0, #EV_DONE
        str  r0, [r4, #ST_EV_TAG]
        str  r7, [r4, #ST_EV_VAL]       /* cur == bcnt */
        ldr  r3, [r4, #ST_CID]
        str  r3, [r4, #ST_EV_CID]
        ldr  r3, [r4, #ST_CMD]
        str  r3, [r4, #ST_EV_CMD]
        pop  {r4, r5, r6, r7, pc}

len_error:
        movs r1, #ERR_INVALID_LEN
        b    emit_error
busy_error:
        movs r1, #ERR_CHANNEL_BUSY
        b    emit_error
seq_error:
        movs r3, #0                     /* a sequence gap kills the tx */
        str  r3, [r4, #ST_IN_TX]
        movs r1, #ERR_INVALID_SEQ
        b    emit_error

emit_error:
        movs r0, #EV_ERROR
        str  r0, [r4, #ST_EV_TAG]
        str  r1, [r4, #ST_EV_VAL]
        str  r6, [r4, #ST_EV_CID]       /* errors report the frame's cid */
        str  r2, [r4, #ST_EV_CMD]
        pop  {r4, r5, r6, r7, pc}
