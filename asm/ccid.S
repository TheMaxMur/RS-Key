/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

/* CCID message core (USB CCID 1.1 rev 1.1): the pure halves of rsk-usb's
 * pub surface — xfr_apdu/secure_apdu payload ranging, put_header's 10-byte
 * response header, and process_message's slot-state machine (power
 * on/off, slot status, T=1 params, data rate). No I/O, no APDU handling:
 * XfrBlock/Secure belong to the async worker in the shipping Ccid::run and
 * earn no reply here either. Differentially tested against the LIVE rsk-usb
 * functions by asm/difftest.sh — the oracle links ccid.rs itself, so every
 * constant below is checked against the real ones, not restated in a
 * mirror.
 *
 * The T1_PARAMS bytes are the one piece of data the kernel owns (ccid.rs
 * keeps them private); they are pinned by the differential, not trusted. */

/* bulk-OUT message types (CCID 1.1 §6.1-1); the rest of the vocabulary
 * (XfrBlock 0x6F, Secure 0x69) is range-checked, never dispatched */
.equ CCID_POWER_ON, 0x62
.equ CCID_POWER_OFF, 0x63
.equ CCID_SET_PARAMS, 0x61
.equ CCID_GET_PARAMS, 0x6c
.equ CCID_RESET_PARAMS, 0x6d
.equ CCID_SLOT_STATUS, 0x65
.equ CCID_SET_RATE, 0x73
/* bulk-IN response types (CCID 1.1 §6.2-1) */
.equ CCID_DATA_BLOCK_RET, 0x80
.equ CCID_SLOT_STATUS_RET, 0x81
.equ CCID_PARAMS_RET, 0x82
.equ CCID_SET_RATE_RET, 0x84
/* bStatus (CCID 1.1 §6.2-6) */
.equ STATUS_ACTIVE, 0
.equ STATUS_INACTIVE, 1

.syntax unified
.cpu cortex-m33
.thumb

.section .rodata
.align 2
/* T=1 parameters, ccid.rs:109 (bmFindexDindex..bNadValue) */
ccid_t1_params:
        .byte 0x11, 0x10, 0xFE, 0x95, 0x03, 0xFE, 0x00

.section .text

/* the 10-byte response header (CCID 1.1 §6.2): type, dwLength LE32, bSlot 0,
 * bSeq echoed, bStatus, bError 0, bChainParameter 0. Clobbers \len (shifted
 * to 0 by the LE32 stores); out is r0 throughout */
.macro CCID_HDR typ, len, seq, stt
        strb \typ, [r0, #0]
        strb \len, [r0, #1]
        lsrs \len, \len, #8
        strb \len, [r0, #2]
        lsrs \len, \len, #8
        strb \len, [r0, #3]
        lsrs \len, \len, #8
        strb \len, [r0, #4]
        movs \len, #0
        strb \len, [r0, #5]
        strb \seq, [r0, #6]
        strb \stt, [r0, #7]
        strb \len, [r0, #8]
        strb \len, [r0, #9]
.endm

/* r0 = out, r1 = msg_type, r2 = length, r3 = seq, [sp] = status
 *
 * The pub put_header, byte for byte. */
.thumb_func
.global ccid_put_header
ccid_put_header:
        push {r4, r5, lr}
        mov  r4, r2            /* HDR clobbers its length register */
        ldr  r5, [sp, #12]     /* the 5th argument: bStatus */
        CCID_HDR r1, r4, r3, r5
        pop  {r4, r5, pc}

/* r0 = msg, r1 = len, r2 = wanted type, r3 = range_out (2 words)
 * -> r0 0 (not that type / shorter than a header) | 1 (range written:
 * (HEADER, HEADER + min(dwLength, len - HEADER)) */
.thumb_func
ccid_range:
        cmp  r1, #10
        blo  cr_none
        push {r4, r5, lr}
        mov  r4, r1            /* len, for the clamp below */
        ldrb r5, [r0]
        cmp  r5, r2
        bne  cr_none_pop
        ldrb r1, [r0, #1]      /* dwLength, LE32 at msg[1..5] */
        ldrb r2, [r0, #2]
        lsls r2, r2, #8
        orrs r1, r1, r2
        ldrb r2, [r0, #3]
        lsls r2, r2, #16
        orrs r1, r1, r2
        ldrb r2, [r0, #4]
        lsls r2, r2, #24
        orrs r1, r1, r2
        subs r4, r4, #10       /* available = len - HEADER */
        cmp  r1, r4
        bls  1f               /* dw <= available: the message holds it all */
        mov  r1, r4           /* else the payload stops at the buffer end */
1:      movs r2, #10
        str  r2, [r3]         /* start */
        adds r2, r2, r1
        str  r2, [r3, #4]     /* end */
        movs r0, #1
        pop  {r4, r5, pc}
cr_none_pop:
        movs r0, #0
        pop  {r4, r5, pc}
cr_none:
        movs r0, #0
        bx   lr

/* r0 = msg, r1 = len, r2 = range_out -> r0 0/1 — the pub xfr_apdu */
.thumb_func
.global ccid_xfr_apdu
ccid_xfr_apdu:
        push {r4, lr}
        mov  r3, r2
        movs r2, #0x6f        /* CCID_XFR_BLOCK */
        bl   ccid_range
        pop  {r4, pc}

/* r0 = msg, r1 = len, r2 = range_out -> r0 0/1 — the pub secure_apdu */
.thumb_func
.global ccid_secure_apdu
ccid_secure_apdu:
        push {r4, lr}
        mov  r3, r2
        movs r2, #0x69        /* CCID_SECURE */
        bl   ccid_range
        pop  {r4, pc}

/* r0 = msg, r1 = msg_len, r2 = atr, r3 = atr_len,
 * [sp] = status ptr, [sp+4] = out, [sp+8] = out_cap -> r0 reply length
 *
 * The pub process_message: one complete bulk-OUT message in, one response
 * written to out (bounded by out_cap, exactly the Rust slice length), the
 * slot bStatus persisted through the status pointer. Unknown types — and
 * the worker-owned XfrBlock/Secure — return 0: no response. */
.thumb_func
.global ccid_process
ccid_process:
        push {r4, r5, r6, r7, r8, lr}
        cmp  r1, #10
        blo  cp_zero
        ldr  r6, [sp, #32]    /* out_cap */
        cmp  r6, #10
        blo  cp_zero
        mov  r7, r2           /* atr */
        mov  r8, r3           /* atr_len */
        ldrb r2, [r0, #6]     /* bSeq, echoed in every reply */
        ldrb r3, [r0, #0]     /* the message type */
        ldr  r0, [sp, #28]    /* out; the message is dead from here */
        ldr  r1, [sp, #24]    /* status ptr */
        /* live: r0 out, r1 status ptr, r2 seq, r3 type, r6 cap,
         *       r7 atr, r8 atr_len; r4/r5 scratch */
        cmp  r3, #CCID_SLOT_STATUS
        beq  cp_slot
        cmp  r3, #CCID_POWER_ON
        beq  cp_on
        cmp  r3, #CCID_POWER_OFF
        beq  cp_off
        cmp  r3, #CCID_SET_PARAMS
        beq  cp_params
        cmp  r3, #CCID_GET_PARAMS
        beq  cp_params
        cmp  r3, #CCID_RESET_PARAMS
        beq  cp_params
        cmp  r3, #CCID_SET_RATE
        beq  cp_rate
        b    cp_zero

cp_slot:
        movs r4, #CCID_SLOT_STATUS_RET
        ldrb r5, [r1]         /* the slot's bStatus, verbatim */
        movs r6, #0
        CCID_HDR r4, r6, r2, r5
        movs r0, #10
        b    cp_ret

cp_on:
        subs r6, r6, #10      /* payload room = out_cap - HEADER */
        cmp  r8, r6
        blo  1f
        mov  r8, r6          /* n = min(atr_len, room) */
1:      movs r4, #CCID_DATA_BLOCK_RET
        movs r5, #STATUS_ACTIVE
        mov  r6, r8
        CCID_HDR r4, r6, r2, r5
        movs r4, #0
        add  r6, r0, #10     /* out[HEADER + i] */
2:      cmp  r4, r8
        bhs  3f
        ldrb r5, [r7, r4]
        strb r5, [r6, r4]
        adds r4, r4, #1
        b    2b
3:      movs r5, #STATUS_ACTIVE
        strb r5, [r1]
        adds r0, r8, #10
        b    cp_ret

cp_off:
        movs r4, #STATUS_INACTIVE
        strb r4, [r1]         /* power off persists before the reply cites it */
        movs r5, #CCID_SLOT_STATUS_RET
        movs r6, #0
        CCID_HDR r5, r6, r2, r4
        movs r0, #10
        b    cp_ret

cp_params:
        movs r4, #CCID_PARAMS_RET
        ldrb r5, [r1]
        movs r6, #7           /* T1_PARAMS.len */
        CCID_HDR r4, r6, r2, r5
        movs r4, #1
        strb r4, [r0, #9]     /* bChainParameter slot carries bProtocolNum T=1 */
        ldr  r7, =ccid_t1_params
        add  r6, r0, #10
        movs r4, #0
1:      cmp  r4, #7
        bhs  2f
        ldrb r5, [r7, r4]
        strb r5, [r6, r4]
        adds r4, r4, #1
        b    1b
2:      movs r0, #17
        b    cp_ret

cp_rate:
        movs r4, #CCID_SET_RATE_RET
        ldrb r5, [r1]
        movs r6, #8           /* dwLength: the 8-byte returned clock array */
        CCID_HDR r4, r6, r2, r5
        movs r4, #0
        add  r5, r0, #10
        movs r6, #8
1:      strb r4, [r5], #1
        subs r6, r6, #1
        bne  1b
        movs r0, #18
        b    cp_ret

cp_zero:
        movs r0, #0
cp_ret:
        pop  {r4, r5, r6, r7, r8, pc}

        .ltorg
