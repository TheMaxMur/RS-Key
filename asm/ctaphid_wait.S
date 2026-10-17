/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

/* CTAPHID worker-wait state machine (CTAP 2.1 11.2.9): what the transport
 * does while the compute worker runs a reassembled MSG/CBOR. Pure, like
 * asm/ctaphid.S: no I/O, no timer — the caller advances the clock, exactly
 * how the firmware's run_with_keepalive races the worker against
 * Timer::after_millis(KEEPALIVE_MS). Differentially tested against the Rust
 * mirror in asm/oracle/src/main.rs by asm/difftest.sh.
 *
 * Two concerns:
 *   cadence  — a KEEPALIVE is due every KEEPALIVE_MS while a request is in
 *              flight; the timer restarts from each deadline it crosses
 *              (chained next += KEEPALIVE_MS), and a due tick asks
 *              ctaphid_keepalive_status (the M8 twin) what to send — for a
 *              U2F fast op that answer is "nothing".
 *   frames   — mid-flight frames are read only while a touch is pending:
 *              a CANCEL on the requesting channel signals the worker (which
 *              answers KEEPALIVE_CANCEL itself), anything else read in that
 *              window is dropped, and off the touch wait nothing is read at
 *              all — the frame stays queued for the dispatcher after the
 *              response.
 *
 * Provenance: the cadence period is the pub KEEPALIVE_MS (ctaphid.rs:61);
 * the read-only-while-up_pending gating and the drop/queue split are
 * body-sourced (shipping run_with_keepalive, ctaphid.rs:737-813); the
 * chained-restart arithmetic and the non-strict due boundary are
 * mirror-defined (the shipping loop restarts its timer at the instant a
 * deadline fires, which the model collapses to the deadline itself). */

/* the state: {active, next_lo, next_hi} — the lock_state pattern */
.equ WAIT_ACTIVE, 0
.equ WAIT_NEXT_LO, 4
.equ WAIT_NEXT_HI, 8

.equ KEEPALIVE_MS, 100 /* ctaphid.rs:61, the pub streaming cadence */

.syntax unified
.cpu cortex-m33
.thumb

.section .text

/* r0 = state, r1 = now_lo, r2 = now_hi
 *
 * A MSG/CBOR request enters the worker; the first KEEPALIVE deadline is one
 * cadence away. */
.thumb_func
.global ctaphid_wait_start
ctaphid_wait_start:
        movs r3, #1
        str  r3, [r0, #WAIT_ACTIVE]
        adds r1, r1, #KEEPALIVE_MS    /* next_lo = now_lo + 100, carry */
        adc  r2, r2, #0               /* next_hi += carry */
        str  r1, [r0, #WAIT_NEXT_LO]
        str  r2, [r0, #WAIT_NEXT_HI]
        bx   lr

/* r0 = state, r1 = now_lo, r2 = now_hi -> r0 0 (nothing due) | 1 (due)
 *
 * Due iff now >= next non-strictly — now == next is the deadline itself, the
 * instant the shipping timer fires. Crossing the deadline advances next by
 * one cadence, so a tick that jumps several deadlines past owes one KEEPALIVE
 * per deadline crossed. An inactive wait is never due. */
.thumb_func
.global ctaphid_wait_tick
ctaphid_wait_tick:
        ldr  r3, [r0, #WAIT_ACTIVE]
        cbz  r3, wtk_no
        push {r4, r5}
        ldr  r4, [r0, #WAIT_NEXT_HI]
        ldr  r5, [r0, #WAIT_NEXT_LO]
        cmp  r2, r4
        bcc  wtk_notdue       /* now_hi < next_hi: strictly before */
        bhi  wtk_due          /* now_hi > next_hi */
        cmp  r1, r5
        bcc  wtk_notdue       /* equal high words, now_lo < next_lo */
wtk_due:
        adds r5, r5, #KEEPALIVE_MS
        adc  r4, r4, #0
        str  r5, [r0, #WAIT_NEXT_LO]
        str  r4, [r0, #WAIT_NEXT_HI]
        movs r0, #1
        pop  {r4, r5}
        bx   lr
wtk_notdue:
        movs r0, #0
        pop  {r4, r5}
        bx   lr
wtk_no:
        movs r0, #0
        bx   lr

/* r0 = up_pending, r1 = frame, r2 = n, r3 = cid
 * -> r0 0 (queued: off the touch wait, read later by the dispatcher)
 *      | 1 (dropped: read mid-wait, not the channel's CANCEL)
 *      | 2 (cancel: the requesting channel's CANCEL, signal the worker)
 *
 * The cancel check is the M8 ctaphid_is_cancel twin; this entry adds only
 * the gating — whether the frame is observed at all. */
.thumb_func
.global ctaphid_wait_frame
ctaphid_wait_frame:
        cbz  r0, wff_queue
        push {r4, lr}
        movs r4, #1           /* drop: the default mid-wait disposition */
        mov  r0, r1
        mov  r1, r2
        mov  r2, r3
        bl   ctaphid_is_cancel
        cmp  r0, #0
        beq  wff_out
        movs r4, #2           /* cancel: abort the worker's touch wait */
wff_out:
        movs r0, r4
        pop  {r4, pc}
wff_queue:
        movs r0, #0
        bx   lr

/* r0 = state
 *
 * The worker answered; the wait (and the cadence) end. */
.thumb_func
.global ctaphid_wait_finish
ctaphid_wait_finish:
        movs r1, #0
        str  r1, [r0, #WAIT_ACTIVE]
        bx   lr
