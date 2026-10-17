/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

/* CTAPHID transport-control kernel (CTAP2.1 11.2.9): the three pure
 * predicates the transport task needs to keep a host <-> device conversation
 * sane — keepalive status choice, cancel detection on a frame read while a
 * request is in flight, and the per-channel request lock (11.2.9.2.2). Pure,
 * like asm/ctaphid.S / asm/ctaphid_tx.S / asm/ctaphid_init.S: no hardware, no
 * allocator; the caller owns every byte of state. Differentially tested
 * against rsk-usb's keepalive_status / is_cancel_frame / ChannelLock by
 * asm/difftest.sh.
 *
 * The three entries are exactly the three pub fns in rsk-usb; the 2x2
 * keepalive table is pinned by keepalive_status_suppresses_processing_for_u2f_msg,
 * the cancel rule by cancel_frame_detected_only_for_active_channel, and the
 * lock rule (owner never blocked, strict-expiry boundary, release only by the
 * owner, broadcast-INIT carve-out) by channel_lock_excludes_other_channels_until_it_expires
 * and only_a_broadcast_init_survives_someone_elses_lock. */

/* caller-owned lock state, starts zeroed:
 *   +0 cid, +4 until_lo, +8 until_hi               (until_ms: now + secs*1000)
 *
 * until_ms is stored as two 32-bit words (not a naturally aligned u64) so the
 * 64-bit comparisons work unaligned-clean; 64-bit compare semantics are kept
 * exactly by the strict-lo/hi software compare in ctaphid_lock_refuses. The
 * owner is stored as a plain u32; until_hi is only ever touched by a full-64
 * add (carry-propagated) in arm, never read on its own. */
.equ LOCK_CID,      0
.equ LOCK_UNTIL_LO, 4
.equ LOCK_UNTIL_HI, 8

/* keepalive status byte values (CTAP1/CTAP2 11.2.9.2.3); 0 is "no keepalive" */
.equ STATUS_PROCESSING, 0x01
.equ STATUS_UPNEEDED,   0x02

/* the wire byte a host uses to abort a running request (CTAPHID_CANCEL,
 * TYPE_INIT | 0x11) — the frame's command slot and the fix IPC's 5th byte */
.equ CANCEL_BYTE,  0x91

/* the one command that passes through someone else's lock: a broadcast
 * allocation (CTAPHID_INIT / CID_BROADCAST) is a request for a channel id,
 * not traffic on a channel (§11.2.9.1.3) */
.equ INIT_CMD,     0x86
.equ CID_BROADCAST, 0xffffffff

/* a lock time in seconds * 1000 → expiry offset; the LOCK_MAX_SECONDS=10
 * guard lives in the shipping dispatcher, not here, so no clamp is applied */
.equ MS_PER_SEC,   1000

.syntax unified
.cpu cortex-m33
.thumb

.section .text

/* r0 = is_cbor, r1 = up_pending -> r0 0 (none) | 1 (processing) | 2 (upneeded)
 *
 * The shipping truth table: a touch wait always wins (UPNEEDED), and only a
 * genuinely slow CTAP2 (CBOR) op gets PROCESSING — a fast U2F MSG must stay
 * silent or the host desyncs (FIDO conformance U2F-Authenticate P-3/F-2). */
.thumb_func
.global ctaphid_keepalive_status
ctaphid_keepalive_status:
        cbz  r1, 1f
        movs r0, #STATUS_UPNEEDED
        bx   lr
1:      cbz  r0, 2f
        movs r0, #STATUS_PROCESSING
        bx   lr
2:      movs r0, #0
        bx   lr

/* r0 = frame ptr, r1 = n (bytes read), r2 = cid -> r0 0/1
 *
 * A frame read while the worker runs is a cancel only if the short read
 * carried a command byte, that byte is CANCEL_BYTE, and the frame's cid
 * matches the in-flight request's channel (FIDO conformance HID-1 P-10/P-15). */
.thumb_func
.global ctaphid_is_cancel
ctaphid_is_cancel:
        push {r4, r5, r6, lr}
        mov  r4, r0
        mov  r5, r1
        mov  r6, r2
        cmp  r5, #5
        bcc  cnl_false
        ldrb r2, [r4, #4]
        cmp  r2, #CANCEL_BYTE
        bne  cnl_false
        ldrb r0, [r4, #0]           /* cid, little-endian on the wire */
        ldrb r1, [r4, #1]
        orr  r0, r0, r1, lsl #8
        ldrb r1, [r4, #2]
        orr  r0, r0, r1, lsl #16
        ldrb r1, [r4, #3]
        orr  r0, r0, r1, lsl #24
        cmp  r0, r6
        bne  cnl_false
        movs r0, #1
        pop  {r4, r5, r6, pc}
cnl_false:
        movs r0, #0
        pop  {r4, r5, r6, pc}

/* r0 = state, r1 = cid, r2 = secs, r3 = now_lo, [sp] = now_hi
 *
 * Takes (secs > 0) or releases (secs == 0) the lock. A release only clears if
 * the caller owns the lock — a non-owner cannot give someone else's lock back.
 * now_ms is passed split into now_lo/now_hi (u32 hi on the stack, the
 * ctaphid_init.S 5th-argument precedent) so a caller never assembles a u64
 * into an even:odd register pair just to call here. until_ms is now_ms plus a
 * plain secs*1000: secs is u8-bounded (the shipping arm takes seconds: u8 and
 * the harness parse enforces it), so the product always fits a word and the
 * add carries into the high word — no clamp. */
.thumb_func
.global ctaphid_lock_arm
ctaphid_lock_arm:
        push {r4, r5, r6, r7, lr}
        mov  r4, r0
        mov  r5, r1
        mov  r6, r2
        ldr  r7, [sp, #20]   /* 5th argument: now_hi */
        cbz  r6, lock_rel
        str  r5, [r4, #LOCK_CID]
        movw r0, #MS_PER_SEC
        mul  r2, r6, r0      /* prod = secs * 1000 */
        adds r0, r3, r2      /* until_lo = now_lo + prod, carry set */
        adc  r7, r7, #0      /* until_hi = now_hi + carry */
        str  r0, [r4, #LOCK_UNTIL_LO]
        str  r7, [r4, #LOCK_UNTIL_HI]
        pop  {r4, r5, r6, r7, pc}
lock_rel:
        ldr  r0, [r4, #LOCK_CID]
        cmp  r0, r5
        bne  1f
        movs r0, #0
        str  r0, [r4, #LOCK_UNTIL_LO]
        str  r0, [r4, #LOCK_UNTIL_HI]
1:      pop  {r4, r5, r6, r7, pc}

/* r0 = state, r1 = cid, r2 = cmd, r3 = now_lo, [sp] = now_hi -> r0 0/1
 *
 * Whether a request from (cid, cmd) at now_ms is refused because the lock is
 * held by someone else. A broadcast CTAPHID_INIT is never refused — it asks
 * for a fresh channel, it is not a message on one. Otherwise blocked iff
 * now_ms < until_ms strictly (now_ms == until_ms is the just-expired instant,
 * pinned by channel_lock_excludes_other_channels_until_it_expires) AND the
 * caller is not the owner. now_ms arrives split like arm's. */
.thumb_func
.global ctaphid_lock_refuses
ctaphid_lock_refuses:
        push {r4, r5, r6, r7, lr}
        mov  r4, r0
        mov  r5, r1
        mov  r6, r2
        ldr  r7, [sp, #20]   /* 5th argument: now_hi */
        mvn  r0, #0          /* CID_BROADCAST */
        cmp  r6, #INIT_CMD
        bne  rfx_check
        cmp  r5, r0
        beq  rfx_false
rfx_check:
        ldr  r0, [r4, #LOCK_UNTIL_HI]
        ldr  r1, [r4, #LOCK_UNTIL_LO]
        cmp  r7, r0
        bhi  rfx_false       /* now_hi > until_hi: now >= until */
        bne  rfx_owner       /* now_hi < until_hi: strictly before */
        cmp  r3, r1          /* equal high words: compare the low */
        bcc  rfx_owner       /* now_lo < until_lo: strictly before */
        b    rfx_false       /* now_lo >= until_lo: not strictly before */
rfx_owner:
        ldr  r0, [r4, #LOCK_CID]
        cmp  r0, r5
        beq  rfx_false       /* the owner is never refused */
        movs r0, #1
        pop  {r4, r5, r6, r7, pc}
rfx_false:
        movs r0, #0
        pop  {r4, r5, r6, r7, pc}