/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

/* CTAPHID dispatcher decisions (CTAP2.1 11.2.9): the pure verdicts that map a
 * reassembled command to the response it earns. Pure, like asm/ctaphid.S /
 * asm/ctaphid_tx.S: no I/O, no framing of its own — the caller frames from the
 * returned verdict and, for LOCK's success, runs ctaphid_lock_arm. Each entry
 * is one concern so the transport can reorder/aggregate them freely.
 * Differentially tested against the Rust mirror in asm/oracle/src/main.rs by
 * asm/difftest.sh.
 *
 * Command/error bytes are read from rsk-usb's pub consts (ctaphid.rs:31-52).
 * Provenance of the designed rows:
 *   wink:        pinned by wink_is_refused_where_the_capability_bit_is_clear.
 *   lock:        the <=10 arm and the empty-LOCK success reply are the code
 *                path the shipping dispatch arms; the len!=1 / >10 error rows
 *                are spec-claimed (reached in dispatch, no unit pins them).
 *   empty CBOR:  spec-claimed (dispatch: ctaphid.rs:714-717). */

/* the command bytes this kernel compares against; the rest of the set
 * (PING/MSG/INIT/CANCEL/ERROR) travels through the harness, not here */
.equ CTAPHID_CBOR, 0x90   /* TYPE_INIT | 0x10 */
.equ LOCK_MAX_SECONDS, 10 /* ctaphid.rs:162, host lock request length limit */

/* error codes, ctaphid.rs:46-52 — the three verdict leaves the entries return */
.equ ERR_INVALID_CMD, 0x01
.equ ERR_INVALID_PAR, 0x02
.equ ERR_INVALID_LEN, 0x03

.syntax unified
.cpu cortex-m33
.thumb

.section .text

/* r0 = body, r1 = body_len -> r0 0 (arm) | 1 (INVALID_LEN) | 2 (INVALID_PAR)
 *
 * LOCK takes exactly one body byte (bcnt 1) holding the seconds 0..=10;
 * anything else is a length error before the seconds are even read. */
.thumb_func
.global ctaphid_lock_command
ctaphid_lock_command:
        cmp  r1, #1
        bne  1f
        ldrb r0, [r0]                     /* body[0]: the lock seconds */
        cmp  r0, #LOCK_MAX_SECONDS
        bhi  2f                           /* secs > 10: parameter error */
        movs r0, #0                       /* arm; caller runs ctaphid_lock_arm */
        bx   lr
1:      movs r0, #1
        bx   lr
2:      movs r0, #2
        bx   lr

/* r0 = can_wink -> r0 0 (wink reply) | 1 (INVALID_CMD)
 *
 * A build with nothing to flash refuses the command: answering an empty
 * success frame would say "no indicator" and "yes, I blinked" at once. */
.thumb_func
.global ctaphid_wink
ctaphid_wink:
        cbz  r0, 1f
        movs r0, #0
        bx   lr
1:      movs r0, #1
        bx   lr

/* r0 = cmd, r1 = body_len -> r0 0 (route) | 1 (INVALID_LEN)
 *
 * MSG routes with any body; only an empty CBOR message (no command byte to
 * run) is refused. PING/INIT also land here and always route. */
.thumb_func
.global ctaphid_msg_guard
ctaphid_msg_guard:
        cmp  r0, #CTAPHID_CBOR
        bne  1f
        cbz  r1, 2f                       /* empty CBOR body */
1:      movs r0, #0
        bx   lr
2:      movs r0, #1
        bx   lr

/* r0 = cmd -> r0 1 (INVALID_CMD). Trivial — kept so the caller's per-command
 * table has a uniform leaf for everything it has not already handled. */
.thumb_func
.global ctaphid_unknown
ctaphid_unknown:
        movs r0, #1
        bx   lr