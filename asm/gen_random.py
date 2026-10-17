#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Seeded random CTAPHID frames for the differential harness.

usage: gen_random.py SEED N [noise|mixed]

noise: every frame is uniform garbage around the framing (wrong cids, seqs,
        bcnts past the cap, broadcast, cid zero).
mixed: valid transactions with random lengths (including empty, exact-fit and
        full 7609) with noise frames interleaved mid-transaction — restarts,
        cross-channel injections and gaps land on live state.
tx:    "T cid cmd payload" lines — response framing with random lengths,
        cmds with and without the INIT bit, and edge cids; roughly every
        third line is instead an "I can_wink nonce-hex" INIT allocation
        demand, so the differential also fuzzes the reply composition.
ctrl:  transport-control lines — "K is_cbor up_pending" keepalive, "C frame
        n cid" cancel detection, and "L arm/refuse ..." channel-lock lines
        with random lock times (0..10 s and occasionally past the dispatcher's
        LOCK_MAX_SECONDS clamp, which neither side may apply) and now_ms drift
        that crosses lock expiry.
dispatch:  dispatcher-verdict lines — "Q can_wink cmd cid body" over random
        commands/cids/bodies, with the passive lock pre-armed so a share of the
        routing commands land on a refused channel; the cannot-acknowledge
        CANCEL and the unknown-command rows are exercised too.
wait:     worker-wait lines — "W start/up/tick/frame/done" with the clock
        drifting across 100ms keepalive deadlines, the touch flag flipping, and
        frames arriving on the waiting channel's and foreign cids (cancel
        shaped and not), so the cadence chain and the queue/drop/cancel
        disposition fuzz together.
ccid:    smart-card transport lines — "A/N" ATR and slot-status seeding, "H"
        header composition, "X/E" XfrBlock/Secure payload ranging, and "M"
        whole messages against caps around the reply-size boundaries. A cap
        in [10,17] is only paired with replies that fit it: the Rust oracle
        would panic slicing its own out buffer there (a crash, not a
        divergence the differential should chase).
"""

import random
import struct
import sys

CIDS = [0x11223344, 0xAABBCCDD, 0x01020304, 0xFFFFFFFF, 0]
LOWNCIDS = [0x11223344, 0xAABBCCDD, 0x01020304]
CONTROL_CMDS = [0x86, 0x81, 0x83, 0x91, 0xBB]
LOCK_SECS = [0, 1, 2, 5, 9, 10, 11, 12, 15, 20, 30, 40]


def pat(rng, n):
    return bytes(rng.randrange(256) for _ in range(n))


def init_frame(cid, cmd, payload):
    b = bytearray(64)
    b[0:4] = struct.pack("<I", cid)
    b[4] = 0x80 | cmd
    b[5:7] = struct.pack(">H", len(payload))
    n = min(len(payload), 57)
    b[7 : 7 + n] = payload[:n]
    return bytes(b)


def cont_frame(cid, seq, payload):
    b = bytearray(64)
    b[0:4] = struct.pack("<I", cid)
    b[4] = seq & 0x7F
    n = min(len(payload), 59)
    b[5 : 5 + n] = payload[:n]
    return bytes(b)


def noise_frame(rng):
    cid = rng.choice(CIDS)
    if rng.randrange(100) < 35:
        b = bytearray(64)
        b[0:4] = struct.pack("<I", cid)
        b[4] = 0x80 | rng.choice([3, 2, 6, rng.randrange(0x80)])
        bcnt = rng.choice([0, 5, 57, 58, 59, 116, rng.randrange(7700), 7610])
        b[5:7] = struct.pack(">H", bcnt)
        d = pat(rng, min(bcnt, 57))
        b[7 : 7 + len(d)] = d
        return bytes(b)
    b = bytearray(64)
    b[0:4] = struct.pack("<I", cid)
    b[4] = rng.randrange(0x88)  # seq, sometimes with the INIT bit set
    d = pat(rng, rng.randrange(60))
    b[5 : 5 + len(d)] = d
    return bytes(b)


def tx_line(rng):
    cid = rng.choice(CIDS)
    cmd = rng.choice(
        [0x83, 0x86, 0xBB, 0xBF, 0x80 | rng.randrange(8), rng.randrange(0x80)]
    )
    ln = rng.choice(
        [0, 1, 56, 57, 58, 59, 116, 117, rng.randrange(1, 2000), rng.randrange(2000, 7610)]
    )
    return "T {:08x} {:02x} {}".format(cid, cmd, pat(rng, ln).hex())


def cancel_frame(cid, cmd):
    b = bytearray(64)
    b[0:4] = struct.pack("<I", cid)
    b[4] = cmd
    return bytes(b)


def ctrl_lines(rng, n):
    """Random transport-control lines. The lock context is threaded through so
    refuse lines land at random now_ms around a just-taken lock's expiry —
    exercising the strict-boundary comparison the expiry tests pin."""
    out = []
    active = None  # (cid, until_ms) of the last arm(secs>0), or None

    def arm_line():
        nonlocal active
        cid = rng.choice(LOWNCIDS + [0xFFFFFFFF])
        secs = rng.choice(LOCK_SECS)
        now = rng.randrange(0, 10_000_000)
        if secs > 0:
            active = (cid, now + secs * 1000)
        elif active and active[0] == cid:
            active = None  # an owner release clears; a non-owner's is ignored
        return "L arm {:08x} {} {}".format(cid, secs, now)

    def refuse_line():
        cid = rng.choice(CIDS)
        cmd = rng.choice(CONTROL_CMDS)
        if active and rng.random() < 0.8:
            # probe across the active lock's expiry instant
            until = active[1]
            now = rng.choice(
                [until - rng.randrange(0, 3000), until - 1, until, until + 1,
                 until + rng.randrange(0, 3000)]
            )
        else:
            now = rng.randrange(0, 10_000_000)
        return "L refuse {:08x} {:02x} {}".format(cid, cmd, max(now, 0))

    for _ in range(n):
        r = rng.random()
        if r < 0.25:
            out.append("K {} {}".format(
                rng.choice(["0", "1"]), rng.choice(["0", "1"])))
        elif r < 0.55:
            out.append(refuse_line())
        elif r < 0.80:
            out.append(arm_line())
            if active and rng.random() < 0.4:
                # a short burst of refuses right at the new lock's boundary
                for _ in range(rng.randrange(1, 4)):
                    out.append(refuse_line())
        else:
            cid = rng.choice(CIDS)
            b = cancel_frame(cid, rng.choice([0x91, 0x86, 0x81, rng.randrange(0x100)]))
            nf = rng.randrange(0, 66)  # 0..65; 65 X-parses identically both sides
            out.append("C {} {} {:08x}".format(b.hex(), nf, cid))
    return out


# 0x83 is this firmware's MSG (TYPE_INIT|0x03, ctaphid.rs:32); 0x87, the
# FIDO spec's MSG, and the rest are unknown-command bytes
DISPATCH_CMDS = [0x81, 0x83, 0x87, 0x90, 0x84, 0x88, 0x91, 0x9F, 0x80, 0xC0, 0x3c]
DISPATCH_OWNER = 0x11223344
DISPATCH_STRANGER = 0xAABBCCDD

# the bulk-OUT vocabulary the message core answers (CCID 1.1 §6.1-1);
# XfrBlock/Secure are worker-owned and only ever range-checked
CCID_TYPES = [0x61, 0x62, 0x63, 0x65, 0x6C, 0x6D, 0x6F, 0x69, 0x73, 0x00]
# caps that answer any message (below HEADER, or with room to spare) vs the
# reply floors: params writes out[10..17], set-rate out[10..18], and the
# Rust oracle would panic slicing its own buffer below those
CCID_SMALL_CAPS = [0, 5, 9]
CCID_PARAMS_CAPS = [17, 18, 19, 20, 32, 64, 2048]
CCID_RATE_CAPS = [18, 19, 20, 32, 64, 2048]
CCID_TIGHT_CAPS = [10, 11, 15, 16, 17]  # only with replies that fit them


def ccid_msg(rng, mtype, dw, payload_len):
    b = bytearray(10)
    b[0] = mtype
    b[1:5] = struct.pack("<I", dw)
    b[5] = rng.randrange(256)  # bSlot (ignored)
    b[6] = rng.randrange(256)  # bSeq, echoed in the reply
    b += pat(rng, payload_len)
    return bytes(b)


def ccid_lines(rng, n):
    """Random CCID lines: the ATR and slot status drift, headers compose, the
    payload rangers see dwLength at and past the bytes actually present, and
    whole messages land against caps around the reply sizes."""
    out = []
    for _ in range(n):
        r = rng.random()
        if r < 0.05:
            ln = rng.choice([0, 1, 22, 23, 64, rng.randrange(0, 65)])
            out.append("A " + pat(rng, ln).hex())
        elif r < 0.10:
            out.append("N {:02x}".format(rng.choice([0, 1, 0x40, 0x80,
                                                     rng.randrange(256)])))
        elif r < 0.20:
            ln = rng.choice([0, 1, 7, 8, 0xFFFF, 0x10000,
                             rng.randrange(0, 0x1_0000_0000)])
            out.append("H {:02x} {} {:02x} {:02x}".format(
                rng.choice(CCID_TYPES + [rng.randrange(256)]), ln,
                rng.randrange(256), rng.randrange(256)))
        elif r < 0.40:
            mtype = rng.choice(CCID_TYPES + [rng.randrange(256)])
            plen = rng.choice([0, 9, 10, 11, rng.randrange(0, 200)])
            dw = rng.choice([0, 1, plen, plen + 1, max(plen - 1, 0),
                             rng.randrange(0, 0x1_0000_0000), 0xFFFF_FFFF])
            msg = ccid_msg(rng, mtype, dw, plen)
            out.append("{} {}".format(rng.choice("XE"), msg.hex()))
        else:
            mtype = rng.choice(CCID_TYPES + [rng.randrange(256)])
            plen = rng.choice([0, 9, 10, 11, 12, 17, 22, rng.randrange(0, 200)])
            msg = ccid_msg(rng, mtype, rng.choice([0, plen, rng.randrange(0, 100)]), plen)
            if mtype in (0x61, 0x6C, 0x6D):
                cap = rng.choice(CCID_SMALL_CAPS + CCID_PARAMS_CAPS
                                 + [rng.randrange(17, 2049)])
            elif mtype == 0x73:
                cap = rng.choice(CCID_SMALL_CAPS + CCID_RATE_CAPS
                                 + [rng.randrange(18, 2049)])
            else:
                cap = rng.choice(CCID_SMALL_CAPS + CCID_PARAMS_CAPS
                                 + CCID_TIGHT_CAPS + [rng.randrange(0, 2049)])
            out.append("M {} {}".format(cap, msg.hex()))
    return out


def dispatch_lines(rng, n):
    """Random dispatcher Q-lines. A passive lock is armed up front and other
    times mid-stream, then routing commands (MSG/CBOR/PING) are sent at up to
    three cids against it, so the channel-busy guard and its carve-outs get
    fuzzed; CANCEL must stay silent on any cid."""
    out = []

    def arm(secs, now):
        out.append("L arm {:08x} {} {}".format(DISPATCH_OWNER, secs, now))

    def q(can_wink, cmd, cid, body):
        out.append("Q {} {:02x} {:08x} {}".format(can_wink, cmd & 0xFF, cid, body.hex()))

    arm(5, 1000)
    for _ in range(n):
        r = rng.random()
        cmd = rng.choice(DISPATCH_CMDS)
        if r < 0.5:
            cid = rng.choice([DISPATCH_OWNER, DISPATCH_STRANGER, 0xFFFFFFFF, 0x01020304])
            ln = rng.choice([0, 1, 2, rng.randrange(1, 200)])
            q(rng.choice(["0", "1"]), cmd, cid, pat(rng, ln))
        elif r < 0.7:
            # a lock change: release/re-arm, drifting the clock she can cross
            secs = rng.choice([0, 5, 10, 11])
            now = rng.randrange(0, 4_000_000)
            arm(secs, now)
        else:
            # exercise an unknown/cancel command independent of the lock
            cid = rng.choice([DISPATCH_OWNER, DISPATCH_STRANGER, 0x01020304])
            q(rng.choice(["0", "1"]), rng.choice([0x91, 0x9F, 0xC0, 0x3c]), cid,
              pat(rng, rng.choice([0, 1, rng.randrange(1, 64)])))
    return out


def wait_lines(rng, n):
    """Random worker-wait W-lines. The clock drifts by 0..300 ms per tick so a
    tick crosses at most a few keepalive deadlines (the catch-up burst stays
    small), sometimes backwards; the touch flag flips; frames arrive cancel-
    shaped or not on the waiting channel's and foreign cids at n around the
    5-byte cancel threshold; starts and dones interleave."""
    out = []
    wcid = 0x0123ABCD
    now = 0
    for _ in range(n):
        r = rng.random()
        if r < 0.1:
            out.append("W start {} {}".format(rng.choice([0, 1]), now))
        elif r < 0.3:
            out.append("W up {}".format(rng.choice([0, 1])))
        elif r < 0.75:
            now += rng.randrange(0, 300)
            if rng.random() < 0.05:
                now = rng.randrange(0, max(now, 1))  # a tick back in time
            out.append("W tick {}".format(now))
        elif r < 0.95:
            cid = rng.choice([wcid, 0xAABBCCDD, 0xFFFFFFFF])
            cmd = rng.choice([0x91, 0x91, 0x81, 0x86, 0x90])
            ln = rng.choice([4, 5, 6, rng.randrange(0, 65)])
            b = bytearray(64)
            b[0:4] = struct.pack("<I", cid)
            b[4] = cmd
            out.append("W frame {} {} {:08x}".format(bytes(b).hex(), ln, cid))
        else:
            out.append("W done")
    return out


def main():
    seed = int(sys.argv[1])
    n = int(sys.argv[2])
    mode = sys.argv[3] if len(sys.argv) > 3 else "noise"
    rng = random.Random(seed)

    out = []
    if mode == "tx":
        for _ in range(n):
            if rng.randrange(3) == 0:
                out.append("I {} {}".format(rng.choice(["0", "1"]), pat(rng, 8).hex()))
            else:
                out.append(tx_line(rng))
        print("\n".join(out))
        return
    if mode == "ctrl":
        print("\n".join(ctrl_lines(rng, n)))
        return
    if mode == "dispatch":
        print("\n".join(dispatch_lines(rng, n)))
        return
    if mode == "wait":
        print("\n".join(wait_lines(rng, n)))
        return
    if mode == "ccid":
        print("\n".join(ccid_lines(rng, n)))
        return
    tx = None  # live valid transaction: (cid, payload, off, seq)
    for _ in range(n):
        if mode == "mixed":
            if tx is None:
                if rng.random() < 0.55:
                    cid = rng.choice([0x11223344, 0xAABBCCDD, 0x01020304])
                    bcnt = rng.choice(
                        [0, 5, 57, 58, 59, 116, rng.randrange(1, 2000), rng.randrange(2000, 7610)]
                    )
                    payload = pat(rng, bcnt)
                    out.append(init_frame(cid, rng.choice([3, 2]), payload))
                    if bcnt > 57:
                        tx = (cid, payload, 57, 0)
                    continue
            else:
                if rng.random() < 0.75:
                    cid, payload, off, seq = tx
                    out.append(cont_frame(cid, seq, payload[off:]))
                    off += 59
                    seq += 1
                    tx = (cid, payload, off, seq) if off < len(payload) else None
                    continue
                # fall through: noise lands mid-transaction
        out.append(noise_frame(rng))

    print("\n".join(f.hex() for f in out))


if __name__ == "__main__":
    main()
