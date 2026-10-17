#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
#
# CTAPHID reassembly vectors (CTAP2.1 11.2.9): one 64-byte report per
# line, 128 hex chars, '#' comments. Frame layout per the shipping
# contract: cid[4 LE], type|0x80 or seq, bcnt[2 BE] (INIT), data.

import struct

CID = 0x11223344
CID2 = 0xAABBCCDD
CID3 = 0x01020304
BROADCAST = 0xFFFFFFFF
CTAPHID_INIT = 0x86
MSG_CAP = 7609  # 57 + 128*59


def pat(n):
    return bytes((i * 7 + 3) & 0xFF for i in range(n))


def init(cid, cmd, payload):
    r = bytearray(64)
    r[0:4] = struct.pack("<I", cid)
    r[4] = 0x80 | cmd
    r[5:7] = struct.pack(">H", len(payload))
    n = min(len(payload), 57)
    r[7 : 7 + n] = payload[:n]
    return bytes(r)


def cont(cid, seq, payload):
    r = bytearray(64)
    r[0:4] = struct.pack("<I", cid)
    r[4] = seq & 0x7F
    n = min(len(payload), 59)
    r[5 : 5 + n] = payload[:n]
    return bytes(r)


frames = []


def case(name, fs):
    frames.append("# " + name)
    frames.extend(f.hex() for f in fs)


case("single-packet message", [init(CID, 3, pat(5))])
case("two-packet message", [init(CID, 3, pat(100)), cont(CID, 0, pat(100)[57:])])
case("sequence gap aborts", [init(CID, 3, pat(100)), cont(CID, 1, pat(100)[57:])])
case("post-gap continuation", [cont(CID, 1, pat(100)[57:])])
case(
    "cross-channel CONT is busy, tx intact",
    [
        init(CID2, 3, pat(100)),
        cont(CID3, 0, pat(100)[57:]),
        cont(CID2, 0, pat(100)[57:]),
    ],
)
case("stray continuation ignored", [cont(CID, 0, pat(59))])
case("zero bcnt is an empty message", [init(CID, 3, b"")])
case("bcnt over cap rejected", [init(CID, 3, pat(MSG_CAP + 1))])
case(
    "mid-tx INIT on the same channel aborts",
    [init(CID, 3, pat(100)), init(CID, 3, pat(4))],
)
case("continuation after the abort is stray", [cont(CID, 0, pat(100)[57:])])
case(
    "mid-tx INIT on another channel is busy",
    [init(CID2, 3, pat(100)), init(CID3, 3, pat(4)), cont(CID2, 0, pat(100)[57:])],
)
case("exact single-frame fill (57)", [init(CID, 3, pat(57))])
case("one byte into a second frame (58)", [init(CID, 3, pat(58)), cont(CID, 0, pat(58)[57:])])
case("exact two-frame fill (116)", [init(CID, 3, pat(116)), cont(CID, 0, pat(116)[57:])])

maxp = pat(MSG_CAP)
maxframes = [init(CID, 3, maxp)]
off = 57
seq = 0
while off < MSG_CAP:
    maxframes.append(cont(CID, seq, maxp[off:]))
    off += 59
    seq += 1
case("maximum message (7609)", maxframes)
case("second message after done", [init(CID, 2, pat(10))])
case("cid zero rejected", [init(0, 3, pat(5))])
case("broadcast MSG rejected", [init(BROADCAST, 3, pat(5))])
case("broadcast CONT rejected", [cont(BROADCAST, 0, pat(59))])
case("broadcast INIT command accepted", [init(BROADCAST, CTAPHID_INIT & 0x7F, b"")])

# TX framing: "T <cid> <cmd> <payload-hex>" lines; both sides split the
# response and must emit identical F-frames.


def tcase(name, cid, cmd, payload):
    frames.append("# " + name)
    frames.append("T {:08x} {:02x} {}".format(cid, cmd & 0xFF, payload.hex()))


tcase("tx: empty message is a bare INIT", CID, 0x86, b"")
tcase("tx: single byte", CID, 0x83, pat(1))
tcase("tx: exact INIT fill (57)", CID, 0x83, pat(57))
tcase("tx: one byte into a CONT (58)", CID, 0x83, pat(58))
tcase("tx: exact two-frame fill (116)", CID, 0x83, pat(116))
tcase("tx: 117", CID, 0x83, pat(117))
tcase("tx: keepalive is a one-byte response", CID, 0xBB, b"\x01")
tcase("tx: error frame shape", CID, 0xBF, b"\x2c")
tcase("tx: cmd passes through verbatim (no bit forcing)", CID, 0x03, pat(5))
tcase("tx: maximum message (7609)", CID, 0x83, pat(MSG_CAP))
tcase("tx: one short of the maximum (7608)", CID, 0x83, pat(MSG_CAP - 1))
tcase("tx: broadcast cid passthrough", BROADCAST, 0x86, pat(100))
tcase("tx: cid zero passthrough", 0, 0x83, pat(100))
tcase("tx: cid one", 1, 0x83, pat(60))

# Harness parse-parity: trailing whitespace and CRLF must trim identically
# on both sides of the differential (the C harness mirrors the oracle's
# trim() in both directions).
frames.append("# tx: trailing spaces after the payload hex")
frames.append("T {:08x} {:02x} {}  ".format(CID, 0x83, pat(5).hex()))
frames.append("# frame line with a trailing \\r (CRLF input)")
frames.append(init(CID, 3, pat(5)).hex() + "\r")
frames.append("# frame line with trailing spaces")
frames.append(init(CID2, 3, pat(57)).hex() + "  ")

# INIT allocation: "I <can_wink> <nonce-hex>" lines; both sides allocate a
# persistent next_cid from FIRST_CID and compose, then broadcast-frame the
# 17-byte reply (nonce||newcid LE||iface 2||major||minor||build||caps).


def icase(name, can_wink, nonce):
    frames.append("# " + name)
    frames.append("I {} {}".format(can_wink, nonce.hex()))


icase("init: broadcast reply, can_wink off", 0, b"\x01\x02\x03\x04\x05\x06\x07\x08")
icase("init: broadcast reply, can_wink on", 1, bytes(range(8)))
icase("init: cid sequence step 1", 0, b"\x00" * 8)
icase("init: cid sequence step 2", 0, b"\x00" * 8)
icase("init: cid sequence step 3", 0, b"\x00" * 8)
icase("init: nonce all-zero", 1, b"\x00" * 8)
icase("init: nonce all-ff", 0, b"\xff" * 8)
icase("init: nonce mixed", 1, bytes([0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]))
frames.append("# init: odd nonce length X-parses identically")
frames.append("I 0 deadbeef")

# Transport control: keepalive / cancel / channel lock. "K <is_cbor> <up_pending>"
# -> "S 00|01|02"; "C <128-hex frame> <n dec> <cid 8-hex>" -> "C 0|1";
# "L arm <cid 8-hex> <secs dec> <now_ms dec>" persists the lock (no output);
# "L refuse <cid 8-hex> <cmd 2-hex> <now_ms dec>" -> "R 0|1".

LOWN = 0x11223344
LOTH = 0x01000001


def kcase(name, is_cbor, up):
    frames.append("# keepalive: " + name)
    frames.append("K {} {}".format(is_cbor, up))


kcase("u2f fast op stays silent", 0, 0)      # None
kcase("u2f touch wait", 0, 1)                # UPNEEDED
kcase("cbor slow op", 1, 0)                  # PROCESSING
kcase("cbor touch wait", 1, 1)               # UPNEEDED (touch wins)


def cframe(cid, cmd):
    b = bytearray(64)
    b[0:4] = struct.pack("<I", cid)
    b[4] = cmd
    return bytes(b)


def ccase(name, cid, cmd, n, want):
    frames.append("# cancel: {0} -> C {1}".format(name, want))
    frames.append("C {} {} {:08x}".format(cframe(cid, cmd).hex(), n, cid))


ccase("full 64-byte frame, matching cid", LOWN, 0x91, 64, 1)
ccase("n=63 matching", LOWN, 0x91, 63, 1)
ccase("n=6 matching", LOWN, 0x91, 6, 1)
ccase("n=5 boundary matching", LOWN, 0x91, 5, 1)
ccase("n=4 too short to carry a command byte", LOWN, 0x91, 4, 0)
ccase("n=64 wrong command byte is not a cancel", LOWN, 0x86, 64, 0)
ccase("n=64 mismatched cid", LOTH, 0x91, 64, 0)
ccase("broadcast frame matching broadcast cid", BROADCAST, 0x91, 5, 1)
ccase("broadcast frame, mismatched cid", LOWN, 0x91, 5, 0)

# the 2x2 keepalive table lives in difftest output already; finish the cancel
# family with the tiny-n differential gold rows
ccase("n=63 mismatched", LOTH, 0x91, 63, 0)
ccase("n=6 non-cancel cmd", LOWN, 0x81, 6, 0)

# channel lock: expiry boundary, strict < (until == now is unblocked). arm
# owner t=2s at now=1000 -> until=3000, then probe at 2999/3000/3001.


def larm(name, cid, secs, now):
    frames.append("# lock: " + name)
    frames.append("L arm {:08x} {} {}".format(cid, secs, now))


def lrefuse(name, cid, cmd, now):
    frames.append("# lock: " + name)
    frames.append("L refuse {:08x} {:02x} {}".format(cid, cmd & 0xFF, now))


larm("expiry boundary cluster: arm owner 2s", LOWN, 2, 1000)
lrefuse("owner at until-1 not blocked", LOWN, 0x81, 2999)
lrefuse("other at until-1 blocked", LOTH, 0x81, 2999)
lrefuse("owner at until not blocked", LOWN, 0x81, 3000)
lrefuse("other at until == unblocked (strict <)", LOTH, 0x81, 3000)
lrefuse("owner at until+1 not blocked", LOWN, 0x81, 3001)
lrefuse("other at until+1 unblocked", LOTH, 0x81, 3001)
lrefuse("broadcast INIT at until-1 carve-out", BROADCAST, 0x86, 2999)
lrefuse("broadcast INIT at until+1 carve-out", BROADCAST, 0x86, 3001)

# carve-out matrix: cmd x cid at a now well before any expiry (arm holds for 5s)
larm("carve-out matrix: owner locks 5s", LOWN, 5, 1000)
for cmd in (0x86, 0x81, 0x83, 0x91, 0xBB):
    for cid, tag in ((LOWN, "owner"), (LOTH, "other"), (BROADCAST, "broadcast")):
        want = "unblocked"
        if cid != LOWN and not (cmd == 0x86 and cid == BROADCAST):
            want = "blocked"
        lrefuse("carve-out cmd=0x{0:02x} cid={1} -> {2}".format(cmd, tag, want),
                cid, cmd, 1500)

# release ownership: only the owner may release
larm("release: owner locks 10s", LOWN, 10, 1000)
lrefuse("other blocked before release", LOTH, 0x81, 1500)
larm("non-owner release is ignored", LOTH, 0, 1500)
lrefuse("still blocked after non-owner release attempt", LOTH, 0x81, 1500)
larm("owner release clears", LOWN, 0, 1500)
lrefuse("other unblocked after owner release", LOTH, 0x81, 1500)
lrefuse("other unblocked after owner release, later now", LOTH, 0x83, 3000)

# secs=0 on a fresh lock is a harmless no-op (no lock was ever taken)
lrefuse("fresh lock refuses nothing", LOTH, 0x81, 500)
larm("secs=0 on a fresh lock is a no-op", LOTH, 0, 500)
lrefuse("still nothing refused", LOTH, 0x81, 1500)

# non-monotonic now_ms: the kernel must not assume a clock that advances
larm("non-monotonic now: arm owner 2s", LOWN, 2, 1000)
lrefuse("refuse at an earlier now still respects the lock", LOTH, 0x81, 500)

# dispatcher verdicts (M9): "Q <can_wink 0|1> <cmd 2-hex> <cid 8-hex> <body-hex>"
# -> "Q <code 2-hex>" (00 = route/no-transport-response, else the error code);
# an immediate error verdict also frames CTAPHID_ERROR through tx. The lock
# guard consults the persistent lock + the L branch's clock. Provenance: the
# wink row is pinned by wink_is_refused_where_the_capability_bit_is_clear; the
# lock len!=1 / >10 and empty-CBOR rows are spec-claimed (shipping dispatch
# ctaphid.rs:674-689, 714-717); the unknown and lock-guard rows are doc/run-time
# pinned (dispatch falls through to ERR_INVALID_CMD, on_frame guards Messages).

CLI = 0x55556666  # a cid reserved for the LOCK sweep's arm side-effects


def qcase(name, can_wink, cmd, cid, body):
    frames.append("# dispatch: " + name)
    # an empty body omits the field entirely (as the T line's empty payload);
    # a bare trailing space would be trimmed and read back as a missing field
    hex = body.hex()
    frames.append("Q {} {:02x} {:08x}{}".format(can_wink, cmd & 0xFF, cid, (" " + hex) if hex else ""))


# LOCK sweep: secs {0,1,9,10,11,255} x body-len {0,1,2}. len!=1 -> INVALID_LEN;
# len 1 with secs>10 -> INVALID_PAR; else arm (Q 00, the empty LOCK reply).
for secs in (0, 1, 9, 10, 11, 255):
    qcase("lock len0 secs={}".format(secs), 0, 0x84, CLI, b"")
    qcase("lock len1 secs={}".format(secs), 0, 0x84, CLI, bytes([secs]))
    qcase("lock len2 secs={}".format(secs), 0, 0x84, CLI, bytes([secs, 0xAB]))

# drop the sweep's leftover lock (owner CLI, expiry 0..10 s) so the routing
# vectors below see a fresh channel; clock returns to 0 with it
frames.append("# dispatch: release the sweep's lock before the routes")
frames.append("L arm {:08x} 0 0".format(CLI))

# WINK: can_wink gates the command (test-pinned).
qcase("wink without an indicator is refused", 0, 0x88, LOWN, b"")
qcase("wink with an indicator answers empty", 1, 0x88, LOWN, b"")

# MSG/CBOR routing: MSG routes with any body; only an empty CBOR refuses.
# MSG is 0x83 (ctaphid.rs:32, TYPE_INIT|0x03), not the spec's 0x87 — which
# this firmware therefore answers as an unknown command.
qcase("msg empty routes", 0, 0x83, LOWN, b"")
qcase("msg non-empty routes", 0, 0x83, LOWN, b"\x05\x06")
qcase("the spec's 0x87 msg byte is unknown here", 0, 0x87, LOWN, b"\x01")
qcase("cbor non-empty routes", 0, 0x90, LOWN, b"\x00\xa1\x01\x02")
qcase("cbor empty refused as invalid len", 0, 0x90, LOWN, b"")

# PING echoes its body (a route here; the echo is harness-level).
qcase("ping with a body routes", 0, 0x81, LOWN, b"\xde\xad\xbe\xef")

# unknown command -> INVALID_CMD.
qcase("unknown command refused", 0, 0x9F, LOWN, b"")

# CANCEL is never acknowledged, never errored, in any state; no F-lines either.
qcase("cancel with nothing in flight", 0, 0x91, LOWN, b"")
qcase("cancel carries a body too, still silent", 0, 0x91, LOWN, b"\x01\x02")

# lock guard on a completed routing message (row 5). arm owner 2s at 1000 ->
# until=3000; Q uses the L branch's clock so a refuse line advances it.
# (INIT is not a Q case: the shipping dispatcher routes it before this table,
# and its broadcast carve-out is already pinned by the L lines above.)
larm("guard: owner locks 2s", LOWN, 2, 1000)
qcase("guard cbor on a stranger is channel-busy", 0, 0x90, LOTH, b"\x00\xa1")
qcase("guard cbor on the owner routes", 0, 0x90, LOWN, b"\x00\xa1")
qcase("guard ping on a stranger is channel-busy", 0, 0x81, LOTH, b"\x01")
qcase("guard msg on a stranger is channel-busy", 0, 0x83, LOTH, b"\x02")
lrefuse("advance the clock to just before expiry", LOWN, 0x81, 2999)
qcase("still busy at 2999", 0, 0x90, LOTH, b"\x00")
lrefuse("advance the clock past expiry", LOWN, 0x81, 3001)
qcase("unblocked at 3001", 0, 0x90, LOTH, b"\x00")

# malformed Q-lines: both sides must X-parse identically
frames.append("# malformed: q can_wink not 0/1 X-parses")
frames.append("Q 2 90 {:08x} aa".format(LOWN))
frames.append("# malformed: q cmd not 2 hex X-parses")
frames.append("Q 0 9 {:08x} aa".format(LOWN))
frames.append("# malformed: q cid short of 8 hex X-parses")
frames.append("Q 0 90 1122 aa")
frames.append("# malformed: q odd-length body X-parses")
frames.append("Q 0 90 {:08x} a".format(LOWN))
frames.append("# malformed: q non-hex body byte X-parses")
frames.append("Q 0 90 {:08x} zz".format(LOWN))
frames.append("# malformed: q missing the cid+body fields X-parses")
frames.append("Q 0 90")
frames.append("# malformed: q extra trailing field X-parses")
frames.append("Q 0 90 {:08x} aa 02".format(LOWN))

# worker-wait orchestration (M10): "W start <is_cbor> <now_ms>" arms the
# cadence, "W up <0|1>" sets the touch flag, "W tick <now_ms>" -> one
# "W ka <status>" per 100ms deadline crossed (00 = the U2F fast-op silence),
# "W frame <128hex> <n> <cid>" -> "W r 0|1|2" (0 queued off the touch wait,
# 1 dropped mid-wait, 2 cancel signalled), "W done" ends the wait.
# Provenance: the period is the pub KEEPALIVE_MS (ctaphid.rs:61); the
# read-only-while-up_pending gating and the drop/queue split are body-sourced
# (shipping run_with_keepalive, ctaphid.rs:737-813); the chained restart and
# the non-strict due boundary are mirror-defined.
WOWN = 0x0123ABCD  # the channel whose MSG/CBOR request is in flight


def wcase(name):
    frames.append("# wait: " + name)


wcase("a tick before any start is never due")
frames.append("W tick 100000")

wcase("cbor wait: nothing before the first deadline, ka on the boundary")
frames.append("W start 1 0")
frames.append("W tick 99")
frames.append("W tick 100")   # now == next: the deadline itself is due
frames.append("W tick 100")   # next moved to 200: not due again
frames.append("W tick 250")   # crosses 200 only

wcase("a tick back in time is simply not due")
frames.append("W tick 150")

wcase("the touch flag flips the status between deadlines")
frames.append("W up 1")
frames.append("W tick 300")   # crosses 300 -> UPNEEDED
frames.append("W up 0")
frames.append("W tick 400")   # crosses 400 -> PROCESSING

wcase("a big jump owes one ka per deadline crossed")
frames.append("W done")
frames.append("W start 1 0")
frames.append("W tick 1000")  # deadlines 100..1000: ten keepalives

wcase("u2f fast op stays silent; a touch wait does not")
frames.append("W done")
frames.append("W start 0 0")
frames.append("W tick 100")   # keepalive_status(false,false) = None -> 00
frames.append("W up 1")
frames.append("W tick 200")   # keepalive_status(false,true) = UPNEEDED
frames.append("W done")

wcase("an inactive wait is never due")
frames.append("W tick 5000")

wcase("frames off the touch wait are queued, not observed")
frames.append("W start 1 0")
frames.append("W up 0")
frames.append("W frame {} 64 {:08x}".format(cframe(WOWN, 0x91).hex(), WOWN))
frames.append("W frame {} 64 {:08x}".format(cframe(0xDEAD, 0x81).hex(), 0xDEAD))

wcase("frames on the touch wait: the channel's cancel signals, the rest drop")
frames.append("W up 1")
frames.append("W frame {} 64 {:08x}".format(cframe(WOWN, 0x91).hex(), WOWN))
frames.append("W frame {} 64 {:08x}".format(cframe(0xBEEF, 0x91).hex(), 0xBEEF))
frames.append("W frame {} 64 {:08x}".format(cframe(WOWN, 0x81).hex(), WOWN))
frames.append("W frame {} 5 {:08x}".format(cframe(WOWN, 0x91).hex(), WOWN))
frames.append("W frame {} 4 {:08x}".format(cframe(WOWN, 0x91).hex(), WOWN))
frames.append("W done")

# malformed W-lines: both sides must X-parse identically
frames.append("# malformed: w unknown subop X-parses")
frames.append("W zzz 1")
frames.append("# malformed: w start is_cbor not 0/1 X-parses")
frames.append("W start 2 0")
frames.append("# malformed: w start missing the now field X-parses")
frames.append("W start 1")
frames.append("# malformed: w up not 0/1 X-parses")
frames.append("W up 2")
frames.append("# malformed: w tick non-decimal X-parses")
frames.append("W tick zz")
frames.append("# malformed: w frame short of 128 hex X-parses")
frames.append("W frame {} 64 {:08x}".format(cframe(WOWN, 0x91).hex()[:-2], WOWN))
frames.append("# malformed: w frame n out of range X-parses")
frames.append("W frame {} 65 {:08x}".format(cframe(WOWN, 0x91).hex(), WOWN))
frames.append("# malformed: w frame cid short of 8 hex X-parses")
frames.append("W frame {} 64 1122".format(cframe(WOWN, 0x91).hex()))
frames.append("# malformed: w done with a trailing field X-parses")
frames.append("W done now")

# malformed control lines: both sides must X-parse identically
frames.append("# malformed: cancel n out of range (65) X-parses")
frames.append("C {} 65 {:08x}".format(cframe(LOWN, 0x91).hex(), LOWN))
frames.append("# malformed: cancel frame short of 128 hex X-parses")
frames.append("C {} 64 {:08x}".format(cframe(LOWN, 0x91).hex()[:-2], LOWN))
frames.append("# malformed: keepalive is_cbor not 0/1 X-parses")
frames.append("K 2 0")
frames.append("# malformed: keepalive missing the up_pending field X-parses")
frames.append("K 1")
frames.append("# malformed: arm secs not decimal X-parses")
frames.append("L arm {:08x} abc 1000".format(LOWN))
frames.append("# malformed: refuse cmd not 2 hex digits X-parses")
frames.append("L refuse {:08x} 0 1000".format(LOWN))
frames.append("# malformed: refuse unknown op X-parses")
frames.append("L bogus {:08x} 81 1000".format(LOWN))
frames.append("# malformed: refuse cid short of 8 hex X-parses")
frames.append("L refuse 1122 81 1000")

# CCID (M13): rsk-usb's smart-card transport, run against the live
# process_message/xfr_apdu/secure_apdu/put_header. The bulk-OUT header is
# type, dwLength LE32, bSlot, bSeq, bStatus, bError, bChainParameter
# (CCID 1.1 §6.1); every reply echoes bSeq and carries bSlot 0, bError 0.
CCID_ATR_RSKEY = bytes.fromhex("3bfc1300008131fe158073c021c05652532d4b65794b")


def cmsg(mtype, seq, dw=0, payload=b""):
    b = bytearray(10)
    b[0] = mtype
    b[1:5] = struct.pack("<I", dw)
    b[5] = 0
    b[6] = seq
    b += payload
    return bytes(b)


def ccidcase(name):
    frames.append("# ccid: " + name)


ccidcase("slot status echoes the live bStatus and bSeq")
frames.append("N 01")
frames.append("M 2048 " + cmsg(0x65, 0x07).hex())
frames.append("N 00")
frames.append("M 2048 " + cmsg(0x65, 0xFF).hex())

ccidcase("power on returns the ATR and activates the slot")
frames.append("N 01")
frames.append("M 2048 " + cmsg(0x62, 0x01).hex())
frames.append("M 2048 " + cmsg(0x62, 0x02).hex())
frames.append("M 2048 " + cmsg(0x65, 0x03).hex())  # reads back ACTIVE
frames.append("M 2048 " + cmsg(0x62, 0x04).hex())  # idempotent re-power

ccidcase("power on: the ATR is clamped to the out cap")
frames.append("M 0 " + cmsg(0x62, 3).hex())
frames.append("M 10 " + cmsg(0x62, 4).hex())
frames.append("M 20 " + cmsg(0x62, 5).hex())
frames.append("M 32 " + cmsg(0x62, 6).hex())

ccidcase("power off deactivates, whatever the status was")
frames.append("M 2048 " + cmsg(0x63, 7).hex())
frames.append("N 40")
frames.append("M 2048 " + cmsg(0x63, 8).hex())

ccidcase("get/set/reset params all answer the same T=1 block")
for t in (0x61, 0x6C, 0x6D):
    frames.append("M 2048 " + cmsg(t, 9).hex())

ccidcase("set data rate returns eight zero bytes")
frames.append("M 2048 " + cmsg(0x73, 10).hex())

ccidcase("params and rate replies exactly at their cap")
frames.append("M 17 " + cmsg(0x6C, 11).hex())
frames.append("M 18 " + cmsg(0x73, 12).hex())

ccidcase("worker-owned and unknown types earn no reply")
for t in (0x6F, 0x69, 0x60, 0x6E, 0x70, 0x00, 0xFF):
    frames.append("M 2048 " + cmsg(t, 13).hex())

ccidcase("a message shorter than a header, or an out slice smaller than one")
frames.append("M 2048 " + pat(9).hex())
frames.append("M 9 " + cmsg(0x65, 14).hex())

ccidcase("the ATR swap: power on presents the caller's bytes")
frames.append("A " + bytes(range(0x20)).hex())
frames.append("M 2048 " + cmsg(0x62, 15).hex())
frames.append("A " + CCID_ATR_RSKEY.hex())

ccidcase("xfr ranging: exact, clamped, zero, absent")
frames.append("X " + cmsg(0x6F, 0, 5, pat(5)).hex())
frames.append("X " + cmsg(0x6F, 0, 100, pat(10)).hex())
frames.append("X " + cmsg(0x6F, 0, 0xFFFF_FFFF, pat(10)).hex())
frames.append("X " + cmsg(0x6F, 0, 0).hex())
frames.append("X " + cmsg(0x62, 0, 5, pat(5)).hex())
frames.append("X " + pat(9).hex())

ccidcase("secure ranging: the pinpad payload, and only on a Secure")
frames.append("E " + cmsg(0x69, 0, 7, pat(7)).hex())
frames.append("E " + cmsg(0x6F, 0, 7, pat(7)).hex())

ccidcase("the header composes from its parts")
frames.append("H 80 2048 7f 00")
frames.append("H 82 0 00 01")
frames.append("H 84 ffffffff 42 80")

# malformed CCID lines: both sides must X-parse identically
frames.append("# malformed: atr not hex X-parses")
frames.append("A zz")
frames.append("# malformed: atr odd-length X-parses")
frames.append("A 3")
frames.append("# malformed: atr missing entirely X-parses")
frames.append("A")
frames.append("# malformed: status short of 2 hex X-parses")
frames.append("N 0")
frames.append("# malformed: status not hex X-parses")
frames.append("N zz")
frames.append("# malformed: header missing fields X-parses")
frames.append("H 80 5")
frames.append("# malformed: header len not decimal X-parses")
frames.append("H 80 x 00 00")
frames.append("# malformed: header len past u32 X-parses")
frames.append("H 80 10000000000 00 00")
frames.append("# malformed: message missing the msg field X-parses")
frames.append("M 100")
frames.append("# malformed: message cap not decimal X-parses")
frames.append("M zz 62")
frames.append("# malformed: message cap past the out buffer X-parses")
frames.append("M 2049 62")
frames.append("# malformed: message odd-length hex X-parses")
frames.append("M 2048 3")
frames.append("# malformed: range not hex X-parses")
frames.append("X zz")
frames.append("# malformed: range odd-length X-parses")
frames.append("E 3")

print("\n".join(frames))
