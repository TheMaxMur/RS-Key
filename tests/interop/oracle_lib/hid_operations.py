# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Interleaved INIT/KA frames retain channel ownership and recovery controls."""
from .fido import auth_data, authorize, info, public_key, verified
from .hid_sequences import allocate, hooks, send
from .timers import wait
from .transport import BROADCAST_CID, HID_CBOR, HID_INIT, HID_PING

ALGORITHMS = (-7, -48, -49, -50)


def channels(session):
    for cid in (bytes(4), BROADCAST_CID, bytes.fromhex("fefffeff")):
        for command, payload in ((HID_PING, b"channel"), (HID_INIT, bytes(8))):
            with session.case(f"transport.CID.reserved-or-unallocated.{cid.hex()}.{command:02x}", ("T02", "T08", "G04", "G14")):
                with hooks(session) as hid:
                    owner = hid.cid
                    try:
                        hid.cid = cid
                        result = session.hid_call(command, payload)
                        if cid == bytes(4) or cid == BROADCAST_CID and command != HID_INIT:
                            session.check("reserved channel refused at HID layer", (result.protocol, result.status), ("transport_error", 0x0b))
                        elif command == HID_INIT:
                            session.check("INIT returns nonce and complete channel allocation", (result.protocol, result.data[:8], len(result.data)), ("success", payload, 17))
                            session.check("INIT returns valid nonreserved channel", result.data[8:12] not in (bytes(4), BROADCAST_CID))
                        else:
                            session.observe("unallocated_channel_policy", (result.protocol, result.status, result.data))
                            if result.protocol == "success":
                                session.check("accepted unallocated PING retains exact payload", result.data, payload)
                            else:
                                session.check("unallocated channel refusal is INVALID_CHANNEL", (result.protocol, result.status), ("transport_error", 0x0b))
                    finally:
                        hid.cid = owner
                    session.check("owner survives reserved-channel probes", session.hid_call(HID_PING, b"owner").data, b"owner")


def pending_init(session):
    for target in ("owner", "foreign", "broadcast"):
        with session.case("transport.INIT.outstanding-UP." + target, ("T02", "T06", "T08", "F22", "G14")):
            with hooks(session) as hid:
                other = allocate(session)
                cid = hid.cid if target == "owner" else other if target == "foreign" else BROADCAST_CID
                nonce, replies, timeline = session.fixture("pending.INIT", 8), [], []
                def report(frame, timestamp):
                    if frame[:4] == cid and frame[4] == HID_INIT | 0x80:
                        replies.append((frame, timestamp))
                        return True
                def keepalive(status, timestamp):
                    timeline.append((status, timestamp))
                    if len(timeline) == 1:
                        send(session, HID_INIT, cid, nonce, "ctaphid.INIT.during-UP")
                    elif len(timeline) >= 3:
                        send(session, 0x11, hid.cid, label="ctaphid.CANCEL.after-interleaved-INIT")
                hid.on_keepalive, hid.on_report = keepalive, report
                response = session.ctap(11)
                session.require(response.status not in (1, 0x2b), "selection unsupported", "unsupported_confirmed")
                session.check("outstanding operation remains owned and cancellable", response.status, 0x2d)
                session.check("owner UP stage observed", any(status == 2 for status, _ in timeline))
                for frame, _ in replies:
                    session.check("interleaved INIT nonce and response width", (frame[5:7], frame[7:15]), (b"\x00\x11", nonce))
                session.observe("INIT_during_UP_policy", "processed" if replies else "ignored by pending-presence loop")
                hid.on_report = hid.on_keepalive = None
                fresh = session.hid_call(HID_INIT, nonce)
                session.check("owner resynchronizes after cancellation", (fresh.data[:8], fresh.data[8:12]), (nonce, hid.cid))
                session.check("resynchronized owner accepts PING", session.hid_call(HID_PING, b"resync").data, b"resync")


def processing(session):
    for algorithm in ALGORITHMS:
        for moment in ("processing", "UP-needed", "final-response"):
            with session.case(f"transport.CANCEL.makeCredential.alg-{algorithm}.{moment}", ("T06", "T07", "T08", "F11", "G14"),
                    effects=("create_fido_credential",), touch=True):
                session.require(algorithm in [row["alg"] for row in info(session).get(10, [])] or session.profile == "rsk" and algorithm in (-48, -49, -50),
                                "algorithm not advertised or defined by the selected RS-Key profile", "unsupported_confirmed")
                with hooks(session) as hid:
                    rp = session.fixture(session.current.name, 8).hex() + ".oracle.invalid"
                    challenge = session.fixture("processing.hash")
                    fields = {1: challenge, 2: {"id": rp}, 3: {"id": b"processing"}, 4: [{"type": "public-key", "alg": algorithm}], 7: {"rk": False}}
                    authorize(session, fields, 1, rp, challenge, 8, 9)
                    timeline, sent = [], []
                    def cancel():
                        if not sent:
                            sent.append(session.trace.now())
                            send(session, 0x11, hid.cid, label="ctaphid.CANCEL." + moment)
                    def keepalive(status, timestamp):
                        timeline.append((status, timestamp))
                        if (moment == "processing" and status == 1) or (moment == "UP-needed" and status == 2):
                            cancel()
                    def report(frame, timestamp):
                        if moment == "final-response" and frame[:4] == hid.cid and frame[4] == HID_CBOR | 0x80:
                            cancel()
                    hid.on_keepalive, hid.on_report = keepalive, report
                    result = session.ctap(1, fields)
                    hid.on_keepalive = hid.on_report = None
                    session.require(result.status != 0x26, "profiled optional algorithm is refused by this build", "unsupported_confirmed")
                    session.observe("keepalive_stages", timeline, "presence")
                    session.observe("cancel_sent", bool(sent))
                    session.check("request reaches success or explicit cancellation", result.status in (0, 0x2d))
                    if moment == "final-response":
                        session.check("cancel after final response cannot rewrite result", result.status, 0)
                    if result.status == 0:
                        value = session.ctap_value(result)
                        parsed = auth_data(value[2])
                        descriptor = {"type": "public-key", "id": parsed["credential_id"]}
                        request = {1: rp, 2: challenge, 3: [descriptor]}
                        authorize(session, request, 2, rp, challenge, 6, 7)
                        signed = session.ctap_value(session.ctap(2, request))
                        verified(session, "completed race retains independently usable key", public_key(parsed["cose"]), algorithm, signed[3], signed[2] + challenge)
                    session.check("CANCEL race leaves channel usable", session.hid_call(HID_PING, b"race-done").data, b"race-done")
                    if not sent:
                        session.require(False, "requested processing/UP stage was not emitted; no cancellation-stage claim", "excluded_by_mode")


def run(session):
    channels(session)
    pending_init(session)
    processing(session)
    lock_interactions(session)


def lock_interactions(session):
    with session.case("transport.LOCK.INIT-WINK-CANCEL-refresh-and-release", ("T02", "T08", "T09", "G10", "G14")):
        session.require(session.profile == "rsk", "prestandard LOCK interactions require the known RS-Key contract", "excluded_by_profile")
        with hooks(session) as hid:
            owner, held = hid.cid, False
            try:
                result = session.hid_call(4, b"\x01")
                session.require(result.protocol == "success", "LOCK unsupported by this build", "unsupported_confirmed")
                held = True
                other = allocate(session)
                hid.cid = other
                for command, body in ((8, b""), (4, b"\x00"), (HID_PING, b"held")):
                    reply = session.hid_call(command, body)
                    session.check("foreign WINK/release/PING cannot bypass the lock", (reply.protocol, reply.status), ("transport_error", 6))
                send(session, 0x11, other, label="ctaphid.CANCEL.foreign-during-LOCK")
                hid.cid = owner
                nonce = session.fixture("LOCK.INIT", 8)
                session.check("owner INIT resynchronizes without changing CID", session.hid_call(HID_INIT, nonce).data[8:12], owner)
                hid.cid = other
                session.check("owner INIT and foreign CANCEL do not release LOCK", session.hid_call(HID_PING, b"still-held").status, 6)
                hid.cid = owner
                wink = session.hid_call(8)
                session.check("owner WINK succeeds or is explicitly unsupported", wink.protocol == "success" or (wink.protocol, wink.status) == ("transport_error", 1))
                wait(session, .75)
                session.check("owner can refresh LOCK", session.hid_call(4, b"\x01").protocol, "success")
                wait(session, .5)
                hid.cid = other
                session.check("refresh extends exclusion beyond the original lock deadline", session.hid_call(HID_PING, b"refreshed").status, 6)
                wait(session, .75)
                session.check("refreshed LOCK still expires", session.hid_call(HID_PING, b"expired").data, b"expired")
                hid.cid = owner
                session.check("owner can arm another LOCK", session.hid_call(4, b"\x01").protocol, "success")
                session.check("owner can release without waiting", session.hid_call(4, b"\x00").protocol, "success")
                held = False
                hid.cid = other
                session.check("explicit release immediately restores foreign channel", session.hid_call(HID_PING, b"released").data, b"released")
            finally:
                hid.cid = owner
                if held and not session.broken:
                    session.hid_call(4, b"\x00")
