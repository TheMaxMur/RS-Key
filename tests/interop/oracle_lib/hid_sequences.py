# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""HID presence/cancellation races and channel isolation on the raw report path."""
from contextlib import contextmanager

from . import codec
from .transport import HID_CBOR, HID_INIT, HID_PING, HID_KEEPALIVE, HID_ERROR, BROADCAST_CID
from .transport_cases import reports
from .timers import wait


@contextmanager
def hooks(session, keepalive=None, report=None):
    session.require(session.hid is not None and hasattr(session.hid, "send_only"), "raw HID scheduler unavailable", "excluded_by_mode")
    session.require(session.profile != "trezor", "raw channel scheduling excluded on wallet profile", "excluded_by_profile")
    hid = session.hid
    old = hid.on_keepalive, hid.on_report
    hid.on_keepalive, hid.on_report = keepalive, report
    try:
        yield hid
    finally:
        hid.on_keepalive, hid.on_report = old


def send(session, command, cid, data=b"", label=None):
    frames = reports(cid, command, data)
    return session._exchange("hid", session.hid.layer, label or f"ctaphid.send.{command:02x}", b"".join(frames), session.options.timeout,
                             lambda deadline, observe: session.hid.send_only(frames, deadline, observe))


def allocate(session):
    original = session.hid.cid
    try:
        session.hid.cid = BROADCAST_CID
        nonce = session.fixture("HID.second-CID", 8)
        response = session.hid_call(HID_INIT, nonce)
        session.check("foreign INIT nonce", response.data[:8], nonce)
        session.check("foreign INIT response length", len(response.data), 17)
        other = response.data[8:12]
        session.check("distinct allocated CID", other not in (original, BROADCAST_CID, bytes(4)))
        return other
    finally:
        session.hid.cid = original


def cancellation(session):
    for moment in ("before", "UP-needed", "foreign-CID", "after"):
        with session.case("transport.CANCEL." + moment, ("T06", "T07", "T08", "F22", "X05", "G12", "G14")):
            with hooks(session) as hid:
                other = allocate(session) if moment == "foreign-CID" else None
                observed = []
                if moment in ("before", "after"):
                    send(session, 0x11, hid.cid)
                    session.check("idle CANCEL does not damage channel", session.hid_call(HID_PING, b"oracle").data, b"oracle")
                else:
                    def on_keepalive(status, timestamp):
                        observed.append((status, timestamp))
                        if status == 2 and sum(value == 2 for value, _ in observed) == 1:
                            if other is not None:
                                send(session, 0x11, other, label="ctaphid.foreign-CANCEL")
                            else:
                                send(session, 0x11, hid.cid)
                        elif status == 2 and other is not None:
                            send(session, 0x11, hid.cid, label="ctaphid.owner-CANCEL")
                    hid.on_keepalive = on_keepalive
                    result = session.ctap(11)
                    session.require(result.status not in (1, 0x2B), "selection command not supported", "unsupported_confirmed")
                    session.check("outstanding selection cancelled", result.status, 0x2D)
                    session.check("UPNEEDED observed before cancellation", any(status == 2 for status, _ in observed))
                    if other is not None:
                        session.check("foreign CANCEL did not complete owner's wait", sum(status == 2 for status, _ in observed) >= 2)
                    session.observe("keepalive_timeline", observed, "presence")
                    hid.on_keepalive = None
                    session.ctap_value(session.ctap(4))
                if moment == "after":
                    send(session, 0x11, hid.cid)
                    session.check("CANCEL after completion leaves PING usable", session.hid_call(HID_PING, b"done").data, b"done")


def concurrent(session):
    with session.case("transport.CID-concurrency.busy-and-recovery", ("T06", "T08", "X05", "G14")):
        with hooks(session) as hid:
            other = allocate(session)
            foreign = []
            issued = False
            def on_report(frame, timestamp):
                if frame[:4] == other:
                    foreign.append((frame, timestamp))
            def on_keepalive(status, timestamp):
                nonlocal issued
                if not issued:
                    issued = True
                    send(session, HID_PING, other, b"busy-control", "ctaphid.foreign-PING")
                elif foreign:
                    send(session, 0x11, hid.cid)
            hid.on_report, hid.on_keepalive = on_report, on_keepalive
            result = session.ctap(11)
            session.require(result.status not in (1, 0x2B), "selection command not supported", "unsupported_confirmed")
            session.check("owner operation remains cancellable", result.status, 0x2D)
            session.check("foreign busy response observed", len(foreign) > 0)
            response = foreign[0][0]
            session.check("foreign channel busy code", (response[4], response[5:8]), (HID_ERROR | 128, b"\x00\x01\x06"))
            hid.on_keepalive, hid.on_report = None, None
            original = hid.cid
            try:
                hid.cid = other
                session.check("second CID usable after owner completion", session.hid_call(HID_PING, b"recovered").data, b"recovered")
            finally:
                hid.cid = original


def wink_lock(session):
    for command, name, payloads in ((8, "WINK", (b"", b"\x00", bytes(2))),
                                     (4, "LOCK", (b"\x00", b"\x01", b"\x0a", b"\x0b", b"", bytes(2)))):
        for payload in payloads:
            with session.case(f"transport.{name}.{payload.hex() or 'empty'}", ("T09", "G03", "G14")):
                with hooks(session):
                    response = session.hid_call(command, payload)
                    session.observe("profile_result", (response.protocol, response.status))
                    if response.protocol == "success":
                        session.check("successful WINK/LOCK has empty reply", response.data, b"")
                        if command == 4 and payload and payload != b"\x00":
                            session.check("LOCK release by owner", session.hid_call(4, b"\x00").protocol, "success")
                    session.check("channel usable after WINK/LOCK", session.hid_call(HID_PING, b"control").data, b"control")


def run(session):
    cancellation(session)
    concurrent(session)
    wink_lock(session)
    lock_expiry(session)


def lock_expiry(session):
    with session.case("transport.LOCK.foreign-channel-and-expiry", ("T09", "T08", "G10", "G14")):
        with hooks(session) as hid:
            other, owner = allocate(session), hid.cid
            held = False
            try:
                result = session.hid_call(4, b"\x01")
                session.require(result.protocol == "success", "LOCK not supported by this profile", "unsupported_confirmed")
                held = True
                hid.cid = other
                result = session.hid_call(HID_PING, b"locked")
                session.check("LOCK excludes another CID", (result.protocol, result.status), ("transport_error", 6))
                wait(session, 1.25)
                session.check("foreign CID works after lock expiry", session.hid_call(HID_PING, b"expired").data, b"expired")
            finally:
                hid.cid = owner
                if held and not session.broken:
                    session.check("owner can release expired lock", session.hid_call(4, b"\x00").protocol, "success")
