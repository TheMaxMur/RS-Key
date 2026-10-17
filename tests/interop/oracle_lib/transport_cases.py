# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Raw PING/INIT faults use the same report writer, receiver, and timer as captures."""
from .transport import HID_INIT, HID_PING, MAX_HID_MESSAGE, REPORT_LEN


def reports(cid, command, payload, declared=None):
    length = len(payload) if declared is None else declared
    frames = [cid + bytes([command | 0x80]) + length.to_bytes(2, "big") + payload[:57]]
    frames.extend(cid + bytes([sequence]) + payload[offset:offset + 59]
                  for sequence, offset in enumerate(range(57, len(payload), 59)))
    return [frame.ljust(REPORT_LEN, b"\x00") for frame in frames]


def raw(session, command, frames, label):
    session.require(session.profile != "trezor", "wallet profile excludes raw malformed report injection", "excluded_by_profile")
    session.require(session.hid is not None and hasattr(session.hid, "transfer_reports"), "raw report backend unavailable", "excluded_by_mode")
    if command not in (HID_INIT, HID_PING):
        raise ValueError("raw fault corpus is restricted to INIT/PING")
    return session._exchange("hid", session.hid.layer, label, b"".join(frames), session.options.timeout,
                             lambda deadline, observe: session.hid.transfer_reports(command, frames, deadline, observe))


def run(session):
    lengths = sorted({length for boundary in range(57, MAX_HID_MESSAGE + 1, 59)
                      for length in (boundary - 1, boundary, boundary + 1) if length <= MAX_HID_MESSAGE})
    for length in lengths:
        with session.case(f"transport.PING.frame-boundary.{length}", ("T03", "T04", "G03")):
            payload = session.fixture("transport.every-boundary", length)
            session.check("every continuation boundary echoes exactly", session.hid_call(HID_PING, payload).data, payload)
    for length in (0, 1, 7, 9, 16):
        with session.case(f"transport.INIT.invalid-length.{length}", ("T02", "G03", "G14")):
            session.require(session.hid is not None, "no HID selected", "excluded_by_mode")
            reply = raw(session, HID_INIT, reports(session.hid.cid, HID_INIT, bytes(length)), "ctaphid.INIT.invalid-length")
            session.check("bad INIT length refused", reply.protocol, "transport_error")
            session.check("bad INIT length error", reply.status, 3)
            trigger = session.evidence()
            nonce = session.fixture("transport.control", 8)
            session.check("PING after invalid INIT", session.hid_call(HID_PING, nonce).data, nonce)
            session.transition("hid.channel", "allocated", "usable_after_invalid_INIT", trigger, [trigger, session.evidence()])
    for fault in ("wrong-first-sequence", "missing-continuation", "duplicate-continuation", "reordered-continuations", "oversized-declaration"):
        with session.case("transport.assembly." + fault, ("T03", "T04", "T05", "G12", "G14")):
            session.require(session.hid is not None, "no HID selected", "excluded_by_mode")
            frames = reports(session.hid.cid, HID_PING, session.fixture("transport.fragmented", 177))
            expected = 4
            if fault == "wrong-first-sequence":
                frames = [frames[0], frames[1][:4] + b"\x01" + frames[1][5:]]
            elif fault == "missing-continuation":
                frames, expected = frames[:1], 5
            elif fault == "duplicate-continuation":
                frames = [*frames[:2], frames[1]]
            elif fault == "reordered-continuations":
                frames = [frames[0], frames[1], frames[3]]
            else:
                frames, expected = reports(session.hid.cid, HID_PING, b"", MAX_HID_MESSAGE + 1), 3
            reply = raw(session, HID_PING, frames, "ctaphid.PING." + fault)
            session.check("assembly fault refused", reply.protocol, "transport_error")
            session.check("assembly fault code", reply.status, expected)
            trigger = session.evidence()
            payload = session.fixture("transport.after-error", 59)
            session.check("complete PING after assembly error", session.hid_call(HID_PING, payload).data, payload)
            session.transition("hid.assembly", fault, "idle_and_usable", trigger, [trigger, session.evidence()])
    with session.case("transport.INIT.resynchronize", ("T02", "T03")):
        session.require(session.hid is not None, "no HID selected", "excluded_by_mode")
        nonce = session.fixture("transport.resync.nonce", 8)
        result = session.hid_call(HID_INIT, nonce)
        session.check("INIT response size", len(result.data), 17)
        session.check("INIT echoes nonce", result.data[:8], nonce)
        session.check("resync preserves CID", result.data[8:12], session.hid.cid)
        session.check("PING after resync", session.hid_call(HID_PING, nonce).data, nonce)
