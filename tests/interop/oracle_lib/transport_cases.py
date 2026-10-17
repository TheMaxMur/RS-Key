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


def raw(session, command, frames, label, delays=None):
    session.require(session.profile != "trezor", "wallet profile excludes raw malformed report injection", "excluded_by_profile")
    session.require(session.hid is not None and hasattr(session.hid, "transfer_reports"), "raw report backend unavailable", "excluded_by_mode")
    if command not in (HID_INIT, HID_PING):
        raise ValueError("raw fault corpus is restricted to INIT/PING")
    return session._exchange("hid", session.hid.layer, label, b"".join(frames), session.options.timeout,
                             lambda deadline, observe: session.hid.transfer_reports(command, frames, deadline, observe, delays=delays))


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


def boundaries(session):
    assembly_intervals(session)
    foreign_continuation(session)
    after_completion(session)


def after_completion(session):
    with session.case("transport.KEEPALIVE.after-completion", ("T06", "G14"), parameters={"idle_observation_ms": 250}):
        session.require(session.profile != "trezor", "raw idle observations excluded on wallet profile", "excluded_by_profile")
        session.require(session.hid is not None and hasattr(session.hid, "idle_reports"), "raw idle report observation unavailable", "excluded_by_mode")
        session.check("PING completes before idle observation", session.hid_call(HID_PING, b"idle-witness").data, b"idle-witness")
        start, frames = session.trace.now(), []
        def observe(frame, timestamp):
            frames.append(frame)
            event = session.trace.emit("io_event", session_id="hid", exchange_id=None, observation_layer="hid_report",
                                       direction="rx", unsolicited=True, observed_ns=timestamp, hex=frame.hex(), length=len(frame))
            session.event_evidence = event["event_id"]
            session.check("idle observation has a complete HID report", len(frame), REPORT_LEN)
        session.hid.idle_reports(start + 250000000, observe)
        session.observe("post_completion_observation", {"start_ns": start, "end_ns": session.trace.now(), "reports": len(frames)}, "presence")
        session.check("no KEEPALIVE or final reply after request completion", not any(frame[:4] == session.hid.cid for frame in frames))
        session.check("PING usable after idle observation", session.hid_call(HID_PING, b"idle-control").data, b"idle-control")


def assembly_intervals(session):
    for delay in (0.40, 0.50, 0.65):
        with session.case(f"transport.assembly.interval-{delay:.2f}", ("T04", "T05", "G12", "G14"),
                          parameters={"delay_seconds": delay, "rsk_timeout_seconds": 0.5}, effects=("malformed_known_command",)):
            session.require(session.profile == "rsk", "assembly deadline is profile-specific", "unknown")
            session.require(session.hid is not None, "no HID selected", "excluded_by_mode")
            payload = session.fixture("assembly.deadline", 58)
            frames = reports(session.hid.cid, HID_PING, payload)
            reply = raw(session, HID_PING, frames, "ctaphid.PING.scheduled-continuation", [0, delay])
            session.observe("boundary_status", {"protocol": reply.protocol, "status": reply.status})
            session.observe("boundary_limit", "host write intervals are recorded; scheduling at 500 ms does not prove arrival at the device boundary")
            intervals = reply.timing["request_report_intervals"]
            host_gap = intervals[1]["write_start_ns"] - intervals[0]["write_end_ns"]
            session.observe("observed_host_interframe_gap_ns", host_gap)
            host_window = intervals[1]["write_end_ns"] - intervals[0]["write_start_ns"]
            session.require(delay != 0.40 or host_window < 500000000, "host scheduling crossed the intended before-boundary interval")
            if delay == 0.40:
                session.check("completion before assembly deadline echoes", (reply.protocol, reply.data), ("success", payload))
            elif delay == 0.65:
                session.check("completion after assembly deadline times out", (reply.protocol, reply.status), ("transport_error", 5))
            else:
                session.check("boundary outcome is echo or assembly timeout", (reply.protocol == "success" and reply.data == payload) or
                              (reply.protocol, reply.status) == ("transport_error", 5))
            trigger = session.evidence()
            control = session.fixture("assembly.deadline.control", 9)
            session.check("PING usable after scheduled continuation", session.hid_call(HID_PING, control).data, control)
            session.transition("hid.assembly", "assembling", "idle_and_usable", trigger, [trigger, session.evidence()])


def foreign_continuation(session):
    with session.case("transport.assembly.foreign-CID-continuation", ("T04", "T08", "G14"), effects=("malformed_known_command",)):
        session.require(session.hid is not None, "no HID selected", "excluded_by_mode")
        from .hid_sequences import allocate
        session.require(session.profile != "trezor", "raw channel scheduling excluded on wallet profile", "excluded_by_profile")
        other = allocate(session)
        payload = session.fixture("foreign.continuation.body", 58)
        frames = reports(session.hid.cid, HID_PING, payload)
        foreign = other + frames[1][4:]
        seen = []
        previous = session.hid.on_report
        def watch(frame, timestamp):
            seen.append(frame)
            if previous:
                previous(frame, timestamp)
        session.hid.on_report = watch
        try:
            result = raw(session, HID_PING, [frames[0], foreign, frames[1]], "ctaphid.PING.foreign-continuation")
            session.check("foreign continuation does not corrupt owning CID", (result.protocol, result.data), ("success", payload))
            if session.profile == "rsk":
                session.check("foreign continuation receives channel busy", any(frame[:4] == other and frame[4:8] == b"\xbf\x00\x01\x06" for frame in seen))
        finally:
            session.hid.on_report = previous
