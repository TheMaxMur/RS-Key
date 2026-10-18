# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Raw CCID framing faults retain transport evidence and explicit recovery."""
from . import codec
from .lifecycle import Action, change
from .trace import Outcome, Reply, TransferError


def message(command=0x6F, body=b"\x00\xfd\x00\x00", declared=None, sequence=17):
    return bytes([command]) + (len(body) if declared is None else declared).to_bytes(4, "little") + bytes([0, sequence, 0, 0, 0]) + body


def vectors():
    normal = message()
    for size in range(10):
        yield "header-length-" + str(size), normal[:size], "framing"
    for size in (0, 1, 2, 3):
        yield "XfrBlock-short-" + str(size), message(body=bytes(size)), "short-APDU"
    for declared in (0, 1, 3, 5, 3062, 3063, 0xFFFFFFFF):
        yield "declared-" + str(declared), message(declared=declared), "short-APDU" if declared < 4 else "framing"
    yield "trailing-beyond-declared-body", normal + b"ignored", "trailing"
    for command in (0, 0x72, 255):
        yield "unsupported-or-idle-ABORT-" + str(command), message(command, b""), "silence"


def raw(session, wire, timeout):
    def transfer(deadline, observe):
        response = session.card.raw(wire, deadline, observe)
        session.check("raw CCID response has a complete header", len(response) >= 10)
        return Reply(response, "transport_error" if response[7] & 0x40 else "success", response[8] if response[7] & 0x40 else None)
    return session._exchange("ccid", "ccid_message", "ccid.inject", wire, timeout, transfer)


def run(session):
    for label, wire, expected in vectors():
        with session.case("transport.CCID.fault." + label, ("T10", "G03", "G05", "G12", "G14"),
                          effects=("session_recovery", "malformed_known_command"), parameters={"defect": label, "expected_boundary": expected}):
            session.require(session.profile == "rsk", "raw CCID fault contract requires RS-Key", "excluded_by_profile")
            session.require(session.card is not None and hasattr(session.card, "raw") and hasattr(session.card, "control"), "raw CCID with bounded reconnect unavailable through PC/SC APDU", "excluded_by_mode")
            session.require(getattr(session.card, "whole_messages", True), "whole-message injection is distinct from native USB packet accumulation", "excluded_by_mode")
            session.select("piv")
            before = session.card_value(session.apdu(codec.apdu(0xFD)))
            try:
                result = raw(session, wire, min(1, session.options.timeout))
            except TransferError as error:
                if expected != "silence":
                    raise
                session.check("unsupported idle CCID command has a bounded silent observation", error.outcome == Outcome.DEADLINE)
                session.observe("silent_command_observation", {"outcome": error.outcome, "deadline_seconds": min(1, session.options.timeout), "physical_disconnect": False}, "presence")
                change(session, Action.RECONNECT)
            else:
                data = result.data
                if expected == "framing":
                    session.check("malformed CCID frame receives transport resynchronization", (data[0], data[10:]), (0x80, b"\x6f\x00"))
                    session.observe("framing_status_scope", "6F00 belongs to the reader's framing response; no applet refusal is inferred")
                elif expected == "short-APDU":
                    session.check("short XfrBlock refuses dwLength at the reader", (data[0], data[7] & 0xC0, data[8], data[10:]), (0x81, 0x40, 1, b""))
                elif expected == "trailing":
                    session.observe("trailing_frame_result", data)
                    session.observe("delivery_limit", "whole-message backend can observe bytes beyond dwLength; USB packet accumulation can differ")
                else:
                    session.check("idle unsupported CCID command must not fabricate a reply", False)
            session.select("piv")
            session.check("reader remains usable after raw CCID fault", session.card_value(session.apdu(codec.apdu(0xFD))), before)
            session.observe("backend_limit", "raw CCID messages; no assertion about USB packet boundaries, control-transfer ABORT or physical card removal")
