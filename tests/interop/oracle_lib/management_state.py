# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Lock authorization precedes identical writes and every writer's confirmation."""
from itertools import product
import sys

from . import codec
from .management_cases import WRITERS, read, write


def cue(session, mode):
    session.trace.emit("interaction", action="management-confirmation-" + mode, stage="requested", source="runner", observed_touch_ns=None)
    print("oracle: management configuration confirmation: " + mode, file=sys.stderr)


def usable(session, writer):
    return "strict-config" not in session.options.features or writer in ("card", "fido")


def locked_writes(session):
    for owner, writer, defect in product(WRITERS, WRITERS, ("missing", "wrong", "empty", "short", "long", "correct")):
        with session.case(f"management.lock.identical.owner-{owner}.writer-{writer}.{defect}",
                ("M02", "M04", "M05", "G01", "G03", "G10", "G11", "G14"), effects=("config_change",), touch=True):
            session.require(session.profile == "rsk", "lock/identical write ordering requires RS-Key", "excluded_by_profile")
            session.require(usable(session, owner), "strict build disables this lock-setting interface", "excluded_by_profile")
            original = read(session, owner)
            read(session, writer)
            session.require(original.get(10) == b"\x00", "known unlocked configuration required")
            code, armed = session.fixture("management.identical.lock", 16), False
            try:
                cue(session, "accept")
                write(session, owner, codec.tlv(10, code))
                armed = read(session, owner).get(10) == b"\x01"
                session.check("lock setting is witnessed before testing identical writes", armed)
                locked = read(session, owner)
                values = {"wrong": bytes([code[0] ^ 1]) + code[1:], "empty": b"", "short": code[:-1], "long": code + b"x", "correct": code}
                auth = b"" if defect == "missing" else codec.tlv(11, values[defect])
                identical = codec.tlv(3, locked[3])
                cue(session, "accept")
                reply = write(session, writer, auth + identical)
                session.observe("identical_write_result", (reply.protocol, reply.status))
                if defect != "correct" and usable(session, writer):
                    session.check("locked identical write still requires the exact unlock code", reply.is_rejection)
                session.check("identical write cannot move any stored field or the lock", read(session, owner), locked)
                changed = codec.tlv(8, bytes([locked[8][0] ^ 0x40]))
                cue(session, "accept")
                write(session, writer, auth + changed)
                current = read(session, owner)
                if defect == "correct" and usable(session, writer):
                    session.check("same writer's valid code authorizes an actual field change", current[8], bytes([locked[8][0] ^ 0x40]))
                else:
                    session.check("invalid code or disabled writer preserves the entire locked configuration", current, locked)
                session.check("changing an ordinary field does not clear the lock", current[10], b"\x01")
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    cue(session, "accept")
                    current = read(session, owner)
                    if current != original:
                        write(session, owner, (codec.tlv(11, code) if current.get(10) == b"\x01" else b"") + codec.tlv(8, original[8]) + codec.tlv(10, bytes(16)))
                    session.check("management lock fixture restores the exact prior fields", read(session, owner), original)


def confirmations(session):
    for writer, mode in product(WRITERS, ("accept", "decline", "panel-cancel", "timeout")):
        with session.case(f"management.lock.confirmation.{writer}.{mode}", ("M02", "M04", "M05", "G10", "G11", "G12", "G14"), effects=("config_change",), touch=True):
            session.require(session.profile == "rsk", "writer confirmation profile requires RS-Key", "excluded_by_profile")
            session.require(session.options.operator, "confirmation/refusal needs a controlled operator action")
            session.require(mode not in ("decline", "panel-cancel") or "display" in session.options.features, "explicit decline requires the positively declared display profile", "excluded_by_profile")
            session.require(mode != "timeout" or session.options.timeout > 130, "confirmation timeout needs the complete presence window")
            cleanup_writer = writer if usable(session, writer) else "card"
            read(session, cleanup_writer)
            original = read(session, writer)
            session.require(original.get(10) == b"\x00", "known unlocked configuration required")
            code, armed = session.fixture("management.confirmation.lock", 16), False
            try:
                cue(session, mode)
                reply = write(session, writer, codec.tlv(10, code) + codec.tlv(8, bytes([original[8][0] ^ 0x40])))
                session.observe("configuration_confirmation_result", (reply.protocol, reply.status))
                current = read(session, writer)
                armed = current.get(10) == b"\x01"
                accepted = mode == "accept" and usable(session, writer)
                session.check("only confirmed enabled writers can arm a new lock", armed, accepted)
                if not accepted:
                    session.check("declined or disabled writer cannot partially persist the ordinary field", current, original)
                else:
                    session.check("confirmed writer stores the requested ordinary field with its lock", current[8], bytes([original[8][0] ^ 0x40]))
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    cue(session, "accept")
                    current = read(session, cleanup_writer)
                    if current != original:
                        write(session, cleanup_writer, (codec.tlv(11, code) if current.get(10) == b"\x01" else b"") + codec.tlv(10, bytes(16)) + codec.tlv(8, original[8]))
                    session.check("confirmed lock fixture is removed with its known code", read(session, writer), original)


def run(session):
    locked_writes(session)
    confirmations(session)
