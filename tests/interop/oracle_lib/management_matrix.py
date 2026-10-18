# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""DeviceInfo grammar and delta semantics are checked through every writer."""
from . import codec
from .management_cases import WRITERS, read, write
from .trace import Outcome, TransferError

WIDTHS = {3: 2, 6: 2, 7: 2, 8: 1, 10: 16, 11: 16, 12: 0, 14: 2, 23: 1}
IDENTITY_TAGS = (1, 2, 4, 5)


def restore(session, writer, original, introduced):
    session.trace.phase = "cleanup"
    fields = {tag: value for tag, value in original.items() if tag in WIDTHS and tag not in (10, 11)}
    for tag in introduced:
        fields.setdefault(tag, b"\x00" * WIDTHS[tag])
    write(session, writer, b"".join(codec.tlv(tag, value) for tag, value in fields.items()))
    current = read(session, writer)
    session.check("original DeviceInfo fields restored", all(current.get(tag) == value for tag, value in original.items()))
    if introduced:
        session.observe("cleanup_limit", {"neutral_fixture_tags_retained": sorted(introduced), "reason": "delta protocol has no delete-tag operation"})


def values(session):
    for writer in WRITERS:
        for tag, width in WIDTHS.items():
            for length in sorted({0, 1, max(0, width - 1), width, width + 1}):
                with session.case(f"management.field.{writer}.tag-{tag:02x}.length-{length}", ("M01", "M02", "M04", "M05", "G01", "G03", "G14"),
                                  effects=("config_change",), touch=True):
                    session.require(session.profile == "rsk", "DeviceInfo widths and merge semantics require RS-Key", "excluded_by_profile")
                    original = read(session, writer)
                    session.require(original.get(10) == b"\x00", "known unlocked fixture configuration required")
                    # Lock setup and replacement are exercised by the lock lifecycle suite.
                    if tag in (10, 11) and length == width:
                        value = bytes(width)
                    elif tag == 3 and length == width:
                        value = original[3]
                    else:
                        value = b"\x00" * length
                    valid = length == width if tag in (3, 10, 11) else length <= width
                    try:
                        reply = write(session, writer, codec.tlv(tag, value))
                        session.observe("field_write_result", (reply.protocol, reply.status))
                        current = read(session, writer)
                        if valid:
                            if tag not in (10, 11):
                                session.check("supported DeviceInfo width applied", current.get(tag), value)
                            session.check("partial update preserves all other fields", {key: val for key, val in current.items() if key != tag},
                                          {key: val for key, val in original.items() if key != tag})
                            write(session, writer, codec.tlv(tag, value))
                            session.check("identical partial write is stable", read(session, writer), current)
                        else:
                            session.check("invalid DeviceInfo width preserves exact config", current, original)
                    finally:
                        if not session.broken:
                            restore(session, writer, original, {tag} if valid and tag not in original and tag not in (10, 11) else set())


def grammar(session):
    for writer in WRITERS:
        vectors = [(f"unknown-tag-{tag:02x}", codec.tlv(tag, b"x")) for tag in range(256) if tag not in WIDTHS]
        vectors += [(f"duplicate-{tag:02x}", codec.tlv(tag, bytes(width)) * 2) for tag, width in WIDTHS.items()]
        vectors += [("truncated-header", b"\x08"), ("truncated-value", b"\x08\x02\x00"),
                    ("trailing-byte", codec.tlv(8, b"\x00") + b"\xff"), ("request-overflow", bytes(129))]
        for defect, data in vectors:
            with session.case(f"management.grammar.{writer}.{defect}", ("M02", "M05", "G04", "G05", "G07", "G14"), effects=("config_change",), touch=True):
                session.require(session.profile == "rsk", "DeviceInfo grammar is profile-specific", "excluded_by_profile")
                original = read(session, writer)
                session.require(original.get(10) == b"\x00", "grammar fixture needs unlocked configuration")
                try:
                    write(session, writer, data)
                except TransferError as error:
                    if error.outcome != Outcome.HOST_REJECTED:
                        raise
                    session.observe("host_framing_refusal", {"outcome": error.outcome, "detail": str(error)}, "presence")
                session.check("grammar refusal preserves entire configuration", read(session, writer), original)
                write(session, writer, codec.tlv(3, original[3]))
                session.check("valid writer control after malformed request", read(session, writer), original)
        for bit in range(16):
            with session.case(f"management.reserved-bit.{writer}.{bit}", ("M02", "M03", "M05", "G04", "G14"), effects=("config_change",), touch=True):
                session.require(session.profile == "rsk", "reserved capability clamping requires RS-Key", "excluded_by_profile")
                original = read(session, writer)
                supported = int.from_bytes(original[1], "big")
                session.require(not supported & (1 << bit), "bit is supported and covered by the application-mask product", "excluded_by_profile")
                session.require(original.get(10) == b"\x00", "reserved-bit case needs unlocked configuration")
                try:
                    write(session, writer, codec.tlv(3, (int.from_bytes(original[3], "big") | 1 << bit).to_bytes(2, "big")))
                    session.check("reserved capability bit is never reported enabled", read(session, writer)[3], original[3])
                finally:
                    if not session.broken:
                        restore(session, writer, original, set())


def pages(session):
    for p1 in (0, 1, 2, 255):
        for p2 in (0, 1, 255):
            for body in (b"", b"\x00", b"\x01", b"\xff" * 32):
                with session.case(f"management.READ.page-{p1}.{p2}.body-{body.hex() or 'empty'}", ("M01", "G03", "G04", "G14")):
                    session.require(session.profile == "rsk", "management READ ignores pages and extra body on RS-Key", "excluded_by_profile")
                    original = read(session, "card")
                    reply = session.apdu(codec.apdu(0x1D, p1, p2, body))
                    data = session.card_value(reply)
                    session.check("READ page has complete outer length", data[0], len(data) - 1)
                    session.check("profiled READ parameters preserve DeviceInfo", dict(codec.parse_tlv(data[1:])), original)


def run(session):
    values(session)
    grammar(session)
    pages(session)
