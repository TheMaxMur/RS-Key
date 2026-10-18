# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OATH moving factors, increasing marks and continuation invalidation."""
from contextlib import contextmanager

from . import codec
from .lifecycle import Action, change
from .oath_states import calculate
from .otp import OATH_HASHES, oath_names, oath_open, oath_request, otp_value


@contextmanager
def records(session, specs, empty=False):
    oath_open(session)
    before = oath_names(session)
    session.require(not empty or not before, "bulk state tests require an empty OATH fixture store")
    session.require(not before.intersection(name for name, _ in specs), "fixture name collision")
    created = []
    try:
        for name, fields in specs:
            oath_request(session, 1, codec.tlv(0x71, name) + fields)
            created.append(name)
        yield
    finally:
        if not session.broken:
            session.trace.phase = "cleanup"
            oath_open(session)
            for name in created:
                oath_request(session, 2, codec.tlv(0x71, name))
            session.check("OATH original names restored", oath_names(session), before)


def hotp(session, reconnect=False):
    for initial in (0, 1, 0xFFFFFFFE, 0xFFFFFFFF):
        with session.case(f"oath.HOTP.initial-{initial}.reconnect-{reconnect}", ("A02", "A04", "A05", "A07", "G03", "G14", "X11"),
                          effects=("create_oath_record", "reboot") if reconnect else ("create_oath_record",)):
            name, secret = b"oracle-counter", OATH_HASHES[0][2]
            body = codec.tlv(0x73, b"\x11\x06" + secret) + codec.tlv(0x7A, initial.to_bytes(4, "big"))
            with records(session, [(name, body)], empty=True):
                session.check("HOTP honors initial moving factor", calculate(session, name, bytes(8)), otp_value(secret, initial.to_bytes(8, "big"), "sha1", 6))
                invalid = codec.tlv(0x71, name) + codec.tlv(0x74, bytes(65))
                session.check("oversize challenge refused before HOTP advance", session.apdu(codec.apdu(0xA2, p2=1, data=invalid)).status, 0x6A80)
                entries = codec.parse_tlv(oath_request(session, 0xA4, codec.tlv(0x74, bytes(8)), p2=1))
                session.check("bulk read reports HOTP without calculating", entries, [(0x71, name), (0x77, b"\x06")])
                if reconnect:
                    change(session, Action.POWER_CYCLE)
                oath_open(session)
                session.check("HOTP counter survives refusal, bulk read and reselect", calculate(session, name, b"ignored"), otp_value(secret, (initial + 1).to_bytes(8, "big"), "sha1", 6))
                session.check("HOTP repeated identical host request advances exactly once", calculate(session, name, b"ignored"), otp_value(secret, (initial + 2).to_bytes(8, "big"), "sha1", 6))
                session.observe("counter_bound", "wire IMF is 32 bits; cases cross 2^32, not unreachable 2^64 wrap")


def increasing(session, reconnect=False):
    with session.case(f"oath.increasing.equal-bulk-reselect.reconnect-{reconnect}", ("A06", "A07", "G11", "G14", "X11"),
                      effects=("create_oath_record", "reboot") if reconnect else ("create_oath_record",)):
        name, plain, secret = b"oracle-increasing", b"oracle-plain", OATH_HASHES[0][2]
        key = codec.tlv(0x73, b"\x21\x06" + secret)
        with records(session, [(name, key + b"\x78\x01"), (plain, key)], empty=True):
            session.check("first increasing challenge", calculate(session, name, (1).to_bytes(8, "big")), otp_value(secret, (1).to_bytes(8, "big"), "sha1", 6))
            for counter in (0, 1):
                reply = session.apdu(codec.apdu(0xA2, p2=1, data=codec.tlv(0x71, name) + codec.tlv(0x74, counter.to_bytes(8, "big"))))
                session.check("equal and lower increasing challenges refused", reply.status, 0x6A80)
            entries = codec.parse_tlv(oath_request(session, 0xA4, codec.tlv(0x74, (2).to_bytes(8, "big")), p2=1))
            session.check("bulk includes both TOTP fixtures", {value for tag, value in entries if tag == 0x71}, {name, plain})
            if reconnect:
                change(session, Action.POWER_CYCLE)
            oath_open(session)
            reply = session.apdu(codec.apdu(0xA2, p2=1, data=codec.tlv(0x71, name) + codec.tlv(0x74, (2).to_bytes(8, "big"))))
            session.check("bulk increasing mark persists after reselect", reply.status, 0x6A80)
            for counter in (0, 0, 1, 1):
                session.check("plain TOTP is independent of increasing mark", calculate(session, plain, counter.to_bytes(8, "big")), otp_value(secret, counter.to_bytes(8, "big"), "sha1", 6))
            session.check("increasing record remains usable above mark", calculate(session, name, (3).to_bytes(8, "big")), otp_value(secret, (3).to_bytes(8, "big"), "sha1", 6))


def paging(session):
    for command in (0xA1, 0xA4):
        for interruption in ("complete", "valid-command", "rejected-command", "same-SELECT", "other-SELECT"):
            with session.case(f"oath.paging.{command:02x}.{interruption}", ("A03", "A07", "A08", "T13", "G11", "G14", "X02"), effects=("create_oath_record",)):
                key = codec.tlv(0x73, b"\x21\x06" + OATH_HASHES[0][2])
                specs = [(f"oracle-page-{index}-".encode().ljust(64, b"x"), key) for index in range(10)]
                with records(session, specs, empty=True):
                    data = codec.tlv(0x74, bytes(8)) if command == 0xA4 else b""
                    complete = oath_request(session, command, data, p2=1 if command == 0xA4 else 0)
                    first = session.apdu(codec.apdu(command, p2=1 if command == 0xA4 else 0, data=data, le=17), "oath.begin-page")
                    if first.status == 0x9000 and session.profile != "rsk":
                        session.check("unpaged profile returns complete result", first.data[:-2], complete)
                        session.require(False, "profile does not expose OATH pages for this response size", "unsupported_confirmed")
                    session.check("initial OATH response exposes required page", first.status >> 8, 0x61)
                    if interruption == "complete":
                        body = bytearray(first.data[:-2])
                        for _ in range(256):
                            if first.status >> 8 != 0x61:
                                break
                            first = session.apdu(codec.apdu(0xA5, le=17), "oath.continue-page")
                            session.check("OATH continuation progress", len(first.data) > 2 or first.status >> 8 != 0x61)
                            body.extend(first.data[:-2])
                        session.card_value(first)
                        session.check("OATH every page reconstructs exact bulk result", bytes(body), complete)
                    elif interruption == "valid-command":
                        calculate(session, specs[0][0], bytes(8))
                    elif interruption == "rejected-command":
                        session.check("intervening malformed CALCULATE refused", session.apdu(codec.apdu(0xA2, p2=1)).protocol, "applet_error")
                    else:
                        if interruption == "other-SELECT":
                            session.select("piv")
                        oath_open(session)
                    for _ in range(2):
                        session.check("retired OATH page cannot be continued", session.apdu(codec.apdu(0xA5)).status, 0x6D00)
                    session.check("OATH paging preserves all records", oath_names(session), {name for name, _ in specs})


def run(session):
    hotp(session)
    increasing(session)
    paging(session)


def reconnect(session):
    hotp(session, True)
    increasing(session, True)
