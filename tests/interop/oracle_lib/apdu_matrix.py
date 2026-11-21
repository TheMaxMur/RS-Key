# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Explicit ISO7816 encodings and pending-response lifetimes on recorded APDUs."""
from . import codec
from .openpgp_lifecycle import fixture_session


def encoded(ins, p1=0, p2=0, data=b"", le=None, extended=False):
    head = bytes((0, ins, p1, p2))
    if data:
        body = head + (b"\x00" + len(data).to_bytes(2, "big") if extended else bytes((len(data),))) + data
        return body + ((le % 65536).to_bytes(2, "big") if extended else bytes((le % 256,))) if le is not None else body
    return head + (b"\x00" + (le % 65536).to_bytes(2, "big") if extended else bytes((le % 256,))) if le is not None else head


def collect(session, response, le=256):
    body = bytearray(response.data[:-2])
    for _ in range(4096):
        if response.status >> 8 != 0x61:
            session.card_value(response)
            return bytes(body)
        response = session.apdu(codec.apdu(0xC0, le=le), "apdu.GET-RESPONSE")
        session.check("continuation makes progress", len(response.data) > 2 or response.status >> 8 != 0x61)
        body.extend(response.data[:-2])
    raise ValueError("response continuation exceeds bounded object size")


def cases(session):
    for extended in (False, True):
        for le in (None, 1, 2, 255, 256):
            if extended and le is None:
                continue
            with session.case(f"transport.APDU.case-{1 if le is None else 2}.extended-{extended}.Le-{le}", ("T11", "G03", "G14")):
                session.select("piv")
                before = collect(session, session.apdu(codec.apdu(0xFD)))
                result = session.apdu(encoded(0xFD, le=le, extended=extended), "piv.VERSION.encoding")
                session.check("APDU case 1/2 returns same version", collect(session, result), before)
    for extended in (False, True):
        for le in (None, 1, 256):
            for size in (1, 127, 128, 254, 255, 256, 2048):
                if not extended and size > 255:
                    continue
                with session.case(f"transport.APDU.case-{3 if le is None else 4}.extended-{extended}.Le-{le}.Lc-{size}", ("T11", "O07", "G03", "G14"),
                                  effects=("write_and_restore_openpgp_DO",)):
                    sdk = fixture_session(session)
                    original = sdk.get_data(0x5E)
                    value = session.fixture("APDU.encoding", size)
                    try:
                        session.card_value(session.apdu(encoded(0xDA, 0, 0x5E, value, le, extended), "openpgp.PUT.encoding"))
                        session.check("APDU case 3/4 writes full declared body", sdk.get_data(0x5E), value)
                    finally:
                        if not session.broken:
                            session.trace.phase = "cleanup"
                            sdk.put_data(0x5E, original)
                            session.check("encoding fixture original restored", sdk.get_data(0x5E), original)


def challenge(session):
    for extended in (False, True):
        for length in (1, 7, 8, 255, 256, 257, 3059, 3060, 3061, 65535, 65536):
            if not extended and length > 256:
                continue
            with session.case(f"openpgp.GET-CHALLENGE.extended-{extended}.Le-{length}", ("O17", "T11", "G03", "G14")):
                session.require(session.profile == "rsk", "challenge ceiling requires confirmed RS-Key profile", "unknown")
                session.select("openpgp")
                result = session.apdu(encoded(0x84, le=length, extended=extended), "openpgp.CHALLENGE.encoding")
                if length <= 3060:
                    value = collect(session, result)
                    session.check("challenge exact requested length", len(value), length)
                    if length >= 16:
                        second = collect(session, session.apdu(encoded(0x84, le=length, extended=extended)))
                        session.check("repeated random challenge differs", value != second)
                else:
                    session.check("unsupported challenge length refused", result.status, 0x6700)
                session.check("challenge usable after boundary probe", len(collect(session, session.apdu(codec.apdu(0x84, le=8)))), 8)


def response_chaining(session):
    for interruption in ("complete", "valid-command", "rejected-command", "same-SELECT", "other-SELECT"):
        for le in (1, 2, 255, 256):
            with session.case(f"transport.APDU.response-chain.{interruption}.Le-{le}", ("T13", "O07", "G11", "G12", "G14"),
                              effects=("write_and_restore_openpgp_DO",)):
                sdk = fixture_session(session)
                original = sdk.get_data(0x5E)
                value = session.fixture("APDU.response-chain", 600)
                try:
                    sdk.put_data(0x5E, value)
                    session.check("GET RESPONSE without pending data refused", session.apdu(codec.apdu(0xC0, le=le)).protocol, "applet_error")
                    first = session.apdu(codec.apdu(0xCA, 0, 0x5E, le=1), "openpgp.GET.start-response")
                    if first.status == 0x9000 and session.card.layer == "pcsc_apdu":
                        session.check("transparent backend returns entire response", first.data[:-2], value)
                        session.require(False, "PC/SC backend did not expose response chaining at Le=1", "excluded_by_mode")
                    session.check("initial GET exposes response continuation", first.status >> 8, 0x61)
                    session.check("response chain first byte", first.data[:-2], value[:1])
                    session.check("61xx is a continuation, never an applet rejection", first.protocol, "response_continuation")
                    if interruption == "complete":
                        session.check("GET RESPONSE concatenation is exact", collect(session, first, le), value)
                    else:
                        if interruption == "valid-command":
                            collect(session, session.apdu(codec.apdu(0x84, le=8)))
                        elif interruption == "rejected-command":
                            session.check("intervening unknown DO refused", session.apdu(codec.apdu(0xCA, 0xFF, 0xFF)).protocol, "applet_error")
                        else:
                            session.select("openpgp" if interruption == "same-SELECT" else "piv")
                        session.check("intervening command retires response tail", session.apdu(codec.apdu(0xC0, le=le)).protocol, "applet_error")
                        session.select("openpgp")
                    for _ in range(2):
                        session.check("final GET RESPONSE cannot be replayed", session.apdu(codec.apdu(0xC0, le=le)).protocol, "applet_error")
                    session.check("response interruptions preserve stored object", sdk.get_data(0x5E), value)
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        sdk = fixture_session(session)
                        sdk.put_data(0x5E, original)
                        session.check("response-chain object restored", sdk.get_data(0x5E), original)


def run(session):
    cases(session)
    challenge(session)
    response_chaining(session)
