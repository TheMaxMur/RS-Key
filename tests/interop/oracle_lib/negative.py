# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Bounded single-defect inputs and recovery controls for known protocols."""
import copy
from dataclasses import dataclass

from . import codec


@dataclass(frozen=True)
class CtapInput:
    name: str
    command: int
    raw: bytes
    families: tuple


def ctap_inputs():
    make = {1: bytes(32), 2: {"id": "negative.oracle.invalid"},
            3: {"id": b"oracle"}, 4: [{"type": "public-key", "alg": -7}]}
    assertion = {1: "negative.oracle.invalid", 2: bytes(32)}
    for command, label, base, family in ((1, "make", make, "F11"), (2, "assert", assertion, "F12")):
        for key in base:
            request = copy.deepcopy(base)
            del request[key]
            yield CtapInput(f"{label}.missing.{key}", command, codec.encode(request), ("G01", family))
            for kind, value in (("null", None), ("array", []), ("bool", False), ("integer", 0)):
                request = copy.deepcopy(base)
                request[key] = value
                yield CtapInput(f"{label}.type.{key}.{kind}", command, codec.encode(request), ("G02", family))
        hash_key = 1 if command == 1 else 2
        for length in (0, 1, 31, 33, 63, 64):
            request = copy.deepcopy(base)
            request[hash_key] = bytes(length)
            yield CtapInput(f"{label}.client-hash.{length}", command, codec.encode(request), ("G03", family))
        for field, member in (((2, "id"), (3, "id")) if command == 1 else ()):
            request = copy.deepcopy(base)
            del request[field][member]
            yield CtapInput(f"{label}.missing.{field}.{member}", command, codec.encode(request), ("G01", family))
        options_key = 7 if command == 1 else 5
        for option in (("rk", "uv") if command == 1 else ("up", "uv")):
            for kind, value in (("null", None), ("integer", 1), ("string", "true"), ("array", [])):
                request = copy.deepcopy(base)
                request[options_key] = {option: value}
                yield CtapInput(f"{label}.option.{option}.{kind}", command, codec.encode(request), ("G02", family))
        for label2, raw in (("truncated", codec.encode(base)[:-1]), ("break", b"\xff"),
                            ("text", codec.encode("map required")), ("null", b"\xf6")):
            yield CtapInput(f"{label}.{label2}", command, raw, ("G02", "G05", "G06", family))
        # The combined case is retained alongside both constituent defects.
        request = copy.deepcopy(base)
        del request[hash_key]
        request[options_key] = {"uv": "true"}
        yield CtapInput(f"{label}.missing-hash-and-invalid-uv", command, codec.encode(request), ("G13", family))
    for protocol in (0, 3, 255, -1):
        yield CtapInput(f"pin.protocol.{protocol}", 6, codec.encode({1: protocol, 2: 2}), ("G04", "F03"))
    for command, key, base, family in ((6, 2, {1: 1}, "F03"), (10, 1, {}, "F14"),
                                        (13, 1, {}, "F21")):
        for value in (0, 255, -1, None, [], "unknown"):
            request = {**base, key: value}
            yield CtapInput(f"command-{command}.subcommand.{codec.encode(value).hex()}", command,
                            codec.encode(request), ("G02", "G04", family))
    for label, request in (("negative-offset", {1: 1, 3: -1}), ("missing-offset", {1: 1}),
                           ("wrong-offset-type", {1: 1, 3: "0"}), ("negative-length", {1: -1, 3: 0}),
                           ("both-get-set", {1: 1, 2: b"x", 3: 0}), ("no-operation", {3: 0})):
        yield CtapInput("large-blobs." + label, 12, codec.encode(request), ("G01", "G02", "G04", "F19", "F20"))


def fido(session):
    for case in ctap_inputs():
        with session.case("negative.ctap." + case.name, (*case.families, "G14"),
                          effects=("malformed_known_command",)):
            session.observe("input_contract", "structural rejection; precedence is measured separately")
            previous_versions = session.values.get("fido.info", {}).get(1)
            rejected = session.ctap(case.command, raw=case.raw)
            session.observe("rejection.status", rejected.status)
            session.check("structurally invalid CTAP input refused", rejected.protocol in ("applet_error", "transport_error"))
            trigger = session.evidence()
            control = session.ctap_value(session.ctap(4))
            session.check("recovery versions array", isinstance(control.get(1), list) and len(control[1]) > 0)
            if previous_versions is not None:
                session.check("recovery versions", control.get(1), previous_versions)
            session.transition("ctap.request", "ready", "ready_after_rejection", trigger, [trigger, session.evidence()])
    for name, raw in (("unknown-key", codec.encode({99: True})), ("non-shortest-key", bytes.fromhex("a118006100")),
                      ("duplicate-key", bytes.fromhex("a21818610018186101")), ("indefinite", b"\xbf\xff"),
                      ("trailing-item", b"\xa0\x00")):
        with session.case("encoding.getinfo." + name, ("G06", "F01", "G14")):
            reply = session.ctap(4, raw=raw)
            session.observe("status", reply.status)
            if reply.protocol == "success":
                session.check("accepted response is getInfo", isinstance(session.ctap_value(reply).get(1), list))
            session.check("control getInfo", isinstance(session.ctap_value(session.ctap(4)).get(1), list))


def apdu_inputs(applet):
    for length in range(4):
        yield f"header.{length}", bytes([0, 0xCA, 0, 0][:length]), ("T11", "G03", "G05")
    for name, request in (("lc-short", bytes.fromhex("00ca00000200")),
                          ("lc-extended", bytes.fromhex("00ca000000000200")),
                          ("extended-prefix", bytes.fromhex("00ca00000001"))):
        yield name, request, ("T11", "G05")
    invalid = {
        "oath": ((0xA1, 1, 0, b""), (0xA2, 1, 0, b""), (0xA4, 0, 2, b""),
                 (4, 0xDE, 0, b""), (5, 1, 0, b"")),
        "piv": ((0xCB, 0, 0, b""), (0x87, 0, 0, b"\x7c\x01"),
                (0x47, 0, 0, b"\xac\x01"), (0xF7, 0, 0xFF, b"")),
        "openpgp": ((0x20, 1, 0xFF, b""), (0xCA, 0xFF, 0xFF, b""),
                    (0x47, 0x81, 0, b"\xff\x00"), (0x22, 0xFF, 0xFF, b"")),
    }
    for ins, p1, p2, data in invalid[applet]:
        yield f"parameters.{ins:02x}.{p1:02x}.{p2:02x}", codec.apdu(ins, p1, p2, data), ("G04", "G05")


def cards(session):
    families = {"oath": "A01", "piv": "P01", "openpgp": "O01"}
    for applet, family in families.items():
        for name, request, axes in apdu_inputs(applet):
            with session.case(f"negative.{applet}.{name}", (*axes, family, "G14"),
                              effects=("malformed_known_command",)):
                session.select(applet)
                reply = session.apdu(request)
                session.observe("rejection.status", reply.status)
                session.check("invalid APDU refused", reply.protocol == "applet_error")
                trigger = session.evidence()
                session.select(applet)
                session.transition("card.request", "selected:" + applet, "usable:" + applet,
                                   trigger, [trigger, session.evidence()])


def run(session):
    fido(session)
    cards(session)
