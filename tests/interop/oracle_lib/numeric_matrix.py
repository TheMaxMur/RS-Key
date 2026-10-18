# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Every parsed integer gets signedness and representable-width controls."""
from . import codec
from .field_matrix import commands, replace, halt
from .fido import info
from .fido_fixtures import credential

def integers(command, fields):
    if command == 1:
        yield (9,), 32, False
        yield (10,), 32, False
        for index in range(len(fields[4])):
            yield (4, index, "alg"), 64, True
    elif command == 2:
        yield (7,), 32, False
    elif command == 6:
        for key in (1, 2, 9):
            yield (key,), 32, False
    elif command == 10:
        for key in (1, 3):
            yield (key,), 32, False
    elif command == 12:
        for key in (1, 3, 4, 6):
            if key in fields:
                yield (key,), 64, False
    elif command == 13:
        for key in (1, 3):
            yield (key,), 32, False
        if fields[1] == 3:
            yield (2, 1), 32, False
        elif fields[1] == 255:
            yield (2, 1), 64, False
            yield (2, 3), 64, False
    elif command == 0x41:
        for key in (1, 3):
            yield (key,), 32, False
        if fields[1] in (12, 13, 14):
            yield (2, 1), 32, False


def variants(command, fields):
    for path, width, signed in integers(command, fields):
        if signed:
            values = (("positive-overflow", 1 << (width - 1), 0x12), ("negative-overflow", -(1 << (width - 1)) - 1, 0x12))
        else:
            values = (("negative", -1, 0x11), ("negative-minimum", -(1 << 63), 0x11))
            if width < 64:
                values += (("overflow-one", 1 << width, 0x12), ("overflow-max", (1 << 64) - 1, 0x12))
        for label, value, status in values:
            yield ".".join(map(str, path)) + "." + label, replace(fields, path, value), status


def run(session):
    for name, command, fields, family, required in commands():
        for label, request, expected in variants(command, fields):
            with session.case("numeric." + name + "." + label, ("G02", "G04", "G13", "G14", family),
                    effects=("malformed_known_command", "create_fido_credential"), touch=True,
                    parameters={"command": command, "parsed_integer": label, "scope": "wire representability; semantic zero/reserved/profile limits have command-specific suites"}):
                session.require(session.profile == "rsk", "integer widths follow the RS-Key typed readers", "excluded_by_profile")
                session.require(all(info(session).get(4, {}).get(option) for option in required), "optional command not advertised", "unknown")
                with credential(session, session.current.name) as retained:
                    retries = session.ctap_value(session.ctap(6, {1: 2, 2: 1}))
                    before = session.ctap_value(session.ctap(4))
                    response = session.ctap(command, request)
                    if (response.protocol, response.status) != ("applet_error", expected):
                        halt(session, "integer parser unexpectedly reached a semantic operation; explicit recovery required")
                    session.check("integer signedness and width reject before semantic authorization", (response.protocol, response.status), ("applet_error", expected))
                    session.check("integer refusal cannot spend PIN retries", session.ctap_value(session.ctap(6, {1: 2, 2: 1})), retries)
                    after = session.ctap_value(session.ctap(4))
                    session.check("integer refusal preserves public policy", {k: v for k, v in after.items() if k not in (25, 30)}, {k: v for k, v in before.items() if k not in (25, 30)})
                    retained.assertion(session)
