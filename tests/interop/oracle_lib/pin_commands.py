# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""ClientPIN's protocol gate precedes subcommands and unused public-read fields."""
from itertools import product

from .fido import info
from .fido_fixtures import credential
from .info_matrix import stable


def inputs():
    for protocol, sub in product((0, 1, 2, 3, 255, 2**32 - 1, 2**32, -1), (0, 1, 2, 3, 4, 5, 8, 9, 10, 255, 2**32 - 1, 2**32, -1)):
        expected = 0x11 if protocol < 0 else 0x12 if protocol > 0xffffffff else 0x11 if sub < 0 else 0x12 if sub > 0xffffffff else 2 if protocol not in (1, 2) else 0x14 if sub in (0, 3, 4, 5, 9) else 0 if sub in (1, 2) else 0x3e
        yield f"protocol-{protocol}.sub-{sub}", {1: protocol, 2: sub}, expected
    yield "empty-map", {}, 2
    yield "missing-protocol", {2: 2}, 0x14
    yield "missing-subcommand", {1: 2}, 0x14
    for version, sub in product((1, 2), (1, 2)):
        for width in (0, 1, 15, 16, 17, 31, 32, 33, 79, 80, 81):
            yield f"public-read-{sub}.protocol-{version}.ignored-MAC-width-{width}", {1: version, 2: sub, 4: bytes(width)}, 0
        for label, extra in (("unknown", {100: [None, {1: True}]}), ("empty-optional-fields", {3: {}, 4: b"", 5: b"", 6: b"", 9: 0, 10: ""}),
                ("NUL-optional-RP", {10: "a\x00b"}), ("multibyte-optional-RP", {10: "é😀" * 65})):
            yield f"public-read-{sub}.protocol-{version}.{label}", {1: version, 2: sub, **extra}, 0


def run(session):
    for label, fields, expected in inputs():
        with session.case("fido.ClientPIN.dispatch." + label, ("F02", "F03", "F04", "F05", "F06", "G01", "G03", "G04", "G08", "G13", "G14"),
                effects=("create_fido_credential",), touch=True, parameters={"protocol": fields.get(1), "subcommand": fields.get(2), "variant": label}):
            session.require(session.profile == "rsk", "ClientPIN dispatch/ignored-field contracts require RS-Key", "excluded_by_profile")
            session.require(session.options.pin and info(session).get(4, {}).get("clientPin"), "known host PIN required before private controls")
            with credential(session, session.current.name) as retained:
                before = session.ctap_value(session.ctap(4))
                retries = session.ctap_value(session.ctap(6, {1: 2, 2: 1}))
                agreement = session.ctap_value(session.ctap(6, {1: 2, 2: 2}))
                result = session.ctap(6, fields)
                session.check("protocol/type/width/subcommand dispatch has the exact isolated outcome", result.status, expected)
                if not expected:
                    session.check("public request ignores unused fields without changing its actual result", session.ctap_value(result), retries if fields[2] == 1 else agreement)
                session.check("dispatch controls do not spend a PIN comparison or retry", session.ctap_value(session.ctap(6, {1: 2, 2: 1})), retries)
                session.check("dispatch controls preserve the original ECDH key", session.ctap_value(session.ctap(6, {1: 2, 2: 2})), agreement)
                session.check("dispatch controls preserve public policy and stored identity", stable(session.ctap_value(session.ctap(4))), stable(before))
                retained.assertion(session)
