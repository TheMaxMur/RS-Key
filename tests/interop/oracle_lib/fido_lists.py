# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Position, capacity and ID boundaries use one otherwise valid credential."""
from . import codec
from .fido import authorize, info
from .fido_fixtures import credential


def lists(session):
    for operation in ("allow", "exclude"):
        for position in ("first", "middle", "last"):
            for boundary in ("one", "maximum-minus-one", "maximum", "maximum-plus-one"):
                with session.case(f"fido.{operation}List.{position}.{boundary}", ("F11", "F12", "G03", "G09", "G14"), effects=("create_fido_credential",), touch=True):
                    maximum = info(session).get(7, 1)
                    session.require(1 <= maximum <= 1024, "advertised credential-list limit exceeds bounded generator")
                    size = {"one": 1, "maximum-minus-one": max(1, maximum - 1), "maximum": maximum, "maximum-plus-one": maximum + 1}[boundary]
                    with credential(session, session.current.name) as fixture:
                        descriptors = [{"type": "public-key", "id": session.fixture(f"foreign.{index}", 32)} for index in range(size)]
                        index = 0 if position == "first" else size // 2 if position == "middle" else size - 1
                        descriptors[index] = fixture.descriptor
                        if operation == "allow":
                            result = session.ctap(2, fixture.query(session, allow=descriptors))
                            if size <= maximum:
                                session.ctap_value(result)
                            else:
                                session.check("allowList over advertised limit refused", result.protocol, "applet_error")
                        else:
                            request = {1: fixture.challenge, 2: {"id": fixture.rp}, 3: {"id": b"different-user"},
                                       4: [{"alg": -7, "type": "public-key"}], 5: descriptors}
                            authorize(session, request, 1, fixture.rp, fixture.challenge, 8, 9)
                            result = session.ctap(1, request)
                            session.check("matching excludeList refuses registration", result.status, 0x19 if size <= maximum else 0x15)
                        fixture.assertion(session)


def identifiers(session):
    for boundary in (0, 1, 31, 32, 33, 747, 748, 749):
        with session.case(f"fido.credential-ID.length-{boundary}", ("F12", "G03", "G09", "G14"), effects=("create_fido_credential",), touch=True):
            with credential(session, session.current.name) as fixture:
                foreign = {"type": "public-key", "id": session.fixture("foreign.id", boundary)}
                result = session.ctap(2, fixture.query(session, allow=[foreign], options={"up": False}))
                session.check("foreign credential ID cannot authenticate", result.protocol, "applet_error")
                session.observe("foreign_ID_length_status", result.status)
                fixture.assertion(session)


def options(session):
    values = (("omitted", None), ("false", False), ("true", True), ("invalid", 1))
    for field in ("rk", "up", "uv"):
        for label, value in values:
            with session.case(f"fido.getAssertion.option-{field}.{label}", ("F12", "G01", "G02", "G14"), effects=("create_fido_credential",), touch=True):
                with credential(session, session.current.name) as fixture:
                    settings = {"up": True}
                    if value is not None:
                        settings[field] = value
                    result = session.ctap(2, fixture.query(session, options=settings))
                    session.observe("option_result", result.status)
                    if label == "invalid" and field in ("up", "uv"):
                        session.check("known option invalid type refused", result.protocol, "applet_error")
                    fixture.assertion(session)


def run(session):
    lists(session)
    identifiers(session)
    options(session)
