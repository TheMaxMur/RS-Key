# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Tokens belong to the device; populated walks belong to their initiating channel."""
import hashlib
from contextlib import ExitStack
from itertools import product

from . import codec
from .binding import require_pair
from .fido import auth_data, cm, pin_token, verified
from .fido_fixtures import credential
from .runner import CtapRoute


def run(session):
    for owner, kind, version, persistent, selection in product(CtapRoute, ("RP", "credential", "assertion"), (1, 2), (False, True), ("none", "same", "different", "invalid")):
        foreign = CtapRoute.CARD if owner == CtapRoute.HID else CtapRoute.HID
        with session.case(f"cross.populated-walk.{kind}.protocol-{version}.readonly-{persistent}.{owner.value}-to-{foreign.value}.SELECT-{selection}",
                ("X02", "X03", "X12", "F09", "F10", "F13", "F14", "F15", "F16", "G09", "G10", "G11", "G14"),
                effects=("create_fido_credential",), touch=True):
            session.require(session.profile == "rsk", "shared token and separate walk ownership require RS-Key", "excluded_by_profile")
            require_pair(session)
            session.select("fido")
            rp = session.fixture(session.current.name + ".rp", 8).hex() + ".oracle.invalid"
            with ExitStack() as stack:
                fixtures = [stack.enter_context(credential(session, session.current.name + f".{i}", True, rp=rp if i < 2 else "other." + rp)) for i in range(3)]
                by_id = {fixture.descriptor["id"]: fixture for fixture in fixtures}
                with session.route(owner):
                    proto, token = pin_token(session, 64 if persistent else 4, version=version)
                    metadata = session.ctap_value(cm(session, proto, token, 1))
                with session.route(foreign):
                    session.check("ordinary transport changes do not revoke the device-wide token", session.ctap_value(cm(session, proto, token, 1)), metadata)
                begin, following, count = (2, 3, 5) if kind == "RP" else (4, 5, 9)
                params = {1: hashlib.sha256(rp.encode()).digest()} if kind == "credential" else None
                query = fixtures[0].query(session, authenticate=False, options={"up": False, "uv": False})
                del query[3]
                def next_leg():
                    return session.ctap(8) if kind == "assertion" else cm(session, proto, token, following)
                with session.route(owner):
                    first = session.ctap_value(session.ctap(2, query)) if kind == "assertion" else session.ctap_value(cm(session, proto, token, begin, params))
                total, seen = first.get(5 if kind == "assertion" else count, 1), set()
                session.check("cross walk starts from at least two populated rows", 2 <= total <= 4096)
                def witness(value):
                    if kind == "RP":
                        identifier = value[4]
                        session.check("cross RP row binds its exact hash", identifier, hashlib.sha256(value[3]["id"].encode()).digest())
                    else:
                        identifier = value[1 if kind == "assertion" else 7]["id"]
                        session.check("cross credential row names an owned private key", identifier in by_id)
                        if kind == "assertion":
                            fixture = by_id[identifier]
                            session.check("cross assertion continuation retains its initiating RP", auth_data(value[2])["rp_hash"], fixture.parsed["rp_hash"])
                            verified(session, "cross assertion continuation retains its initiating clientDataHash", fixture.key, fixture.algorithm, value[3], value[2] + fixtures[0].challenge)
                    session.check("cross walk never repeats an emitted row", identifier not in seen)
                    seen.add(identifier)
                witness(first)
                if selection == "different":
                    session.select("piv")
                elif selection == "invalid":
                    session.check("unrecognized card AID cannot select a different applet", session.apdu(codec.apdu(0xa4, 4, data=b"\xf0\xff\xff\xff\xff")).status, 0x6a82)
                if selection != "none":
                    session.select("fido")
                with session.route(foreign):
                    session.check("other transport cannot inherit a populated continuation", next_leg().status, 0x30)
                with session.route(owner):
                    for _ in range(total - 1):
                        witness(session.ctap_value(next_leg()))
                    session.check("foreign continuation refusal preserves the complete owner's walk", len(seen), total)
                    session.check("completed owner walk cannot replay its last row", next_leg().status, 0x30)
                for route in (owner, foreign):
                    with session.route(route):
                        session.check("walk ownership refusals cannot revoke the shared grant", session.ctap_value(cm(session, proto, token, 1)), metadata)
                for fixture in fixtures:
                    fixture.assertion(session)
