# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Discovery cursors are exercised with several owned credentials under one RP."""
from contextlib import ExitStack

from .fido import auth_data, verified
from .fido_fixtures import credential
from .timers import wait


def run(session):
    for interruption in ("complete", "getInfo", "new-begin", "idle-expiry"):
        with session.case("fido.assertion-walk." + interruption, ("F11", "F12", "F13", "G09", "G11", "G12", "G14"),
                          effects=("create_fido_credential",), touch=True):
            session.require(interruption != "idle-expiry" or session.options.timeout > 31,
                            "increase --timeout for the 30-second assertion cursor idle window")
            rp = session.fixture(session.current.name + ".rp", 8).hex() + ".oracle.invalid"
            with ExitStack() as stack:
                fixtures = [stack.enter_context(credential(session, session.current.name + f".{index}", resident=True, rp=rp)) for index in range(3)]
                by_id = {item.descriptor["id"]: item for item in fixtures}
                query = fixtures[0].query(session, allow=[])
                del query[3]
                session.ctap_value(session.ctap(4))
                session.check("getNextAssertion without initializer refused", session.ctap(8).status, 0x30)
                first = session.ctap_value(session.ctap(2, query))
                session.check("discovery reports all owned credentials", first[5], len(fixtures))
                seen = set()
                def witness(value):
                    identifier = value[1]["id"]
                    session.check("assertion walk returns owned credential", identifier in by_id)
                    session.check("assertion walk has no duplicate credential", identifier not in seen)
                    seen.add(identifier)
                    fixture = by_id[identifier]
                    signed = auth_data(value[2])
                    session.check("continuation retains initiating RP", signed["rp_hash"], fixture.parsed["rp_hash"])
                    verified(session, "continuation retains initiating clientDataHash", fixture.key, fixture.algorithm,
                             value[3], value[2] + fixtures[0].challenge)
                witness(first)
                if interruption == "getInfo":
                    session.ctap_value(session.ctap(4))
                    outcome = session.ctap(8)
                    session.observe("continuation_after_getInfo", (outcome.protocol, outcome.status))
                    if session.profile == "rsk":
                        session.check("getInfo retires assertion walk", outcome.status, 0x30)
                    first = session.ctap_value(session.ctap(2, query))
                    seen.clear()
                    witness(first)
                elif interruption == "new-begin":
                    first = session.ctap_value(session.ctap(2, query))
                    seen.clear()
                    witness(first)
                elif interruption == "idle-expiry":
                    wait(session, 30.25)
                    session.check("idle assertion continuation refused", session.ctap(8).status, 0x30)
                    query = fixtures[0].query(session, allow=[])
                    del query[3]
                    first = session.ctap_value(session.ctap(2, query))
                    seen.clear()
                    witness(first)
                for _ in range(len(fixtures) - 1):
                    witness(session.ctap_value(session.ctap(8)))
                session.check("completed discovery covers every owned key", seen, set(by_id))
                for _ in range(2):
                    session.check("past-end getNextAssertion refused", session.ctap(8).status, 0x30)
                fixtures[0].assertion(session)
