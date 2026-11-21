# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Factory-unset PIN does not make authenticatorConfig an unauthenticated writer."""
from itertools import product

from .fido_fixtures import credential, provision_after_reset
from .config_matrix import public
from .lifecycle import Action, change
from .reset_witness import snapshot, preserved


def run(session):
    with session.case("fido.CONFIG.factory-unset-PIN.authorization-and-preservation", ("F01", "F21", "F23", "G01", "G03", "G10", "G13", "G14"),
            effects=("applet_reset", "pin_change", "config_change", "reboot", "create_fido_credential"), touch=True,
            parameters={"PIN_state": "verified factory-unset", "protocols": [None, 0, 1, 2, 3], "authentication_shapes": ["absent", "empty", "short", "valid-width-zero", "long"]}):
        session.require(session.profile == "rsk", "factory configuration ACL requires RS-Key", "excluded_by_profile")
        neighbors = snapshot(session, "fido")
        change(session, Action.POWER_CYCLE)
        session.ctap_value(session.ctap(7))
        factory = session.ctap_value(session.ctap(4))
        session.check("configuration fixture has no configured PIN", factory.get(4, {}).get("clientPin"), False)
        session.bind("fido.info", factory)
        session.failed_auth.discard("fido.pin")
        session.options.pin = None
        try:
            session.require(not factory.get(4, {}).get("alwaysUv"), "non-UV retained-key control needs a factory profile without mandatory UV", "excluded_by_profile")
            with credential(session, session.current.name, authenticate=False) as fixture:
                for subcommand, protocol, auth in product((1, 2, 3, 255), (None, 0, 1, 2, 3), (None, b"", bytes(15), bytes(16), bytes(32), bytes(33))):
                    request = {1: subcommand}
                    if subcommand == 3:
                        request[2] = {1: factory.get(13, 4), 2: ["factory.oracle.invalid"], 3: True, 4: True}
                    elif subcommand == 255:
                        request[2] = {1: 0}
                    if protocol is not None:
                        request[3] = protocol
                    if auth is not None:
                        request[4] = auth
                    expected = 2 if protocol in (0, 3) else 0x36 if auth is None else 0x14 if protocol is None else 0x33
                    result = session.ctap(13, request)
                    if result.status != expected:
                        session.broken = True
                        session.values["halt_reason"] = "unexpected factory CONFIG result; policy state needs explicit recovery"
                    session.check("unset PIN preserves the CONFIG protocol/authorization ordering", result.status, expected)
                    session.check("unauthenticated factory CONFIG cannot change any public policy", public(session.ctap_value(session.ctap(4))), public(factory))
                    fixture.assertion(session, authenticate=False)
                fixture.assertion(session, authenticate=False)
        finally:
            if not session.broken:
                session.trace.phase = "cleanup"
                provision_after_reset(session, session.ctap_value(session.ctap(4)))
        preserved(session, "fido", neighbors)
