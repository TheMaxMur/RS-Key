# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Provision batch identity around real applet resets, then prove its private key."""
from . import fido_lifecycle, oath_states, openpgp_lifecycle, piv_lifecycle
from .binding import require_pair
from .fido import info
from .identity_chain import identity_control
from .vendor_cases import handshake, vendor
from .vendor_lifecycle import identity_fixture, wrap


def reset_evidence(exchanges, target):
    for exchange in exchanges:
        if exchange["protocol_outcome"] != "success":
            continue
        data = bytes.fromhex(exchange["request"]["hex"])
        if target == "fido" and data == b"\x07":
            return exchange["exchange_id"]
        if len(data) >= 4 and data[1] == {"piv": 0xfb, "openpgp": 0x44, "oath": 4}.get(target) and (target != "oath" or data[2:4] == b"\xde\xad"):
            return exchange["exchange_id"]
    return None


def run(session):
    for target, reset in (("piv", piv_lifecycle.reset), ("openpgp", openpgp_lifecycle.lifecycle),
                          ("oath", oath_states.reset), ("fido", fido_lifecycle.reset)):
        installed = False
        with session.case("rsk.identity.reset." + target + ".prepare", ("V06", "X06", "X11"), effects=("replace_identity",), touch=True):
            session.require(session.profile == "rsk", "organization reset persistence requires RS-Key", "excluded_by_profile")
            session.require(session.hid is not None and session.card is not None and session.options.pin,
                "reset witness requires paired interfaces and the known host PIN")
            require_pair(session)
            session.require(not info(session).get(4, {}).get("alwaysUv"), "U2F private identity witness requires ordinary policy")
            session.require(not session.ctap_value(vendor(session, 11))[1], "pre-existing organization identity cannot be restored")
            private, chain = identity_fixture(session)
            session.ctap_value(vendor(session, 9, {1: wrap(session, private.private_numbers().private_value.to_bytes(32, "big")), 2: chain}, authenticated=True))
            installed = True
            identity_control(session, private, chain)
        if not installed and not session.planning:
            continue
        start = len(session.trace.exchanges)
        try:
            with session.namespace("rsk.identity.reset." + target + "."):
                reset(session)
        finally:
            evidence = reset_evidence(session.trace.exchanges[start:], target)
            with session.case("rsk.identity.reset." + target + ".private-witness", ("V06", "X06", "X11", "G14"), effects=("replace_identity",), touch=True):
                try:
                    session.require(evidence is not None, "no completed target reset was observed; persistence cannot be claimed")
                    session.observe("actual_reset_exchange", evidence)
                    identity_control(session, private, chain)
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        handshake(session)
                        session.ctap_value(vendor(session, 10, authenticated=True))
                        session.check("owned reset identity removed after its private witness", session.ctap_value(vendor(session, 11))[1], False)
