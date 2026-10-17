# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Temporary and permanent PIN blocking require bounded attempts and reset recovery."""
import hashlib

from .fido import info, pin_protocol, pin_token
from .lifecycle import Action, change
from .fido_fixtures import provision_after_reset


def run(session):
    with session.case("fido.PIN.temporary-permanent-block-and-reset", ("F02", "F03", "F04", "F06", "F09", "F23", "G10", "G14"),
                      effects=("pin_attempts", "pin_change", "applet_reset", "reboot"), touch=True):
        session.require(session.profile != "trezor", "blocking and resets excluded on wallet device", "excluded_by_profile")
        session.require(session.options.pin is not None and info(session).get(4, {}).get("clientPin"), "known configured PIN required")
        session.require(session.card is not None and hasattr(session.card, "control") and (session.options.operator or getattr(session.card, "emulated", False)),
                        "PIN blocking requires an explicit power-cycle recovery backend")
        pin_token(session, 4)
        initial = session.ctap_value(session.ctap(6, {1: 2, 2: 1}))[3]
        session.require(1 <= initial <= 16, "PIN retry budget exceeds bounded scenario")
        consumed = False
        try:
            with session.attempts("fido.pin", initial + 1):
                for ordinal in range(initial):
                    protocol = pin_protocol(session, 2)
                    wrong = hashlib.sha256((session.options.pin + "!").encode()).digest()[:16]
                    result = session.ctap(6, {1: 2, 2: 9, 3: protocol.cose, 6: protocol.encrypt(wrong), 9: 4})
                    consumed = True
                    session.check("wrong PIN refusal has PIN cause", result.status in (0x31, 0x32, 0x34))
                    remaining = session.ctap_value(session.ctap(6, {1: 2, 2: 1}))[3]
                    session.check("each failed comparison spends exactly one persistent retry", remaining, initial - ordinal - 1)
                    if remaining == 0:
                        break
                    if result.status == 0x34:
                        session.trace.emit("state_transition", state="fido.PIN", current="temporarily_blocked", evidence=session.evidence(), basis="PIN_AUTH_BLOCKED and explicit remaining-retry query")
                        change(session, Action.POWER_CYCLE)
                        session.check("power cycle does not replenish persistent retries", session.ctap_value(session.ctap(6, {1: 2, 2: 1}))[3], remaining)
                protocol = pin_protocol(session, 2)
                correct = protocol.encrypt(hashlib.sha256(session.options.pin.encode()).digest()[:16])
                blocked = session.ctap(6, {1: 2, 2: 9, 3: protocol.cose, 6: correct, 9: 4})
                session.check("correct PIN cannot bypass permanent block", blocked.status, 0x32)
                session.check("blocked PIN remains at retry floor", session.ctap_value(session.ctap(6, {1: 2, 2: 1}))[3], 0)
        finally:
            if consumed and not session.broken:
                session.trace.phase = "cleanup"
                change(session, Action.POWER_CYCLE)
                session.ctap_value(session.ctap(7))
                current = session.ctap_value(session.ctap(4))
                session.check("reset recovers unset PIN state", current[4]["clientPin"], False)
                provision_after_reset(session, current)
                session.observe("cleanup_limit", "factory FIDO store retained; supplied fixture PIN reprovisioned when available")
