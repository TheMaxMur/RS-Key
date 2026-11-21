# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Local UV soft/hard blocks share the host PIN counter and explicit reset recovery."""
import hashlib

from .fido import info, pin_protocol
from .fido_fixtures import credential, provision_after_reset
from .lifecycle import Action, change
from .reset_witness import snapshot, preserved
from .uv_matrix import ready, cue, issue


def retries(session, version):
    info(session)
    uv = session.ctap_value(session.ctap(6, {1: version, 2: 7}))
    host = session.ctap_value(session.ctap(6, {1: version, 2: 1}))
    session.check("local and host counters are the same persistent budget", uv[5], host[3])
    return uv


def run(session):
    for version in (1, 2):
        with session.case(f"fido.local-UV.soft-hard-block.protocol-{version}", ("F02", "F07", "F08", "F09", "F23", "X06", "G14"),
                effects=("pin_attempts", "pin_change", "applet_reset", "reboot", "create_fido_credential"), touch=True):
            ready(session)
            session.require(not info(session).get(4, {}).get("alwaysUv"), "retained-key control during blocking requires non-UV assertions")
            session.require(session.card is not None and hasattr(session.card, "control"), "local blocking requires power-cycle and factory-reset recovery")
            neighbors, consumed = snapshot(session, "fido"), False
            with credential(session, session.current.name) as fixture:
                initial = retries(session, version)[5]
                session.require(1 <= initial <= 16, "local UV retry budget is outside the explicit scenario bound")
                try:
                    with session.attempts("fido.pin", initial + 8):
                        for ordinal in range(initial):
                            cue(session, "submit exactly one WRONG PIN; do not retry inside the panel")
                            consumed = True
                            result, token = issue(session, version, 2, fixture.rp)
                            current = retries(session, version)
                            remaining = initial - ordinal - 1
                            session.check("one local mismatch spends one persistent retry", current[5], remaining)
                            session.check("local mismatch reports UV_INVALID or UV_BLOCKED", result.status in (0x3f, 0x3c))
                            session.check("failed local verification returns no grant", token, None)
                            if current.get(4) or remaining == 0:
                                cue(session, "enter the CORRECT PIN only if an entry screen unexpectedly opens")
                                blocked, _ = issue(session, version, 2, fixture.rp)
                                session.check("correct local PIN cannot bypass a block", blocked.status, 0x3c)
                                session.check("blocked entry does not spend another retry", retries(session, version)[5], remaining)
                                change(session, Action.POWER_CYCLE)
                                session.check("power cycle preserves the remaining local budget", retries(session, version)[5], remaining)
                                fixture.assertion(session, authenticate=False)
                        cue(session, "enter the CORRECT PIN only if an entry screen unexpectedly opens")
                        result, _ = issue(session, version, 2, fixture.rp)
                        session.check("permanent local block survives a cold power cycle", result.status, 0x3c)
                        protocol = pin_protocol(session, version)
                        correct = protocol.encrypt(hashlib.sha256(session.options.pin.encode()).digest()[:16])
                        session.check("host PIN cannot bypass the same exhausted local budget", session.ctap(6, {1: version, 2: 9, 3: protocol.cose, 6: correct, 9: 2, 10: fixture.rp}).status, 0x32)
                        fixture.assertion(session, authenticate=False)
                finally:
                    if consumed and not session.broken:
                        session.trace.phase = "cleanup"
                        change(session, Action.POWER_CYCLE)
                        cue(session, "approve the FIDO reset needed to recover the deliberately exhausted test PIN")
                        session.ctap_value(session.ctap(7))
                        factory = session.ctap_value(session.ctap(4))
                        session.check("blocking recovery reset establishes an unset PIN", factory.get(4, {}).get("clientPin"), False)
                        session.bind("fido.info", factory)
                        session.options.pin = None
                        session.check("reset revokes the deliberately blocked fixture key", session.ctap(2, fixture.query(session, options={"up": False}, authenticate=False)).status, 0x2e)
                        provision_after_reset(session, factory)
                preserved(session, "fido", neighbors)
