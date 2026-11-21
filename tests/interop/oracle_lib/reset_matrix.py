# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Reset refusals preserve private keys; display consent has a distinct window."""
import sys

from .fido import cm, info, pin_token
from .fido_fixtures import credential, provision_after_reset
from .hid_sequences import hooks, send
from .lifecycle import Action, change
from .reset_witness import snapshot, preserved
from .timers import wait
from .token_matrix import assertion

RESET_WINDOW_SECONDS = 10


def run(session):
    for mode in ("outside-window", "decline", "cancel", "timeout"):
        with session.case("fido.RESET.refusal." + mode, ("F23", "F09", "F10", "X06", "G14"),
                effects=("applet_reset", "pin_change", "reboot", "create_fido_credential"), touch=True,
                parameters={"reset_action": mode, "window_seconds": RESET_WINDOW_SECONDS}):
            session.require(session.profile == "rsk", "reset window/consent contract requires RS-Key", "excluded_by_profile")
            session.require(session.card is not None and hasattr(session.card, "control"), "reset window requires an explicit power-cycle backend")
            display = "display" in session.options.features
            session.require(mode != "decline" or display and session.options.operator, "explicit decline needs a display and an operator")
            session.require(mode != "timeout" or session.options.operator and session.options.timeout > 130, "withheld reset presence needs an operator and the full panel timeout")
            session.require(mode != "outside-window" or session.options.timeout > RESET_WINDOW_SECONDS + 1, "outside-window control requires a longer host timeout")
            neighbors = snapshot(session, "fido")
            reset = False
            with credential(session, session.current.name) as fixture:
                change(session, Action.POWER_CYCLE)
                if mode == "outside-window":
                    wait(session, RESET_WINDOW_SECONDS + .25)
                version, token = pin_token(session, 2, fixture.rp)
                _, readonly = pin_token(session, 64, version=version)
                metadata = session.ctap_value(cm(session, version, readonly, 1))
                session.check("ordinary grant is live immediately before reset request", assertion(session, fixture, version, token).status, 0)
                before = session.ctap_value(session.ctap(4))
                print("oracle: RESET test: " + ("approve the displayed reset even though the boot window has passed" if mode == "outside-window" and display else "withhold reset touch" if mode == "timeout" else mode), file=sys.stderr)
                session.trace.emit("interaction", action="RESET-" + mode, source="runner", stage="requested", observed_touch_ns=None)
                if mode == "cancel":
                    timeline = []
                    def cancel(status, timestamp):
                        timeline.append((status, timestamp))
                        if status == 2:
                            send(session, 0x11, session.hid.cid)
                    with hooks(session, keepalive=cancel):
                        result = session.ctap(7)
                    session.check("reset cancellation follows actual UP-needed", any(status == 2 for status, _ in timeline))
                else:
                    result = session.ctap(7)
                expected = 0 if mode == "outside-window" and display else 0x30 if mode == "outside-window" else {"decline": 0x27, "cancel": 0x2d, "timeout": 0x2f}[mode]
                reset = result.status == 0
                try:
                    session.check("reset window and consent have their profiled outcome", result.status, expected)
                    if not reset:
                        after = session.ctap_value(session.ctap(4))
                        session.check("refused reset preserves all public state", {k: v for k, v in after.items() if k not in (25, 30)}, {k: v for k, v in before.items() if k not in (25, 30)})
                        session.check("refused reset preserves ordinary grant", assertion(session, fixture, version, token).status, 0)
                        session.check("refused reset preserves persistent grant", session.ctap_value(cm(session, version, readonly, 1)), metadata)
                        fixture.assertion(session)
                    else:
                        session.options.pin = None
                        session.values.pop("fido.info", None)
                        session.check("confirmed late display reset revokes the private key", session.ctap(2, fixture.query(session, options={"up": False}, authenticate=False)).status, 0x2e)
                finally:
                    if reset and not session.broken:
                        session.trace.phase = "cleanup"
                        provision_after_reset(session, session.ctap_value(session.ctap(4)))
                preserved(session, "fido", neighbors)
