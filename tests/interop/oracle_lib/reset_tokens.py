# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Reset revocation is isolated from token replacement and the preceding reboot."""
from .fido import cm, info
from .fido_fixtures import credential, provision_after_reset
from .lifecycle import Action, change
from .reset_witness import snapshot, preserved
from .token_matrix import issue, assertion


def run(session):
    for version in (1, 2):
        for legacy in (False, True):
            with session.case(f"fido.RESET.live-grants.protocol-{version}.legacy-{legacy}", ("F06", "F09", "F10", "F23", "X06", "G10", "G14"),
                              effects=("applet_reset", "pin_change", "reboot", "create_fido_credential"), touch=True):
                session.require(session.profile == "rsk", "live-grant reset contract requires RS-Key", "excluded_by_profile")
                session.require(session.options.pin is not None, "reset grant fixture requires the configured PIN")
                session.require(session.card is not None and hasattr(session.card, "control") and (session.options.operator or getattr(session.card, "emulated", False)), "reset grants require an explicit power-cycle backend")
                session.require(version in info(session).get(6, []), "selected PIN protocol not advertised", "unknown")
                neighbors = snapshot(session, "fido")
                reset_done = False
                with credential(session, session.current.name) as fixture:
                    change(session, Action.POWER_CYCLE)
                    started = session.trace.now()
                    result, ordinary = issue(session, version, legacy, None if legacy else 2, None if legacy else fixture.rp)
                    session.ctap_value(result)
                    persistent = None
                    if info(session).get(4, {}).get("perCredMgmtRO"):
                        result, persistent = issue(session, version, permissions=64)
                        session.ctap_value(result)
                        session.ctap_value(cm(session, version, persistent, 1))
                    session.check("ordinary grant is live after reboot and persistent issuance", assertion(session, fixture, version, ordinary).status, 0)
                    session.observe("reset_window_host_interval_ns", session.trace.now() - started, "presence")
                    session.observe("reset_window_limit", "interval starts after backend power/rebinding returns; it does not identify the device's exact boot time")
                    session.ctap_value(session.ctap(7))
                    reset_done = True
                    session.options.pin = None
                    current = session.ctap_value(session.ctap(4))
                    session.bind("fido.info", current)
                    session.check("reset removes the PIN record", current.get(4, {}).get("clientPin"), False)
                    try:
                        session.check("reset independently revokes a live ordinary/legacy grant", assertion(session, fixture, version, ordinary).status, 0x33)
                        session.check("old private credential is also independently revoked", session.ctap(2, fixture.query(session, options={"up": False}, authenticate=False)).status, 0x2E)
                        if persistent is not None:
                            session.check("reset independently revokes a live persistent grant", cm(session, version, persistent, 1).status, 0x33)
                    finally:
                        if reset_done and not session.broken:
                            session.trace.phase = "cleanup"
                            provision_after_reset(session, current)
                    if persistent is not None:
                        session.check("PIN reprovision cannot revive the reset persistent token", cm(session, version, persistent, 1).status, 0x33)
                    session.check("PIN reprovision cannot revive the reset ordinary token", assertion(session, fixture, version, ordinary).status, 0x33)
                    preserved(session, "fido", neighbors)
                    session.observe("cleanup_limit", "factory FIDO store retained; supplied original PIN reprovisioned")
