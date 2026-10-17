# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Token and cursor idle windows use separate setup and explicit host waits."""
from .fido import cm, info, pin_token
from .timers import wait

IDLE_WINDOW_SECONDS = 30
BOUNDARY_MARGIN_SECONDS = 0.25
ABSOLUTE_LIFETIME_SECONDS = 600


def run(session):
    for version in (1, 2):
        for persistent in (False, True):
            for elapsed in (1, IDLE_WINDOW_SECONDS + BOUNDARY_MARGIN_SECONDS):
                with session.case(f"fido.token.idle.protocol-{version}.readonly-{persistent}.seconds-{elapsed}", ("F09", "F10", "F14", "G10", "G14"),
                                  parameters={"protocol": version, "readonly": persistent, "wait_seconds": elapsed}):
                    session.require(session.profile == "rsk", "timer assertion requires the RS-Key protocol profile", "excluded_by_profile")
                    options = info(session).get(4, {})
                    session.require(options.get("perCredMgmtRO") if persistent else options.get("credMgmt"), "required management permission not advertised", "unknown")
                    session.require(session.options.timeout > elapsed + 0.25, "increase --timeout for the declared idle window")
                    protocol, token = pin_token(session, 64 if persistent else 4, version=version)
                    original = session.ctap_value(cm(session, protocol, token, 1))
                    wait(session, elapsed)
                    result = cm(session, protocol, token, 1)
                    if persistent or elapsed < IDLE_WINDOW_SECONDS:
                        session.check("live or persistent token remains authorized", session.ctap_value(result), original)
                    else:
                        session.check("ordinary token expires after idle window", result.status, 0x33)
                        protocol, fresh = pin_token(session, 4, version=version)
                        session.check("fresh token works after idle expiry", session.ctap_value(cm(session, protocol, fresh, 1)), original)
        with session.case(f"fido.token.replacement.protocol-{version}", ("F06", "F09", "G11", "G14")):
            session.require(info(session).get(4, {}).get("credMgmt"), "credential management not advertised", "unknown")
            protocol, old = pin_token(session, 4, version=version)
            original = session.ctap_value(cm(session, protocol, old, 1))
            _, fresh = pin_token(session, 4, version=version)
            outcome = cm(session, protocol, old, 1)
            session.observe("old_token_after_replacement", (outcome.protocol, outcome.status))
            if outcome.protocol == "success":
                session.check("retained token observes same metadata", session.ctap_value(outcome), original)
            session.check("new token authorizes valid control", session.ctap_value(cm(session, protocol, fresh, 1)), original)
        with session.case(f"fido.RP-walk.idle.protocol-{version}", ("F15", "F16", "F09", "G12", "G14")):
            session.require(info(session).get(4, {}).get("perCredMgmtRO"), "read-only token needed to isolate cursor expiry from token expiry", "unknown")
            session.require(session.options.timeout > IDLE_WINDOW_SECONDS + 1, "increase --timeout for cursor idle expiry")
            protocol, token = pin_token(session, 64, version=version)
            first = session.ctap_value(cm(session, protocol, token, 2))
            session.require(first.get(5, 0) >= 2, "cursor expiry needs at least two existing resident RPs")
            wait(session, IDLE_WINDOW_SECONDS + BOUNDARY_MARGIN_SECONDS)
            session.check("idle RP continuation expires", cm(session, protocol, token, 3).status, 0x30)
            session.ctap_value(cm(session, protocol, token, 1))
            session.check("fresh walk works after cursor expiry", session.ctap_value(cm(session, protocol, token, 2))[4], first[4])
    with session.case("fido.token.absolute-lifetime-with-periodic-use", ("F09", "G10", "G14"),
                      parameters={"lifetime_seconds": ABSOLUTE_LIFETIME_SECONDS, "use_interval_seconds": 20}):
        session.require(session.profile == "rsk", "absolute token lifetime requires the RS-Key profile", "excluded_by_profile")
        session.require(session.options.timeout > ABSOLUTE_LIFETIME_SECONDS + 1, "increase --timeout above the 600-second absolute-lifetime scenario")
        session.require(info(session).get(4, {}).get("credMgmt"), "credential management not advertised", "unknown")
        version, token = pin_token(session, 4)
        original = session.ctap_value(cm(session, version, token, 1))
        for elapsed in range(20, ABSOLUTE_LIFETIME_SECONDS, 20):
            wait(session, 20)
            session.check("periodic use keeps ordinary token live before absolute cap", session.ctap_value(cm(session, version, token, 1)), original)
        wait(session, 20 + BOUNDARY_MARGIN_SECONDS)
        session.check("periodic use cannot extend absolute token lifetime", cm(session, version, token, 1).status, 0x33)
        version, fresh = pin_token(session, 4)
        session.check("fresh token after absolute expiry", session.ctap_value(cm(session, version, fresh, 1)), original)
