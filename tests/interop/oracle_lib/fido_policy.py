# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Configuration changes have explicit reset recovery for irreversible PIN floors."""
from .fido import info
from .fido_fixtures import credential, provision_after_reset
from .fido_states import change_pin
from .lifecycle import Action, change
from .vendor_lifecycle import config


def run(session):
    with session.case("fido.policy.alwaysUv.toggle-and-restore", ("F21", "F01", "F11", "F12", "G14"), effects=("config_change",), touch=True):
        original = info(session)
        session.require(original.get(4, {}).get("authnrCfg") and "alwaysUv" in original.get(4, {}), "alwaysUv configuration not advertised", "unknown")
        changed = False
        try:
            session.ctap_value(config(session, 2))
            changed = True
            current = session.ctap_value(session.ctap(4))
            session.check("alwaysUv toggled in advertised state", current[4]["alwaysUv"], not original[4]["alwaysUv"])
            session.bind("fido.info", current)
            with credential(session, session.current.name) as fixture:
                _, signed = fixture.assertion(session)
                if current[4]["alwaysUv"]:
                    session.check("alwaysUv requires signed UV", bool(signed["flags"] & 4))
        finally:
            if changed and not session.broken:
                session.trace.phase = "cleanup"
                session.ctap_value(config(session, 2))
                current = session.ctap_value(session.ctap(4))
                session.check("alwaysUv restored", current[4]["alwaysUv"], original[4]["alwaysUv"])
                session.bind("fido.info", current)
    with session.case("fido.policy.minPINLength.RP-and-force-change", ("FE07", "F21", "F04", "F05", "F09", "G14"),
                      effects=("config_change", "pin_change", "applet_reset", "reboot", "create_fido_credential"), touch=True):
        session.require(session.profile != "trezor", "PIN policy mutation excluded on wallet device", "excluded_by_profile")
        session.require(session.options.pin is not None, "PIN policy tests require a known configured PIN")
        session.require(info(session).get(4, {}).get("setMinPINLength"), "minimum PIN configuration not advertised", "unknown")
        session.require(session.card is not None and hasattr(session.card, "control") and (session.options.operator or getattr(session.card, "emulated", False)),
                        "nondecreasing PIN floor needs explicit power-cycle/reset recovery")
        original = info(session)
        changed = False
        try:
            label = session.current.name + ".permitted"
            rp = session.fixture(label + ".rp", 8).hex() + ".oracle.invalid"
            floor = original.get(13, 4)
            session.ctap_value(config(session, 3, {1: floor, 2: [rp]}))
            changed = True
            with credential(session, label, extensions={"minPinLength": True}) as fixture:
                session.check("permitted RP receives minimum PIN length", fixture.parsed["extensions"]["minPinLength"], floor)
            with credential(session, label + ".unrelated", extensions={"minPinLength": True}) as fixture:
                session.check("unrelated RP cannot read PIN policy", "minPinLength" not in fixture.parsed.get("extensions", {}))
            for invalid in (floor - 1, original.get(29, 63) + 1):
                result = config(session, 3, {1: invalid})
                session.check("invalid PIN minimum refused", result.protocol, "applet_error")
                session.check("refused decrease preserves floor", session.ctap_value(session.ctap(4))[13], floor)
            if session.profile == "rsk":
                session.ctap_value(config(session, 3, {1: 0}))
                session.check("omitted minimum preserves existing floor", session.ctap_value(session.ctap(4))[13], floor)
            if "pinComplexityPolicy" in original.get(2, []):
                for enabled in (False, True):
                    session.ctap_value(config(session, 3, {4: enabled}))
                    policy = original.get(27, False) or enabled
                    current = session.ctap_value(session.ctap(4))
                    session.check("PIN complexity advertised after update", current[27], policy)
                    with credential(session, label, extensions={"minPinLength": True, "pinComplexityPolicy": True}) as fixture:
                        session.check("permitted RP receives complexity policy", fixture.parsed["extensions"]["pinComplexityPolicy"], policy)
                    with credential(session, label + ".unrelated", extensions={"pinComplexityPolicy": True}) as fixture:
                        session.check("unrelated RP cannot read complexity policy", "pinComplexityPolicy" not in fixture.parsed.get("extensions", {}))
            higher = min(original.get(29, 63), floor + 1)
            session.ctap_value(config(session, 3, {1: higher, 3: True}))
            current = session.ctap_value(session.ctap(4))
            session.check("force-change policy visible", current[12], True)
            session.check("new PIN minimum visible", current[13], higher)
            new = "Or4!" + "a" * (max(higher, 12) - 4)
            session.require(len(new.encode()) <= 63, "new policy leaves no bounded ASCII fixture PIN")
            change_pin(session, session.options.pin, new)
            session.options.pin = new
            session.check("PIN change satisfies force-change policy", session.ctap_value(session.ctap(4))[12], False)
        finally:
            if changed and not session.broken:
                session.trace.phase = "cleanup"
                change(session, Action.POWER_CYCLE)
                session.ctap_value(session.ctap(7))
                provision_after_reset(session, session.ctap_value(session.ctap(4)))
                session.observe("cleanup_limit", "factory FIDO policy and store retained; supplied fixture PIN reprovisioned when available")
