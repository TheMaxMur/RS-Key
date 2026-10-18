# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Configuration auth, RP-list bounds and PIN-policy recovery use owned keys."""
from . import codec
from .fido import info, pin_token, token_mac
from .fido_fixtures import credential, provision_after_reset
from .fido_states import change_pin
from .pin_matrix import request as pin_request
from .lifecycle import Action, change
from .vendor_lifecycle import config


def request(session, version, token, subcommand, parameters=None):
    fields = {1: subcommand, 3: version}
    if parameters is not None:
        fields[2] = parameters
    fields[4] = token_mac(version, token, b"\xff" * 32 + bytes([13, subcommand]) + (codec.encode(parameters) if parameters is not None else b""))
    return fields


def public(value):
    return {key: child for key, child in value.items() if key not in (25, 30)}


def authorization(session):
    for version in (1, 2):
        for subcommand in (1, 2, 3):
            for defect in ("missing-auth", "missing-protocol", "empty-auth", "short-auth", "long-auth", "wrong-MAC", "wrong-permission", "readonly", "protocol-zero", "protocol-unknown"):
                with session.case(f"fido.CONFIG.auth.protocol-{version}.sub-{subcommand}.{defect}", ("F21", "F01", "F09", "F10", "G01", "G03", "G04", "G10", "G14"),
                                  effects=("config_change", "create_fido_credential"), touch=True):
                    session.require(session.profile == "rsk", "config authorization contract requires RS-Key", "excluded_by_profile")
                    session.require(info(session).get(4, {}).get("authnrCfg"), "configuration command not advertised", "unknown")
                    with credential(session, session.current.name) as fixture:
                        before = session.ctap_value(session.ctap(4))
                        permission = 2 if defect == "wrong-permission" else 64 if defect == "readonly" else 32
                        session.require(permission != 64 or before.get(4, {}).get("perCredMgmtRO"), "persistent RO grant not advertised", "unknown")
                        _, token = pin_token(session, permission, version=version)
                        fields = request(session, version, token, subcommand, {1: before.get(13, 4)} if subcommand == 3 else None)
                        if defect == "missing-auth":
                            fields.pop(4)
                        elif defect == "missing-protocol":
                            fields.pop(3)
                        elif defect == "empty-auth":
                            fields[4] = b""
                        elif defect == "short-auth":
                            fields[4] = fields[4][:-1]
                        elif defect == "long-auth":
                            fields[4] += b"x"
                        elif defect == "wrong-MAC":
                            fields[4] = bytes([fields[4][0] ^ 1]) + fields[4][1:]
                        elif defect.startswith("protocol-"):
                            fields[3] = 0 if defect == "protocol-zero" else 3
                        result = session.ctap(13, fields)
                        session.check("CONFIG isolates the authorization failure cause", result.status, 0x36 if defect == "missing-auth" else 0x14 if defect == "missing-protocol" else 2 if defect.startswith("protocol-") else 0x33)
                        session.check("CONFIG refusal preserves every public policy field", public(session.ctap_value(session.ctap(4))), public(before))
                        fixture.assertion(session)
                        session.ctap_value(config(session, 2))
                        session.ctap_value(config(session, 2))
                        session.check("fresh valid config control restores the same policy", public(session.ctap_value(session.ctap(4))), public(before))
    for subcommand in (0, 4, 254, 256, 0xFFFFFFFF):
        for protocol in (None, 0, 2):
            with session.case(f"fido.CONFIG.subcommand-{subcommand}.protocol-{protocol}", ("F21", "G01", "G04", "G13", "G14")):
                session.require(session.profile == "rsk", "CONFIG validation precedence requires RS-Key", "excluded_by_profile")
                before = session.ctap_value(session.ctap(4))
                fields = {1: subcommand}
                if protocol is not None:
                    fields[3] = protocol
                result = session.ctap(13, fields)
                session.check("CONFIG protocol validation precedes subcommand and auth", result.status, 2 if protocol == 0 else 0x14 if subcommand == 0 else 2)
                session.check("unknown CONFIG command preserves public policy", public(session.ctap_value(session.ctap(4))), public(before))


def extension(session, label, rp, floor, allowed, complexity):
    with credential(session, label, rp=rp, extensions={"minPinLength": True, "pinComplexityPolicy": True}) as fixture:
        output = fixture.parsed.get("extensions", {})
        session.check("PIN policy is visible only to its permitted RP", output.get("minPinLength"), floor if allowed else None)
        session.check("complexity output follows the same RP authorization", output.get("pinComplexityPolicy"), complexity if allowed else None)


def policy(session):
    with session.case("fido.CONFIG.policy.RP-boundaries-complexity-and-forced-change", ("F01", "F04", "F05", "F06", "F09", "F10", "F21", "FE07", "G03", "G04", "G08", "G10", "G14"),
                      effects=("config_change", "pin_change", "pin_attempts", "applet_reset", "reboot", "create_fido_credential"), touch=True,
                      method="profile-derived bounds with independent code-point/PIN witnesses"):
        session.require(session.profile == "rsk", "policy edge contract requires RS-Key", "excluded_by_profile")
        original = info(session)
        session.require(original.get(4, {}).get("setMinPINLength") and "pinComplexityPolicy" in original.get(2, []), "required policy features not advertised", "unknown")
        session.require(session.options.pin is not None and not original.get(12), "known PIN with no pending forced change is required")
        session.require(session.card is not None and hasattr(session.card, "control") and (session.options.operator or getattr(session.card, "emulated", False)), "monotonic policy requires explicit power-cycle/reset recovery")
        floor, maximum = original.get(13, 4), original.get(16)
        session.require(type(maximum) is int and 1 <= maximum <= 16, "bounded advertised RP-list size is required")
        changed = False
        try:
            with credential(session, session.current.name + ".retained") as retained:
                last = None
                for count in sorted({1, max(1, maximum - 1), maximum, maximum + 1}):
                    rps = [f"r{index}.oracle.invalid" for index in range(count)]
                    result = config(session, 3, {1: floor, 2: rps})
                    if count <= maximum:
                        session.ctap_value(result)
                        changed = True
                        last = rps[-1]
                    else:
                        session.check("RP-list overflow is not silently truncated", result.status, 0x28)
                    extension(session, "policy.RP" + str(count), last, floor, True, bool(original.get(27)))
                    retained.assertion(session)
                session.ctap_value(config(session, 3, {2: []}))
                extension(session, "policy.empty-list", last, floor, True, bool(original.get(27)))
                session.ctap_value(config(session, 3, {2: ["replacement.oracle.invalid"] * maximum}))
                extension(session, "policy.replaced-list", last, floor, False, bool(original.get(27)))
                for value in sorted({1, max(1, floor - 1), 64, 255, 256, 0xFFFFFFFF}):
                    result = config(session, 3, {1: value})
                    session.check("out-of-policy PIN floor is refused", result.status, 0x37)
                    session.check("refused floor cannot alter policy", session.ctap_value(session.ctap(4))[13], floor)
                session.ctap_value(config(session, 3, {1: 0, 4: True}))
                session.check("complexity policy is enabled", session.ctap_value(session.ctap(4))[27], True)
                weak = ["a" * 63, ("ab" * 32)[:63]]
                if floor <= 8:
                    weak.append("password")
                if floor <= 31:
                    weak.append("é" * max(4, floor))
                for candidate in weak:
                    _, fields = pin_request(session, 2, candidate.encode().ljust(64, b"\x00"), session.options.pin)
                    session.check("complexity rejects a length-valid trivial PIN", session.ctap(6, fields).status, 0x37)
                    retained.assertion(session)
                strong = "Or4!" + "x" * max(0, floor - 4)
                change_pin(session, session.options.pin, strong)
                session.options.pin = strong
                if floor <= 61:
                    unicode_pin = "éΩ7!" + "x" * max(0, floor - 4)
                    change_pin(session, strong, unicode_pin)
                    session.options.pin = unicode_pin
                    retained.assertion(session)
                session.ctap_value(config(session, 3, {4: False}))
                session.check("complexity cannot be downgraded", session.ctap_value(session.ctap(4))[27], True)
                long_pin = "Or4!" + "x" * 59
                change_pin(session, session.options.pin, long_pin)
                session.options.pin = long_pin
                retained.assertion(session)
                readonly = pin_token(session, 64) if original.get(4, {}).get("perCredMgmtRO") else None
                session.ctap_value(config(session, 3, {1: 63, 3: True}))
                current = session.ctap_value(session.ctap(4))
                session.check("maximum PIN floor and force-change are advertised", (current[13], current[12]), (63, True))
                retries = session.ctap_value(session.ctap(6, {1: 2, 2: 1}))[3]
                from .token_matrix import issue
                from .fido import cm
                with session.attempts("fido.pin", 8):
                    _, unchanged = pin_request(session, 2, long_pin.encode().ljust(64, b"\x00"), long_pin)
                    session.check("forced change rejects an identical length-valid complex PIN", session.ctap(6, unchanged).status, 0x37)
                    session.check("forced change refuses legacy grant after correct PIN", issue(session, 2, True)[0].status, 0x31)
                    session.check("forced change refuses scoped grant after correct PIN", issue(session, 2, permissions=4)[0].status, 0x37)
                    if readonly is not None:
                        session.check("forcing a PIN change revokes persistent RO", cm(session, *readonly, 1).status, 0x33)
                    session.check("forced-change refusal is not a wrong-PIN comparison", session.ctap_value(session.ctap(6, {1: 2, 2: 1}))[3], retries)
                    new = "Qr8?" + "z" * 59
                    change_pin(session, session.options.pin, new)
                    session.options.pin = new
                    pin_token(session, 4)
                session.check("valid maximum-width PIN clears force-change", session.ctap_value(session.ctap(4))[12], False)
                retained.assertion(session)
                change(session, Action.POWER_CYCLE)
                current = session.ctap_value(session.ctap(4))
                session.check("PIN policy survives a power cycle", (current[13], current[27], current[12]), (63, True, False))
                retained.assertion(session)
        finally:
            if changed and not session.broken:
                session.trace.phase = "cleanup"
                change(session, Action.POWER_CYCLE)
                session.ctap_value(session.ctap(7))
                provision_after_reset(session, session.ctap_value(session.ctap(4)))
                session.observe("cleanup_limit", "policy reset retains factory FIDO store; supplied original PIN is reprovisioned")


def run(session):
    authorization(session)
    policy(session)
