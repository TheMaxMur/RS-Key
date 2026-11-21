# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Local UV grants carry passcode provenance and share the recorded PIN budget."""
import sys
from itertools import product

from .fido import auth_data, cm, info, pin_protocol, pin_token, public_key, token_mac, verified
from .fido_fixtures import credential
from .fido_states import change_pin
from .token_matrix import assertion

PERMISSIONS = (*range(256), 256, 257, 319, 320, 321, 65535, 0xffffffff)


def ready(session):
    session.require(session.profile == "rsk", "local-UV dialect requires the confirmed RS-Key profile", "excluded_by_profile")
    session.require(session.options.operator and session.options.touch, "local UV requires an operator at the selected test key")
    session.require(info(session).get(4, {}).get("uv"), "configured local UV not advertised", "unsupported_confirmed")
    session.require(session.options.pin is not None, "supply the known PIN for independent host controls and recovery")


def cue(session, action):
    session.trace.emit("interaction", source="runner", stage="requested", action=action, observed_touch_ns=None)
    print("oracle: selected test key local UV: " + action, file=sys.stderr)


def issue(session, version, permissions, rp=None):
    protocol = pin_protocol(session, version)
    fields = {1: version, 2: 6, 3: protocol.cose, 9: permissions}
    if rp is not None:
        fields[10] = rp
    result = session.ctap(6, fields)
    token = protocol.decrypt(session.ctap_value(result)[2]) if result.protocol == "success" else None
    return result, token


def provenance(session, fixture, version, token, factor):
    request = fixture.query(session, extensions={"uvm": True}, authenticate=False)
    request.update({6: token_mac(version, token, fixture.challenge), 7: version})
    value = session.ctap_value(session.ctap(2, request))
    signed = auth_data(value[2])
    session.check("UV grant is signed as verified", bool(signed["flags"] & 4))
    session.check("UV token provenance names the actual verification path", signed.get("extensions", {}).get("uvm"), [[1, 2, 4], [factor, 2, 4]])
    verified(session, "UV provenance is signed by the retained credential", fixture.key, fixture.algorithm, value[3], value[2] + fixture.challenge)


def permissions(session):
    for version in (1, 2):
        for bits in PERMISSIONS:
            with session.case(f"fido.local-UV.permissions.protocol-{version}.bits-{bits}", ("F06", "F07", "F09", "F10", "FE08", "G04", "G14"),
                    effects=("create_fido_credential",), touch=True, parameters={"protocol": version, "permissions": bits}):
                ready(session)
                with credential(session, session.current.name) as fixture:
                    _, old = pin_token(session, 4, version=version)
                    metadata = session.ctap_value(cm(session, version, old, 1))
                    retries = session.ctap_value(session.ctap(6, {1: version, 2: 7}))
                    cue(session, "approve consent and enter the CORRECT fixture PIN if the pad opens")
                    reply, token = issue(session, version, bits)
                    low = bits & 255
                    expected = 2 if bits == 0 else 0x40 if low & (8 | 32) or low & 64 and low != 64 else 0
                    session.check("local-UV permissions follow their own option gates", reply.status, expected)
                    if token is None:
                        session.check("permission refusal preserves old grant", session.ctap_value(cm(session, version, old, 1)), metadata)
                    else:
                        session.check("local UV token has complete key bytes", len(token), 32)
                        result = cm(session, version, token, 1)
                        if low & (4 | 64):
                            session.check("local CM grant opens metadata", session.ctap_value(result), metadata)
                        else:
                            session.check("local non-CM token cannot list metadata", result.status, 0x33)
                        if low & 2:
                            provenance(session, fixture, version, token, 4)
                    session.check("correct local UV preserves full retry budget", session.ctap_value(session.ctap(6, {1: version, 2: 7})), retries)
                    fixture.assertion(session)


def refusals(session):
    for version in (1, 2):
        for mode, expected in (("decline-consent", 0x27), ("decline-pad", 0x27), ("cancel", 0x2d), ("timeout", 0x2f), ("wrong-PIN-once", 0x3f)):
            with session.case(f"fido.local-UV.failure.protocol-{version}.{mode}", ("F07", "F08", "F09", "G10", "G14"),
                    effects=("create_fido_credential", "pin_attempts"), touch=True, parameters={"operator_action": mode}):
                ready(session)
                session.require(mode != "timeout" or session.options.timeout > 130, "increase timeout for the complete local ceremony")
                with credential(session, session.current.name) as fixture:
                    _, old = pin_token(session, 2, fixture.rp, version)
                    session.check("old grant is live before the local refusal", assertion(session, fixture, version, old).status, 0)
                    before = session.ctap_value(session.ctap(6, {1: version, 2: 7}))
                    session.require(before[5] > 1 and not before.get(4), "local failure needs a recoverable retry budget")
                    with session.attempts("fido.pin", 2):
                        try:
                            cue(session, mode + "; do not submit any additional wrong PIN")
                            result, token = issue(session, version, 2, fixture.rp)
                            session.check("local UV reports the requested refusal cause", result.status, expected)
                            session.check("refused local UV returns no token", token, None)
                            after = session.ctap_value(session.ctap(6, {1: version, 2: 7}))
                            session.check("only a submitted mismatch consumes a UV retry", after[5], before[5] - (mode == "wrong-PIN-once"))
                            session.check("UV and host PIN share one retry record", session.ctap_value(session.ctap(6, {1: version, 2: 1}))[3], after[5])
                            session.check("non-entry keeps old grant; wrong PIN revokes it", assertion(session, fixture, version, old).status, 0x33 if mode == "wrong-PIN-once" else 0)
                        finally:
                            if not session.broken:
                                pin_token(session, 2, fixture.rp, version)
                    fixture.assertion(session)


def options(session):
    for version, resident, up, uv, host in product((1, 2), (False, True), (None, False, True), (None, False, True), (False, True)):
        with session.case(f"fido.local-UV.options.protocol-{version}.rk-{resident}.up-{up}.uv-{uv}.host-{host}",
                ("F11", "F12", "FE01", "FE03", "FE04", "FE08", "G14"), effects=("create_fido_credential",), touch=True):
            ready(session)
            flags = {"rk": resident, **({"up": up} if up is not None else {}), **({"uv": uv} if uv is not None else {})}
            rp = session.fixture(session.current.name, 8).hex() + ".oracle.invalid"
            challenge = session.fixture("local-UV.options")
            fields = {1: challenge, 2: {"id": rp}, 3: {"id": b"local-UV-options"}, 4: [{"type": "public-key", "alg": -7}], 6: {"uvm": True, "hmac-secret": True, "credProtect": 3}, 7: flags}
            if host:
                _, token = pin_token(session, 1, rp, version)
                fields.update({8: token_mac(version, token, challenge), 9: version})
            descriptor = None
            try:
                cue(session, "accept presence; enter the correct PIN ONLY if the device asks")
                result = session.ctap(1, fields)
                expected = 0x2c if up is False else 0x36 if resident and not host and uv is not True else 0
                session.check("built-in UV MC option product has the profiled outcome", result.status, expected)
                if expected:
                    continue
                value = session.ctap_value(result)
                parsed = auth_data(value[2])
                descriptor = {"type": "public-key", "id": parsed["credential_id"]}
                is_uv = host or uv is True
                session.check("registration UV reflects the method actually used", bool(parsed["flags"] & 4), is_uv)
                expected_factors = [[1, 2, 4]] + ([[0x800 if host else 4, 2, 4]] if is_uv else [])
                session.check("registration UVM gives host token precedence over uv option", parsed["extensions"]["uvm"], expected_factors)
                request = {1: rp, 2: challenge, 3: [descriptor], 4: {"uvm": True}, 5: {k: v for k, v in flags.items() if k != "rk"}}
                if host:
                    _, token = pin_token(session, 2, rp, version)
                    request.update({6: token_mac(version, token, challenge), 7: version})
                reply = session.ctap(2, request)
                denied = not is_uv
                session.check("credProtect requires actual UV independently of presence", reply.status, 0x2e if denied else 0)
                if not denied:
                    signed = session.ctap_value(reply)
                    data = auth_data(signed[2])
                    session.check("assertion UV is signed", bool(data["flags"] & 4))
                    session.check("assertion provenance matches registration method", data["extensions"]["uvm"], expected_factors)
                    verified(session, "local UV option key verifies independently", public_key(parsed["cose"]), -7, signed[3], signed[2] + challenge)
                _, control_token = pin_token(session, 2, rp, version)
                control = {1: rp, 2: challenge, 3: [descriptor], 6: token_mac(version, control_token, challenge), 7: version}
                signed = session.ctap_value(session.ctap(2, control))
                verified(session, "every successful MC option leaves an independently usable key", public_key(parsed["cose"]), -7, signed[3], signed[2] + challenge)
            finally:
                if resident and descriptor is not None and not session.broken:
                    session.trace.phase = "cleanup"
                    proto, token = pin_token(session, 4, version=version)
                    session.ctap_value(cm(session, proto, token, 6, {2: descriptor}))


def local_change(session):
    for version in (1, 2):
        with session.case(f"fido.local-UV.PIN-change.protocol-{version}", ("F05", "F09", "F10", "X11", "G14"),
                effects=("pin_change", "create_fido_credential"), touch=True):
            ready(session)
            session.require(not info(session).get(27), "local PIN fixture requires ordinary reversible policy")
            original = session.options.pin
            replacement = "7391846250" + "6" * max(0, info(session).get(13, 4) - 10)
            session.require(len(replacement) <= 63 and original != replacement, "local change needs a distinct bounded numeric PIN")
            with credential(session, session.current.name) as fixture:
                result, ordinary = issue(session, version, 2, fixture.rp)
                session.ctap_value(result)
                _, persistent = pin_token(session, 64, version=version)
                session.check("local grant initially live", assertion(session, fixture, version, ordinary).status, 0)
                session.ctap_value(cm(session, version, persistent, 1))
                started = session.trace.now()
                cue(session, "use device Settings to change the FIDO PIN to " + replacement)
                input("oracle: finish the local FIDO PIN change, then press Enter: ")
                session.trace.emit("interaction", action="local_fido_PIN_change", stage="reported_complete", source="operator_report", interval_start_ns=started, interval_end_ns=session.trace.now())
                session.options.pin = replacement
                confirmed = False
                try:
                    # A read-only issuance verifies the new PIN without replacing the old ordinary grant.
                    pin_token(session, 64, version=version)
                    confirmed = True
                    session.check("local PIN change revokes the standing local grant", assertion(session, fixture, version, ordinary).status, 0x33)
                    session.check("local PIN change revokes persistent RO", cm(session, version, persistent, 1).status, 0x33)
                    pin_token(session, 2, fixture.rp, version)
                    fixture.assertion(session)
                finally:
                    if confirmed and not session.broken:
                        session.trace.phase = "cleanup"
                        change_pin(session, replacement, original)
                        session.options.pin = original
                    elif not confirmed:
                        session.broken = True
                        session.values["halt_reason"] = "operator-reported local PIN change was not confirmed; no guessed PIN recovery attempted"


def assertion_options(session):
    for version, resident, level, up, uv, host, allow in product((1, 2), (False, True), (1, 2, 3),
            (None, False, True), (None, False, True), (False, True), (False, True)):
        if not resident and not allow:
            continue
        with session.case(f"fido.local-UV.GA.protocol-{version}.rk-{resident}.CP-{level}.up-{up}.uv-{uv}.host-{host}.allow-{allow}",
                ("F12", "FE01", "FE08", "G14"), effects=("create_fido_credential",), touch=True):
            ready(session)
            session.require(not info(session).get(4, {}).get("alwaysUv"), "non-UV visibility fixture requires alwaysUv disabled")
            with credential(session, session.current.name, resident, {"credProtect": level, "uvm": True}) as fixture:
                flags = {**({"up": up} if up is not None else {}), **({"uv": uv} if uv is not None else {})}
                fields = fixture.query(session, extensions={"uvm": True}, options=flags, authenticate=False)
                if not allow:
                    del fields[3]
                if host:
                    _, token = pin_token(session, 2, fixture.rp, version)
                    fields.update({6: token_mac(version, token, fixture.challenge), 7: version})
                is_uv = host or uv is True and up is not False
                visible = is_uv or level == 1 or level == 2 and allow
                cue(session, "accept requested presence/local UV using the CORRECT fixture PIN")
                result = session.ctap(2, fields)
                session.check("GA visibility uses actual UV and allow-list provenance", result.status, 0 if visible else 0x2e)
                if visible:
                    value = session.ctap_value(result)
                    data = auth_data(value[2])
                    session.check("silent GA cannot start local UV", bool(data["flags"] & 4), is_uv)
                    session.check("GA presence matches its requested ceremony", bool(data["flags"] & 1), up is not False)
                    factors = ([[1, 2, 4]] if up is not False else []) + ([[0x800 if host else 4, 2, 4]] if is_uv else [])
                    session.check("GA UVM includes every used factor and no unused one", data["extensions"]["uvm"], factors or [[0x200, 2, 4]])
                    verified(session, "GA option result verifies with owned key", fixture.key, fixture.algorithm, value[3], value[2] + fixture.challenge)
                fixture.assertion(session)


def extension_outputs(session):
    from .fido_properties import hmac_request
    for version, resident in product((1, 2), (False, True)):
        with session.case(f"fido.local-UV.extension-isolation.protocol-{version}.rk-{resident}",
                ("FE01", "FE02", "FE03", "FE04", "FE05", "FE08", "G14"), effects=("create_fido_credential",), touch=True):
            ready(session)
            advertised = info(session).get(2, [])
            session.require(all(name in advertised for name in ("hmac-secret", "credBlob", "uvm")), "required extension set not advertised", "unknown")
            blob = session.fixture("local-UV.credBlob", 16)
            extensions = {"hmac-secret": True, "credBlob": blob, "credProtect": 3}
            if resident and "largeBlobKey" in advertised:
                extensions["largeBlobKey"] = True
            with credential(session, session.current.name, resident, extensions) as fixture:
                outputs = []
                salts = session.fixture("local-UV.salts", 64)
                for method in ("host", "local-token", "local-ceremony"):
                    protocol, hmac = hmac_request(session, version, salts)
                    requested = {"hmac-secret": hmac, "credBlob": True, "uvm": True}
                    if "largeBlobKey" in extensions:
                        requested["largeBlobKey"] = True
                    request = fixture.query(session, extensions=requested, options={"up": True, "uv": True}, authenticate=False)
                    if method == "host":
                        _, token = pin_token(session, 2, fixture.rp, version)
                    elif method == "local-token":
                        cue(session, "approve token consent and enter the CORRECT fixture PIN")
                        result, token = issue(session, version, 2, fixture.rp)
                        session.ctap_value(result)
                    if method != "local-ceremony":
                        request.update({6: token_mac(version, token, fixture.challenge), 7: version})
                    value = session.ctap_value(session.ctap(2, request))
                    parsed = auth_data(value[2])
                    session.check("local UV exports the exact retained credBlob", parsed["extensions"]["credBlob"], blob)
                    session.check("local UV largeBlobKey is the registration key", value.get(7), fixture.registration.get(5))
                    session.check("local UV extension method is signed accurately", parsed["extensions"]["uvm"], [[1, 2, 4], [0x800 if method == "host" else 4, 2, 4]])
                    outputs.append(protocol.decrypt(parsed["extensions"]["hmac-secret"]))
                    verified(session, "local extension outputs belong to the retained key", fixture.key, fixture.algorithm, value[3], value[2] + fixture.challenge)
                session.check("all UV verification methods use the same per-credential UV secret", outputs, [outputs[0]] * len(outputs))
            if "hmac-secret-mc" in advertised:
                protocol, encrypted_salts = hmac_request(session, version, salts)
                extensions = {"hmac-secret": True, "hmac-secret-mc": encrypted_salts, "uvm": True}
                cue(session, "register using local UV and the CORRECT PIN; no host token is supplied")
                with credential(session, session.current.name + ".local-MC", resident, extensions,
                        options={"rk": resident, "uv": True}, authenticate=False) as fixture:
                    session.check("local MC has a signed UV flag", bool(fixture.parsed["flags"] & 4))
                    session.check("local MC reports internal passcode provenance", fixture.parsed["extensions"]["uvm"], [[1, 2, 4], [4, 2, 4]])
                    initial = protocol.decrypt(fixture.parsed["extensions"]["hmac-secret-mc"])
                    values = []
                    for local in (False, True):
                        fresh, fields = hmac_request(session, version, salts)
                        _, signed = fixture.assertion(session, extensions={"hmac-secret": fields},
                            options={"up": True, "uv": local}, authenticate=not local)
                        values.append(fresh.decrypt(signed["extensions"]["hmac-secret"]))
                    session.check("local registration HMAC output matches later host and local UV assertions", values, [initial, initial])


def run(session):
    permissions(session)
    refusals(session)
    options(session)
    assertion_options(session)
    extension_outputs(session)
    local_change(session)
