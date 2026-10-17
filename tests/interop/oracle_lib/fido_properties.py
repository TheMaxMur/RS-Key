# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Extension absence, credential isolation and counters with owned fixtures."""
from contextlib import ExitStack

from .fido import authorize, cm, info, pin_protocol, pin_token
from .fido_extensions import supported
from .fido_fixtures import credential
from .lifecycle import Action, change

EXTENSION_FAMILIES = {"credProtect": "FE01", "credBlob": "FE02", "hmac-secret": "FE03", "largeBlobKey": "FE05",
                      "minPinLength": "FE07", "pinComplexityPolicy": "FE07", "uvm": "FE08", "thirdPartyPayment": "FE09"}


def extension_types(session):
    for name, family in EXTENSION_FAMILIES.items():
        for operation in (1, 2):
            correct_type = int if name == "credProtect" else bytes if name == "credBlob" and operation == 1 else dict if name == "hmac-secret" and operation == 2 else bool
            for label, value in (("null", None), ("int", 1), ("bool", True), ("text", "x"), ("bytes", b"x"), ("array", []), ("map", {})):
                if type(value) is correct_type or name == "hmac-secret" and operation == 2 and type(value) is bool:
                    continue
                with session.case(f"fido.extension-type.{operation}.{name}.{label}", (family, "FE11", "G02", "G14"),
                                  effects=("create_fido_credential",), touch=True):
                    supported(session, name)
                    with credential(session, session.current.name) as fixture:
                        if operation == 2:
                            request = fixture.query(session, extensions={name: value})
                        else:
                            request = {1: fixture.challenge, 2: {"id": fixture.rp}, 3: {"id": b"invalid-extension"},
                                       4: [{"type": "public-key", "alg": -7}], 6: {name: value}}
                            authorize(session, request, 1, fixture.rp, fixture.challenge, 8, 9)
                        result = session.ctap(operation, request)
                        session.check("known extension wrong type refused", result.protocol, "applet_error")
                        if session.profile == "rsk":
                            session.check("extension refusal is a type error", result.status, 0x11)
                        fixture.assertion(session)
    for label, value in (("null", None), ("int", 1), ("bool", True), ("text", "x"), ("bytes", b"x"), ("array", []), ("map", {})):
        with session.case("fido.unknown-extension." + label, ("FE11", "G02", "G14"), effects=("create_fido_credential",), touch=True):
            unknown = "oracle-unknown-extension"
            with credential(session, session.current.name, extensions={unknown: value}) as fixture:
                session.check("unknown extension not echoed in registration", unknown not in fixture.parsed.get("extensions", {}))
                _, signed = fixture.assertion(session, extensions={unknown: value})
                session.check("unknown extension not echoed in assertion", unknown not in signed.get("extensions", {}))


def cred_blob_visibility(session):
    for resident in (False, True):
        for present in (False, True):
            with session.case(f"fido.credBlob.visibility.rk-{resident}.present-{present}", ("FE02", "G01", "G10", "G14"),
                              effects=("create_fido_credential",), touch=True):
                supported(session, "credBlob")
                session.require(not info(session).get(4, {}).get("alwaysUv"), "non-UV visibility requires a policy permitting a non-UV assertion")
                blob = session.fixture("visible.credBlob", 16)
                with credential(session, session.current.name, resident, {"credBlob": blob} if present else {}) as fixture:
                    _, signed = fixture.assertion(session)
                    session.check("no unsolicited credBlob", "credBlob" not in signed.get("extensions", {}))
                    fixture.assertion(session, extensions={"credBlob": True})
                    result = session.ctap(2, fixture.query(session, extensions={"credBlob": True}, authenticate=False))
                    session.observe("credBlob_without_UV_status", result.status)
                    if result.protocol == "success":
                        from .fido import auth_data, verified
                        value = session.ctap_value(result)
                        data = auth_data(value[2])
                        session.check("non-UV blob response RP binding", data["rp_hash"], fixture.parsed["rp_hash"])
                        verified(session, "non-UV blob response signature", fixture.key, fixture.algorithm, value[3], value[2] + fixture.challenge)
                        session.check("credBlob non-UV read exact", data.get("extensions", {}).get("credBlob"), blob if present else b"")
                        session.check("non-UV read does not invent UV", bool(data["flags"] & 4), False)
                    fixture.assertion(session)


def hmac_request(session, version, salts):
    protocol = pin_protocol(session, version)
    encrypted = protocol.encrypt(salts)
    return protocol, {1: protocol.cose, 2: encrypted, 3: protocol.authenticate(encrypted), 4: version}


def hmac_isolation(session):
    for version in (1, 2):
        for resident in (False, True):
            with session.case(f"fido.hmac-secret.isolation.protocol-{version}.rk-{resident}", ("FE03", "FE04", "F18", "G09", "G14"),
                              effects=("create_fido_credential",), touch=True):
                supported(session, "hmac-secret")
                salts = session.fixture("hmac.isolation.salts", 64)
                with ExitStack() as stack:
                    fixtures = [stack.enter_context(credential(session, session.current.name + f".{i}", resident, {"hmac-secret": True})) for i in range(2)]
                    def evaluate(fixture):
                        protocol, fields = hmac_request(session, version, salts)
                        _, signed = fixture.assertion(session, extensions={"hmac-secret": fields})
                        value = protocol.decrypt(signed["extensions"]["hmac-secret"])
                        session.check("HMAC two-salt output width", len(value), len(salts))
                        return value
                    values = [evaluate(item) for item in fixtures]
                    session.check("different credentials have different HMAC secrets", values[0] != values[1])
                    for index, fixture in enumerate(fixtures):
                        session.check("repeated HMAC evaluation stable", evaluate(fixture), values[index])
                    if resident:
                        version_token, token = pin_token(session, 4)
                        session.ctap_value(cm(session, version_token, token, 7, {2: fixtures[0].descriptor,
                            3: {"id": session.fixture(session.current.name + ".0.user", 16), "name": "updated"}}))
                        session.check("user update preserves HMAC secret", evaluate(fixtures[0]), values[0])
                    protocol, fields = hmac_request(session, version, salts)
                    result = session.ctap(2, fixtures[0].query(session, extensions={"hmac-secret": fields}, options={"up": False}))
                    session.check("silent request cannot export HMAC output", result.protocol, "applet_error")
                    session.check("refusal preserves HMAC secret", evaluate(fixtures[0]), values[0])


def hmac_fields(session):
    for version in (1, 2):
        for member in (1, 2, 3, 4):
            for defect in ("missing", "null", "text", "short", "long"):
                if member == 4 and defect == "missing":
                    continue
                with session.case(f"fido.hmac-secret.member-{member}.{defect}.protocol-{version}", ("FE03", "G01", "G02", "G03", "G14"),
                                  effects=("create_fido_credential",), touch=True):
                    supported(session, "hmac-secret")
                    with credential(session, session.current.name, extensions={"hmac-secret": True}) as fixture:
                        salts = session.fixture("hmac.fields", 32)
                        protocol, fields = hmac_request(session, version, salts)
                        _, baseline = fixture.assertion(session, extensions={"hmac-secret": fields})
                        expected = protocol.decrypt(baseline["extensions"]["hmac-secret"])
                        if defect == "missing":
                            del fields[member]
                        elif defect in ("null", "text"):
                            fields[member] = None if defect == "null" else "invalid"
                        elif member in (2, 3):
                            fields[member] = fields[member][:-1] if defect == "short" else fields[member] + b"\x00"
                            if member == 2:
                                fields[3] = protocol.authenticate(fields[2])
                        elif member == 1:
                            fields[member] = {**fields[member], -2: bytes(31 if defect == "short" else 33)}
                        else:
                            fields[member] = 0 if defect == "short" else 255
                        result = session.ctap(2, fixture.query(session, extensions={"hmac-secret": fields}))
                        session.check("invalid HMAC field refused", result.protocol, "applet_error")
                        protocol, control = hmac_request(session, version, salts)
                        _, signed = fixture.assertion(session, extensions={"hmac-secret": control})
                        session.check("HMAC valid control preserves secret after malformed field", protocol.decrypt(signed["extensions"]["hmac-secret"]), expected)


def blob_key(session, action=None):
    suffix = action.value if action else "update"
    for opted in (False, True):
        with session.case(f"fido.largeBlobKey.{suffix}.opted-{opted}", ("FE05", "F18", "G01", "G14", "X11"),
                          effects=("create_fido_credential", "reboot") if action == Action.POWER_CYCLE else ("create_fido_credential",), touch=True):
            supported(session, "largeBlobKey")
            with credential(session, session.current.name, True, {"largeBlobKey": True} if opted else {}) as fixture:
                key = fixture.registration.get(5)
                session.check("registration largeBlobKey opt-in", key is not None, opted)
                if opted:
                    session.check("largeBlobKey registration width", len(key), 32)
                value, _ = fixture.assertion(session)
                session.check("no unsolicited assertion largeBlobKey", 7 not in value)
                value, _ = fixture.assertion(session, extensions={"largeBlobKey": True})
                session.check("largeBlobKey initial binding", value.get(7), key)
                if action:
                    session.require(session.profile == "rsk", "explicit paired reconnect requires RS-Key binding", "excluded_by_profile")
                    change(session, action)
                else:
                    version, token = pin_token(session, 4)
                    session.ctap_value(cm(session, version, token, 7, {2: fixture.descriptor,
                        3: {"id": session.fixture(session.current.name + ".user", 16), "name": "updated"}}))
                value, _ = fixture.assertion(session, extensions={"largeBlobKey": True})
                session.check("largeBlobKey survives " + suffix, value.get(7), key)
                result = session.ctap(2, fixture.query(session, extensions={"largeBlobKey": False}))
                session.check("largeBlobKey false is refused", result.protocol, "applet_error")
                fixture.assertion(session)


def counters(session, action=None):
    for resident in (False, True):
        with session.case(f"fido.counters.rk-{resident}." + (action.value if action else "operations"), ("FE13", "F11", "F12", "G14", "X11"),
                          effects=("create_fido_credential", "reboot") if action == Action.POWER_CYCLE else ("create_fido_credential",), touch=True):
            with ExitStack() as stack:
                fixtures = [stack.enter_context(credential(session, session.current.name + f".{index}", resident)) for index in range(2)]
                counts = []
                for fixture in (fixtures[0], fixtures[0], fixtures[1], fixtures[0]):
                    counts.append(fixture.assertion(session)[1]["counter"])
                invalid = fixtures[0].query(session, allow=[{"type": "public-key", "id": session.fixture("counter.unknown", 32)}])
                session.check("counter control rejection", session.ctap(2, invalid).protocol, "applet_error")
                after = fixtures[0].assertion(session)[1]["counter"]
                session.observe("counter_sequence", [*counts, after])
                if session.profile == "rsk":
                    if resident:
                        session.check("per-credential counter advances once per successful assertion", [counts[1] - counts[0], counts[3] - counts[1], after - counts[3]], [1, 1, 1])
                    else:
                        session.check("stateless credential reports zero counter", [*counts, after], [0] * 5)
                if action:
                    session.require(session.profile == "rsk", "explicit paired reconnect requires RS-Key binding", "excluded_by_profile")
                    change(session, action)
                    got = fixtures[0].assertion(session)[1]["counter"]
                    session.check("counter retained across " + action.value, got, after + 1 if resident else 0)


def run(session):
    extension_types(session)
    cred_blob_visibility(session)
    hmac_isolation(session)
    hmac_fields(session)
    blob_key(session)
    counters(session)


def reconnect(session):
    for action in (Action.USB_RECONNECT, Action.POWER_CYCLE):
        blob_key(session, action)
        counters(session, action)
