# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Registration dimensions start with valid authentication and a retained key."""
import hashlib
import itertools

from . import codec
from .credential_matrix import owned, metadata, user_rows
from .fido import auth_data, authorize, info, public_key
from .fido_fixtures import Credential, credential
from .fido_properties import hmac_request
from .vendor_lifecycle import config

LEVELS = (("omitted", None), ("false", False), ("true", True), ("wrong-type", 1))


def base(session, label, authenticate=True):
    rp = session.fixture(label + ".rp", 8).hex() + ".oracle.invalid"
    request = {1: session.fixture(label + ".hash"), 2: {"id": rp}, 3: {"id": session.fixture(label + ".user", 16)},
               4: [{"type": "public-key", "alg": -7}], 7: {"rk": False}}
    if authenticate:
        authorize(session, request, 1, rp, request[1], 8, 9)
    return request


def attempt(session, store, request, expected, raw=None):
    before = metadata(session)
    # Metadata needs a different grant; reacquire the request's MAC afterward.
    if 8 in request:
        authorize(session, request, 1, request[2]["id"], request[1], 8, 9)
    response = session.ctap(1, raw=raw(request)) if raw else session.ctap(1, request)
    fixture = None
    if response.protocol == "success":
        value = session.ctap_value(response)
        parsed = auth_data(value[2])
        fixture = Credential(request[2]["id"], {"type": "public-key", "id": parsed["credential_id"]},
            public_key(parsed["cose"]), parsed["cose"][3], value, parsed, request[1])
        if metadata(session)[1] > before[1]:
            store.live[fixture.descriptor["id"]] = fixture
    session.check("registration matrix exact outcome", (response.protocol, response.status), ("success", 0) if expected == 0 else ("applet_error", expected))
    if fixture is not None:
        session.check("registration uses requested RP", fixture.parsed["rp_hash"], hashlib.sha256(fixture.rp.encode()).digest())
        session.check("registration has signed presence", bool(fixture.parsed["flags"] & 1))
        fixture.assertion(session)
    else:
        session.check("refused registration preserves resident store", metadata(session), before)
    return fixture


def options(session):
    for always in (False, True):
        for auth in (False, True):
            for rk, up, uv in itertools.product(LEVELS, repeat=3):
                label = f"fido.make.options.alwaysUv-{always}.auth-{auth}.rk-{rk[0]}.up-{up[0]}.uv-{uv[0]}"
                with session.case(label, ("F01", "F11", "F12", "F21", "FE01", "G01", "G02", "G10", "G14"),
                                  effects=("config_change", "create_resident_credentials"), touch=True,
                                  parameters={"alwaysUv": always, "authenticated": auth, "rk": rk[0], "up": up[0], "uv": uv[0]},
                                  method="full product of declared option, authorization and policy levels"):
                    session.require(session.profile == "rsk", "makeCredential policy outcomes are profiled for RS-Key", "excluded_by_profile")
                    original = info(session)
                    session.require(session.options.pin and original.get(4, {}).get("clientPin"), "known PIN required for policy restore and resident cleanup")
                    session.require(not original.get(4, {}).get("uv"), "host-only matrix excludes built-in UV ceremonies; local-UV suite owns them", "excluded_by_profile")
                    toggled = False
                    try:
                        if original[4].get("alwaysUv", False) != always:
                            session.ctap_value(config(session, 2))
                            toggled = True
                            session.bind("fido.info", session.ctap_value(session.ctap(4)))
                        with owned(session) as store:
                            control = store.create(label + ".control")
                            request = base(session, label, auth)
                            request[7] = {name: item[1] for name, item in (("rk", rk), ("up", up), ("uv", uv)) if item[0] != "omitted"}
                            wrong_type = any(item[0] == "wrong-type" for item in (rk, up, uv))
                            expected = 0x11 if wrong_type else 0x2C if up[1] is False or uv[1] is True and not auth else 0x36 if not auth and (always or rk[1] is True) else 0
                            result = attempt(session, store, request, expected)
                            if result:
                                session.check("UV flag matches actual verification", bool(result.parsed["flags"] & 4), auth)
                            control.assertion(session)
                    finally:
                        if toggled and not session.broken:
                            session.trace.phase = "cleanup"
                            session.ctap_value(config(session, 2))
                            current = session.ctap_value(session.ctap(4))
                            session.check("option matrix restores alwaysUv", current[4]["alwaysUv"], original[4].get("alwaysUv", False))
                            session.bind("fido.info", current)


def fields(session):
    vectors = [(f"missing-{key}", (key,), None, 0x26 if key == 4 else 0x14, "omit") for key in (1, 2, 3, 4)]
    vectors += [("missing-RP-ID", (2, "id"), None, 0x14, "omit"), ("missing-user-ID", (3, "id"), None, 0x14, "omit"),
                ("missing-algorithm-type", (4, 0, "type"), None, 0x12, "omit"), ("missing-algorithm", (4, 0, "alg"), None, 0x12, "omit")]
    for key, value, expected in ((2, {}, 0x14), (3, {}, 0x14), (4, [], 0x26), (5, [], 0), (6, {}, 0), (7, {}, 0)):
        vectors.append((f"empty-field-{key}", (key,), value, expected, "replace"))
    for size in (0, 1, 31, 32, 33):
        vectors.append((f"hash-length-{size}", (1,), b"h" * size, 0 if size == 32 else 3, "replace"))
    for size in (0, 1, 2, 252, 253, 254):
        vectors.append((f"RP-length-{size}", (2, "id"), "x" * size, 0 if 1 <= size <= 253 else 3, "replace"))
    for value in (" ", " bank.invalid", "bank.invalid ", "bank\t.invalid", "bank\n.invalid"):
        vectors.append(("RP-whitespace-" + value.encode().hex(), (2, "id"), value, 2, "replace"))
    for value in ("\x00", "bank\x00.invalid", "\u00a0", "é", "é" * 126, "é" * 126 + "x", "é" * 127):
        vectors.append(("RP-opaque-" + value.encode().hex(), (2, "id"), value, 0 if len(value.encode()) <= 253 else 3, "replace"))
    for size in (0, 1, 2, 63, 64, 65):
        vectors.append((f"user-ID-length-{size}", (3, "id"), b"u" * size, 0 if 1 <= size <= 64 else 2, "replace"))
    for field in ("name", "displayName"):
        for size in (0, 1, 63, 64, 65):
            vectors.append((f"user-{field}-length-{size}", (3, field), "x" * size, 0, "replace"))
        vectors.append((f"user-{field}-UTF8-cut", (3, field), "é" * 33, 0, "replace"))
        for value in ("\x00", "a\x00b", "é" * 31 + "xé"):
            vectors.append((f"user-{field}-opaque-" + value.encode().hex(), (3, field), value, 0, "replace"))
    for label, path, value, expected, operation in vectors:
        with session.case("fido.make.fields." + label, ("F11", "F12", "F14", "G01", "G03", "G04", "G08", "G14"),
                          effects=("create_resident_credentials",), touch=True, parameters={"path": list(path), "defect": label}):
            session.require(session.profile == "rsk", "registration bounds require RS-Key", "excluded_by_profile")
            with owned(session) as store:
                control = store.create(session.current.name + ".control")
                request = base(session, session.current.name)
                if path == (1,) and expected != 0:
                    request.pop(8, None)
                    request.pop(9, None)
                parent = request
                for key in path[:-1]:
                    parent = parent[key]
                if operation == "omit":
                    del parent[path[-1]]
                else:
                    parent[path[-1]] = value
                if path == (2, "id") and value is not None and value:
                    authorize(session, request, 1, value, request[1], 8, 9)
                if expected != 0:
                    # A parser/length failure must precede crypto; keep its valid control separate.
                    response = session.ctap(1, request)
                    session.check("single registration field defect cause", (response.protocol, response.status), ("applet_error", expected))
                    control.assertion(session)
                    continue
                if path[0] == 3 and path[-1] in ("name", "displayName"):
                    request[7]["rk"] = True
                got = attempt(session, store, request, expected)
                session.check("successful field boundary retains key", got is not None)
                if path[0] == 3 and path[-1] in ("name", "displayName"):
                    expected_text = value.encode()[:64].decode("utf-8", errors="ignore")
                    session.check("user text truncates at complete UTF8 codepoints", user_rows(session, got)[0][6][path[-1]], expected_text)
                control.assertion(session)


def encoding(session):
    for defect in ("truncated", "trailing", "duplicate-key", "reordered-keys", "indefinite-map", "wide-map-length", "wide-key"):
        with session.case("fido.make.encoding." + defect, ("F11", "G05", "G06", "G14"), effects=("create_resident_credentials",), touch=True):
            session.require(session.profile == "rsk", "CBOR encoding behavior is profiled for RS-Key", "excluded_by_profile")
            with owned(session) as store:
                control = store.create(session.current.name + ".control")
                request = base(session, session.current.name)
                def encoded(fields):
                    entries = [(codec.encode(key), codec.encode(value)) for key, value in sorted(fields.items())]
                    if defect == "duplicate-key":
                        entries.append(entries[-1])
                    elif defect == "reordered-keys":
                        entries[-2:] = reversed(entries[-2:])
                    elif defect == "wide-key":
                        entries[-1] = (b"\x18" + bytes([max(fields)]), entries[-1][1])
                    body = b"".join(key + value for key, value in entries)
                    head = bytes([0xA0 | len(entries)])
                    if defect == "indefinite-map":
                        return b"\xbf" + body + b"\xff"
                    wire = (b"\xb8" + bytes([len(entries)]) if defect == "wide-map-length" else head) + body
                    return wire[:-1] if defect == "truncated" else wire + b"\x00" if defect == "trailing" else wire
                attempt(session, store, request, 0 if defect in ("wide-map-length", "wide-key") else 0x12, raw=encoded)
                control.assertion(session)


def extensions(session):
    for resident in (False, True):
        for level in (1, 2, 3):
            for uv in (False, True):
                with session.case(f"fido.credProtect.exclude.rk-{resident}.level-{level}.UV-{uv}", ("FE01", "F11", "G10", "G14"), effects=("create_resident_credentials",), touch=True):
                    session.require("credProtect" in info(session).get(2, []), "credProtect not advertised", "unknown")
                    session.require(not info(session).get(4, {}).get("alwaysUv"), "non-UV exclusion visibility requires a policy allowing non-UV registration")
                    with credential(session, session.current.name, resident, {"credProtect": level}) as fixture:
                        request = base(session, session.current.name + ".excluded", uv)
                        request[2]["id"] = fixture.rp
                        request[5] = [fixture.descriptor]
                        if uv:
                            authorize(session, request, 1, fixture.rp, request[1], 8, 9)
                        reply = session.ctap(1, request)
                        expected = 0x19 if uv or level != 3 else 0
                        session.check("credProtect excludeList visibility", reply.status, expected)
                        fixture.assertion(session)
    for version in (1, 2):
        for opted in (None, False, True):
            with session.case(f"fido.hmac-secret-mc.opt-in-{opted}.protocol-{version}", ("FE03", "FE04", "G01", "G14"), effects=("create_resident_credentials",), touch=True):
                session.require("hmac-secret-mc" in info(session).get(2, []), "registration HMAC not advertised", "unknown")
                protocol, fields = hmac_request(session, version, session.fixture("hmac.registration.salt", 32))
                with owned(session) as store:
                    control = store.create(session.current.name + ".control")
                    request = base(session, session.current.name)
                    request[6] = {"hmac-secret-mc": fields}
                    if opted is not None:
                        request[6]["hmac-secret"] = opted
                    made = attempt(session, store, request, 0 if opted else 0x14)
                    if made:
                        output = protocol.decrypt(made.parsed["extensions"]["hmac-secret-mc"])
                        fresh, again = hmac_request(session, version, session.fixture("hmac.registration.salt", 32))
                        _, signed = made.assertion(session, extensions={"hmac-secret": again})
                        session.check("registration output matches later UV HMAC result", fresh.decrypt(signed["extensions"]["hmac-secret"]), output)
                    control.assertion(session)
    for value in (False, True):
        with session.case(f"fido.largeBlobKey.nonresident.{value}", ("FE05", "F11", "G14"), effects=("create_resident_credentials",), touch=True):
            session.require("largeBlobKey" in info(session).get(2, []), "largeBlobKey not advertised", "unknown")
            with owned(session) as store:
                control = store.create(session.current.name + ".control")
                request = base(session, session.current.name)
                request[6] = {"largeBlobKey": value}
                attempt(session, store, request, 0x2C)
                control.assertion(session)


def run(session):
    options(session)
    fields(session)
    encoding(session)
    extensions(session)
