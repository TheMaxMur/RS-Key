# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Assertion field boundaries are exercised against retained private credentials."""
from . import codec
from .fido import auth_data, info, verified
from .fido_fixtures import credential


def vectors(resident):
    for key in (1, 2, 3, 4, 5):
        yield f"omit-{key}", key, None, 0x14 if key in (1, 2) else 0 if key != 3 or resident else 0x2e, True
    yield "empty-allowList", 3, [], 0x2e, False
    for size in (0, 1, 31, 32, 33, 63, 64, 65):
        yield f"hash-length-{size}", 2, b"h" * size, 0 if size == 32 else 3, False
    for size in (0, 1, 252, 253, 254, 255, 256, 1024):
        yield f"RP-bytes-{size}", 1, "x" * size, 3 if size == 0 else 0x2e, False
    for text in (" ", " rp.invalid", "rp.invalid ", "rp\t.invalid", "rp\n.invalid", "rp\r.invalid", "rp\v.invalid", "rp\f.invalid", "\u00a0", "\u0000", "\u00e9" * 128):
        yield "RP-text-" + text.encode().hex(), 1, text, 2 if any(c in " \t\n\r\v\f" for c in text) else 0x2e, False
    for key, value in ((4, {}), (4, {"unknown": [1, None, b"x"]}), (5, {}), (5, {"up": False, "unknown": [False]}),
                       (5, {"rk": True, "up": False}), (5, {"rk": False, "up": False})):
        yield "map-" + str(key) + "-" + codec.encode(value).hex(), key, value, 0x2b if value.get("rk") is True else 0, False


def signature(session, fixture, result, challenge):
    value = session.ctap_value(result)
    signed = auth_data(value[2])
    session.check("accepted assertion retains exact credential reference", value[1]["id"], fixture.descriptor["id"])
    session.check("accepted assertion retains the fixture RP", signed["rp_hash"], fixture.parsed["rp_hash"])
    verified(session, "boundary assertion signature covers the actual clientDataHash", fixture.key, fixture.algorithm, value[3], value[2] + challenge)


def fields(session):
    for resident in (False, True):
        for label, key, value, expected, omit in vectors(resident):
            with session.case(f"fido.assertion.fields.rk-{resident}.{label}", ("F12", "FE13", "G01", "G03", "G04", "G08", "G13", "G14"),
                    effects=("create_fido_credential",), touch=True, parameters={"field": key, "defect": label, "resident": resident}):
                session.require(session.profile == "rsk", "assertion boundary outcomes require RS-Key", "excluded_by_profile")
                session.require(not info(session).get(4, {}).get("alwaysUv"), "omitted options need a profile permitting non-UV assertions")
                with credential(session, session.current.name, resident) as fixture:
                    before = fixture.assertion(session)[1]["counter"]
                    query = fixture.query(session, authenticate=False, options={"up": False, "uv": False}, extensions={})
                    if omit:
                        query.pop(key)
                    else:
                        query[key] = value
                    result = session.ctap(2, query)
                    session.check("assertion single-field boundary has the exact outcome", result.status, expected)
                    if expected == 0:
                        signature(session, fixture, result, query[2])
                    after = fixture.assertion(session)[1]["counter"]
                    session.check("field refusal cannot consume a credential counter", after - before, (2 if expected == 0 else 1) if resident else 0)


def authentication(session):
    for version in (1, 2):
        for defect in ("omit-auth", "omit-protocol", "empty-auth", "short-auth", "long-auth", "wrong-auth", "zero-protocol", "unknown-protocol", "overflow-protocol"):
            with session.case(f"fido.assertion.auth.protocol-{version}.{defect}", ("F02", "F09", "F12", "G01", "G03", "G04", "G10", "G13", "G14"),
                    effects=("create_fido_credential",), touch=True):
                session.require(session.profile == "rsk", "assertion authorization order requires RS-Key", "excluded_by_profile")
                with credential(session, session.current.name, True) as fixture:
                    query = fixture.query(session, options={"up": False})
                    from .fido import pin_token, token_mac
                    _, token = pin_token(session, 2, fixture.rp, version)
                    query[6], query[7] = token_mac(version, token, fixture.challenge), version
                    retries = session.ctap_value(session.ctap(6, {1: version, 2: 1}))[3]
                    expected = 0x33
                    if defect == "omit-auth":
                        del query[6]
                        expected = 0
                    elif defect == "omit-protocol":
                        del query[7]
                        expected = 0x14
                    elif defect == "empty-auth":
                        query[6] = b""
                        expected = 0x31
                    elif defect == "short-auth":
                        query[6] = query[6][:-1]
                    elif defect == "long-auth":
                        query[6] += b"x"
                    elif defect == "wrong-auth":
                        query[6] = bytes([query[6][0] ^ 1]) + query[6][1:]
                    else:
                        query[7] = {"zero-protocol": 0, "unknown-protocol": 3, "overflow-protocol": 0x100000000}[defect]
                        expected = 0x12 if defect == "overflow-protocol" else 2
                    result = session.ctap(2, query)
                    session.check("assertion auth field has the exact isolated refusal", result.status, expected)
                    if expected == 0:
                        signature(session, fixture, result, fixture.challenge)
                    session.check("selection probes and invalid MACs spend no PIN retries", session.ctap_value(session.ctap(6, {1: version, 2: 1}))[3], retries)
                    fixture.assertion(session)


def run(session):
    fields(session)
    authentication(session)
