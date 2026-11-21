# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Credential-bound extension variants; unsigned outputs stay separate from authData."""
import hashlib
import zlib

from . import codec
from .fido import auth_data, authorize, cm, info, pin_protocol, pin_token
from .fido_fixtures import credential


def supported(session, name):
    session.require(name in info(session).get(2, []), name + " not advertised; no support inference", "unknown")


def cred_protect(session):
    for level in (1, 2, 3):
        for resident in (False, True):
            with session.case(f"fido.credProtect.{level}.rk-{resident}", ("FE01", "F11", "F12", "G10", "G14"), effects=("create_fido_credential",), touch=True):
                supported(session, "credProtect")
                with credential(session, session.current.name, resident, {"credProtect": level}) as fixture:
                    session.check("credProtect echoed in signed registration", fixture.parsed["extensions"]["credProtect"], level)
                    fixture.assertion(session)
                    for allow in ([fixture.descriptor], []):
                        if not allow and not resident:
                            continue
                        query = fixture.query(session, allow=allow, options={"up": False, "uv": False}, authenticate=False)
                        if not allow:
                            del query[3]
                        result = session.ctap(2, query)
                        session.observe("without_UV." + ("allowList" if allow else "discoverable"), result.status)
                        if result.protocol == "success":
                            signed = auth_data(session.ctap_value(result)[2])
                            session.check("credProtect visibility without UV", level == 1 or level == 2 and bool(allow) or bool(signed["flags"] & 4))
                        if session.profile == "rsk" and not info(session).get(4, {}).get("alwaysUv"):
                            visible = level == 1 or level == 2 and bool(allow)
                            session.check("credProtect profile visibility", result.status, 0 if visible else 0x2E)
                        fixture.assertion(session)


def cred_blob(session):
    for size in (0, 1, 31, 32, 33, 127, 128, 129):
        for resident in (False, True):
            with session.case(f"fido.credBlob.{size}.rk-{resident}", ("FE02", "G03", "F18", "G14"), effects=("create_fido_credential",), touch=True):
                supported(session, "credBlob")
                maximum = info(session).get(15, 32)
                blob = session.fixture("credBlob", size)
                with credential(session, session.current.name, resident, {"credBlob": blob}) as fixture:
                    stored = fixture.parsed.get("extensions", {}).get("credBlob")
                    session.check("credBlob registration storage result", stored, size <= maximum)
                    _, signed = fixture.assertion(session, extensions={"credBlob": True})
                    session.check("credBlob signed readback", signed.get("extensions", {}).get("credBlob"), blob if stored else b"")
                    if resident:
                        version, token = pin_token(session, 4)
                        session.ctap_value(cm(session, version, token, 7, {2: fixture.descriptor, 3: {"id": session.fixture(session.current.name + ".user", 16), "name": "updated"}}))
                        _, signed = fixture.assertion(session, extensions={"credBlob": True})
                        session.check("credBlob survives user update", signed.get("extensions", {}).get("credBlob"), blob if stored else b"")


def hmac_mc(session):
    for version in (1, 2):
        for count in (1, 2):
            with session.case(f"fido.hmac-secret-mc.protocol-{version}.salts-{count}", ("FE04", "FE03", "G14"), effects=("create_fido_credential",), touch=True):
                supported(session, "hmac-secret-mc")
                protocol = pin_protocol(session, version)
                salts = session.fixture("hmac-mc.salts", 32 * count)
                encrypted = protocol.encrypt(salts)
                fields = {1: protocol.cose, 2: encrypted, 3: protocol.authenticate(encrypted), 4: version}
                with credential(session, session.current.name, extensions={"hmac-secret": True, "hmac-secret-mc": fields}) as fixture:
                    registered = protocol.decrypt(fixture.parsed["extensions"]["hmac-secret-mc"])
                    session.check("hmac-secret-mc output width", len(registered), len(salts))
                    fresh = pin_protocol(session, version)
                    encrypted = fresh.encrypt(salts)
                    query = {1: fresh.cose, 2: encrypted, 3: fresh.authenticate(encrypted), 4: version}
                    _, signed = fixture.assertion(session, extensions={"hmac-secret": query})
                    session.check("registration and assertion HMAC match", fresh.decrypt(signed["extensions"]["hmac-secret"]), registered)
                    for defect in ("MAC", "point", "length"):
                        invalid = dict(query)
                        if defect == "MAC":
                            invalid[3] = bytes(len(invalid[3]))
                        elif defect == "point":
                            invalid[1] = {**fresh.cose, -2: bytes(32), -3: bytes(32)}
                        else:
                            invalid[2] = encrypted[:-1]
                        result = session.ctap(2, fixture.query(session, extensions={"hmac-secret": invalid}))
                        session.check("invalid HMAC " + defect + " refused", result.protocol, "applet_error")
                        control = pin_protocol(session, version)
                        encrypted_control = control.encrypt(salts)
                        control_fields = {1: control.cose, 2: encrypted_control, 3: control.authenticate(encrypted_control), 4: version}
                        _, checked = fixture.assertion(session, extensions={"hmac-secret": control_fields})
                        session.check("HMAC secret survives rejected input", control.decrypt(checked["extensions"]["hmac-secret"]), registered)


def payment_uvm(session):
    for enabled in (False, True):
        for resident in (False, True):
            with session.case(f"fido.thirdPartyPayment.{enabled}.rk-{resident}", ("FE09", "FE08", "G02", "G14"), effects=("create_fido_credential",), touch=True):
                supported(session, "thirdPartyPayment")
                with credential(session, session.current.name, resident, {"thirdPartyPayment": enabled, "uvm": True}) as fixture:
                    session.check("payment flag has no registration output", "thirdPartyPayment" not in fixture.parsed.get("extensions", {}))
                    _, signed = fixture.assertion(session, extensions={"thirdPartyPayment": True, "uvm": True})
                    session.check("stored payment opt-in", signed["extensions"]["thirdPartyPayment"], enabled)
                    methods = signed["extensions"].get("uvm")
                    if "uvm" in info(session).get(2, []):
                        session.check("uvm factor triples", isinstance(methods, list) and bool(methods) and all(len(row) == 3 and all(isinstance(item, int) for item in row) for row in methods))
                        factors = {row[0] for row in methods}
                        session.check("uvm presence agrees with signed UP", (1 in factors), bool(signed["flags"] & 1))
                        session.check("uvm verification agrees with signed UV", bool(factors - {1, 512}), bool(signed["flags"] & 4))
                    for invalid in (None, 0, "true", [], {}):
                        result = session.ctap(2, fixture.query(session, extensions={"thirdPartyPayment": invalid}))
                        session.check("payment invalid type refused", result.protocol, "applet_error")
                        fixture.assertion(session)


def large_blob(session):
    for resident in (False, True):
        for support in ("preferred", "required"):
            with session.case(f"fido.largeBlob-extension.{support}.rk-{resident}", ("FE06", "FE05", "G03", "G14"), effects=("create_fido_credential",), touch=True):
                supported(session, "largeBlob")
                if not resident and support == "required":
                    challenge, rp = session.fixture("largeBlob.refusal.hash"), "largeblob-required.oracle.invalid"
                    request = {1: challenge, 2: {"id": rp}, 3: {"id": b"oracle"},
                               4: [{"type": "public-key", "alg": -7}], 7: {"rk": False},
                               6: {"largeBlob": {"support": "required"}}}
                    authorize(session, request, 1, rp, challenge, 8, 9)
                    session.check("required blob storage cannot be silently unmet", session.ctap(1, request).status, 0x18)
                    session.ctap_value(session.ctap(4))
                    continue
                with credential(session, session.current.name, resident, {"largeBlob": {"support": support}}) as fixture:
                    session.check("largeBlob support is unsigned", "largeBlob" not in fixture.parsed.get("extensions", {}))
                    session.check("largeBlob storage capability", fixture.registration.get(6, {}).get("largeBlob", {}).get("supported", False), resident)
                    for size in (0, 1, 31, 32, 255, 256, 1024):
                        plain = session.fixture("largeBlob.plain", size)
                        compressor = zlib.compressobj(wbits=-15)
                        compressed = compressor.compress(plain) + compressor.flush()
                        value, _ = fixture.assertion(session, extensions={"largeBlob": {"write": compressed, "originalSize": size}})
                        session.check("largeBlob write result", value.get(8, {}).get("largeBlob", {}).get("written"), resident)
                        if resident:
                            value, _ = fixture.assertion(session, extensions={"largeBlob": {"read": True}})
                            read = value[8]["largeBlob"]
                            session.check("largeBlob original size", read["originalSize"], size)
                            session.check("largeBlob exact compressed bytes", read["blob"], compressed)
                            session.check("largeBlob independent decompression", zlib.decompress(read["blob"], -15), plain)
                    for invalid in ({}, {"read": False}, {"write": b"x"}, {"read": True, "write": b"x", "originalSize": 1}):
                        result = session.ctap(2, fixture.query(session, extensions={"largeBlob": invalid}))
                        session.check("invalid largeBlob CDDL refused", result.status, 0x12)
                        control, _ = fixture.assertion(session, extensions={"largeBlob": {"read": True}})
                        if resident:
                            session.check("largeBlob survives rejected request", control[8]["largeBlob"], {"blob": compressed, "originalSize": size})


def algorithm_preferences(session):
    for algorithms in ((-7, -35), (-35, -7), (0x7FFFFFFF, -7), (-19, -8), (-9, -7), (-51, -35), (-52, -36)):
        with session.case("fido.algorithm-preference." + ".".join(map(str, algorithms)), ("F11", "G04"), effects=("create_fido_credential",), touch=True):
            advertised = {row["alg"] for row in info(session).get(10, [])}
            session.require(session.profile == "rsk" or any(alg in advertised for alg in algorithms), "algorithm list outside confirmed profile", "unknown")
            with credential(session, session.current.name, algorithms=list(algorithms)) as fixture:
                from .fido import RSK_ALGORITHMS
                supported_algorithms = set(RSK_ALGORITHMS) if session.profile == "rsk" else advertised
                expected = next(alg for alg in algorithms if alg in supported_algorithms)
                session.check("first supported algorithm wins preference order", fixture.algorithm, expected)
                fixture.assertion(session)


def run(session):
    cred_protect(session)
    cred_blob(session)
    hmac_mc(session)
    payment_uvm(session)
    large_blob(session)
    algorithm_preferences(session)
