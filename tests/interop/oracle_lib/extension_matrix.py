# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Extension output products and blob lifetime checks use owned credential state."""
from itertools import product

from cryptography import x509

from . import codec
from .fido import auth_data, authorize, info, token_mac, verified
from .fido_fixtures import credential
from .fido_extensions import supported
from .lifecycle import Action, change

MAX_CRED_BLOB = 4078 - 32
LEVELS = (None, False, True)


def formats(session):
    preferences = [None, [], ["none"], ["packed"], ["unknown"], ["none", "packed"], ["packed", "none"], ["none", "none"], [""], ["x" * 255]]
    preferences += [["unknown"] * count + ["packed"] for count in (16, 17, 64, 65, 255, 256)]
    preferences += [[value] for value in (None, False, 0, b"packed", [], {})]
    for index, preference in enumerate(preferences):
        with session.case(f"fido.attestation.format-list-{index}", ("F11", "FE12", "G01", "G02", "G03", "G04", "G14"), effects=("create_fido_credential",), touch=True,
                parameters={"attestationFormatsPreference": preference}):
            session.require(session.profile == "rsk", "format-list decision is profiled for RS-Key", "excluded_by_profile")
            if preference and any(type(item) is not str for item in preference):
                with credential(session, session.current.name + ".control") as fixture:
                    request = {1: fixture.challenge, 2: {"id": fixture.rp}, 3: {"id": b"format-refusal"}, 4: [{"type": "public-key", "alg": -7}], 11: preference}
                    authorize(session, request, 1, fixture.rp, fixture.challenge, 8, 9)
                    session.check("every format list element is type checked", session.ctap(1, request).status, 0x11)
                    fixture.assertion(session)
                continue
            with credential(session, session.current.name, extra={11: preference} if preference is not None else {}) as fixture:
                expected = "none" if preference == ["none"] else "packed"
                session.check("format preference follows the profiled whole-list rule", fixture.registration[1], expected)
                statement = fixture.registration[3]
                if expected == "none":
                    session.check("none format has exactly an empty statement", statement, {})
                else:
                    session.check("packed basic attestation carries a nonempty DER chain", isinstance(statement.get("x5c"), list) and bool(statement["x5c"]))
                    certificates = [x509.load_der_x509_certificate(raw) for raw in statement["x5c"]]
                    verified(session, "chosen attestation certificate signs the registration", certificates[0].public_key(), statement["alg"], statement["sig"], fixture.registration[2] + fixture.challenge)
                fixture.assertion(session)


def payment(session):
    for resident, stored, requested, policy, verification, up in product((False, True), LEVELS, LEVELS, (1, 2, 3), ("none", "host", "local"), (False, True)):
        with session.case(f"fido.payment.rk-{resident}.stored-{stored}.request-{requested}.policy-{policy}.UV-{verification}.up-{up}",
                ("FE01", "FE08", "FE09", "FE11", "FE13", "F12", "G01", "G10", "G14"), effects=("create_fido_credential",), touch=True,
                parameters={"resident": resident, "stored": stored, "requested": requested, "credProtect": policy, "verification": verification, "up": up}):
            supported(session, "thirdPartyPayment")
            supported(session, "uvm")
            if verification == "local":
                from .uv_matrix import ready
                ready(session)
            extensions = {"credProtect": policy}
            if stored is not None:
                extensions["thirdPartyPayment"] = stored
            with credential(session, session.current.name, resident, extensions) as fixture:
                session.check("payment has no signed or unsigned registration output", "thirdPartyPayment" not in fixture.parsed.get("extensions", {}) and "thirdPartyPayment" not in fixture.registration.get(6, {}))
                query = fixture.query(session, authenticate=verification == "host", extensions={"uvm": True, **({"thirdPartyPayment": requested} if requested is not None else {})}, options={"up": up})
                if verification == "local":
                    from .uv_matrix import cue, issue
                    cue(session, "approve local token issuance and enter the CORRECT fixture PIN")
                    _, token = issue(session, 2, 2, fixture.rp)
                    query.update({6: token_mac(2, token, fixture.challenge), 7: 2})
                result = session.ctap(2, query)
                if verification == "none" and policy == 3:
                    session.check("payment cannot disclose a UV-required credential", result.status, 0x2e)
                else:
                    value = session.ctap_value(result)
                    signed = auth_data(value[2])
                    verified(session, "payment and verification outputs are independently signed", fixture.key, fixture.algorithm, value[3], value[2] + fixture.challenge)
                    output = signed.get("extensions", {})
                    session.check("payment output requires an explicit true request", output.get("thirdPartyPayment"), bool(stored) if requested is True else None)
                    factors = ([[1, 2, 4]] if up else []) + ([[4 if verification == "local" else 2048, 2, 4]] if verification != "none" else [] if up else [[512, 2, 4]])
                    session.check("UVM factor list matches actual presence and verification provenance", output.get("uvm"), factors)
                    session.check("payment is never an unsigned GA output", "thirdPartyPayment" not in value.get(8, {}))
                fixture.assertion(session)


def large_blob(session):
    from contextlib import ExitStack
    for lifecycle in ("delete", "replace", *(item.value for item in Action)):
        with session.case("fido.largeBlob.lifecycle." + lifecycle, ("FE06", "FE11", "F11", "F12", "F17", "G09", "G11", "G14", "X11"),
                effects=("create_fido_credential", "reboot") if lifecycle == Action.POWER_CYCLE.value else ("create_fido_credential",), touch=True):
            supported(session, "largeBlob")
            with ExitStack() as stack:
                old = stack.enter_context(credential(session, session.current.name + ".old", True, {"largeBlob": {"support": "required"}}))
                neighbor = stack.enter_context(credential(session, session.current.name + ".neighbor", True, {"largeBlob": {"support": "required"}}))
                bodies = {old.rp: b"old-owned-compressed-blob", neighbor.rp: b"neighbor-compressed-blob"}
                for item in (old, neighbor):
                    value, signed = item.assertion(session, extensions={"largeBlob": {"write": bodies[item.rp], "originalSize": 100}})
                    session.check("largeBlob write appears only in unsigned output", ("largeBlob" in signed.get("extensions", {}), value.get(8, {}).get("largeBlob")), (False, {"written": True}))
                fresh = old
                if lifecycle == "delete":
                    old.delete(session)
                    fresh = stack.enter_context(credential(session, session.current.name + ".new", True, {"largeBlob": {"support": "required"}}))
                elif lifecycle == "replace":
                    fresh = stack.enter_context(credential(session, session.current.name + ".old", True, {"largeBlob": {"support": "required"}}, rp=old.rp))
                    old.deleted = True
                else:
                    change(session, Action(lifecycle))
                if old.deleted:
                    session.check("deleted/replaced reference cannot read its former blob", session.ctap(2, old.query(session, extensions={"largeBlob": {"read": True}})).status, 0x2e)
                for item in (fresh, neighbor):
                    value, signed = item.assertion(session, extensions={"largeBlob": {"read": True}})
                    session.check("largeBlob read never enters signed extensions", "largeBlob" not in signed.get("extensions", {}))
                    expected = None if item is fresh and old.deleted else {"blob": bodies[item.rp], "originalSize": 100}
                    session.check("blob lifetime follows the exact credential rather than a reused slot", value.get(8, {}).get("largeBlob"), expected)


def blob_fields(session):
    shapes = ({}, {"read": False}, {"read": 1}, {"read": b""}, {"write": b""}, {"originalSize": 0},
        {"write": "x", "originalSize": 0}, {"write": b"x", "originalSize": -1}, {"write": b"x", "originalSize": False},
        {"read": True, "write": b"x", "originalSize": 1}, {"read": True, "unknown": True},
        {"write": b"x", "originalSize": 1, "unknown": None})
    for index, fields in enumerate(shapes):
        with session.case(f"fido.largeBlob.grammar-{index}", ("FE06", "G01", "G02", "G04", "G14"), effects=("create_fido_credential",), touch=True):
            supported(session, "largeBlob")
            with credential(session, session.current.name, True, {"largeBlob": {"support": "required"}}) as fixture:
                fixture.assertion(session, extensions={"largeBlob": {"write": b"retained", "originalSize": 15}})
                session.check("invalid largeBlob CDDL refuses before mutation", session.ctap(2, fixture.query(session, extensions={"largeBlob": fields})).status, 0x12)
                value, _ = fixture.assertion(session, extensions={"largeBlob": {"read": True}})
                session.check("malformed blob request preserves the previous exact blob", value[8]["largeBlob"], {"blob": b"retained", "originalSize": 15})
    for size, original in product((0, 1, MAX_CRED_BLOB - 1, MAX_CRED_BLOB, MAX_CRED_BLOB + 1), (0, 0xffffffff, 0x100000000, 0xffffffffffffffff)):
        with session.case(f"fido.largeBlob.bounds.bytes-{size}.original-{original}", ("FE06", "G03", "G04", "G14"), effects=("create_fido_credential",), touch=True):
            supported(session, "largeBlob")
            session.require(session.profile == "rsk", "per-credential blob ceiling requires RS-Key", "excluded_by_profile")
            with credential(session, session.current.name, True, {"largeBlob": {"support": "required"}}) as fixture:
                fixture.assertion(session, extensions={"largeBlob": {"write": b"retained", "originalSize": 15}})
                body = session.fixture("largeBlob.bound", size)
                value, _ = fixture.assertion(session, extensions={"largeBlob": {"write": body, "originalSize": original}})
                accepted = size <= MAX_CRED_BLOB and original <= 0xffffffff
                session.check("blob capacity and integer overflow return written false", value[8]["largeBlob"], {"written": accepted})
                value, _ = fixture.assertion(session, extensions={"largeBlob": {"read": True}})
                session.check("refused blob write retains the exact previous body", value[8]["largeBlob"], {"blob": body, "originalSize": original} if accepted else {"blob": b"retained", "originalSize": 15})


def run(session):
    formats(session)
    payment(session)
    large_blob(session)
    blob_fields(session)
