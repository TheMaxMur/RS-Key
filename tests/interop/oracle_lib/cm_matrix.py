# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Every CM subcommand starts from a populated store and correctly scoped MAC."""
import hashlib
import copy
from itertools import product

from . import codec
from .config_grammar import RAW_LIMIT
from .credential_matrix import metadata, owned, user_rows
from .fido import cm, info, pin_token, token_mac
from .timers import wait

AUTH = ("valid", "missing-auth", "missing-protocol", "empty-auth", "one-byte-auth", "short-auth", "long-auth", "bad-MAC",
    "zero-protocol", "unknown-protocol", "overflow-protocol", "wrong-permission", "readonly", "revoked", "expired")


def vectors(sub):
    for defect in AUTH:
        yield defect, None, None
    yield "missing-subcommand", None, None
    yield "unknown-extra-field", (100,), {"ignored": [False, None]}
    if sub in (4, 6, 7):
        yield "missing-parameters", (2,), None
        yield "empty-parameters", (2,), {}
    if sub == 4:
        yield "missing-RP-hash", (2, 1), None
        for size in (0, 1, 31, 32, 33):
            yield "RP-hash-width-" + str(size), (2, 1), size
    if sub in (6, 7):
        yield "missing-descriptor", (2, 2), None
        yield "missing-credential-ID", (2, 2, "id"), None
        for size in (0, 1, 41, 42, 43, 747, 748, 749):
            yield "foreign-credential-width-" + str(size), (2, 2, "id"), size
        for size in (RAW_LIMIT - 1, RAW_LIMIT, RAW_LIMIT + 1):
            yield "raw-parameters-width-" + str(size), (2, 2, "id"), size
    if sub == 7:
        yield "missing-user", (2, 3), None
        yield "missing-user-ID", (2, 3, "id"), None
        for size in (0, 1, 2, 63, 64, 65):
            yield "different-user-ID-width-" + str(size), (2, 3, "id"), bytes(size)
        for field in ("name", "displayName"):
            yield "omitted-user-" + field, (2, 3, field), None
            for text in ("", "x", "x" * 63, "x" * 64, "x" * 65, "é" * 33, "😀" * 17, "a\x00b"):
                yield "user-" + field + "-" + text.encode().hex(), (2, 3, field), text


def run(session):
    for version, sub in product((1, 2), range(1, 8)):
        for defect, path, value in vectors(sub):
            with session.case(f"fido.CM.complete-fields.protocol-{version}.sub-{sub}.{defect}", ("F14", "F15", "F16", "F17", "F18", "G01", "G03", "G04", "G08", "G09", "G10", "G11", "G13", "G14"),
                    effects=("create_resident_credentials",), touch=True, parameters={"subcommand": sub, "field_path": list(path or ()), "defect": defect}):
                session.require(session.profile == "rsk", "CM field and validation-order expectations require RS-Key", "excluded_by_profile")
                session.require(session.options.pin and info(session).get(4, {}).get("perCredMgmtRO") and not info(session).get(12), "known host PIN and persistent listing grant without force-change required")
                session.require(defect != "expired" or session.options.timeout > 31, "expired grant/walk controls require a full 30-second idle interval")
                session.require(metadata(session)[1] == 0, "exact RP and credential continuation witnesses require an empty resident fixture store")
                with owned(session) as store:
                    target = store.create(session.current.name + ".target")
                    sibling = store.create(session.current.name + ".sibling", rp=target.rp)
                    neighbor = store.create(session.current.name + ".neighbor")
                    original_rows = {row[7]["id"]: row[6] for row in user_rows(session, target)}
                    parameters = {1: hashlib.sha256(target.rp.encode()).digest()} if sub == 4 else {
                        2: target.descriptor, **({3: {**original_rows[target.descriptor["id"]], "name": "Oracle CM updated", "displayName": "Oracle CM changed"}} if sub == 7 else {})} if sub in (6, 7) else None
                    fields = {1: sub, 3: version}
                    if parameters is not None:
                        fields[2] = copy.deepcopy(parameters)
                    if path:
                        parent = fields
                        for key in path[:-1]:
                            parent = parent[key]
                        if value is None:
                            parent.pop(path[-1], None)
                        else:
                            replacement = value
                            if defect.startswith("RP-hash-width-"):
                                replacement = hashlib.sha256(target.rp.encode()).digest() if value == 32 else bytes(value)
                            elif defect.startswith("foreign-credential-width-"):
                                replacement = session.fixture("CM.other-reference", value)
                            elif defect.startswith("raw-parameters-width-"):
                                replacement = None
                                for size in range(value + 1):
                                    parent[path[-1]] = session.fixture("CM.raw-parameter-reference", size)
                                    if len(codec.encode(fields[2])) == value:
                                        replacement = parent[path[-1]]
                                        break
                                session.check("raw CM parameter bound is represented exactly", replacement is not None)
                            parent[path[-1]] = replacement
                    permission = 2 if defect == "wrong-permission" else 64 if defect == "readonly" else 4
                    proto, token = pin_token(session, permission, version=version)
                    payload = bytes([sub]) + (codec.encode(fields[2]) if sub in (4, 6, 7) and 2 in fields else b"")
                    fields[4] = token_mac(proto, token, payload)
                    if defect == "revoked":
                        pin_token(session, 4, version=version)
                    starter = pin_token(session, 64, version=version)
                    if defect == "missing-auth":
                        del fields[4]
                    elif defect == "missing-protocol":
                        del fields[3]
                    elif defect in ("empty-auth", "one-byte-auth", "short-auth", "long-auth", "bad-MAC"):
                        fields[4] = b"" if defect == "empty-auth" else fields[4][:1] if defect == "one-byte-auth" else fields[4][:-1] if defect == "short-auth" else fields[4] + b"x" if defect == "long-auth" else bytes([fields[4][0] ^ 1]) + fields[4][1:]
                    elif defect.endswith("protocol"):
                        fields[3] = {"zero-protocol": 0, "unknown-protocol": 3, "overflow-protocol": 2**32}[defect]
                    elif defect == "missing-subcommand":
                        del fields[1]
                    # Establish all channels/grants before Begin so they cannot retire the walk.
                    begin = 4 if sub == 5 else 2
                    first = session.ctap_value(cm(session, *starter, begin, {1: hashlib.sha256(target.rp.encode()).digest()} if begin == 4 else None))
                    session.check("CM control starts a real two-row continuation", first[9 if begin == 4 else 5], 2)
                    retries = session.ctap_value(session.ctap(6, {1: version, 2: 1})) if sub not in (3, 5) else None
                    if sub not in (3, 5):
                        # ClientPIN is itself an interruption, so restore the cursor afterward.
                        session.ctap_value(cm(session, *starter, 2))
                    if defect == "expired":
                        wait(session, 30.25)
                    expected = 0
                    if defect == "overflow-protocol":
                        expected = 0x12
                    elif defect == "missing-subcommand":
                        expected = 0x14
                    elif sub in (3, 5):
                        expected = 0x30 if defect == "expired" else 0
                    elif defect == "missing-auth":
                        expected = 0x36
                    elif defect == "missing-protocol":
                        expected = 0x14
                    elif defect in ("zero-protocol", "unknown-protocol"):
                        expected = 2
                    elif defect in ("empty-auth", "one-byte-auth", "short-auth", "long-auth", "bad-MAC", "wrong-permission", "revoked", "expired") or defect == "readonly" and sub in (6, 7):
                        expected = 0x33
                    elif defect in ("missing-parameters", "empty-parameters", "missing-RP-hash", "missing-descriptor", "missing-credential-ID", "missing-user", "missing-user-ID") or defect.startswith("RP-hash-width-") and value != 32:
                        expected = 0x14
                    elif sub in (4, 6, 7) and len(codec.encode(fields.get(2, {}))) > RAW_LIMIT:
                        expected = 0x39
                    elif defect.startswith(("foreign-credential-width-", "raw-parameters-width-")):
                        expected = 0x2e
                    elif defect.startswith("different-user-ID-width-"):
                        expected = 2
                    response = session.ctap(10, fields)
                    session.check("CM single field/grant defect has its isolated exact result", response.status, expected)
                    if sub in (3, 5) and expected == 0:
                        row = session.ctap_value(response)
                        if sub == 3:
                            session.check("RP continuation binds its actual hash", row[4], hashlib.sha256(row[3]["id"].encode()).digest())
                        else:
                            session.check("credential continuation returns an owned key and exact user", row[6], original_rows[row[7]["id"]])
                        session.check("successful Next exhausts the initialized two-row cursor", cm(session, *starter, sub).status, 0x30)
                    elif sub == 2 and expected == 0:
                        row = session.ctap_value(cm(session, *starter, 3))
                        session.check("new RP Begin replaces the old walk and retains a valid second RP", row[4], hashlib.sha256(row[3]["id"].encode()).digest())
                        session.check("new RP Begin exhausts exactly its own two rows", cm(session, *starter, 3).status, 0x30)
                    elif sub not in (3, 5) and expected not in (0x12, 0x14):
                        session.check("parsed non-Next command retires the old walk even on auth refusal", cm(session, *starter, 3).status, 0x30)
                    if sub == 6 and expected == 0:
                        target.deleted = True
                        store.live.pop(target.descriptor["id"])
                        session.check("successful CM DELETE revokes the original private reference", session.ctap(2, target.query(session)).status, 0x2e)
                    else:
                        target.assertion(session)
                    session.check("CM field and auth controls preserve exact resident occupancy", metadata(session)[1], 2 if sub == 6 and expected == 0 else 3)
                    rows = {row[7]["id"]: row[6] for row in user_rows(session, sibling)}
                    if sub == 6 and expected == 0:
                        original_rows.pop(target.descriptor["id"])
                    elif sub == 7 and expected == 0:
                        user = fields[2][3]
                        original_rows[target.descriptor["id"]] = {key: child if key == "id" else child.encode()[:64].decode("utf-8", errors="ignore") for key, child in user.items() if child}
                    session.check("CM refusals/updates preserve the exact complete user catalog", rows, original_rows)
                    sibling.assertion(session)
                    neighbor.assertion(session)
                    if retries is not None:
                        session.check("CM probes do not consume host PIN retries", session.ctap_value(session.ctap(6, {1: version, 2: 1})), retries)
