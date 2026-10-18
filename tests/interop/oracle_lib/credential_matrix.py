# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Resident-store invariants have owned objects and authenticated controls."""
import hashlib
from contextlib import contextmanager

from . import codec
from .fido import auth_data, authorize, cm, info, pin_token, public_key, token_mac
from .fido_fixtures import Credential
from .fido_manage import walk, MAX_ENUMERATION
from .hid_sequences import allocate, hooks


class Residents:
    def __init__(self, session):
        self.session, self.live = session, {}

    def create(self, label, rp=None, user=None, extensions=None):
        s = self.session
        rp = rp or s.fixture(label + ".rp", 8).hex() + ".oracle.invalid"
        challenge = s.fixture(label + ".hash")
        user = user or {"id": s.fixture(label + ".user", 16), "name": "Oracle", "displayName": "Fixture"}
        request = {1: challenge, 2: {"id": rp}, 3: user, 4: [{"type": "public-key", "alg": -7}], 7: {"rk": True}}
        if extensions is not None:
            request[6] = extensions
        authorize(s, request, 1, rp, challenge, 8, 9)
        value = s.ctap_value(s.ctap(1, request))
        parsed = auth_data(value[2])
        item = Credential(rp, {"type": "public-key", "id": parsed["credential_id"]}, public_key(parsed["cose"]), -7, value, parsed, challenge)
        self.live[item.descriptor["id"]] = item
        return item

    def delete(self, fixture):
        s = self.session
        version, token = pin_token(s, 4)
        s.ctap_value(cm(s, version, token, 6, {2: fixture.descriptor}))
        del self.live[fixture.descriptor["id"]]


@contextmanager
def owned(session):
    session.require(info(session).get(4, {}).get("rk") and info(session).get(4, {}).get("credMgmt") and session.options.pin,
                    "owned resident fixtures require rk, credMgmt and a configured PIN")
    store = Residents(session)
    try:
        yield store
    finally:
        if not session.broken:
            session.trace.phase = "cleanup"
            for item in list(store.live.values()):
                store.delete(item)


def metadata(session):
    version, token = pin_token(session, 4)
    return session.ctap_value(cm(session, version, token, 1))


def user_rows(session, fixture):
    version, token = pin_token(session, 4)
    return walk(session, version, token, 4, 5, 9, {1: hashlib.sha256(fixture.rp.encode()).digest()})


def mutations(session):
    for operation in (6, 7):
        for defect in ("missing-auth", "wrong-permission", "bad-MAC", "readonly-token", "wrong-RP", "unknown-ID", "missing-ID",
                       "missing-user", "different-user", "short-user", "long-user"):
            if operation == 6 and defect.endswith("user"):
                continue
            with session.case(f"fido.CM.{operation}.{defect}", ("F06", "F10", "F14", "F16", "F17", "F18", "G01", "G03", "G09", "G10", "G14"),
                              effects=("create_resident_credentials",), touch=True):
                session.require(session.profile == "rsk", "credential-management rejection catalog requires RS-Key", "excluded_by_profile")
                with owned(session) as store:
                    fixture = store.create(session.current.name)
                    user = {"id": session.fixture(session.current.name + ".user", 16), "name": "Updated"}
                    before, rows = metadata(session), user_rows(session, fixture)
                    permission = 2 if defect == "wrong-permission" else 64 if defect == "readonly-token" else 4
                    session.require(permission != 64 or info(session).get(4, {}).get("perCredMgmtRO"), "persistent read-only permission not advertised", "unknown")
                    version, token = pin_token(session, permission, "foreign.oracle.invalid" if defect == "wrong-RP" else None)
                    parameters = {2: dict(fixture.descriptor)}
                    if operation == 7:
                        parameters[3] = dict(user)
                    if defect == "unknown-ID":
                        parameters[2]["id"] = session.fixture("CM.unknown", len(fixture.descriptor["id"]))
                    elif defect == "missing-ID":
                        del parameters[2]["id"]
                    elif defect == "missing-user":
                        del parameters[3]
                    elif defect in ("different-user", "short-user", "long-user"):
                        parameters[3]["id"] = b"foreign" if defect == "different-user" else user["id"][:-1] if defect == "short-user" else user["id"] + b"x"
                    message = bytes([operation]) + codec.encode(parameters)
                    fields = {1: operation, 2: parameters, 3: version, 4: token_mac(version, token, message)}
                    if defect == "missing-auth":
                        fields.pop(4)
                    if defect == "bad-MAC":
                        fields[4] = bytes([fields[4][0] ^ 1]) + fields[4][1:]
                    outcome = session.ctap(10, fields)
                    session.check("CM invalid mutation refused", outcome.protocol, "applet_error")
                    session.check("CM refusal preserves populated metadata", metadata(session), before)
                    session.check("CM refusal preserves exact user information", user_rows(session, fixture), rows)
                    fixture.assertion(session)
                    version, token = pin_token(session, 4)
                    if operation == 7:
                        session.ctap_value(cm(session, version, token, 7, {2: fixture.descriptor, 3: user}))
                        updated = user_rows(session, fixture)[0][6]
                        session.check("authorized user update succeeds after refusal", updated["name"], "Updated")
                        session.check("user update preserves user ID", updated["id"], user["id"])
                        fixture.assertion(session)
                    else:
                        store.delete(fixture)
                        for _ in range(2):
                            version, token = pin_token(session, 4)
                            session.check("repeated deletion refuses absent ID", cm(session, version, token, 6, {2: fixture.descriptor}).status, 0x2E)
                        session.check("deleted ID no longer authenticates", session.ctap(2, fixture.query(session)).status, 0x2E)
                        session.check("deletion reclaims exactly one credential", metadata(session)[1], before[1] - 1)


def replacement(session):
    for relation in ("same-RP-same-user", "same-RP-different-user", "different-RP-same-user"):
        with session.case("fido.resident.replacement." + relation, ("F11", "F12", "F14", "F16", "F17", "FE14", "G09", "G14"),
                          effects=("create_resident_credentials",), touch=True):
            session.require(session.profile == "rsk", "resident replacement semantics are profiled for RS-Key", "excluded_by_profile")
            with owned(session) as store:
                before = metadata(session)
                first = store.create(session.current.name + ".first")
                rp = first.rp if relation != "different-RP-same-user" else None
                user = {"id": session.fixture(session.current.name + ".first.user", 16)} if relation != "same-RP-different-user" else None
                second = store.create(session.current.name + ".second", rp=rp, user=user)
                replaced = relation == "same-RP-same-user"
                if replaced:
                    del store.live[first.descriptor["id"]]
                    session.check("replaced credential ID cannot authenticate", session.ctap(2, first.query(session)).status, 0x2E)
                else:
                    first.assertion(session)
                second.assertion(session)
                session.check("replacement count matches RP and user identity", metadata(session)[1], before[1] + (1 if replaced else 2))


def walks(session):
    for kind in ("RP", "credential"):
        for interruption in ("complete", "delete", "create", "other-CID"):
            with session.case(f"fido.CM.walk.{kind}.{interruption}", ("F13", "F14", "F15", "F16", "G09", "G11", "G12", "G14"),
                              effects=("create_resident_credentials",), touch=True):
                session.require(session.profile == "rsk", "cursor retirement contract requires RS-Key", "excluded_by_profile")
                if interruption == "other-CID":
                    session.require(session.hid is not None and hasattr(session.hid, "cid") and hasattr(session.hid, "send_only"), "raw allocated CID backend required", "excluded_by_mode")
                with owned(session) as store:
                    first = store.create(session.current.name + ".0")
                    fixtures = [first] + [store.create(session.current.name + f".{i}", rp=first.rp if kind == "credential" else None) for i in (1, 2)]
                    other = None
                    if interruption == "other-CID":
                        with hooks(session):
                            other = allocate(session)
                    version, token = pin_token(session, 4)
                    begin, following, count = (2, 3, 5) if kind == "RP" else (4, 5, 9)
                    parameters = None if kind == "RP" else {1: hashlib.sha256(first.rp.encode()).digest()}
                    initial = session.ctap_value(cm(session, version, token, begin, parameters))
                    session.check("owned walk has multiple entries", initial[count] >= 3)
                    if interruption == "delete":
                        store.delete(fixtures[-1])
                    elif interruption == "create":
                        store.create(session.current.name + ".added", rp=first.rp if kind == "credential" else None)
                    elif interruption == "other-CID":
                        owner = session.hid.cid
                        try:
                            session.hid.cid = other
                            foreign = cm(session, version, token, following)
                            session.check("foreign CID cannot continue owned CM walk", foreign.status, 0x30)
                        finally:
                            session.hid.cid = owner
                        owner_next = session.ctap_value(cm(session, version, token, following))
                        session.check("owner continues after refused foreign CID", (4 if kind == "RP" else 7) in owner_next)
                    if interruption in ("create", "delete"):
                        session.check("mutation retires pending CM walk", cm(session, version, token, following).status, 0x30)
                    elif interruption == "complete":
                        rows = [initial] + [session.ctap_value(cm(session, version, token, following)) for _ in range(initial[count] - 1)]
                        key = 4 if kind == "RP" else 7
                        values = [row[key] if kind == "RP" else row[key]["id"] for row in rows]
                        session.check("complete owned walk has no duplicates", len(set(values)), len(values))
                        session.check("completed walk has no continuation", cm(session, version, token, following).status, 0x30)
                    version, token = pin_token(session, 4)
                    rows = walk(session, version, token, begin, following, count, parameters)
                    session.check("restarted walk includes retained owned fixtures", all(any(row[4] == hashlib.sha256(item.rp.encode()).digest() if kind == "RP" else row[7]["id"] == item.descriptor["id"] for row in rows) for item in store.live.values()))
                    for item in store.live.values():
                        item.assertion(session)


def capacity(session):
    with session.case("fido.resident.capacity.fill-delete-recreate", ("F11", "F14", "F15", "F16", "F17", "X10", "G03", "G14"),
                      effects=("create_resident_credentials", "capacity"), touch=True):
        session.require(session.profile == "rsk", "capacity fixture requires the RS-Key profile", "excluded_by_profile")
        with owned(session) as store:
            before = metadata(session)
            session.require(before[1] == 0 and 1 <= before[2] <= MAX_ENUMERATION, "capacity matrix requires an empty bounded resident store")
            session.check("empty RP walk refused", cm(session, *pin_token(session, 4), 2).status, 0x2E)
            for index in range(before[2]):
                store.create(session.current.name + f".{index}")
            session.check("full store metadata", metadata(session), {1: before[2], 2: 0})
            item = next(iter(store.live.values()))
            query = {1: item.challenge, 2: {"id": item.rp}, 3: {"id": b"overflow"}, 4: [{"type": "public-key", "alg": -7}], 7: {"rk": True}}
            authorize(session, query, 1, item.rp, item.challenge, 8, 9)
            session.check("full resident store refuses new user", session.ctap(1, query).status, 0x28)
            item.assertion(session)
            store.delete(item)
            session.check("deletion frees one full-store slot", metadata(session)[2], 1)
            replacement = store.create(session.current.name + ".reclaimed")
            replacement.assertion(session)
            session.check("reclaimed slot is occupied", metadata(session)[2], 0)


def run(session):
    mutations(session)
    replacement(session)
    walks(session)
    capacity(session)
