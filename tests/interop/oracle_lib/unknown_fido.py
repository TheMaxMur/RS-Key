# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Resolve one lost FIDO mutation from owned credentials, policy or blob bytes."""
import hashlib
from itertools import product

from . import codec
from .blob_matrix import array_bytes, fragment
from .config_matrix import public, request as config_request
from .credential_matrix import owned, metadata, user_rows
from .fido import auth_data, authorize, cm, info, pin_token, public_key, token_mac, verified
from .fido_fixtures import Credential, credential
from .fido_manage import blob_read, restore_blob
from .fido_states import change_pin
from .pin_matrix import request as pin_request
from .runner import CtapRoute
from .unknown_secrets import candidate
from .uncertain_writes import classify, lose, require_loss
from .vendor_lifecycle import config


def pins(session):
    for version in (1, 2):
        with session.case(f"cross.unknown-write.FIDO.PIN.protocol-{version}", ("X10", "F03", "F05", "F06", "F09", "F10", "G10", "G11", "G12", "G14"),
                effects=("session_recovery", "pin_change", "pin_attempts", "create_fido_credential"), touch=True):
            require_loss(session)
            current = info(session)
            session.require(session.options.pin and current.get(4, {}).get("clientPin") and not current.get(12), "known configured PIN without forced change required")
            session.require(session.ctap_value(session.ctap(6, {1: version, 2: 1}))[3] > 1, "old/new PIN candidates need an available recovery retry")
            original = session.options.pin
            replacement = "Or4!" + "x" * 59 if original != "Or4!" + "x" * 59 else "Qr8?" + "z" * 59
            with credential(session, session.current.name) as retained:
                _, fields = pin_request(session, version, replacement.encode().ljust(64, b"\x00"), original)
                session.select("fido")
                with session.route(CtapRoute.CARD):
                    lose(session, 0x10, lambda: session.ctap(6, fields))
                def verify(value):
                    from .token_matrix import issue
                    session.options.pin = value
                    return issue(session, version, permissions=4)[0]
                active = candidate(session, "fido.pin", (("unchanged", original), ("committed", replacement)), verify, success=0)
                session.options.pin = active
                retained.assertion(session)
                session.check("PIN readback retains public policy and capability state", public(session.ctap_value(session.ctap(4))), public(current))
                if active != original:
                    change_pin(session, active, original)
                session.options.pin = original
                pin_token(session, 4)
                retained.assertion(session)


def residents(session):
    for version, operation in product((1, 2), ("create", "replace", "update", "delete")):
        with session.case(f"cross.unknown-write.FIDO.resident.protocol-{version}.{operation}", ("X10", "F11", "F12", "F14", "F16", "F17", "F18", "G09", "G11", "G12", "G14"),
                effects=("session_recovery", "create_resident_credentials"), touch=True):
            require_loss(session)
            with owned(session) as store:
                retained = store.create(session.current.name + ".neighbor")
                target = store.create(session.current.name + ".target")
                before, rows = metadata(session), user_rows(session, target)
                session.check("unique owned RP has one original resident before loss", len(rows), 1)
                old_user = rows[0][6]
                new_user = {**old_user, "name": "oracle-unknown-updated", "displayName": "Oracle changed"}
                if operation == "create":
                    new_user["id"] = session.fixture(session.current.name + ".new-user", 16)
                if operation in ("create", "replace"):
                    fields = {1: session.fixture(session.current.name + ".lost-hash"), 2: {"id": target.rp}, 3: new_user,
                        4: [{"type": "public-key", "alg": -7}], 7: {"rk": True}}
                    authorize(session, fields, 1, target.rp, fields[1], 8, 9)
                    command = 1
                else:
                    parameters = {2: target.descriptor, **({3: new_user} if operation == "update" else {})}
                    proto, token = pin_token(session, 4, version=version)
                    sub = 7 if operation == "update" else 6
                    fields = {1: sub, 2: parameters, 3: proto, 4: token_mac(proto, token, bytes([sub]) + codec.encode(parameters))}
                    command = 10
                session.select("fido")
                with session.route(CtapRoute.CARD):
                    lose(session, 0x10, lambda: session.ctap(command, fields))
                proto, token = pin_token(session, 4)
                first = cm(session, proto, token, 4, {1: hashlib.sha256(target.rp.encode()).digest()})
                if first.status == 0x2e:
                    session.check("only committed deletion can remove the entire target RP", operation, "delete")
                    after_rows = []
                else:
                    value = session.ctap_value(first)
                    total = value.get(9, 1)
                    session.check("unknown mutation cannot create an unbounded resident set", 1 <= total <= 2)
                    after_rows = [value, *(session.ctap_value(cm(session, proto, token, 5)) for _ in range(total - 1))]
                    session.check("recovered RP walk exhausts exactly", cm(session, proto, token, 5).status, 0x30)
                old_id = target.descriptor["id"]
                ids = {row[7]["id"] for row in after_rows}
                session.check("unknown mutation cannot duplicate a resident reference", len(ids), len(after_rows))
                target.deleted = old_id not in ids
                if target.deleted:
                    store.live.pop(old_id)
                    session.check("only replacement/deletion may revoke the original private reference", operation in ("replace", "delete"))
                    session.check("readback-confirmed removed reference cannot assert", session.ctap(2, target.query(session)).status, 0x2e)
                for row in after_rows:
                    identifier, user = row[7]["id"], row[6]
                    if identifier == old_id:
                        session.check("retained resident has complete old or updated user fields", user == old_user or operation == "update" and user == new_user)
                        target.assertion(session)
                    else:
                        session.check("only create/replace may publish a newly referenced key", operation in ("create", "replace"))
                        session.check("new resident preserves the complete intended user", user, new_user)
                        session.check("new resident publishes the requested algorithm", row[8][3], -7)
                        query = {1: target.rp, 2: session.fixture("unknown.resident.private-proof"), 3: [row[7]], 5: {"up": True}}
                        authorize(session, query, 2, target.rp, query[2], 6, 7)
                        value = session.ctap_value(session.ctap(2, query))
                        parsed = auth_data(value[2])
                        key = public_key(row[8])
                        session.check("new resident RP remains exactly bound", parsed["rp_hash"], target.parsed["rp_hash"])
                        verified(session, "lost makeCredential response recovered through real new-key possession", key, -7, value[3], value[2] + query[2])
                        store.live[identifier] = Credential(target.rp, row[7], key, -7, {}, target.parsed, query[2])
                count = metadata(session)[1]
                session.check("unknown resident mutation has exactly the readback-known count", count, before[1] - 1 + len(ids))
                session.observe("unknown_resident_readback", {"operation": operation, "old_reference_retained": not target.deleted,
                    "target_count": len(ids), "mutator_replayed": False})
                retained.assertion(session)


def blobs(session):
    for version, stage in product((1, 2), ("partial", "final")):
        with session.case(f"cross.unknown-write.FIDO.largeBlobs.protocol-{version}.{stage}", ("X10", "F19", "F20", "G09", "G11", "G12", "G14"),
                effects=("session_recovery", "replace_and_restore_large_blob_array", "create_fido_credential"), touch=True):
            require_loss(session)
            session.require(info(session).get(4, {}).get("largeBlobs"), "large blob array not advertised", "unknown")
            with credential(session, session.current.name) as retained:
                old, new = blob_read(session), array_bytes(session, "unknown.blob")
                with restore_blob(session, old):
                    proto, token = pin_token(session, 16, version=version)
                    session.select("fido")
                    with session.route(CtapRoute.CARD):
                        if stage == "final":
                            session.ctap_value(fragment(session, proto, token, 0, new[:8], len(new)))
                        lose(session, 0x10, lambda: fragment(session, proto, token, 8 if stage == "final" else 0,
                            new[8:] if stage == "final" else new[:8], None if stage == "final" else len(new)))
                    actual = blob_read(session)
                    classify(session, "committed large blob array", actual, old, new if stage == "final" else old)
                    retained.assertion(session)


def policies(session):
    for version in (1, 2):
        with session.case(f"cross.unknown-write.FIDO.CONFIG.alwaysUv.protocol-{version}", ("X08", "X10", "F01", "F21", "G10", "G11", "G12", "G14"),
                effects=("session_recovery", "config_change", "create_fido_credential"), touch=True):
            require_loss(session)
            before = info(session)
            session.require(before.get(4, {}).get("authnrCfg") and session.options.pin, "known PIN and CONFIG support required")
            with credential(session, session.current.name) as retained:
                proto, token = pin_token(session, 32, version=version)
                fields = config_request(session, proto, token, 2)
                session.select("fido")
                with session.route(CtapRoute.CARD):
                    lose(session, 0x10, lambda: session.ctap(13, fields))
                current = session.ctap_value(session.ctap(4))
                expected = {**public(before), 4: {**before[4], "alwaysUv": not before[4].get("alwaysUv", False)}}
                # Version advertisement also follows alwaysUv; compare policy independently.
                classify(session, "FIDO CONFIG policy", current[4], before[4], expected[4])
                session.check("unknown policy toggle preserves every other public limit", {k: v for k, v in public(current).items() if k not in (1, 4)},
                    {k: v for k, v in public(before).items() if k not in (1, 4)})
                session.bind("fido.info", current)
                retained.assertion(session)
                if current[4] != before[4]:
                    session.ctap_value(config(session, 2))
                session.bind("fido.info", session.ctap_value(session.ctap(4)))
                session.check("readback-known policy recovery restores original public state", public(info(session)), public(before))
                retained.assertion(session)


def run(session):
    pins(session)
    residents(session)
    blobs(session)
    policies(session)
