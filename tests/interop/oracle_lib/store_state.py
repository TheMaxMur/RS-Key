# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Encrypted store-state tags follow successful resident mutations and FIDO reset."""
from .fido import cm, info, pin_token
from .fido_fixtures import credential, provision_after_reset
from .fido_lifecycle import decrypt_member
from .lifecycle import Action, change
from .reset_witness import snapshot, preserved


def plaintext(session, token):
    value = session.ctap_value(session.ctap(4))
    session.check("encrypted identity/store-state pair is available", all(key in value for key in (25, 30)))
    return tuple(decrypt_member(token, label, value[key]) for key, label in ((25, b"encIdentifier"), (30, b"encCredStoreState")))


def mutations(session):
    for version in (1, 2):
        with session.case(f"fido.encrypted-state.resident-mutations.protocol-{version}", ("F18", "FE05", "FE14", "G09", "G11", "G14"),
                effects=("create_fido_credential",), touch=True):
            session.require(info(session).get(4, {}).get("perCredMgmtRO"), "encrypted state requires persistent read-only support", "unknown")
            _, token = pin_token(session, 64, version=version)
            initial = plaintext(session, token)
            session.check("plaintext identity and store state are stable across fresh IVs", plaintext(session, token), initial)
            first, second = (session.ctap_value(session.ctap(4)) for _ in range(2))
            for key in (25, 30):
                session.check("encrypted state uses a fresh IV for each anonymous read", first[key][:16] != second[key][:16])
            with credential(session, session.current.name, True, {"largeBlobKey": True} if "largeBlobKey" in info(session).get(2, []) else {}) as fixture:
                created = plaintext(session, token)
                session.check("resident create changes the store tag", created[1] != initial[1])
                session.check("resident create preserves the platform identifier", created[0], initial[0])
                fixture.assertion(session)
                session.check("ordinary assertion is not a store mutation", plaintext(session, token), created)
                proto, write_token = pin_token(session, 4, version=version)
                user = {"id": session.fixture(session.current.name + ".user", 16), "name": "state-updated"}
                session.ctap_value(cm(session, proto, write_token, 7, {2: fixture.descriptor, 3: user}))
                updated = plaintext(session, token)
                session.check("user update changes the store tag", updated[1] != created[1])
                session.check("user update preserves the platform identifier", updated[0], initial[0])
                proto, write_token = pin_token(session, 4, version=version)
                result = cm(session, proto, write_token, 7, {2: fixture.descriptor, 3: {"id": b"wrong-user-id", "name": "must-not-apply"}})
                session.check("refused update has its semantic cause", result.status, 2)
                session.check("refused update cannot advance the store tag", plaintext(session, token), updated)
                fixture.assertion(session)
                blob_key = fixture.registration.get(5)
                if blob_key is not None:
                    value, _ = fixture.assertion(session, extensions={"largeBlobKey": True})
                    session.check("updated credential retains its blob key", value[7], blob_key)
                fixture.delete(session)
                deleted = plaintext(session, token)
                session.check("resident delete advances the store tag", deleted[1] != updated[1])
                session.check("resident delete preserves the platform identifier", deleted[0], initial[0])
                query = fixture.query(session, extensions={"largeBlobKey": True} if blob_key else None, options={"up": False}, authenticate=False)
                session.check("deleted credential cannot export an assertion or its blob key", session.ctap(2, query).status, 0x2e)
                session.ctap_value(cm(session, version, token, 1))


def reset(session):
    for version in (1, 2):
        with session.case(f"fido.encrypted-state.reset.protocol-{version}", ("FE14", "F10", "F23", "X06", "G14"),
                effects=("applet_reset", "pin_change", "reboot"), touch=True):
            session.require(session.profile == "rsk", "reset identity contract requires RS-Key", "excluded_by_profile")
            session.require(info(session).get(4, {}).get("perCredMgmtRO"), "persistent read-only support required", "unknown")
            session.require(session.card is not None and hasattr(session.card, "control"), "reset requires an explicit power-cycle backend")
            neighbors = snapshot(session, "fido")
            change(session, Action.POWER_CYCLE)
            _, token = pin_token(session, 64, version=version)
            original = plaintext(session, token)
            reset_done = False
            try:
                session.ctap_value(session.ctap(7))
                reset_done = True
                session.options.pin = None
                current = session.ctap_value(session.ctap(4))
                session.check("reset removes encrypted identifiers until a fresh RO grant exists", 25 not in current and 30 not in current)
                session.check("reset revokes the old platform grant", cm(session, version, token, 1).status, 0x33)
            finally:
                if reset_done and not session.broken:
                    session.trace.phase = "cleanup"
                    provision_after_reset(session, session.ctap_value(session.ctap(4)))
            _, fresh = pin_token(session, 64, version=version)
            current = plaintext(session, fresh)
            session.check("reset starts a different platform identifier", current[0] != original[0])
            session.check("reset starts a different store-state tag", current[1] != original[1])
            session.check("fresh grant differs from the reset platform grant", fresh != token)
            preserved(session, "fido", neighbors)


def run(session):
    mutations(session)
    reset(session)
