# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Token scope, PIN changes, and continuation invalidation with controls."""
import hashlib

from . import codec
from .fido import (auth_data, authorize, cm, info, pin_protocol, pin_token,
                   public_key, token_mac, verified)
from .fido_manage import blob_read, restore_blob, walk


def rejected(session, reply, label):
    session.observe(label + ".status", reply.status)
    session.check(label + " refused by authenticator", reply.protocol, "applet_error")
    return session.evidence()


def tokens(session):
    for version in (1, 2):
        with session.case(f"fido.transition.token-scope.{version}", ("F03", "F06", "F09", "F14", "G10", "G14")):
            session.require(info(session).get(4, {}).get("credMgmt"), "credMgmt not advertised", "unknown")
            protocol, token = pin_token(session, 4, version=version)
            before = session.ctap_value(cm(session, protocol, token, 1))
            damaged = token[:-1] + bytes([token[-1] ^ 1])
            trigger = rejected(session, cm(session, protocol, damaged, 1), "wrong-token-MAC")
            session.check("valid token still works after bad MAC", session.ctap_value(cm(session, protocol, token, 1)), before)
            session.transition("fido.token", "authorized", "authorized_after_bad_mac", trigger, [trigger, session.evidence()])
            session.require(info(session).get(4, {}).get("pinUvAuthToken"), "scoped tokens not advertised", "unknown")
            _, scoped = pin_token(session, 2, "scope.oracle.invalid", version=version)
            trigger = rejected(session, cm(session, protocol, scoped, 1), "wrong-token-permission")
            protocol, fresh = pin_token(session, 4, version=version)
            session.check("fresh correctly scoped token works", session.ctap_value(cm(session, protocol, fresh, 1)), before)
            session.transition("fido.token.permission", "getAssertion_only", "credMgmt_authorized", trigger, [trigger, session.evidence()])


def change_pin(session, old, new):
    protocol = pin_protocol(session)
    encrypted = protocol.encrypt(new.encode().ljust(64, b"\x00"))
    old_hash = protocol.encrypt(hashlib.sha256(old.encode()).digest()[:16])
    request = {1: protocol.version, 2: 4, 3: protocol.cose, 4: protocol.authenticate(encrypted + old_hash),
               5: encrypted, 6: old_hash}
    session.ctap_value(session.ctap(6, request))


def pin_change(session):
    with session.case("fido.transition.pin-change", ("F05", "F09", "F11", "F12", "G14"),
                      effects=("pin_change", "create_fido_credential"), touch=True):
        session.require(session.profile != "trezor", "wallet profile excludes host PIN changes", "excluded_by_profile")
        session.require(session.options.pin is not None, "PIN change requires --pin-env")
        session.require(info(session).get(4, {}).get("clientPin") is True, "PIN must already be set")
        session.require(not info(session).get(0x1B), "PIN complexity profile needs an explicit replacement PIN")
        old = session.options.pin
        new = "Or4!" + session.fixture("fido.changed-pin", 14).hex()
        session.require(info(session).get(13, 4) <= len(new), "fixture PIN does not meet advertised minimum")
        rp, challenge = "pin-change.oracle.invalid", session.fixture("pin-change.challenge")
        request = {1: challenge, 2: {"id": rp}, 3: {"id": b"oracle-pin-change"},
                   4: [{"type": "public-key", "alg": -7}], 7: {"rk": False}}
        authorize(session, request, 1, rp, challenge, 8, 9)
        registration = session.ctap_value(session.ctap(1, request))
        parsed = auth_data(registration[2])
        descriptor = {"id": parsed["credential_id"], "type": "public-key"}
        key = public_key(parsed["cose"])
        version, token = pin_token(session, 2, rp)
        changed = False
        try:
            change_pin(session, old, new)
            changed = True
            session.options.pin = new
            trigger = session.evidence()
            query = {1: rp, 2: challenge, 3: [descriptor], 5: {"up": False},
                     6: token_mac(version, token, challenge), 7: version}
            rejected(session, session.ctap(2, query), "token-before-PIN-change")
            authorize(session, query, 2, rp, challenge, 6, 7)
            query[5] = {"up": True}
            assertion = session.ctap_value(session.ctap(2, query))
            signed = auth_data(assertion[2])
            session.check("existing credential RP after PIN change", signed["rp_hash"], hashlib.sha256(rp.encode()).digest())
            verified(session, "existing key after PIN change", key, -7, assertion[3], assertion[2] + challenge)
            session.transition("fido.pin", "original_PIN", "replacement_PIN_with_usable_old_key", trigger, [trigger, session.evidence()])
        finally:
            if changed and not session.broken:
                session.trace.phase = "cleanup"
                change_pin(session, new, old)
                session.options.pin = old
                session.bind("fido.info", session.ctap_value(session.ctap(4)))
                pin_token(session, 2, rp)
                session.observe("cleanup", "original PIN restored and token acquisition checked")


def walks(session):
    for interruption in ("getinfo", "new-begin"):
        with session.case("fido.transition.RP-walk." + interruption, ("F14", "F15", "G11", "G14")):
            session.require(info(session).get(4, {}).get("credMgmt"), "credMgmt not advertised", "unknown")
            version, token = pin_token(session, 4)
            metadata = session.ctap_value(cm(session, version, token, 1))
            session.require(metadata[1] > 0, "RP walk requires resident credentials")
            first = session.ctap_value(cm(session, version, token, 2))
            session.check("RP count bounded", 1 <= first[5] <= 4096)
            if interruption == "getinfo":
                session.ctap_value(session.ctap(4))
                trigger = session.evidence()
                outcome = cm(session, version, token, 3)
                # CTAP versions differ on which commands invalidate a walk.
                session.observe("continuation_after_getinfo", outcome.status)
                if outcome.status == 0:
                    value = session.ctap_value(outcome)
                    session.check("continued RP has hash", len(value[4]), 32)
                session.transition("fido.RP_walk", "started", "observed_after_getInfo", trigger, [trigger, session.evidence()])
            else:
                second = session.ctap_value(cm(session, version, token, 2))
                session.check("new begin restarts first RP", second[4], first[4])
            rows = walk(session, version, token, 2, 3, 5)
            hashes = [row[4] for row in rows]
            session.check("RP walk contains no duplicate hashes", len(set(hashes)), len(hashes))
            for row in rows:
                session.check("RP hash matches identifier", row[4], hashlib.sha256(row[3]["id"].encode()).digest())
    for subcommand in (3, 5):
        with session.case(f"fido.transition.cm-next-without-begin.{subcommand}", ("F15", "F16")):
            session.ctap_value(session.ctap(4))
            rejected(session, session.ctap(10, {1: subcommand}), "continuation-without-initializer")


def blob_faults(session):
    for defect in ("missing-auth", "wrong-MAC", "offset-gap", "offset-overlap", "oversized-total"):
        with session.case("fido.transition.large-blob." + defect, ("F19", "F20", "G10", "G14"),
                          effects=("replace_and_restore_large_blob_array",)):
            session.require(info(session).get(4, {}).get("largeBlobs"), "largeBlobs not advertised", "unknown")
            version, token = pin_token(session, 16)
            original = blob_read(session)
            body = codec.encode([])
            data = body + hashlib.sha256(body).digest()[:16]

            def fragment(offset, value, total=None, authenticate=True, corrupt=False):
                request = {2: value, 3: offset}
                if total is not None:
                    request[4] = total
                if authenticate:
                    mac = token_mac(version, token, b"\xff" * 32 + b"\x0c\x00" + offset.to_bytes(4, "little") + hashlib.sha256(value).digest())
                    request.update({5: bytes(len(mac)) if corrupt else mac, 6: version})
                return session.ctap(12, request)

            with restore_blob(session, original):
                if defect in ("offset-gap", "offset-overlap"):
                    session.ctap_value(fragment(0, data[:8], len(data)))
                    offset = 9 if defect == "offset-gap" else 7
                    reply = fragment(offset, data[8:])
                else:
                    reply = fragment(0, data, (info(session).get(11, 1024) + 1) if defect == "oversized-total" else len(data),
                                     authenticate=defect != "missing-auth", corrupt=defect == "wrong-MAC")
                trigger = rejected(session, reply, defect)
                session.check("committed blob survives failed fragment", blob_read(session), original)
                session.transition("fido.large_blob", "committed_original", "committed_original", trigger, [trigger, session.evidence()])


def run(session):
    tokens(session)
    walks(session)
    blob_faults(session)
    pin_change(session)
