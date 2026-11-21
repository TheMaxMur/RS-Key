# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Credential walks and large-blob writes retain each continuation exchange."""
import hashlib
from contextlib import contextmanager

from . import codec
from .fido import auth_data, authorize, cm, info, pin_token, public_key, token_mac, verified

MAX_ENUMERATION = 4096
MAX_BLOB_BYTES = 16 * 1024 * 1024


def walk(session, version, token, begin, following, count_key, parameters=None):
    first = session.ctap_value(cm(session, version, token, begin, parameters))
    count = first.get(count_key, 1)
    session.check("bounded enumeration count", isinstance(count, int) and 1 <= count <= MAX_ENUMERATION)
    rows = [first]
    for _ in range(count - 1):
        rows.append(session.ctap_value(cm(session, version, token, following)))
    end = cm(session, version, token, following)
    session.observe(f"walk.{begin}.past_end_status", end.status)
    session.check("continuation past end refused", end.is_rejection)
    return rows


def credentials(session):
    with session.case("fido.fixture.credential-management", ("F11", "F12", "F13", "F14", "F15", "F16", "F17", "F18"), effects=("create_resident_credentials",), touch=True):
        session.require(info(session).get(4, {}).get("credMgmt"), "credMgmt is not advertised; command support is unmeasured", "unknown")
        version, token = pin_token(session, 4)
        before = session.ctap_value(cm(session, version, token, 1))[1]
        prefix = session.fixture("cm.rp", 8).hex()
        rps = [f"{prefix}.{index}.oracle.invalid" for index in range(2)]
        if before:
            existing = walk(session, version, token, 2, 3, 5)
            session.require(not ({row[3]["id"] for row in existing} & set(rps)), "fixture RP already exists; refusing to merge state")
        created, keys = [], {}
        challenge = session.fixture("cm.client_hash")
        try:
            for index, rp in enumerate((rps[0], rps[0], rps[1])):
                user = {"id": bytes([index + 1]), "name": f"oracle-{index}", "displayName": f"Oracle {index}"}
                request = {1: challenge, 2: {"id": rp}, 3: user, 4: [{"type": "public-key", "alg": -7}], 7: {"rk": True}}
                authorize(session, request, 1, rp, challenge, 8, 9)
                registration = session.ctap_value(session.ctap(1, request))
                parsed = auth_data(registration[2])
                descriptor = {"id": parsed["credential_id"], "type": "public-key"}
                created.append(descriptor)
                keys[descriptor["id"]] = public_key(parsed["cose"])
                session.bind(f"cm.credential.{index}", descriptor)
            version, token = pin_token(session, 4)
            session.check("resident count increased", session.ctap_value(cm(session, version, token, 1))[1], before + 3)
            rows = walk(session, version, token, 2, 3, 5)
            session.check("fixture RPs enumerated", set(rps).issubset({row[3]["id"] for row in rows}))
            rp_hash = hashlib.sha256(rps[0].encode()).digest()
            listed = walk(session, version, token, 4, 5, 9, {1: rp_hash})
            session.check("two fixture credentials", {row[7]["id"] for row in listed}, {row["id"] for row in created[:2]})
            session.check("user IDs enumerated", {row[6]["id"] for row in listed}, {b"\x01", b"\x02"})
            updated = {"id": b"\x01", "name": "oracle-updated", "displayName": "Oracle Updated"}
            session.ctap_value(cm(session, version, token, 7, {2: created[0], 3: updated}))
            listed = walk(session, version, token, 4, 5, 9, {1: rp_hash})
            session.check("user update readback", next(row[6]["name"] for row in listed if row[7]["id"] == created[0]["id"]), updated["name"])
            query = {1: rps[0], 2: challenge, 5: {"up": True}}
            authorize(session, query, 2, rps[0], challenge, 6, 7)
            first = session.ctap_value(session.ctap(2, query))
            session.check("discoverable assertion count", first.get(5, 1), 2)
            assertions = [first, session.ctap_value(session.ctap(8))]
            for assertion in assertions:
                parsed = auth_data(assertion[2])
                session.check("discoverable RP binding", parsed["rp_hash"], rp_hash)
                verified(session, "discoverable signature", keys[assertion[1]["id"]], -7, assertion[3], assertion[2] + challenge)
            session.check("discoverable IDs", {row[1]["id"] for row in assertions}, {row["id"] for row in created[:2]})
            session.check("getNextAssertion exhausted", session.ctap(8).is_rejection)
            session.observe("fixture_rp_count", 2)
            session.observe("fixture_credential_count", len(created))
        finally:
            if created and not session.broken:
                session.trace.phase = "cleanup"
                version, token = pin_token(session, 4)
                for descriptor in created:
                    session.ctap_value(cm(session, version, token, 6, {2: descriptor}))
                session.check("resident count restored", session.ctap_value(cm(session, version, token, 1))[1], before)


def blob_read(session):
    offset, result = 0, bytearray()
    while offset < MAX_BLOB_BYTES:
        fragment = session.ctap_value(session.ctap(12, {1: 512, 3: offset}))[1]
        session.check("bounded blob fragment", isinstance(fragment, bytes) and len(fragment) <= 512)
        result.extend(fragment)
        if len(fragment) < 512:
            return bytes(result)
        offset += len(fragment)
    raise ValueError("large-blob array exceeds capture size limit")


def blob_write(session, version, token, data, fragment_size=32):
    for offset in range(0, len(data), fragment_size):
        fragment = data[offset:offset + fragment_size]
        message = b"\xff" * 32 + b"\x0c\x00" + offset.to_bytes(4, "little") + hashlib.sha256(fragment).digest()
        request = {2: fragment, 3: offset, 5: token_mac(version, token, message), 6: version}
        if offset == 0:
            request[4] = len(data)
        reply = session.ctap(12, request)
        if reply.status != 0:
            return reply
    return reply


@contextmanager
def restore_blob(session, original):
    try:
        yield
    finally:
        if not session.broken:
            session.trace.phase = "cleanup"
            version, token = pin_token(session, 16)
            session.ctap_value(blob_write(session, version, token, original))
            session.check("original blob restored after fault probe", blob_read(session), original)


def large_blobs(session):
    with session.case("fido.fixture.large-blobs", ("F19", "F20"), effects=("replace_and_restore_large_blob_array",)):
        session.require(info(session).get(4, {}).get("largeBlobs"), "largeBlobs is not advertised; command support is unmeasured", "unknown")
        version, token = pin_token(session, 16)
        original = blob_read(session)
        session.check("original array digest", hashlib.sha256(original[:-16]).digest()[:16], original[-16:])
        body = codec.encode([{1: session.fixture("largeblob.ciphertext"), 2: session.fixture("largeblob.nonce", 12), 3: 16}])
        replacement = body + hashlib.sha256(body).digest()[:16]
        began = False
        try:
            began = True
            session.ctap_value(blob_write(session, version, token, replacement))
            session.check("fragmented array readback", blob_read(session), replacement)
            bad = replacement[:-1] + bytes([replacement[-1] ^ 1])
            refused = blob_write(session, version, token, bad)
            session.observe("bad_digest.status", refused.status)
            session.check("bad digest refused", refused.is_rejection)
            session.check("committed array survived rejected digest", blob_read(session), replacement)
        finally:
            if began and not session.broken:
                session.trace.phase = "cleanup"
                session.ctap_value(blob_write(session, version, token, original))
                session.check("original array restored", blob_read(session), original)
