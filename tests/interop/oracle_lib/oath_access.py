# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Access-code proofs have independent hashes and populated record witnesses."""
import hashlib
import hmac
from contextlib import contextmanager

from . import codec
from .oath_matrix import records
from .otp import OATH_HASHES, oath_names, oath_request, otp_value

HASHES = {1: "sha1", 2: "sha256", 3: "sha512"}


def unlock(session, algorithm, secret, selected=None, host=None):
    selected = selected or dict(codec.parse_tlv(session.select("oath")))
    host = session.fixture("oath.access.host", 8) if host is None else host
    result = oath_request(session, 0xA3, codec.tlv(0x75, hmac.digest(secret, selected[0x74], HASHES[algorithm])) + codec.tlv(0x74, host))
    session.check("access-code mutual proof matches independently selected hash", codec.parse_tlv(result), [(0x75, hmac.digest(secret, host, HASHES[algorithm]))])


def set_code(session, algorithm, secret):
    challenge = session.fixture("oath.access.install.challenge", 8)
    oath_request(session, 3, codec.tlv(0x73, bytes([algorithm]) + secret) + codec.tlv(0x74, challenge) + codec.tlv(0x75, hmac.digest(secret, challenge, HASHES[algorithm])))


def lock(session):
    session.select("piv")
    return dict(codec.parse_tlv(session.select("oath")))


@contextmanager
def code(session, algorithm, secret):
    session.require(session.profile == "rsk", "access-code semantic catalog requires RS-Key", "excluded_by_profile")
    selected = dict(codec.parse_tlv(session.select("oath")))
    original = None
    if 0x74 in selected:
        session.require(session.options.oath_password is not None, "existing access code requires its known password")
        original = hashlib.pbkdf2_hmac("sha1", session.options.oath_password.encode(), selected[0x71], 1000, 16)
        unlock(session, 1, original, selected)
    installed = False
    try:
        set_code(session, algorithm, secret)
        installed = True
        unlock(session, algorithm, secret)
        yield
    finally:
        if installed and not session.broken:
            session.trace.phase = "cleanup"
            unlock(session, algorithm, secret)
            if original is None:
                oath_request(session, 3, codec.tlv(0x73, b""))
                session.check("temporary access code removed", 0x74 not in dict(codec.parse_tlv(session.select("oath"))))
            else:
                set_code(session, 1, original)
                unlock(session, 1, original)


def known_record(session, name, counter):
    challenge = bytes(8)
    result = oath_request(session, 0xA2, codec.tlv(0x71, name) + codec.tlv(0x74, challenge), p2=1)
    session.check("authorization checks preserve HOTP secret and moving factor", dict(codec.parse_tlv(result))[0x76],
                  b"\x06" + otp_value(OATH_HASHES[0][2], counter.to_bytes(8, "big"), "sha1", 6).to_bytes(4, "big"))


def proof_matrix(session):
    for algorithm in HASHES:
        for length in (14, 15, 63, 64):
            with session.case(f"oath.access.algorithm-{algorithm}.key-length-{length}", ("A01", "A10", "A11", "G03", "G11", "G14"), effects=("config_change", "create_oath_record")):
                secret = session.fixture("oath.access.secret", length)
                name = b"oracle-access-HOTP"
                with records(session, [(name, codec.tlv(0x73, b"\x11\x06" + OATH_HASHES[0][2]))]):
                    with code(session, algorithm, secret):
                        names = oath_names(session)
                        for index, host_length in enumerate((0, 1, 7, 8, 63, 64, 65)):
                            selected = lock(session)
                            session.check("fresh selection has a challenge", len(selected.get(0x74, b"")), 8)
                            session.observe("SELECT_advertised_algorithm", selected.get(0x7B))
                            session.check("fresh selection is locked", session.apdu(codec.apdu(0xA1)).status, 0x6982)
                            unlock(session, algorithm, secret, selected, session.fixture("oath.access.host-width", host_length))
                            session.check("valid proof preserves full name set", oath_names(session), names)
                            known_record(session, name, index)
                            reselected = dict(codec.parse_tlv(session.select("oath")))
                            session.check("same SELECT keeps access-code authorization", oath_names(session), names)
                            session.check("same SELECT refreshes challenge", reselected[0x74] != selected[0x74])


def validation_failures(session):
    for algorithm, hash_name in HASHES.items():
        for standing in (False, True):
            for defect in ("missing-response", "missing-challenge", "empty-proof", "short-proof", "long-proof", "wrong-proof", "reordered", "duplicate", "truncated", "trailing", "stale-proof"):
                with session.case(f"oath.VALIDATE.algorithm-{algorithm}.standing-{standing}.{defect}", ("A01", "A10", "A11", "G01", "G03", "G05", "G07", "G10", "G11", "G14"), effects=("config_change", "create_oath_record")):
                    secret, name = session.fixture("oath.access.secret", 20), b"oracle-access-HOTP"
                    with records(session, [(name, codec.tlv(0x73, b"\x11\x06" + OATH_HASHES[0][2]))]):
                        with code(session, algorithm, secret):
                            selected = lock(session)
                            proof = hmac.digest(secret, selected[0x74], hash_name)
                            if standing:
                                unlock(session, algorithm, secret, selected)
                            response, challenge = codec.tlv(0x75, proof), codec.tlv(0x74, bytes(8))
                            if defect == "missing-response":
                                body = challenge
                            elif defect == "missing-challenge":
                                body = response
                            elif defect in ("empty-proof", "short-proof", "long-proof", "wrong-proof"):
                                bad = b"" if defect == "empty-proof" else proof[:-1] if defect == "short-proof" else proof + b"x" if defect == "long-proof" else bytes([proof[0] ^ 1]) + proof[1:]
                                body = codec.tlv(0x75, bad) + challenge
                            elif defect == "reordered":
                                body = challenge + response
                            elif defect == "duplicate":
                                body = response + response + challenge
                            elif defect == "truncated":
                                body = (response + challenge)[:-1]
                            elif defect == "trailing":
                                body = response + challenge + b"\x00"
                            else:
                                session.select("oath")
                                body = response + challenge
                            result = session.apdu(codec.apdu(0xA3, data=body))
                            session.check("invalid VALIDATE proof/grammar is refused", result.status, 0x6A80)
                            result = session.apdu(codec.apdu(0xA1))
                            session.check("failed VALIDATE preserves its prior grant state", result.status, 0x9000 if standing else 0x6982)
                            unlock(session, algorithm, secret)
                            known_record(session, name, 0)


def install_failures(session):
    for algorithm, hash_name in HASHES.items():
        for defect in ("no-body", "key-only", "missing-key", "missing-challenge", "missing-proof", "reordered", "duplicate", "truncated", "trailing",
                       "key-0", "key-1", "key-13", "key-65", "algorithm-0", "algorithm-4", "algorithm-255",
                       "challenge-0", "challenge-1", "challenge-7", "challenge-9", "challenge-64", "proof-empty", "proof-short", "proof-long", "proof-wrong"):
            with session.case(f"oath.SET-CODE.algorithm-{algorithm}.{defect}", ("A10", "A11", "G01", "G03", "G04", "G05", "G07", "G14"), effects=("config_change", "create_oath_record")):
                secret, name = session.fixture("oath.access.secret", 20), b"oracle-access-HOTP"
                with records(session, [(name, codec.tlv(0x73, b"\x11\x06" + OATH_HASHES[0][2]))]):
                    with code(session, algorithm, secret):
                        new = session.fixture("oath.access.replacement", 20)
                        candidate_algorithm, challenge = algorithm, bytes(8)
                        if defect.startswith("key-") and defect != "key-only":
                            new = bytes(int(defect.split("-")[1]))
                        if defect.startswith("algorithm-"):
                            candidate_algorithm = int(defect.split("-")[1])
                        if defect.startswith("challenge-"):
                            challenge = bytes(int(defect.split("-")[1]))
                        proof = hmac.digest(new, challenge, hash_name)
                        if defect == "proof-empty":
                            proof = b""
                        elif defect == "proof-short":
                            proof = proof[:-1]
                        elif defect == "proof-long":
                            proof += b"x"
                        elif defect == "proof-wrong":
                            proof = bytes([proof[0] ^ 1]) + proof[1:]
                        items = [(0x73, bytes([candidate_algorithm]) + new), (0x74, challenge), (0x75, proof)]
                        if defect.startswith("missing-"):
                            items.pop({"missing-key": 0, "missing-challenge": 1, "missing-proof": 2}[defect])
                        elif defect == "no-body":
                            items = []
                        elif defect == "key-only":
                            items = items[:1]
                        elif defect == "reordered":
                            items.reverse()
                        elif defect == "duplicate":
                            items.insert(1, items[0])
                        body = b"".join(codec.tlv(tag, value) for tag, value in items)
                        if defect == "truncated":
                            body = body[:-1]
                        elif defect == "trailing":
                            body += b"\x00"
                        result = session.apdu(codec.apdu(3, data=body))
                        if result.status == 0x9000:
                            session.broken = True
                            session.values["halt_reason"] = "malformed SET CODE unexpectedly succeeded; access-code state needs explicit recovery"
                        session.check("SET CODE validates grammar before proof", result.status, 0x6984 if defect.startswith("proof-") else 0x6A80)
                        lock(session)
                        unlock(session, algorithm, secret)
                        known_record(session, name, 0)


def run(session):
    proof_matrix(session)
    validation_failures(session)
    install_failures(session)
