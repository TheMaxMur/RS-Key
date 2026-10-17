# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OATH authorization, rejected mutations, and witnessed record transitions."""
import hashlib
import hmac

from . import codec
from .otp import OATH_HASHES, oath_names, oath_open, oath_request, otp_value


def refused(session, ins, data=b"", p1=0, p2=0, label="request"):
    reply = session.apdu(codec.apdu(ins, p1, p2, data), "oath." + label)
    session.observe(label + ".status", reply.status)
    session.check(label + " refused by applet", reply.protocol, "applet_error")
    return session.evidence()


def calculate(session, name, challenge):
    body = oath_request(session, 0xA2, codec.tlv(0x71, name) + codec.tlv(0x74, challenge), p2=1)
    values = codec.parse_tlv(body)
    session.check("truncated OTP shape", [(t, len(v)) for t, v in values], [(0x76, 5)])
    session.check("six digits", values[0][1][0], 6)
    return int.from_bytes(values[0][1][1:], "big")


def put(session, name, secret, extra=b""):
    oath_request(session, 1, codec.tlv(0x71, name) + codec.tlv(0x73, b"\x21\x06" + secret) + extra)


def records(session):
    for defect in ("missing-name", "missing-key", "bad-digits", "bad-algorithm", "truncated-key",
                   "rename-collision", "rename-missing", "delete-missing", "calculate-missing"):
        with session.case("oath.transition." + defect, ("A02", "A03", "A04", "A09", "G09", "G14"),
                          effects=("create_oath_record",)):
            oath_open(session)
            name = b"oracle-state-" + session.fixture("oath.state", 5).hex().encode()
            other = name + b"-other"
            before = oath_names(session)
            session.require(not {name, other} & before, "fixture names already exist")
            secret = OATH_HASHES[0][2]
            created = []
            try:
                put(session, name, secret)
                created.append(name)
                put(session, other, secret[::-1])
                created.append(other)
                challenge = (1).to_bytes(8, "big")
                session.check("fixture before refusal", calculate(session, name, challenge), otp_value(secret, challenge, "sha1", 6))
                initial = session.evidence()
                key = codec.tlv(0x73, b"\x21\x06" + secret)
                named = codec.tlv(0x71, name)
                mutations = {
                    "missing-name": (1, key), "missing-key": (1, named),
                    "bad-digits": (1, named + codec.tlv(0x73, b"\x21\x00" + secret)),
                    "bad-algorithm": (1, named + codec.tlv(0x73, b"\x2f\x06" + secret)),
                    "truncated-key": (1, named + b"\x73\x14\x21"),
                    "rename-collision": (5, named + codec.tlv(0x71, other)),
                    "rename-missing": (5, codec.tlv(0x71, name + b"-absent") + codec.tlv(0x71, name)),
                    "delete-missing": (2, codec.tlv(0x71, name + b"-absent")),
                    "calculate-missing": (0xA2, codec.tlv(0x71, name + b"-absent") + codec.tlv(0x74, challenge)),
                }
                ins, data = mutations[defect]
                trigger = refused(session, ins, data, label=defect)
                session.check("names preserved after refusal", oath_names(session), before | {name, other})
                session.check("key preserved after refusal", calculate(session, name, challenge), otp_value(secret, challenge, "sha1", 6))
                session.check("neighbor preserved after refusal", calculate(session, other, challenge), otp_value(secret[::-1], challenge, "sha1", 6))
                session.transition("oath.record", "present_and_usable", "unchanged_and_usable", trigger,
                                   [initial, trigger, session.evidence()])
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    for fixture in created:
                        oath_request(session, 2, codec.tlv(0x71, fixture))
                    session.check("original record set restored", oath_names(session), before)


def encodings(session):
    prefix = b"oracle-name-" + session.fixture("oath.name", 4).hex().encode()
    names = (("empty", b""), ("ASCII", prefix), ("UTF8", prefix + "-caf\u00e9".encode()),
             ("NUL", prefix + b"\x00x"), ("binary", prefix + b"\xff\xfe"),
             *((str(length), prefix.ljust(length, b"x")) for length in (63, 64, 65)))
    for label, name in names:
        with session.case("oath.encoding.name." + label, ("A02", "A03", "A04", "A09", "G03", "G08", "G14"),
                          effects=("create_oath_record",)):
            oath_open(session)
            before = oath_names(session)
            session.require(name not in before, "fixture name already exists")
            created = False
            try:
                reply = session.apdu(codec.apdu(1, data=codec.tlv(0x71, name) + codec.tlv(0x73, b"\x21\x06" + OATH_HASHES[0][2])))
                session.observe("PUT.status", reply.status)
                created = reply.protocol == "success"
                if len(name) == 0 or len(name) > 64:
                    session.check("out-of-bounds name refused", not created)
                if created:
                    session.check("LIST retains exact name bytes", oath_names(session), before | {name})
                    challenge = bytes(8)
                    session.check("named credential is usable", calculate(session, name, challenge), otp_value(OATH_HASHES[0][2], challenge, "sha1", 6))
                else:
                    session.check("rejection preserves names", oath_names(session), before)
            finally:
                if created and not session.broken:
                    session.trace.phase = "cleanup"
                    oath_request(session, 2, codec.tlv(0x71, name))
                    session.check("original names restored", oath_names(session), before)
    for encoding in ("unknown-tag", "duplicate-key", "reordered", "long-length", "nested-unknown"):
        with session.case("oath.encoding.TLV." + encoding, ("A02", "A04", "A09", "G07", "G14"), effects=("create_oath_record",)):
            oath_open(session)
            before = oath_names(session)
            name = prefix + b"-tlv"
            session.require(name not in before, "fixture name already exists")
            first, second = OATH_HASHES[0][2], OATH_HASHES[0][2][::-1]
            named, key = codec.tlv(0x71, name), codec.tlv(0x73, b"\x21\x06" + first)
            variants = {"unknown-tag": named + key + codec.tlv(0x7E, b"x"),
                        "duplicate-key": named + key + codec.tlv(0x73, b"\x21\x06" + second),
                        "reordered": key + named,
                        "long-length": b"\x71\x81" + bytes([len(name)]) + name + key,
                        "nested-unknown": named + key + codec.tlv(0x7E, named + key)}
            created = False
            try:
                reply = session.apdu(codec.apdu(1, data=variants[encoding]))
                session.observe("PUT.status", reply.status)
                created = reply.protocol == "success"
                if created:
                    challenge = bytes(8)
                    result = calculate(session, name, challenge)
                    expected = [otp_value(secret, challenge, "sha1", 6) for secret in (first, second)]
                    session.check("accepted TLV selects a declared fixture key", result in expected)
                    session.observe("selected_key_index", expected.index(result))
                    session.check("accepted TLV retains exact name", oath_names(session), before | {name})
                else:
                    session.check("refused TLV leaves no record", oath_names(session), before)
            finally:
                if created and not session.broken:
                    session.trace.phase = "cleanup"
                    oath_request(session, 2, codec.tlv(0x71, name))
                    session.check("original names restored", oath_names(session), before)


def validate(session, key, selected=None):
    fields = selected if selected is not None else dict(codec.parse_tlv(session.select("oath")))
    if 0x74 not in fields:
        return
    challenge = session.fixture("oath.state.host-challenge", 8)
    data = codec.tlv(0x75, hmac.digest(key, fields[0x74], "sha1")) + codec.tlv(0x74, challenge)
    response = oath_request(session, 0xA3, data)
    session.check("VALIDATE mutual proof", codec.parse_tlv(response), [(0x75, hmac.digest(key, challenge, "sha1"))])
    return data


def set_code(session, key):
    challenge = session.fixture("oath.state.set-challenge", 8)
    data = codec.tlv(0x73, b"\x01" + key) + codec.tlv(0x74, challenge) + codec.tlv(0x75, hmac.digest(key, challenge, "sha1"))
    oath_request(session, 3, data)


def access(session):
    with session.case("oath.transition.access-code", ("A01", "A10", "A11", "G10", "G11", "G14", "X02"),
                      effects=("config_change",)):
        selected = dict(codec.parse_tlv(session.select("oath")))
        old_key = None
        if 0x74 in selected:
            session.require(session.options.oath_password is not None, "existing access code requires --oath-password-env")
            old_key = hashlib.pbkdf2_hmac("sha1", session.options.oath_password.encode(), selected[0x71], 1000, 16)
            validate(session, old_key, selected)
        original = oath_names(session)
        active_key = old_key
        try:
            key = session.fixture("oath.state.access-key", 16)
            set_code(session, key)
            active_key = key
            trigger = session.evidence()
            locked = dict(codec.parse_tlv(session.select("oath")))
            session.check("locked SELECT has SHA1 challenge", (len(locked.get(0x74, b"")), locked.get(0x7B)), (8, b"\x01"))
            refused(session, 0xA1, label="locked-list")
            session.transition("oath.authorization", "unlocked", "locked", trigger, [trigger, session.evidence()])
            refused(session, 0xA3, codec.tlv(0x75, bytes(20)) + codec.tlv(0x74, bytes(8)), label="wrong-proof")
            refused(session, 0xA1, label="still-locked")
            replay = validate(session, key)
            trigger = session.evidence()
            session.check("authorized LIST preserves names", oath_names(session), original)
            session.transition("oath.authorization", "locked", "authenticated", trigger, [trigger, session.evidence()])
            session.select("oath")
            refused(session, 0xA3, replay, label="stale-proof")
            refused(session, 0xA1, label="replay-did-not-unlock")
            validate(session, key)
            next_key = session.fixture("oath.state.replacement-key", 16)
            set_code(session, next_key)
            active_key = next_key
            validate(session, next_key)
            session.check("replacement access key works", oath_names(session), original)
        finally:
            if active_key is not old_key and not session.broken:
                session.trace.phase = "cleanup"
                validate(session, active_key)
                if old_key is None:
                    oath_request(session, 3, codec.tlv(0x73, b""))
                    session.check("access code removed", 0x74 not in dict(codec.parse_tlv(session.select("oath"))))
                else:
                    set_code(session, old_key)
                    validate(session, old_key)
                session.check("record set survived access changes", oath_names(session), original)


def increasing(session):
    with session.case("oath.transition.increasing-challenge", ("A02", "A06", "A07", "A09", "G14"), effects=("create_oath_record",)):
        oath_open(session)
        name = b"oracle-increasing-" + session.fixture("oath.increasing", 4).hex().encode()
        session.require(name not in oath_names(session), "fixture name already exists")
        created = False
        try:
            put(session, name, OATH_HASHES[0][2], b"\x78\x01")
            created = True
            for counter in (1, 2):
                challenge = counter.to_bytes(8, "big")
                session.check("increasing TOTP", calculate(session, name, challenge), otp_value(OATH_HASHES[0][2], challenge, "sha1", 6))
            trigger = refused(session, 0xA2, codec.tlv(0x71, name) + codec.tlv(0x74, (1).to_bytes(8, "big")), p2=1, label="decreasing-challenge")
            challenge = (3).to_bytes(8, "big")
            session.check("greater challenge after rejection", calculate(session, name, challenge), otp_value(OATH_HASHES[0][2], challenge, "sha1", 6))
            session.transition("oath.increasing", "challenge:2", "challenge:3", session.evidence(), [trigger, session.evidence()])
        finally:
            if created and not session.broken:
                session.trace.phase = "cleanup"
                oath_request(session, 2, codec.tlv(0x71, name))


def reset(session):
    with session.case("oath.transition.reset", ("A12", "X06"), effects=("applet_reset",)):
        from .reset_witness import snapshot, preserved
        neighbors = snapshot(session, "oath")
        oath_open(session)
        name = b"oracle-reset-" + session.fixture("oath.reset", 4).hex().encode()
        session.require(name not in oath_names(session), "fixture name already exists")
        put(session, name, OATH_HASHES[0][2])
        refused(session, 4, p1=0xDE, label="wrong-reset-parameters")
        session.check("bad RESET preserves fixture", name in oath_names(session))
        oath_request(session, 4, p1=0xDE, p2=0xAD)
        trigger = session.evidence()
        selected = dict(codec.parse_tlv(session.select("oath")))
        session.check("RESET removes access code", 0x74 not in selected)
        session.check("RESET empties records", oath_names(session), set())
        refused(session, 0xA2, codec.tlv(0x71, name) + codec.tlv(0x74, bytes(8)), p2=1, label="old-name-after-reset")
        session.transition("oath.lifecycle", "populated", "empty_unlocked", trigger, [trigger, session.evidence()])
        preserved(session, "oath", neighbors)


def run(session):
    records(session)
    encodings(session)
    increasing(session)
    access(session)
    reset(session)
