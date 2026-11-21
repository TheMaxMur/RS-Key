# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""RENAME preserves an already-used secret, moving factor and private record fields."""
from . import codec
from .oath_access import lock, unlock
from .oath_gates import reset
from .oath_pin_matrix import EXTRAS, NAME, PIN, setup
from .otp import OATH_HASHES, oath_names, oath_request, otp_value


def variants():
    target = b"oracle-renamed-private"
    old, new = codec.tlv(0x71, NAME), codec.tlv(0x71, target)
    yield "no-fields", b"", None, 0x6a80
    yield "missing-target", old, None, 0x6a80
    yield "truncated-target", old + new[:-1], None, 0x6a80
    yield "nested", codec.tlv(0x53, old + new), None, 0x6a80
    yield "unknown-prefix", codec.tlv(0x99, b"x") + old + new, None, 0x6a80
    yield "unknown-between", old + codec.tlv(0x99, b"x") + new, target, 0x9000
    yield "compact-property-between", old + b"\x78\x02" + new, target, 0x9000
    yield "trailing-incomplete", old + new + b"\xff", target, 0x9000
    yield "third-NAME", old + new + codec.tlv(0x71, b"ignored"), target, 0x9000
    yield "reversed-references", new + old, None, 0x6984
    yield "empty-source", codec.tlv(0x71, b"") + new, None, 0x6984
    yield "source-and-target-empty", codec.tlv(0x71, b"") * 2, None, 0x6a80
    yield "nonshort-old-length", b"\x71\x81" + bytes([len(NAME)]) + NAME + new, target, 0x9000
    yield "nonshort-new-length", old + b"\x71\x82\x00" + bytes([len(target)]) + target, target, 0x9000
    names = [("bytes-" + str(size), b"x" * size) for size in (0, 1, 2, 63, 64, 65)]
    names += [("UTF8-64", "é".encode() * 32), ("UTF8-overflow", "é".encode() * 33),
              ("binary", b"\xff\x80"), ("embedded-NUL", b"a\x00b")]
    for label, value in names:
        valid = 1 <= len(value) <= 64
        yield label, old + codec.tlv(0x71, value), value if valid else None, 0x9000 if valid else 0x6a80


def calculate(session, name, counter):
    value = dict(codec.parse_tlv(oath_request(session, 0xa2, codec.tlv(0x71, name) + codec.tlv(0x74, bytes(8)), p2=1)))[0x76]
    session.check("RENAME preserves an already-used HOTP secret and counter", value,
        b"\x06" + otp_value(OATH_HASHES[0][2], counter.to_bytes(8, "big"), "sha1", 6).to_bytes(4, "big"))


def run(session):
    for granted in (False, True):
        for label, body, target, status in variants():
            with session.case(f"oath.RENAME.grammar.grant-{granted}.{label}", ("A01", "A05", "A09", "A15", "G03", "G07", "G08", "G13", "G14"),
                    effects=("applet_reset", "pin_change", "config_change", "create_oath_record"), touch=True,
                    parameters={"defect": label, "code_grant": granted}):
                secret = setup(session)
                try:
                    calculate(session, NAME, 0)
                    if not granted:
                        lock(session)
                    reply = session.apdu(codec.apdu(5, data=body))
                    expected = status if granted else 0x6982
                    session.check("RENAME enforces code authorization before grammar/reference checks", reply.status, expected)
                    if not granted:
                        unlock(session, 2, secret)
                        oath_request(session, 0xb2, codec.tlv(0x80, PIN))
                    name = target if expected == 0x9000 else NAME
                    session.check("RENAME changes only the intended name", oath_names(session), {name})
                    value = dict(codec.parse_tlv(oath_request(session, 0xb5, codec.tlv(0x71, name))))
                    session.check("RENAME preserves every private field byte", value, {0x71: name, **EXTRAS})
                    calculate(session, name, 1)
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        reset(session)
