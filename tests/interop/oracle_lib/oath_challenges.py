# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Individual and bulk challenge readers have deliberately different TLV grammars."""
import hmac
from itertools import product

from . import codec
from .oath_access import lock, unlock
from .oath_gates import Grant, reset, record_body
from .oath_pin_matrix import NAME, PIN, private_record, setup
from .otp import OATH_HASHES, oath_request, otp_value

TOTP = b"oracle-challenge-TOTP"
LENGTHS = (0, 1, 7, 8, 9, 63, 64, 65, 127, 128, 255, 256)


def variants(command):
    challenge = bytes(range(8))
    named, chal = codec.tlv(0x71, TOTP), codec.tlv(0x74, challenge)
    prefix = named if command == 0xa2 else b""
    base = prefix + chal
    for size in LENGTHS:
        value = bytes(range(256))[:size]
        yield f"challenge-length-{size}", prefix + codec.tlv(0x74, value), value, 0x9000 if size <= 64 else 0x6a80
    yield "missing-challenge", prefix, challenge, 0x6a80
    yield "wrong-first-tag", codec.tlv(0x99, b"x") + base, challenge, 0x6a80
    yield "nested", codec.tlv(0x53, base), challenge, 0x6a80
    yield "truncated-challenge", base[:-1], challenge, 0x6a80
    yield "wide-challenge-length", prefix + b"\x74\x81\x08" + challenge, challenge, 0x9000
    for label, suffix in (("duplicate-challenge", chal), ("unknown-tail", codec.tlv(0x99, b"x")), ("trailing-incomplete", b"\xff")):
        yield label, base + suffix, challenge, 0x9000 if command == 0xa4 else 0x6a80
    if command == 0xa2:
        yield "missing-name", chal, challenge, 0x6a80
        yield "reordered", chal + named, challenge, 0x6a80
        yield "duplicate-name", named * 2 + chal, challenge, 0x6a80
        yield "unknown-middle", named + codec.tlv(0x99, b"x") + chal, challenge, 0x6a80
        yield "wide-name-length", b"\x71\x82\x00" + bytes([len(TOTP)]) + TOTP + chal, challenge, 0x9000


def response(session, command, full, result, challenge):
    secret = OATH_HASHES[0][2]
    expected = b"\x06" + (hmac.digest(secret, challenge, "sha1") if full else otp_value(secret, challenge, "sha1", 6).to_bytes(4, "big"))
    fields = codec.parse_tlv(session.card_value(result))
    tag = 0x75 if full else 0x76
    wanted = [(tag, expected)] if command == 0xa2 else [(0x71, NAME), (0x77, b"\x06"), (0x71, TOTP), (tag, expected)]
    session.check("challenge grammar computes only the exact accepted challenge bytes", fields, wanted)


def run(session):
    for command, full, grant in product((0xa2, 0xa4), (False, True), Grant):
        for label, body, challenge, status in variants(command):
            with session.case(f"oath.challenge-grammar.{command:02x}.full-{full}.{grant.value}.{label}", ("A01", "A04", "A05", "A07", "A10", "A14", "A15", "G01", "G03", "G07", "G10", "G13", "G14"),
                    effects=("applet_reset", "pin_change", "config_change", "create_oath_record"), touch=True,
                    parameters={"command": command, "full": full, "grant": grant.value, "defect": label}):
                secret = setup(session)
                try:
                    oath_request(session, 1, record_body(TOTP, kind=0x21))
                    selected = lock(session)
                    if grant in (Grant.CODE, Grant.BOTH):
                        unlock(session, 2, secret, selected)
                    if grant in (Grant.PIN, Grant.BOTH):
                        oath_request(session, 0xb2, codec.tlv(0x80, PIN))
                    result = session.apdu(codec.apdu(command, p2=0 if full else 1, data=body))
                    expected = status if grant in (Grant.CODE, Grant.BOTH) else 0x6982
                    session.check("challenge command enforces code authorization before its own grammar", result.status, expected)
                    if expected == 0x9000:
                        response(session, command, full, result, challenge)
                    else:
                        session.check("refused challenge returns no OTP bytes", result.data[:-2], b"")
                    protected = session.apdu(codec.apdu(0xb5, data=codec.tlv(0x71, NAME)))
                    session.check("challenge success/refusal cannot invent or revoke private-record grants", protected.status, 0x9000 if grant == Grant.BOTH else 0x6982)
                    unlock(session, 2, secret)
                    oath_request(session, 0xb2, codec.tlv(0x80, PIN))
                    private_record(session)
                    control = bytes(8)
                    response(session, 0xa2, False, session.apdu(codec.apdu(0xa2, p2=1, data=codec.tlv(0x71, TOTP) + codec.tlv(0x74, control))), control)
                    hotp = dict(codec.parse_tlv(oath_request(session, 0xa2, codec.tlv(0x71, NAME) + codec.tlv(0x74, control), p2=1)))[0x76]
                    session.check("individual/bulk challenge grammar never consumes the neighboring HOTP", hotp,
                        b"\x06" + otp_value(OATH_HASHES[0][2], control, "sha1", 6).to_bytes(4, "big"))
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        reset(session)
