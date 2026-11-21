# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Known OATH commands vary class, P1/P2 and grants with otherwise valid bodies."""
import hmac
from itertools import product

from . import codec
from .oath_access import lock, unlock
from .oath_gates import reset
from .oath_pin_matrix import EXTRAS, NAME, NEW_PIN, PIN, private_record, setup
from .otp import OATH_HASHES, oath_names, oath_request, otp_value

COMMANDS = (1, 2, 3, 4, 5, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5)
PARAMETERS = (0, 1, 2, 0x7f, 0xff)


def body(session, command, secret, selected):
    named = codec.tlv(0x71, NAME)
    host = session.fixture("OATH.command.host", 8)
    return {1: named + codec.tlv(0x73, b"\x11\x06" + OATH_HASHES[0][2]) + b"".join(codec.tlv(tag, value) for tag, value in EXTRAS.items()),
        2: named, 3: codec.tlv(0x73, b"\x02" + secret) + codec.tlv(0x74, host) + codec.tlv(0x75, hmac.digest(secret, host, "sha256")),
        4: b"", 5: named + codec.tlv(0x71, b"oracle-renamed-PIN-password"), 0xa1: b"",
        0xa2: named + codec.tlv(0x74, bytes(8)), 0xa3: codec.tlv(0x75, hmac.digest(secret, selected[0x74], "sha256")) + codec.tlv(0x74, host),
        0xa4: codec.tlv(0x74, bytes(8)), 0xa5: b"", 0xb1: named + codec.tlv(0x75, otp_value(OATH_HASHES[0][2], bytes(8), "sha1", 6).to_bytes(4, "big")),
        0xb2: codec.tlv(0x80, PIN), 0xb3: codec.tlv(0x80, PIN) + codec.tlv(0x81, NEW_PIN), 0xb4: codec.tlv(0x80, PIN), 0xb5: named}[command]


def pair_valid(command, p1, p2):
    if command == 4:
        return (p1, p2) == (0xde, 0xad)
    if command in (0xa2, 0xa4):
        return p1 == 0 and p2 in (0, 1)
    if command == 0xa3:
        return p1 == 0 or p2 == 0
    return command == 0xa5 or (p1, p2) == (0, 0)


def outcome(command, cla, p1, p2, granted):
    if cla:
        return 0x6e00
    if not pair_valid(command, p1, p2):
        return 0x6b00
    if command == 0xa5:
        return 0x6d00
    if not granted and command not in (4, 0xa3, 0xb2, 0xb3):
        return 0x6982
    return 0x9000


def run(session):
    vectors = [(f"P1-{p1}.P2-{p2}", 0, p1, p2) for p1, p2 in product(PARAMETERS, repeat=2)]
    vectors += [(f"CLA-{cla:02x}", cla, 0, 0) for cla in (1, 4, 0x0c, 0x80, 0xff)]
    for command, granted in product(COMMANDS, (False, True)):
        for label, cla, p1, p2 in vectors:
            with session.case(f"oath.command.{command:02x}.grant-{granted}.{label}", ("A01", "A02", "A03", "A04", "A07", "A10", "A11", "A14", "A15", "T11", "G04", "G10", "G13", "G14"),
                    effects=("applet_reset", "pin_change", "config_change", "create_oath_record"), touch=True,
                    parameters={"INS": command, "CLA": cla, "P1": p1, "P2": p2, "standing_grants": granted}):
                secret = setup(session, pin=None if command == 0xb4 else PIN)
                try:
                    selected = dict(codec.parse_tlv(session.select("oath")))
                    if granted:
                        unlock(session, 2, secret, selected)
                        if command != 0xb4:
                            oath_request(session, 0xb2, codec.tlv(0x80, PIN))
                    else:
                        selected = lock(session)
                    request = body(session, command, secret, selected)
                    response = session.apdu(codec.apdu(command, p1, p2, request, cla=cla))
                    expected = outcome(command, cla, p1, p2, granted)
                    session.check("known OATH command validates class/parameters before its own authorization", response.status, expected)
                    active_pin = NEW_PIN if command == 0xb3 and expected == 0x9000 else PIN
                    if expected != 0x9000 and granted:
                        private_record(session)
                    elif command in (0xb2, 0xb3) and not granted and expected == 0x9000:
                        session.check("OTP-PIN cannot open the access-code gate", session.apdu(codec.apdu(0xa1)).status, 0x6982)
                    if command == 0xa3 and expected == 0x9000:
                        session.check("VALIDATE response has the independent host proof", codec.parse_tlv(response.data[:-2]),
                            [(0x75, hmac.digest(secret, session.fixture("OATH.command.host", 8), "sha256"))])
                    unlock(session, 2, secret)
                    if command != 0xb4 or expected == 0x9000:
                        oath_request(session, 0xb2, codec.tlv(0x80, active_pin))
                    if expected == 0x9000 and command == 2:
                        session.check("authorized DELETE removes only the owned record", oath_names(session), set())
                        oath_request(session, 1, body(session, 1, secret, selected))
                    elif expected == 0x9000 and command == 5:
                        renamed = b"oracle-renamed-PIN-password"
                        session.check("authorized RENAME changes the owned reference only", oath_names(session), {renamed})
                        oath_request(session, 5, codec.tlv(0x71, renamed) + codec.tlv(0x71, NAME))
                    private_record(session)
                    counter = 1 if expected == 0x9000 and command == 0xa2 else 0
                    value = dict(codec.parse_tlv(oath_request(session, 0xa2, codec.tlv(0x71, NAME) + codec.tlv(0x74, bytes(8)), p2=1)))[0x76]
                    session.check("command outcome has only its declared HOTP counter effect", value,
                        b"\x06" + otp_value(OATH_HASHES[0][2], counter.to_bytes(8, "big"), "sha1", 6).to_bytes(4, "big"))
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        reset(session)
