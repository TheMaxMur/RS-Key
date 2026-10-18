# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OTP-PIN byte/TLV semantics and persisted private records use explicit reset fixtures."""
from . import codec
from .lifecycle import Action, change
from .oath_access import set_code, unlock
from .oath_gates import reset, record_body
from .otp import OATH_HASHES, oath_names, oath_request, otp_value

PIN, NEW_PIN, NAME = b"oracle-old-PIN", b"oracle-new-PIN", b"oracle-PIN-password"
EXTRAS = {0x83: b"login\x00binary", 0x84: bytes(range(256))[:255], 0x85: b"metadata\xff"}


def setup(session, pin=PIN, code=True, algorithm=2):
    session.require(session.profile == "rsk", "OTP-PIN byte/reference contract requires RS-Key", "excluded_by_profile")
    reset(session)
    oath_request(session, 1, record_body(NAME, extra=b"".join(codec.tlv(tag, value) for tag, value in EXTRAS.items())))
    secret = session.fixture("OATH.PIN.code", 20)
    if code:
        set_code(session, algorithm, secret)
        unlock(session, algorithm, secret)
    if pin is not None:
        oath_request(session, 0xb4, codec.tlv(0x80, pin))
        oath_request(session, 0xb2, codec.tlv(0x80, pin))
    return secret


def private_record(session):
    value = dict(codec.parse_tlv(oath_request(session, 0xb5, codec.tlv(0x71, NAME))))
    session.check("OTP-PIN scenarios preserve all private fields", value, {0x71: NAME, **EXTRAS})


def grammar_vectors(command):
    good = codec.tlv(0x80, PIN) + (codec.tlv(0x81, NEW_PIN) if command == 0xb3 else b"")
    yield "absent-password", b"", 0x6a80, PIN
    yield "unknown-only", codec.tlv(0x99, b"x"), 0x6a80, PIN
    yield "truncated-password", b"\x80\x7f" + PIN, 0x6a80, PIN
    yield "nested-password", codec.tlv(0x53, good), 0x6a80, PIN
    yield "unknown-before", codec.tlv(0x99, b"x") + good, 0x9000, NEW_PIN if command == 0xb3 else PIN
    yield "trailing-incomplete", good + b"\xff", 0x9000, NEW_PIN if command == 0xb3 else PIN
    yield "duplicate-password", good + codec.tlv(0x80, b"ignored"), 0x9000, NEW_PIN if command == 0xb3 else PIN
    yield "wide-length", b"\x80\x81" + bytes([len(PIN)]) + PIN + (codec.tlv(0x81, NEW_PIN) if command == 0xb3 else b""), 0x9000, NEW_PIN if command == 0xb3 else PIN
    if command == 0xb3:
        yield "missing-new", codec.tlv(0x80, PIN), 0x6a80, PIN
        yield "reordered", codec.tlv(0x81, NEW_PIN) + codec.tlv(0x80, PIN), 0x9000, NEW_PIN
        yield "duplicate-new", good + codec.tlv(0x81, b"ignored"), 0x9000, NEW_PIN


def grammar(session):
    for command in (0xb2, 0xb3, 0xb4):
        for label, body, status, active_pin in grammar_vectors(command):
            with session.case(f"oath.OTP-PIN.grammar.{command:02x}.{label}", ("A10", "A11", "A14", "A15", "G01", "G05", "G07", "G14"),
                    effects=("pin_change", "applet_reset", "config_change", "create_oath_record"), touch=True):
                setup(session, pin=None if command == 0xb4 else PIN)
                try:
                    private_record(session)
                    response = session.apdu(codec.apdu(command, data=body))
                    session.check("OTP-PIN TLV grammar has the profiled first-match outcome", response.status, status)
                    if status != 0x9000:
                        private_record(session)
                    if command == 0xb3 and status == 0x9000:
                        session.check("successful PIN change drops both standing authorizations", session.apdu(codec.apdu(0xa1)).status, 0x6982)
                        unlock(session, 2, session.fixture("OATH.PIN.code", 20))
                        session.check("access-code proof alone cannot inherit changed PIN grant", session.apdu(codec.apdu(0xb5, data=codec.tlv(0x71, NAME))).status, 0x6982)
                    if command != 0xb4 or status == 0x9000:
                        oath_request(session, 0xb2, codec.tlv(0x80, active_pin))
                    private_record(session)
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        reset(session)


def boundaries(session):
    values = [(f"bytes-{size}", bytes(range(256))[:size] if size <= 256 else b"x" * size)
              for size in (0, 1, 2, 31, 32, 63, 64, 127, 128, 255, 256, 257)]
    values += [("UTF8", "é😀".encode()), ("invalid-UTF8", b"\xff\x80"), ("embedded-NUL", b"a\x00b")]
    for command in (0xb4, 0xb3):
        for label, pin in values:
            with session.case(f"oath.OTP-PIN.boundary.{command:02x}.{label}", ("A14", "A15", "G03", "G08", "G14"),
                    effects=("pin_change", "applet_reset", "config_change", "create_oath_record"), touch=True):
                setup(session, pin=None if command == 0xb4 else PIN)
                try:
                    body = (codec.tlv(0x80, PIN) + codec.tlv(0x81, pin)) if command == 0xb3 else codec.tlv(0x80, pin)
                    oath_request(session, command, body)
                    unlock(session, 2, session.fixture("OATH.PIN.code", 20))
                    oath_request(session, 0xb2, codec.tlv(0x80, pin))
                    private_record(session)
                    session.observe("PIN_byte_contract", "OTP-PIN hashes opaque TLV bytes, including empty/binary values; no invented UTF-8 or FIDO length policy")
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        reset(session)


def persistence(session):
    for action in Action:
        for algorithm in (1, 2, 3):
            with session.case(f"oath.private-records.persistence.{action.value}.code-hash-{algorithm}", ("A01", "A09", "A10", "A11", "A14", "A15", "X11", "G14"),
                    effects=("pin_change", "applet_reset", "config_change", "create_oath_record", "reboot") if action == Action.POWER_CYCLE else ("pin_change", "applet_reset", "config_change", "create_oath_record"), touch=True):
                secret = setup(session, algorithm=algorithm)
                try:
                    private_record(session)
                    change(session, action)
                    selected = dict(codec.parse_tlv(session.select("oath")))
                    session.check("access-code challenge persists across the connection action", 0x74 in selected)
                    session.observe("code_grant_after_connection", session.apdu(codec.apdu(0xa1)).status)
                    unlock(session, algorithm, secret, selected)
                    session.check("SELECT revokes OTP-PIN independently of the code grant", session.apdu(codec.apdu(0xb5, data=codec.tlv(0x71, NAME))).status, 0x6982)
                    oath_request(session, 0xb2, codec.tlv(0x80, PIN))
                    private_record(session)
                    session.check("connection action preserves record enumeration", oath_names(session), {NAME})
                    result = dict(codec.parse_tlv(oath_request(session, 0xa2, codec.tlv(0x71, NAME) + codec.tlv(0x74, bytes(8)), p2=1)))[0x76]
                    session.check("connection action preserves HOTP secret and moving factor", result, b"\x06" + otp_value(OATH_HASHES[0][2], bytes(8), "sha1", 6).to_bytes(4, "big"))
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        reset(session)


def run(session):
    grammar(session)
    boundaries(session)
    persistence(session)
