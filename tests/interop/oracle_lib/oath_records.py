# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Profiled password-safe records, OTP verification and bounded PIN lifecycle."""
from . import codec
from .otp import oath_open, oath_names, oath_request, otp_value, OATH_HASHES


def refused(session, ins, data, status):
    reply = session.apdu(codec.apdu(ins, data=data), f"oath.{ins:02x}.refusal")
    session.check("OATH refusal cause", (reply.protocol, reply.status), ("applet_error", status))


def get_record(session, name):
    return dict(codec.parse_tlv(oath_request(session, 0xB5, codec.tlv(0x71, name))))


def establish_record_access(session, missing_name):
    response = session.apdu(codec.apdu(0xB5, data=codec.tlv(0x71, missing_name)), "oath.password-read.precondition")
    if response.status == 0x6982:
        session.require(session.options.oath_pin is not None, "password-safe reads require known --oath-pin-env")
        oath_request(session, 0xB2, codec.tlv(0x80, session.options.oath_pin.encode()))
        refused(session, 0xB5, codec.tlv(0x71, missing_name), 0x6984)
    else:
        session.check("password-safe missing-name precondition", response.status, 0x6984)


def records(session):
    for size in (0, 1, 127, 128, 254, 255):
        with session.case(f"oath.password-record.{size}", ("A15", "G03", "G09", "G14"), effects=("create_oath_record",)):
            session.require(session.profile == "rsk", "password-safe protocol needs a confirmed profile", "excluded_by_profile")
            oath_open(session)
            name = b"oracle-password-" + session.fixture("password.name", 5).hex().encode()
            session.require(name not in oath_names(session), "fixture name already exists")
            establish_record_access(session, name)
            fields = {0x71: name, 0x83: session.fixture("login", size), 0x84: session.fixture("password", size),
                      0x85: session.fixture("metadata", size)}
            body = codec.tlv(0x71, name) + codec.tlv(0x73, b"\x21\x06" + OATH_HASHES[0][2])
            body += b"".join(codec.tlv(tag, value) for tag, value in fields.items() if tag != 0x71)
            created = False
            try:
                oath_request(session, 1, body)
                created = True
                session.check("password-safe exact readback", get_record(session, name), fields)
                for tag in (0x83, 0x84, 0x85):
                    invalid = codec.tlv(0x71, name) + codec.tlv(0x73, b"\x21\x06" + OATH_HASHES[0][2]) + codec.tlv(tag, bytes(256))
                    refused(session, 1, invalid, 0x6A80)
                    session.check("oversize replacement preserves all fields", get_record(session, name), fields)
            finally:
                if created and not session.broken:
                    session.trace.phase = "cleanup"
                    if name in oath_names(session):
                        oath_request(session, 2, codec.tlv(0x71, name))
                    refused(session, 0xB5, codec.tlv(0x71, name), 0x6984)


def verify_code(session):
    with session.case("oath.verify-code.primary-hotp", ("A13", "A05", "G13", "G14"), effects=("create_oath_record",)):
        session.require(session.profile == "rsk", "VERIFY CODE semantics require the RS-Key profile", "excluded_by_profile")
        oath_open(session)
        session.require(not oath_names(session), "VERIFY CODE addresses primary slot; requires empty OATH storage")
        name, secret = b"oracle-primary", OATH_HASHES[0][2]
        establish_record_access(session, name)
        created = False
        try:
            oath_request(session, 1, codec.tlv(0x71, name) + codec.tlv(0x73, b"\x11\x06" + secret))
            created = True
            code = otp_value(secret, bytes(8), "sha1", 6)
            good = codec.tlv(0x71, name) + codec.tlv(0x75, code.to_bytes(4, "big"))
            for bad in ((code + 1) % 1000000, (code + 2) % 1000000):
                refused(session, 0xB1, codec.tlv(0x71, name) + codec.tlv(0x75, bad.to_bytes(4, "big")), 0x6A80)
                oath_request(session, 0xB1, good)
            oath_request(session, 0xB1, good)
            session.observe("replay_policy", "RS-Key VERIFY CODE compares without advancing HOTP")
            response = dict(codec.parse_tlv(oath_request(session, 0xA2, codec.tlv(0x71, name) + codec.tlv(0x74, bytes(8)), p2=1)))[0x76]
            session.check("VERIFY CODE never advances moving factor", int.from_bytes(response[1:], "big"), code)
            refused(session, 0xB1, good, 0x6A80)
            next_code = otp_value(secret, (1).to_bytes(8, "big"), "sha1", 6)
            oath_request(session, 0xB1, codec.tlv(0x71, name) + codec.tlv(0x75, next_code.to_bytes(4, "big")))
        finally:
            if created and not session.broken:
                session.trace.phase = "cleanup"
                oath_request(session, 2, codec.tlv(0x71, name))


def pin_lifecycle(session):
    with session.case("oath.otp-pin.lifecycle-block-reset", ("A14", "A12", "A15", "G10", "G14"),
                      effects=("pin_change", "pin_attempts", "applet_reset", "create_oath_record"), touch=True):
        session.require(session.profile == "rsk", "OTP-PIN protocol needs confirmed RS-Key profile", "excluded_by_profile")
        oath_open(session)
        session.require(not oath_names(session), "OTP-PIN lifecycle requires empty test applet")
        session.require(session.options.oath_pin is not None, "supply --oath-pin-env for the known fixture PIN")
        oath_request(session, 4, p1=0xDE, p2=0xAD)
        session.check("OTP-PIN factory precondition has no records", oath_names(session), set())
        session.failed_auth.discard(("oath", 0xB2))
        pin = session.options.oath_pin.encode()
        new_pin, name = b"oracle-otp-pin-new", b"oracle-pin-record"
        body = codec.tlv(0x71, name) + codec.tlv(0x73, b"\x21\x06" + OATH_HASHES[0][2]) + codec.tlv(0x84, b"fixture-password")
        reset_needed = False
        try:
            reply = session.apdu(codec.apdu(0xB4, data=codec.tlv(0x80, pin)), "oath.set-pin")
            session.card_value(reply)
            reset_needed = True
            oath_request(session, 0xB2, codec.tlv(0x80, pin))
            oath_request(session, 1, body)
            session.check("verified PIN reads password", get_record(session, name)[0x84], b"fixture-password")
            session.select("oath")
            refused(session, 0xB5, codec.tlv(0x71, name), 0x6982)
            with session.attempts(("oath", 0xB2), 8):
                wrong = session.apdu(codec.apdu(0xB2, data=codec.tlv(0x80, pin + b"!")), "oath.pin-wrong")
                session.check("wrong OTP-PIN refused", wrong.status, 0x6982)
                refused(session, 0xB5, codec.tlv(0x71, name), 0x6982)
                oath_request(session, 0xB2, codec.tlv(0x80, pin))
                oath_request(session, 0xB3, codec.tlv(0x80, pin) + codec.tlv(0x81, new_pin))
                oath_request(session, 0xB2, codec.tlv(0x80, new_pin))
                for _ in range(3):
                    wrong = session.apdu(codec.apdu(0xB2, data=codec.tlv(0x80, pin)), "oath.consume-retry")
                    session.check("wrong old PIN refused after change", wrong.status, 0x6982)
                blocked = session.apdu(codec.apdu(0xB2, data=codec.tlv(0x80, new_pin)), "oath.blocked-correct-pin")
                session.check("correct OTP-PIN cannot bypass block", blocked.status, 0x6982)
            refused(session, 0xB5, codec.tlv(0x71, name), 0x6982)
            session.select("oath")
            refused(session, 0xB4, codec.tlv(0x80, pin), 0x6985)
        finally:
            if reset_needed and not session.broken:
                session.trace.phase = "cleanup"
                oath_request(session, 4, p1=0xDE, p2=0xAD)
                session.check("reset deletes password record", oath_names(session), set())
                session.failed_auth.discard(("oath", 0xB2))
                refused(session, 0xB2, codec.tlv(0x80, pin), 0x6985)


def run(session):
    records(session)
    verify_code(session)
    pin_lifecycle(session)
