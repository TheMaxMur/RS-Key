# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Access-code and OTP-PIN grants are independent, including at full capacity."""
from enum import Enum

from . import codec
from .oath_access import set_code, unlock, lock, known_record
from .otp import OATH_HASHES, oath_names, oath_request, otp_value

MAX_RECORDS = 255


class Grant(Enum):
    NONE = "none"
    CODE = "code"
    PIN = "PIN"
    BOTH = "both"


def reset(session):
    session.select("oath")
    oath_request(session, 4, p1=0xDE, p2=0xAD)
    session.failed_auth.discard(("oath", 0xB2))
    session.check("OATH reset establishes an empty fixture store", oath_names(session), set())


def record_body(name, kind=0x11, extra=b""):
    return codec.tlv(0x71, name) + codec.tlv(0x73, bytes([kind, 6]) + OATH_HASHES[0][2]) + extra


def pin_gates(session):
    for access_code in (False, True):
        for grant in Grant:
            for command in (0xB1, 0xB5):
                with session.case(f"oath.gates.command-{command:02x}.code-{access_code}.{grant.value}", ("A10", "A11", "A12", "A13", "A14", "A15", "G10", "G14"),
                                  effects=("config_change", "pin_change", "applet_reset", "create_oath_record"), touch=True):
                    session.require(session.profile == "rsk", "OTP-PIN cross-gates require RS-Key", "excluded_by_profile")
                    pin, secret, name = b"oracle-OTP-PIN", session.fixture("OATH.gate.code", 20), b"oracle-gated-password"
                    reset(session)
                    try:
                        extras = {0x83: b"oracle-login", 0x84: b"oracle-password", 0x85: b"oracle-metadata"}
                        oath_request(session, 1, record_body(name, extra=b"".join(codec.tlv(tag, value) for tag, value in extras.items())))
                        oath_request(session, 0xB4, codec.tlv(0x80, pin))
                        if access_code:
                            set_code(session, 2, secret)
                        selected = lock(session)
                        if grant in (Grant.PIN, Grant.BOTH):
                            oath_request(session, 0xB2, codec.tlv(0x80, pin))
                        if access_code and grant in (Grant.CODE, Grant.BOTH):
                            unlock(session, 2, secret, selected)
                        code_ok = not access_code or grant in (Grant.CODE, Grant.BOTH)
                        pin_ok = grant in (Grant.PIN, Grant.BOTH)
                        listing = session.apdu(codec.apdu(0xA1))
                        session.check("LIST enforces the access code independently of OTP-PIN", listing.status, 0x9000 if code_ok else 0x6982)
                        code_value = otp_value(OATH_HASHES[0][2], bytes(8), "sha1", 6)
                        body = codec.tlv(0x71, name) + (codec.tlv(0x75, code_value.to_bytes(4, "big")) if command == 0xB1 else b"")
                        reply = session.apdu(codec.apdu(command, data=body))
                        session.check("secret record operation requires both independently configured grants", reply.status, 0x9000 if code_ok and pin_ok else 0x6982)
                        if access_code and grant == Grant.BOTH:
                            selected = lock(session)
                            unlock(session, 2, secret, selected)
                            oath_request(session, 0xB2, codec.tlv(0x80, pin))
                            session.check("code-then-PIN also authorizes the secret operation", session.apdu(codec.apdu(command, data=body)).status, 0x9000)
                            session.select("oath")
                            session.check("same SELECT retains code authorization", session.apdu(codec.apdu(0xA1)).status, 0x9000)
                            session.check("same SELECT independently revokes OTP-PIN authorization", session.apdu(codec.apdu(command, data=body)).status, 0x6982)
                        if access_code:
                            unlock(session, 2, secret)
                        oath_request(session, 0xB2, codec.tlv(0x80, pin))
                        result = dict(codec.parse_tlv(oath_request(session, 0xB5, codec.tlv(0x71, name))))
                        session.check("all password fields survive authorization refusal", result, {0x71: name, **extras})
                        oath_request(session, 0xB1, codec.tlv(0x71, name) + codec.tlv(0x75, code_value.to_bytes(4, "big")))
                        known_record(session, name, 0)
                    finally:
                        if not session.broken:
                            session.trace.phase = "cleanup"
                            reset(session)


def reset_catalog(session):
    with session.case("oath.reset.all-record-types-and-grants", ("A02", "A05", "A06", "A10", "A12", "A13", "A14", "A15", "X06", "G14"),
                      effects=("config_change", "pin_change", "applet_reset", "create_oath_record"), touch=True):
        session.require(session.profile == "rsk", "additional record reset catalog requires RS-Key", "excluded_by_profile")
        reset(session)
        pin, code = b"oracle-OTP-PIN", session.fixture("OATH.reset.code", 20)
        names = []
        try:
            for label, kind, extra in (("HOTP", 0x11, b""), ("TOTP", 0x21, b""), ("touch", 0x21, b"\x78\x02"),
                                       ("increasing", 0x21, b"\x78\x01"), ("password", 0x21, codec.tlv(0x84, b"oracle-password"))):
                name = b"oracle-reset-" + label.encode()
                oath_request(session, 1, record_body(name, kind, extra))
                names.append(name)
            oath_request(session, 0xB4, codec.tlv(0x80, pin))
            set_code(session, 3, code)
            unlock(session, 3, code)
            oath_request(session, 0xB2, codec.tlv(0x80, pin))
            session.check("all reset record fixtures exist", oath_names(session), set(names))
            reset(session)
            selected = dict(codec.parse_tlv(session.select("oath")))
            session.check("reset removes the access-code challenge", 0x74 not in selected)
            session.check("reset removes the OTP-PIN itself", session.apdu(codec.apdu(0xB2, data=codec.tlv(0x80, pin))).status, 0x6985)
            for name in names:
                result = session.apdu(codec.apdu(0xB5, data=codec.tlv(0x71, name)))
                session.check("reset removes every private record's secret fields", result.status, 0x6984)
            name = b"oracle-after-reset"
            oath_request(session, 1, record_body(name, extra=codec.tlv(0x84, b"new-password")))
            session.check("reset retired old PIN gate as well as old record names", dict(codec.parse_tlv(oath_request(session, 0xB5, codec.tlv(0x71, name))))[0x84], b"new-password")
        finally:
            if not session.broken:
                session.trace.phase = "cleanup"
                reset(session)


def full_store(session):
    with session.case("oath.capacity.rename-replace-and-reclaim", ("A02", "A03", "A09", "A12", "X07", "G09", "G11", "G14"),
                      effects=("capacity", "applet_reset", "create_oath_record")):
        session.require(session.profile == "rsk", "bounded OATH quota requires RS-Key", "excluded_by_profile")
        reset(session)
        names = {f"oracle-full-{index:03d}".encode() for index in range(MAX_RECORDS)}
        try:
            for name in sorted(names):
                oath_request(session, 1, record_body(name, 0x21))
            session.check("every profiled OATH slot can be populated", oath_names(session), names)
            extra = b"oracle-beyond-full"
            reply = session.apdu(codec.apdu(1, data=record_body(extra, 0x21)))
            session.check("full store refuses an additional record", reply.status, 0x6A84)
            source, target = min(names), b"oracle-renamed-while-full"
            oath_request(session, 5, codec.tlv(0x71, source) + codec.tlv(0x71, target))
            names.remove(source)
            names.add(target)
            session.check("rename needs no extra free slot", oath_names(session), names)
            for old, new in ((target, target), (source, target), (source, b"unused")):
                reply = session.apdu(codec.apdu(5, data=codec.tlv(0x71, old) + codec.tlv(0x71, new)))
                session.check("self/collision/unknown rename refused", reply.status, 0x6984)
                session.check("refused full-store rename preserves all names", oath_names(session), names)
            oath_request(session, 1, record_body(target, 0x21))
            session.check("replacement at capacity retains exact occupancy", oath_names(session), names)
            oath_request(session, 2, codec.tlv(0x71, target))
            names.remove(target)
            oath_request(session, 1, record_body(extra, 0x21))
            names.add(extra)
            session.check("deletion reclaims one OATH slot", oath_names(session), names)
            challenge = bytes(8)
            for name in sorted(names):
                value = dict(codec.parse_tlv(oath_request(session, 0xA2, codec.tlv(0x71, name) + codec.tlv(0x74, challenge), p2=1)))[0x76]
                session.check("full store retains each private secret", value, b"\x06" + otp_value(OATH_HASHES[0][2], challenge, "sha1", 6).to_bytes(4, "big"))
        finally:
            if not session.broken:
                session.trace.phase = "cleanup"
                reset(session)


def run(session):
    pin_gates(session)
    reset_catalog(session)
    full_store(session)
