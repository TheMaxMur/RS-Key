# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Paged reads retire at command dispatch, independently of either authorization grant."""
from itertools import product

from . import codec
from .oath_access import lock, set_code, unlock
from .oath_gates import Grant, record_body, reset
from .oath_pin_matrix import NAME, PIN, private_record, setup
from .otp import OATH_HASHES, oath_names, oath_request, otp_value

INTERRUPTIONS = ("complete", "bad-CLA", "bad-parameters", "unknown-command", "PUT", "DELETE", "RENAME",
    "SET-CODE", "remove-CODE", "bad-VALIDATE", "VALIDATE", "VERIFY-PIN", "CHANGE-PIN", "SET-existing-PIN",
    "same-SELECT", "other-SELECT", "invalid-SELECT", "restart-LIST", "restart-CALCULATE-ALL")


def request(command, le=None):
    return codec.apdu(command, p2=1 if command == 0xa4 else 0,
        data=codec.tlv(0x74, bytes(8)) if command == 0xa4 else b"", le=le)


def finish(session, first):
    body = bytearray(first.data[:-2])
    for index in range(256):
        if first.status >> 8 != 0x61:
            session.card_value(first)
            return bytes(body)
        first = session.apdu(codec.apdu(0xa5, p1=index & 255, p2=255, data=b"ignored", le=17))
        session.check("each SEND REMAINING makes bounded progress", len(first.data) > 2 or first.status >> 8 != 0x61)
        body.extend(first.data[:-2])
    session.check("page cursor terminates within its record bound", False)


def run(session):
    for command, grant, interruption in product((0xa1, 0xa4), Grant, INTERRUPTIONS):
        with session.case(f"oath.pages.{command:02x}.{grant.value}.{interruption}", ("A03", "A05", "A07", "A08", "A10", "A11", "A14", "A15", "G10", "G11", "G13", "G14", "X02"),
                effects=("applet_reset", "pin_change", "config_change", "create_oath_record"), touch=True,
                parameters={"command": command, "grant": grant.value, "interruption": interruption}):
            secret = setup(session)
            names = {NAME}
            try:
                for index in range(10):
                    name = f"oracle-paging-{index}-".encode().ljust(64, b"x")
                    oath_request(session, 1, record_body(name, kind=0x21))
                    names.add(name)
                expected = {ins: finish(session, session.apdu(request(ins))) for ins in (0xa1, 0xa4)}
                selected = lock(session)
                if grant in (Grant.CODE, Grant.BOTH):
                    unlock(session, 2, secret, selected)
                if grant in (Grant.PIN, Grant.BOTH):
                    oath_request(session, 0xb2, codec.tlv(0x80, PIN))
                first = session.apdu(request(command, le=17))
                authorized = grant in (Grant.CODE, Grant.BOTH)
                session.check("paged read requires access code rather than OTP-PIN", first.status >> 8 if authorized else first.status, 0x61 if authorized else 0x6982)
                if not authorized:
                    session.check("unauthorized read creates no page cursor", session.apdu(codec.apdu(0xa5)).status, 0x6d00)
                elif interruption in ("complete", "bad-CLA", "invalid-SELECT"):
                    if interruption == "bad-CLA":
                        session.check("class refusal precedes page retirement", session.apdu(codec.apdu(0xff, cla=0x80)).status, 0x6e00)
                    elif interruption == "invalid-SELECT":
                        session.check("unrecognized AID does not dispatch OATH SELECT or retire its internal page", session.apdu(codec.apdu(0xa4, 4, data=b"\xf0\xff\xff\xff\xff")).status, 0x6a82)
                    session.check("continuation retains exact authorized bulk bytes", finish(session, first), expected[command])
                else:
                    target = sorted(names - {NAME})[0]
                    if interruption == "bad-parameters":
                        session.check("parameter refusal follows page retirement", session.apdu(codec.apdu(0xa1, p1=1)).status, 0x6b00)
                    elif interruption == "unknown-command":
                        session.check("unknown command retires the old page", session.apdu(codec.apdu(0xff)).status, 0x6d00)
                    elif interruption == "PUT":
                        oath_request(session, 1, record_body(target, kind=0x21))
                    elif interruption == "DELETE":
                        oath_request(session, 2, codec.tlv(0x71, target))
                        names.remove(target)
                    elif interruption == "RENAME":
                        renamed = b"oracle-paging-renamed"
                        oath_request(session, 5, codec.tlv(0x71, target) + codec.tlv(0x71, renamed))
                        names.remove(target)
                        names.add(renamed)
                    elif interruption == "SET-CODE":
                        set_code(session, 2, secret)
                    elif interruption == "remove-CODE":
                        oath_request(session, 3, codec.tlv(0x73, b""))
                    elif interruption == "bad-VALIDATE":
                        session.check("wrong proof refuses without preserving a page", session.apdu(codec.apdu(0xa3, data=codec.tlv(0x75, bytes(32)) + codec.tlv(0x74, bytes(8)))).status, 0x6a80)
                    elif interruption == "VALIDATE":
                        unlock(session, 2, secret, selected)
                    elif interruption == "VERIFY-PIN":
                        oath_request(session, 0xb2, codec.tlv(0x80, PIN))
                    elif interruption == "CHANGE-PIN":
                        oath_request(session, 0xb3, codec.tlv(0x80, PIN) + codec.tlv(0x81, PIN))
                    elif interruption == "SET-existing-PIN":
                        session.check("existing PIN refuses replacement", session.apdu(codec.apdu(0xb4, data=codec.tlv(0x80, PIN))).status, 0x6985)
                    elif interruption.endswith("SELECT"):
                        if interruption == "other-SELECT":
                            session.select("piv")
                        session.select("oath")
                    else:
                        replacement = 0xa1 if interruption == "restart-LIST" else 0xa4
                        session.check("a new begin reconstructs only the new response", finish(session, session.apdu(request(replacement, le=17))), expected[replacement])
                session.check("retired or exhausted page cannot be resumed", session.apdu(codec.apdu(0xa5)).status, 0x6d00)
                code_live, pin_live = authorized, grant in (Grant.PIN, Grant.BOTH)
                if authorized:
                    code_live = interruption not in ("SET-CODE", "CHANGE-PIN", "other-SELECT")
                    pin_live = (pin_live or interruption == "VERIFY-PIN") and interruption not in ("CHANGE-PIN", "same-SELECT", "other-SELECT")
                listing = session.apdu(codec.apdu(0xa1))
                session.check("page outcome retains exactly the access-code grant", listing.status in (0x9000,) or listing.status >> 8 == 0x61, code_live)
                if code_live:
                    finish(session, listing)
                session.check("page outcome retains exactly the independent private-record grant", session.apdu(codec.apdu(0xb5, data=codec.tlv(0x71, NAME))).status, 0x9000 if code_live and pin_live else 0x6982)
                if interruption == "remove-CODE" and authorized:
                    set_code(session, 2, secret)
                unlock(session, 2, secret)
                oath_request(session, 0xb2, codec.tlv(0x80, PIN))
                private_record(session)
                session.check("page interruption preserves exact resulting record set", oath_names(session), names)
                result = dict(codec.parse_tlv(oath_request(session, 0xa2, codec.tlv(0x71, NAME) + codec.tlv(0x74, bytes(8)), p2=1)))[0x76]
                session.check("pages and their interruptions never consume HOTP", result, b"\x06" + otp_value(OATH_HASHES[0][2], bytes(8), "sha1", 6).to_bytes(4, "big"))
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    reset(session)
