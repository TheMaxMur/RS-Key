# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OATH touch refusal cannot spend HOTP/increasing state or install a PIN."""
import sys
from itertools import product

from . import codec
from .oath_gates import reset, record_body
from .oath_pin_matrix import NAME, PIN
from .oath_semantics import answer, key_fields
from .otp import OATH_HASHES, oath_names, oath_request, otp_value

MODES = ("confirm", "decline", "panel-cancel", "timeout")


def ready(session, mode):
    session.require(session.profile == "rsk", "OATH touch/refusal state contract requires RS-Key", "excluded_by_profile")
    session.require(session.options.operator, "controlled OATH presence needs the declared operator action")
    session.require(mode not in ("decline", "panel-cancel") or "display" in session.options.features, "explicit refusal requires a positively declared display")
    session.require(mode != "timeout" or session.options.timeout > 130, "withheld presence needs the full device timeout")


def cue(session, mode):
    print("oracle: OATH presence: " + mode, file=sys.stderr)
    session.trace.emit("interaction", action="OATH-presence-" + mode, stage="requested", source="runner", observed_touch_ns=None)


def run(session):
    for kind, algorithm, full, mode in product(("HOTP", "TOTP", "increasing-TOTP"), (1, 2, 3), (False, True), MODES):
        with session.case(f"oath.CALCULATE.presence.{kind}.hash-{algorithm}.full-{full}.{mode}", ("A04", "A05", "A06", "G10", "G12", "G14"),
                effects=("applet_reset", "create_oath_record"), touch=True, parameters={"presence_action": mode}):
            ready(session, mode)
            reset(session)
            secret = OATH_HASHES[algorithm - 1][2]
            hash_name = {1: "sha1", 2: "sha256", 3: "sha512"}[algorithm]
            challenge = (1).to_bytes(8, "big")
            try:
                fields = key_fields(0x10 if kind == "HOTP" else 0x20, algorithm, 6, secret, 3 if kind == "increasing-TOTP" else 2)
                oath_request(session, 1, codec.tlv(0x71, NAME) + fields)
                cue(session, mode)
                result = session.apdu(codec.apdu(0xa2, p2=0 if full else 1, data=codec.tlv(0x71, NAME) + codec.tlv(0x74, challenge)))
                session.check("CALCULATE requires the requested confirmed presence", result.status, 0x9000 if mode == "confirm" else 0x6982)
                if mode != "confirm":
                    session.check("refused presence cannot disclose any OTP response bytes", result.data[:-2], b"")
                cue(session, "confirm")
                if kind == "increasing-TOTP" and mode == "confirm":
                    same = session.apdu(codec.apdu(0xa2, p2=1, data=codec.tlv(0x71, NAME) + codec.tlv(0x74, challenge)))
                    session.check("confirmed increasing request alone raises the mark", same.status, 0x6a80)
                    answer(session, NAME, (2).to_bytes(8, "big"), secret, hash_name, 6)
                else:
                    answer(session, NAME, challenge, secret, hash_name, 6, counter=(1 if mode == "confirm" else 0) if kind == "HOTP" else None)
                session.check("touch outcome preserves the owned record reference", oath_names(session), {NAME})
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    reset(session)
    verify_code(session)
    pin_install(session)


def verify_code(session):
    for mode in MODES:
        with session.case("oath.VERIFY-CODE.presence." + mode, ("A05", "A13", "G14"), effects=("applet_reset", "create_oath_record"), touch=True):
            ready(session, mode)
            reset(session)
            try:
                oath_request(session, 1, record_body(NAME, extra=b"\x78\x02"))
                expected = otp_value(OATH_HASHES[0][2], bytes(8), "sha1", 6)
                cue(session, mode)
                result = session.apdu(codec.apdu(0xb1, data=codec.tlv(0x71, NAME) + codec.tlv(0x75, expected.to_bytes(4, "big"))))
                session.check("VERIFY CODE enforces the record's touch policy", result.status, 0x9000 if mode == "confirm" else 0x6982)
                cue(session, "confirm")
                answer(session, NAME, bytes(8), OATH_HASHES[0][2], "sha1", 6, counter=0)
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    reset(session)


def pin_install(session):
    for mode in MODES:
        with session.case("oath.SET-PIN.no-access-code.presence." + mode, ("A10", "A14", "A15", "G14"), effects=("applet_reset", "pin_change", "create_oath_record"), touch=True):
            ready(session, mode)
            reset(session)
            try:
                oath_request(session, 1, record_body(NAME, extra=codec.tlv(0x84, b"owned-password")))
                cue(session, mode)
                result = session.apdu(codec.apdu(0xb4, data=codec.tlv(0x80, PIN)))
                session.check("code-less OTP-PIN installation needs operator consent", result.status, 0x9000 if mode == "confirm" else 0x6982)
                if mode == "confirm":
                    session.check("installed PIN closes private record access", session.apdu(codec.apdu(0xb5, data=codec.tlv(0x71, NAME))).status, 0x6982)
                    oath_request(session, 0xb2, codec.tlv(0x80, PIN))
                else:
                    session.check("declined consent cannot create an OTP-PIN verifier", session.apdu(codec.apdu(0xb2, data=codec.tlv(0x80, PIN))).status, 0x6985)
                value = dict(codec.parse_tlv(oath_request(session, 0xb5, codec.tlv(0x71, NAME))))
                session.check("PIN-install consent outcome preserves the password", value[0x84], b"owned-password")
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    reset(session)
