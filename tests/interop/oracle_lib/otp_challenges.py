# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Challenge boundaries distinguish CCID lengths from HID's fixed padded payload."""
import hmac
from itertools import product
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .lifecycle import Action, change
from .otp_commands import Mode, Route, address, checksum, configure, fixture, hmac_command, request, result, status, witness


def cue(session, action):
    session.trace.emit("interaction", action="OTP-challenge-" + action, source="runner", stage="requested", observed_touch_ns=None)
    print("oracle: OTP challenge: " + action, file=sys.stderr)


def check(session, route, slot, config, data, expected=0x9000):
    kind = Mode.HMAC if config[47] & 0x22 == 0x22 else Mode.YUBICO_CHALLENGE
    command, offset = hmac_command(slot) if kind == Mode.HMAC else address(slot, yubico=True)
    output = result(session, route, request(session, route, command, data, offset, 20 if kind == Mode.HMAC else 16), expected)
    if expected != 0x9000:
        session.check("refused challenge returns no private bytes", output, b"")
        return
    effective = data.ljust(64, b"\x00") if route == Route.HID else data
    if kind == Mode.HMAC:
        effective = effective[:64]
        if config[47] & 4:
            effective = effective.rstrip(effective[-1:])
        session.check("HMAC uses the exact fixed or trimmed challenge bytes", output, hmac.digest(config[22:38] + config[16:22], effective, "sha1"))
    else:
        worker = Cipher(algorithms.AES(config[22:38]), modes.ECB()).decryptor()
        plain = worker.update(output) + worker.finalize()
        session.check("Yubico challenge uses exactly the first six effective host bytes", plain[:6], effective[:6])


def run(session):
    for route, slot, kind, variable in product(Route, range(1, 5), (Mode.HMAC, Mode.YUBICO_CHALLENGE), (False, True)):
        for size in (0, 1, 5, 6, 7, 31, 63, 64, 65, 127, 128, 255):
            with session.case(f"otp.challenge.length.{route.value}.slot-{slot}.{kind.name}.variable-{variable}.length-{size}", ("Y01", "Y02", "Y07", "Y08", "Y14", "G01", "G03", "G14"), effects=("otp_extra_slots",) if slot > 2 else (f"replace_otp_slot_{slot}",)):
                session.require(route == Route.CARD or size <= 64, "HID payloads are at most 64 bytes and zero padded", "excluded_by_mode")
                config = bytearray(configure(session.fixture("OTP.challenge.key", 20), kind))
                config[47] |= 4 if variable else 0
                config = checksum(config)
                with fixture(session, route, slot, config):
                    before = status(session, route)
                    minimum = 64 if kind == Mode.HMAC else 6
                    check(session, route, slot, config, session.fixture("OTP.challenge.bytes", size), 0x6700 if route == Route.CARD and size < minimum else 0x9000)
                    session.check("challenge success/refusal never programs the slot", status(session, route), before)
                    witness(session, route, slot, config)
        for padding in (0, 1, 127, 255):
            for prefix in (0, 1, 31, 63, 64):
                with session.case(f"otp.challenge.padding.{route.value}.slot-{slot}.{kind.name}.variable-{variable}.prefix-{prefix}.padding-{padding}", ("Y07", "Y08", "Y14", "G03", "G14"), effects=("otp_extra_slots",) if slot > 2 else (f"replace_otp_slot_{slot}",)):
                    config = bytearray(configure(session.fixture("OTP.challenge.key", 20), kind))
                    config[47] |= 4 if variable else 0
                    config = checksum(config)
                    body = bytes([padding ^ 255]) * prefix + bytes([padding]) * (64 - prefix)
                    with fixture(session, route, slot, config):
                        check(session, route, slot, config, body)
                        witness(session, route, slot, config)
    presence(session)
    persistence(session)


def presence(session):
    for route, slot, kind, touch, action in product(Route, range(1, 5), (Mode.HMAC, Mode.YUBICO_CHALLENGE), (False, True), ("confirm", "decline", "panel-cancel", "timeout")):
        with session.case(f"otp.challenge.presence.{route.value}.slot-{slot}.{kind.name}.touch-{touch}.{action}", ("Y07", "Y08", "Y12", "Y14", "G10", "G12", "G14"), effects=("otp_extra_slots",) if slot > 2 else (f"replace_otp_slot_{slot}",), touch=True):
            session.require(session.options.operator, "challenge outcomes need a controlled operator action")
            session.require(not touch or action not in ("decline", "panel-cancel") or "display" in session.options.features, "decline/panel cancellation needs a declared display")
            session.require(not touch or action != "timeout" or session.options.timeout > 130, "withheld touch requires the complete device window")
            config = bytearray(configure(session.fixture("OTP.presence.key", 20), kind))
            config[47] |= 8 if touch else 0
            config = checksum(config)
            with fixture(session, route, slot, config):
                before = status(session, route)
                cue(session, action)
                if touch and action != "confirm":
                    command, offset = hmac_command(slot) if kind == Mode.HMAC else address(slot, yubico=True)
                    reply = request(session, route, command, session.fixture("OTP.presence.challenge", 64), offset, 20 if kind == Mode.HMAC else 16)
                    if route == Route.CARD:
                        session.check("OTP touch refusal has its exact applet cause", reply.status, 0x6985)
                    else:
                        session.check("OTP HID touch refusal is a complete protocol outcome, not a host deadline", reply.protocol == "applet_error" and reply.status in ("CommandRejectedError", "TimeoutError"))
                        session.observe("feature_touch_refusal", reply.status)
                    session.check("refused touch emits no challenge result", reply.data[:-2] if route == Route.CARD else reply.data, b"")
                else:
                    check(session, route, slot, config, session.fixture("OTP.presence.challenge", 64))
                session.check("touch outcomes preserve status/sequence", status(session, route), before)
                cue(session, "confirm")
                witness(session, route, slot, config)


def persistence(session):
    for route, slot, kind, action in product(Route, range(1, 5), (Mode.HMAC, Mode.YUBICO_CHALLENGE), Action):
        with session.case(f"otp.challenge.persistence.{route.value}.slot-{slot}.{kind.name}.{action.value}", ("Y01", "Y02", "Y06", "Y07", "Y08", "Y14", "X11", "G14"), effects=("otp_extra_slots", "reboot") if slot > 2 else (f"replace_otp_slot_{slot}", "reboot")):
            config = configure(session.fixture("OTP.persistence.key", 20), kind, b"known!")
            with fixture(session, route, slot, config):
                witness(session, route, slot, config)
                change(session, action)
                if route == Route.CARD:
                    session.select("otp")
                else:
                    session.otp_call(0x10, expected_len=4)
                witness(session, route, slot, config)
                command, offset = address(slot)
                result(session, route, request(session, route, command, bytes(58), offset), 0x6982)
                witness(session, route, slot, config)
