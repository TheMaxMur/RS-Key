# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Access-code replacement/removal and slot references retain exact key controls."""
from itertools import product

from . import codec
from .lifecycle import Action, change
from .otp_commands import Mode, Route, address, checksum, configure, fixture, hmac_command, mutate, request, result, status, witness


def codes(session):
    for route, slot, update, action in product(Route, range(1, 5), (False, True), Action):
        for old, new in ((bytes(6), b"code-A"), (b"code-A", b"code-B"), (b"code-A", bytes(6)),
                         (b"\x00\xff\x01\x80\x7f\x00", b"\xff\x00\x80\x01\x00\xff")):
            with session.case(f"otp.access-code.{route.value}.slot-{slot}.UPDATE-{update}.{action.value}.{old.hex()}-to-{new.hex()}", ("Y01", "Y02", "Y03", "Y04", "Y06", "Y07", "Y14", "X11", "G09", "G10", "G14"), effects=("otp_extra_slots", "reboot") if slot > 2 else (f"replace_otp_slot_{slot}", "reboot")):
                initial = configure(session.fixture("OTP.code-lifetime.key", 20), Mode.HMAC, old)
                with fixture(session, route, slot, initial) as state:
                    proposed = bytearray(initial)
                    proposed[38:44] = new
                    proposed = checksum(proposed)
                    command, offset = address(slot, update=update)
                    mutate(session, route, command, proposed + old, offset, committed=lambda: state.update(config=proposed))
                    witness(session, route, slot, proposed)
                    change(session, action)
                    if route == Route.CARD:
                        session.select("otp")
                    else:
                        session.otp_call(0x10, expected_len=4)
                    witness(session, route, slot, proposed)
                    command, offset = address(slot)
                    mutate(session, route, command, bytes(52) + old, offset, 0x6982, False)
                    witness(session, route, slot, proposed)
                    mutate(session, route, command, proposed + new, offset)
                    witness(session, route, slot, proposed)


def references(session):
    for command, offset in product((1, 3, 4, 5, 0x20, 0x28, 0x30, 0x38), (0, 1, 2, 3, 4, 127, 128, 255)):
        with session.case(f"otp.slot-reference.CCID.command-{command:02x}.P2-{offset}", ("Y01", "Y02", "Y03", "Y04", "Y07", "Y08", "Y14", "G04", "G09", "G13", "G14"), effects=("otp_extra_slots",)):
            base = 2 if command in (3, 5, 0x28, 0x38) else 1
            slot = base + offset
            valid = slot <= 4 and (base == 1 or offset == 0)
            fixture_slot = slot if valid else 1
            kind = Mode.YUBICO_CHALLENGE if command in (0x20, 0x28) else Mode.HMAC
            config = configure(session.fixture("OTP.reference.key", 20), kind)
            with fixture(session, Route.CARD, fixture_slot, config):
                before = status(session, Route.CARD)
                data = config + bytes(6) if command in (1, 3, 4, 5) else session.fixture("OTP.reference.challenge", 64)
                reply = request(session, Route.CARD, command, data, offset)
                result(session, Route.CARD, reply, 0x9000 if valid else 0x6a86)
                session.check("invalid slot references never advance the program sequence", status(session, Route.CARD)[3], (before[3] + (valid and command in (1, 3, 4, 5))) & 255)
                witness(session, Route.CARD, fixture_slot, config)


def reads_and_unknown(session):
    for route in Route:
        for command in range(256):
            if command in (1, 3, 4, 5, 6, 8, 9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x20, 0x28, 0x30, 0x38):
                continue
            with session.case(f"otp.unknown-command.{route.value}.{command:02x}", ("Y01", "Y13", "G04", "G14"), effects=("replace_otp_slot_1",)):
                config = configure(session.fixture("OTP.unknown-command.key", 20), Mode.HMAC)
                with fixture(session, route, 1, config):
                    before = status(session, route)
                    result(session, route, request(session, route, command, session.fixture("OTP.unknown.body", 64)), changed=False)
                    session.check("silent unknown commands preserve complete status", status(session, route), before)
                    witness(session, route, 1, config)
    for p1, p2, size in product((0, 1, 255), (0, 1, 255), (0, 1, 255)):
        with session.case(f"otp.STATUS.CCID.parameters-{p1}-{p2}.body-{size}", ("Y01", "G03", "G04", "G14")):
            session.require(session.profile == "rsk", "status parameter semantics require RS-Key", "excluded_by_profile")
            session.select("otp")
            before = status(session, Route.CARD)
            body = session.card_value(session.apdu(codec.apdu(3, p1, p2, bytes(size))))
            session.check("legacy status ignores P1/P2/body and preserves exact status", body, before)


def run(session):
    codes(session)
    references(session)
    reads_and_unknown(session)
