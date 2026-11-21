# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Slot grammar and flag outcomes use explicit CCID versus feature-report routes."""
from contextlib import contextmanager
from enum import Enum
import hmac
from itertools import product
import re

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import codec
from .otp import crc16, slot_config

CONFIG_SIZE, ACCESS_SIZE = 52, 6
FIXED, UID, KEY, ACCESS, FIXED_LENGTH, EXT, TICKET, FLAGS, RFU = 0, 16, 22, 38, 44, 45, 46, 47, 48
FLAG_BOUNDARIES = (0, 1, 2, 4, 8, 16, 32, 64, 128, 255)


class Route(Enum):
    CARD = "CCID"
    HID = "OTP-HID"


class Mode(Enum):
    YUBICO = (0, 0)
    HOTP6 = (0x40, 0)
    HOTP8 = (0x40, 2)
    STATIC = (0, 0x20)
    SHORT_STATIC = (0, 2)
    HMAC = (0x40, 0x22)
    YUBICO_CHALLENGE = (0x40, 0x20)


def checksum(config):
    value = bytearray(config)
    value[-2:] = (~crc16(value[:-2]) & 65535).to_bytes(2, "little")
    return bytes(value)


def configure(key, mode, access=bytes(ACCESS_SIZE)):
    value = bytearray(slot_config(key, access=access, variable=False))
    value[TICKET], value[FLAGS] = mode.value
    value[:16] = b"oracle-fixed-id".ljust(16, b"\x00")
    value[FIXED_LENGTH] = 6
    return checksum(value)


def open_route(session, route, slot):
    session.require(session.profile == "rsk", "exact slot command/flag outcomes require RS-Key", "excluded_by_profile")
    if route == Route.CARD:
        session.select("otp", required=True)
    else:
        session.require(slot in (1, 2), "extra slots require the CCID offset", "excluded_by_mode")
        session.require(session.otp_hid is not None, "select an explicit OTP HID interface", "excluded_by_mode")
        session.check("serial read refreshes the feature status cache after CCID commands", session.otp_call(0x10, expected_len=4).protocol, "success")


def request(session, route, command, body=b"", offset=0, expected_len=0):
    if route == Route.CARD:
        return session.apdu(codec.apdu(1, command, offset, body))
    session.require(offset == 0 and len(body) <= 64, "OTP HID has no offset and always carries a 64-byte payload", "excluded_by_mode")
    return session.otp_call(command, body, expected_len)


def result(session, route, reply, status=0x9000, changed=True):
    if route == Route.CARD:
        session.check("OTP CCID has the exact applet status", reply.status, status)
        return reply.data[:-2]
    accepted = status == 0x9000 and changed
    session.check("OTP HID distinguishes data/sequence acknowledgment from a silent refusal", (reply.protocol, reply.status), ("success", None) if accepted else ("applet_error", "CommandRejectedError"))
    return reply.data


def status(session, route):
    reply = session.apdu(codec.apdu(3)) if route == Route.CARD else session.otp_call(-1)
    body = session.card_value(reply) if route == Route.CARD else reply.data
    session.check("OTP status is the six-byte legacy record", len(body), 6)
    return body


def mutate(session, route, command, body, offset=0, expected=0x9000, changes=True, committed=None):
    before = status(session, route)
    reply = request(session, route, command, body, offset)
    after = status(session, route)
    if after[3] == (before[3] + 1) & 255 and committed is not None:
        committed()
    session.check("program sequence advances exactly for a committed slot mutation", after[3], (before[3] + changes) & 255)
    acknowledged = changes and (before[3] != 255 or after[4] & 3 == 0)
    result(session, route, reply, expected, acknowledged)
    if route == Route.HID and changes and not acknowledged:
        session.observe("SDK_sequence_wrap", "No data after committed 255-to-0 sequence wrap; status and private-operation readback disambiguate the write")
    return reply


def feature_payload(body):
    ends = [end for end in range(2, len(body) + 1) if crc16(body[:end]) == 0xf0b8 and not any(body[end:])]
    if len(ends) != 1:
        raise ValueError("OTP feature stream has no unique CRC/padding boundary")
    return body[:ends[0] - 2]


def extended(session, route):
    reply = request(session, route, 0x14)
    if route == Route.CARD:
        body = session.card_value(reply)
    else:
        session.check("OTP HID extended status has a response stream", reply.protocol, "success")
        body = feature_payload(reply.data)
    return dict(codec.parse_tlv(body))


def address(slot, update=False, yubico=False):
    offset = slot - 1 if slot > 2 else 0
    return (4 if slot != 2 else 5) if update else (0x20 if slot != 2 else 0x28) if yubico else (1 if slot != 2 else 3), offset


def hmac_command(slot):
    return (0x30 if slot != 2 else 0x38), slot - 1 if slot > 2 else 0


def challenge_kind(config):
    if config[TICKET] & 0x40:
        if config[FLAGS] & 0x22 == 0x22:
            return Mode.HMAC
        if config[FLAGS] & 0x20 and not config[FLAGS] & 2:
            return Mode.YUBICO_CHALLENGE
    return None


def witness(session, route, slot, config):
    entries = extended(session, route)
    expected = codec.tlv(0xa0, config[TICKET:FLAGS + 1])
    plain = not config[TICKET] & 0x40 and not config[FLAGS] & 0x22
    if plain:
        expected += codec.tlv(0xc0, config[:6])
    session.check("extended status preserves exact mode/flag bytes and public ID", entries[0xb0 + slot - 1], expected)
    legacy = status(session, route)
    if slot <= 2:
        needs_touch = challenge_kind(config) is None or bool(config[FLAGS] & 8)
        mask = (1 << (slot - 1)) | (4 << (slot - 1))
        session.check("legacy status reports the actual slot mode and touch requirement", legacy[4] & mask, (1 << (slot - 1)) | ((4 << (slot - 1)) if needs_touch else 0))
    challenge = session.fixture("OTP.command.control", 64)
    for kind in (Mode.HMAC, Mode.YUBICO_CHALLENGE):
        command, offset = hmac_command(slot) if kind == Mode.HMAC else address(slot, yubico=True)
        reply = request(session, route, command, challenge, offset, 20 if kind == Mode.HMAC else 16)
        allowed = challenge_kind(config) == kind
        output = result(session, route, reply, 0x9000 if allowed else 0x6700)
        if not allowed:
            continue
        if kind == Mode.HMAC:
            actual = challenge
            if config[FLAGS] & 4:
                actual = challenge.rstrip(bytes([challenge[-1]]))
            session.check("stored HMAC secret survives exact flag interpretation", output, hmac.digest(config[KEY:ACCESS] + config[UID:KEY], actual, "sha1"))
        else:
            worker = Cipher(algorithms.AES(config[KEY:ACCESS]), modes.ECB()).decryptor()
            plain = worker.update(output) + worker.finalize()
            session.check("stored Yubico challenge key recovers the exact host bytes", plain[:6], challenge[:6])
            session.check("Yubico challenge suffix is ten uppercase serial hex characters", re.fullmatch(b"[0-9A-F]{10}", plain[6:]) is not None)


@contextmanager
def fixture(session, route, slot, config):
    open_route(session, route, slot)
    vacant = not status(session, route)[4] & (1 << (slot - 1)) if route == Route.HID else 0xb0 + slot - 1 not in extended(session, route)
    session.require(vacant, "slot command fixture requires a confirmed empty owned slot")
    command, offset = address(slot)
    state = {"config": None}
    try:
        if config is not None:
            mutate(session, route, command, config + bytes(ACCESS_SIZE), offset, committed=lambda: state.update(config=config))
        yield state
    finally:
        if state["config"] is not None and not session.broken:
            session.trace.phase = "cleanup"
            mutate(session, route, command, bytes(CONFIG_SIZE) + state["config"][ACCESS:FIXED_LENGTH], offset)


def flags(session):
    for route, slot, mode in product(Route, range(1, 5), Mode):
        for field, bit in product((EXT, TICKET, FLAGS), FLAG_BOUNDARIES):
            with session.case(f"otp.configure-flags.{route.value}.slot-{slot}.{mode.name}.field-{field}.mask-{bit}", ("Y01", "Y02", "Y04", "Y07", "Y08", "Y14", "G04", "G14"), effects=("otp_extra_slots",) if slot > 2 else (f"replace_otp_slot_{slot}",), touch=True):
                config = bytearray(configure(session.fixture("OTP.flags.key", 20), mode))
                config[field] ^= bit
                config = checksum(config)
                with fixture(session, route, slot, config):
                    witness(session, route, slot, config)


def run(session):
    flags(session)
    mutations(session)
    update_flags(session)


def merged(previous, proposed):
    value = bytearray(proposed)
    value[:ACCESS] = previous[:ACCESS]
    value[FIXED_LENGTH] = previous[FIXED_LENGTH]
    value[TICKET] = previous[TICKET] & ~0x3f | proposed[TICKET] & 0x3f
    value[FLAGS] = previous[FLAGS] if previous[TICKET] & 0x40 else previous[FLAGS] & ~0x0c | proposed[FLAGS] & 0x0c
    return bytes(value)


def vacant(session, route, slot):
    if slot <= 2:
        session.check("deleted/absent slot has no legacy valid bit", status(session, route)[4] & (1 << (slot - 1)), 0)
    if route == Route.CARD:
        session.check("deleted/absent slot has no extended status entry", 0xb0 + slot - 1 not in extended(session, route))
    command, offset = hmac_command(slot)
    session.check("empty challenge returns no private result", result(session, route, request(session, route, command, bytes(64), offset, 20), changed=False), b"")


def mutations(session):
    defects = ("valid", "CRC", "RFU-0", "RFU-1", "wrong-code", "CRC-and-wrong-code", "missing-code", "trailing", "length-0", "length-1", "length-51", "length-52", "length-57", "length-65", "length-255")
    for route, slot, occupied, operation in product(Route, range(1, 5), (False, True), ("configure", "update", "delete")):
        for defect in defects:
            with session.case(f"otp.mutation.{route.value}.slot-{slot}.occupied-{occupied}.{operation}.{defect}", ("Y01", "Y02", "Y03", "Y04", "Y06", "Y07", "Y14", "G01", "G03", "G04", "G09", "G10", "G13", "G14"), effects=("otp_extra_slots",) if slot > 2 else (f"replace_otp_slot_{slot}",)):
                session.require(route == Route.CARD or not defect.startswith("length-") and defect not in ("missing-code", "trailing"), "HID always pads its payload to 64 bytes; variable APDU Lc cases require CCID", "excluded_by_mode")
                initial = configure(session.fixture("OTP.mutation.original", 20), Mode.HMAC, b"oldkey")
                proposal = configure(session.fixture("OTP.mutation.replacement", 20), Mode.HMAC, b"newkey")
                with fixture(session, route, slot, initial if occupied else None) as state:
                    current = initial if occupied else None
                    if operation == "delete":
                        proposal = bytes(CONFIG_SIZE)
                    body = proposal + (b"oldkey" if occupied else bytes(ACCESS_SIZE))
                    invalid_crc = defect in ("CRC", "RFU-0", "RFU-1", "CRC-and-wrong-code")
                    wrong_code = defect in ("wrong-code", "CRC-and-wrong-code")
                    if invalid_crc:
                        damaged = bytearray(proposal)
                        if defect.startswith("RFU-"):
                            damaged[RFU + int(defect[-1])] = 1
                            damaged = bytearray(checksum(damaged))
                        else:
                            damaged[-1] ^= 1
                        proposal, body = bytes(damaged), bytes(damaged) + body[CONFIG_SIZE:]
                    if wrong_code:
                        body = body[:CONFIG_SIZE] + b"badkey"
                    if defect == "missing-code":
                        body = body[:CONFIG_SIZE]
                    elif defect == "trailing":
                        body += b"ignored-after-access-code"
                    elif defect.startswith("length-"):
                        size = int(defect.split("-")[-1])
                        body = body[:size].ljust(size, b"x")
                    update = operation == "update"
                    command, offset = address(slot, update=update)
                    expected = 0x9000
                    if len(body) < CONFIG_SIZE:
                        expected = 0x6700
                    elif update and (body[RFU:RFU + 2] != bytes(2) or crc16(body[:CONFIG_SIZE]) != 0xf0b8):
                        expected = 0x6700
                    elif occupied and len(body) < CONFIG_SIZE + ACCESS_SIZE:
                        expected = 0x6700
                    elif occupied and body[CONFIG_SIZE:CONFIG_SIZE + ACCESS_SIZE] != b"oldkey":
                        expected = 0x6982
                    elif not update and any(body[:CONFIG_SIZE]) and (body[RFU:RFU + 2] != bytes(2) or crc16(body[:CONFIG_SIZE]) != 0xf0b8):
                        expected = 0x6700
                    changes = expected == 0x9000 and (not update or occupied)
                    proposed_state = (merged(initial, body[:CONFIG_SIZE]) if update and occupied else body[:CONFIG_SIZE] if not update and any(body[:CONFIG_SIZE]) else None) if len(body) >= CONFIG_SIZE else None
                    mutate(session, route, command, body, offset, expected, changes,
                        committed=(lambda: state.update(config=proposed_state)) if len(body) >= CONFIG_SIZE else None)
                    current = state["config"]
                    if current is None:
                        vacant(session, route, slot)
                    else:
                        witness(session, route, slot, current)


def update_flags(session):
    for route, slot, mode in product(Route, range(1, 5), Mode):
        for field, value in product((EXT, TICKET, FLAGS), FLAG_BOUNDARIES):
            with session.case(f"otp.UPDATE.flags.{route.value}.slot-{slot}.{mode.name}.field-{field}.value-{value}", ("Y01", "Y02", "Y03", "Y04", "Y06", "Y07", "Y08", "Y14", "G04", "G10", "G14"), effects=("otp_extra_slots",) if slot > 2 else (f"replace_otp_slot_{slot}",), touch=True):
                initial = configure(session.fixture("OTP.UPDATE.old-key", 20), mode, b"oldkey")
                proposed = bytearray(configure(session.fixture("OTP.UPDATE.decoy-key", 20), Mode.YUBICO_CHALLENGE, b"newkey"))
                proposed[field] = value
                proposed = checksum(proposed)
                with fixture(session, route, slot, initial) as state:
                    expected = merged(initial, proposed)
                    command, offset = address(slot, update=True)
                    mutate(session, route, command, proposed + b"oldkey", offset, committed=lambda: state.update(config=expected))
                    witness(session, route, slot, expected)
                    # Presenting the replaced code must not modify or delete the slot.
                    command, offset = address(slot)
                    mutate(session, route, command, bytes(CONFIG_SIZE) + b"oldkey", offset, 0x6982, False)
                    witness(session, route, slot, expected)
