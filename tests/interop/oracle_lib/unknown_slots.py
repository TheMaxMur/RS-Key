# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Read back lost slot mutations, including secret access codes, without replay."""
import hmac
from contextlib import ExitStack
from itertools import combinations, product

from . import codec
from .otp_commands import ACCESS, CONFIG_SIZE, Mode, Route, address, configure, extended, fixture, hmac_command, merged, request, status, vacant, witness
from .uncertain_writes import classify, lose, require_loss


def code_probe(session, slot, candidate):
    command, offset = address(slot)
    before = status(session, Route.CARD)
    invalid = b"\x01" + bytes(CONFIG_SIZE - 1)
    result = request(session, Route.CARD, command, invalid + candidate, offset)
    session.check("readback code probe reaches code comparison or bad CRC, never a write", result.status in (0x6700, 0x6982))
    session.check("bad-CRC access-code readback preserves the complete program status", status(session, Route.CARD), before)
    return result.status == 0x6700


def slots(session):
    for slot, operation in product(range(1, 5), ("create", "replace", "update", "delete", "access-code")):
        with session.case(f"cross.unknown-write.OTP.slot-{slot}.{operation}", ("X10", "Y01", "Y02", "Y03", "Y04", "Y06", "Y07", "Y14", "G09", "G10", "G11", "G12", "G14"),
                effects=("session_recovery", "otp_extra_slots", "otp_both_slots")):
            require_loss(session)
            before = configure(session.fixture("unknown.OTP.original", 20), Mode.HMAC, b"oldkey")
            proposal = configure(session.fixture("unknown.OTP.replacement", 20), Mode.HMAC, b"newkey")
            if operation == "access-code":
                proposal = before[:ACCESS] + b"newkey" + before[ACCESS + 6:]
                from .otp_commands import checksum
                proposal = checksum(proposal)
            expected = merged(before, proposal) if operation == "update" else None if operation == "delete" else proposal
            initial = None if operation == "create" else before
            with fixture(session, Route.CARD, slot, initial) as state:
                command, offset = address(slot, update=operation in ("update", "access-code"))
                payload = bytes(CONFIG_SIZE) if operation == "delete" else proposal
                payload += bytes(6) if initial is None else b"oldkey"
                lose(session, 1, lambda: session.apdu(codec.apdu(1, command, offset, payload)))
                session.select("otp")
                entries = extended(session, Route.CARD)
                present = 0xaf + slot in entries
                session.check("only create/delete may change slot occupancy", present == (initial is not None) or operation in ("create", "delete"))
                if not present:
                    session.check("only a complete empty old/new state is permitted", initial is None or expected is None)
                    state["config"] = None
                    vacant(session, Route.CARD, slot)
                    session.observe("OTP.slot.readback", {"outcome": "unchanged" if initial is None else "committed", "replayed": False})
                    continue
                candidates = [value for value in (initial, expected) if value is not None]
                recognized = [value for value in candidates if code_probe(session, slot, value[38:44])]
                session.check("readback retains a complete old or new access code", bool(recognized))
                if len(recognized) > 1:
                    # Equal codes need a private-secret observation to distinguish replacement.
                    challenge = session.fixture("OTP.command.control", 64)
                    calculate, delta = hmac_command(slot)
                    actual = session.card_value(request(session, Route.CARD, calculate, challenge, delta))
                    recognized = [value for value in recognized if actual == hmac.digest(value[22:38] + value[16:22], challenge, "sha1")]
                session.check("readback identifies exactly one complete slot result", len(recognized), 1)
                state["config"] = recognized[0]
                witness(session, Route.CARD, slot, state["config"])
                session.observe("OTP.slot.readback", {"outcome": "unchanged" if state["config"] == initial else "committed", "replayed": False})


def swaps(session):
    for first, second in combinations(range(1, 5), 2):
        with session.case(f"cross.unknown-write.OTP.SWAP.{first}-{second}", ("X10", "Y01", "Y05", "Y06", "Y14", "G09", "G11", "G12", "G14"),
                effects=("session_recovery", "otp_extra_slots", "otp_both_slots")):
            require_loss(session)
            configs = [configure(session.fixture(f"unknown.OTP.SWAP.{slot}", 20), Mode.HMAC) for slot in (first, second)]
            with ExitStack() as stack:
                states = [stack.enter_context(fixture(session, Route.CARD, slot, config)) for slot, config in zip((first, second), configs)]
                lose(session, 1, lambda: request(session, Route.CARD, 6, bytes([first - 1, second - 2])))
                session.select("otp")
                challenge, values = session.fixture("OTP.command.control", 64), []
                for slot in (first, second):
                    command, offset = hmac_command(slot)
                    values.append(session.card_value(request(session, Route.CARD, command, challenge, offset)))
                original = [hmac.digest(config[22:38] + config[16:22], challenge, "sha1") for config in configs]
                classify(session, "complete OTP swap pair", values, original, list(reversed(original)))
                if values != original:
                    configs.reverse()
                for slot, state, config in zip((first, second), states, configs):
                    state["config"] = config
                    witness(session, Route.CARD, slot, config)


def management(session):
    from .management_cases import read, write
    for operation in ("fields", "arm-lock", "replace-lock", "clear-lock"):
        with session.case("cross.unknown-write.management." + operation, ("X08", "X10", "M02", "M04", "M05", "G10", "G11", "G12", "G14"),
                effects=("session_recovery", "config_change"), touch=True):
            require_loss(session)
            original = read(session, "card")
            session.require(original.get(10) == b"\x00", "unknown configuration fixture requires a known unlocked initial state")
            first, second = session.fixture("unknown.management.old", 16), session.fixture("unknown.management.new", 16)
            try:
                if operation in ("replace-lock", "clear-lock"):
                    write(session, "card", codec.tlv(10, first))
                    session.check("known original configuration lock is armed", read(session, "card")[10], b"\x01")
                before = read(session, "card")
                fields = codec.tlv(8, bytes([before[8][0] ^ 0x40]))
                if operation != "fields":
                    fields += codec.tlv(10, bytes(16) if operation == "clear-lock" else second)
                if operation in ("replace-lock", "clear-lock"):
                    fields += codec.tlv(11, first)
                expected = {**before, 8: bytes([before[8][0] ^ 0x40])}
                if operation != "fields":
                    expected[10] = b"\x00" if operation == "clear-lock" else b"\x01"
                lose(session, 0x1c, lambda: write(session, "card", fields))
                after = read(session, "card")
                classify(session, "whole management configuration", after, before, expected)
                actual_code = (first if after == before else second) if after[10] == b"\x01" else None
                if actual_code is not None:
                    locked = after
                    reply = write(session, "card", codec.tlv(8, before[8]))
                    session.check("unknown configuration write cannot bypass the retained lock", reply.is_rejection)
                    session.check("lock refusal preserves all configuration fields", read(session, "card"), locked)
                    write(session, "card", codec.tlv(11, actual_code) + codec.tlv(10, bytes(16)) + codec.tlv(8, original[8]))
                else:
                    write(session, "card", codec.tlv(8, original[8]))
                session.check("readback-known configuration and code restore the complete original", read(session, "card"), original)
            finally:
                if session.broken:
                    session.observe("cleanup_limit", "no unknown configuration mutation or secret code is retried automatically")


def run(session):
    slots(session)
    swaps(session)
    management(session)
