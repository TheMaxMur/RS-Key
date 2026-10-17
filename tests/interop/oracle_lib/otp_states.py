# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Slot updates, access-code transitions, swaps, and RS-Key extra-slot isolation."""
import hmac

from . import codec
from .otp import crc16, slot_config, slot_select


def commands(slot):
    return (1, 0x30, 0) if slot == 1 else (3, 0x38, 0) if slot == 2 else (1, 0x30, slot - 1)


def raw(session, command, data=b"", expected=0, offset=0):
    if session.otp_hid:
        session.require(offset == 0, "extra slots require the explicitly selected card path", "excluded_by_mode")
        return session.otp_call(command, data, expected)
    return session.apdu(codec.apdu(1, command, offset, data), f"otp.{command:02x}.offset-{offset}")


def accepted(session, reply):
    if session.otp_hid:
        session.check("OTP feature command accepted", reply.protocol, "success")
        return reply.data
    return session.card_value(reply)


def config(key, access=bytes(6), allow_update=False):
    value = bytearray(slot_config(key, access=access, variable=False))
    value[45] |= 0x20 if allow_update else 0
    value[50:52] = (~crc16(value[:50]) & 0xFFFF).to_bytes(2, "little")
    return bytes(value)


def check_hmac(session, slot, key, label):
    _, command, offset = commands(slot)
    challenge = session.fixture("otp.state.challenge", 64)
    actual = accepted(session, raw(session, command, challenge, 20, offset))
    session.check(label, actual, hmac.digest(key, challenge, "sha1"))


def mutations(session):
    slot = session.options.otp_slot
    write, _, offset = commands(slot)
    update = 4 if slot == 1 else 5
    for allow_update in (False, True):
        with session.case(f"otp.transition.slot{slot}.update.{allow_update}", ("Y02", "Y03", "Y04", "Y06", "Y07", "G14"),
                          effects=(f"replace_otp_slot_{slot}",)):
            slot_select(session)
            key = session.fixture("otp.state.key", 20)
            old, new = session.fixture("otp.state.access", 6), session.fixture("otp.state.new-access", 6)
            active, created = old, False
            try:
                accepted(session, raw(session, write, config(key, old, allow_update) + bytes(6), offset=offset))
                created = True
                check_hmac(session, slot, key, "HMAC before slot mutation")
                damaged = bytearray(config(key, old, allow_update))
                damaged[-1] ^= 1
                reply = raw(session, write, bytes(damaged) + old, offset=offset)
                session.check("bad config CRC refused", reply.protocol != "success")
                trigger = session.evidence()
                check_hmac(session, slot, key, "key preserved after bad CRC")
                session.transition("otp.slot", "configured", "unchanged_after_bad_CRC", trigger, [trigger, session.evidence()])
                proposal = config(session.fixture("otp.state.decoy-key", 20), new, allow_update)
                reply = raw(session, update, proposal + old)
                session.observe("update.status", reply.status)
                if reply.protocol == "success":
                    active = new
                    check_hmac(session, slot, key, "UPDATE preserves original secret")
                    refused = raw(session, write, bytes(52) + old)
                    session.check("old access code revoked by UPDATE", refused.protocol != "success")
                    check_hmac(session, slot, key, "key survives old access-code refusal")
                else:
                    check_hmac(session, slot, key, "key survives refused UPDATE")
                accepted(session, raw(session, write, config(key) + active))
                active = bytes(6)
                check_hmac(session, slot, key, "access-code removal preserves key")
            finally:
                if created and not session.broken:
                    session.trace.phase = "cleanup"
                    accepted(session, raw(session, write, bytes(52) + active))


def swaps(session):
    for occupancy in ("empty-empty", "empty-full", "full-full"):
        with session.case("otp.transition.swap." + occupancy, ("Y02", "Y04", "Y05", "Y07", "G09"),
                          effects=("otp_both_slots",)):
            slot_select(session)
            keys = {slot: session.fixture(f"otp.swap.key{slot}", 20) for slot in (1, 2)}
            began = False
            try:
                for slot in (1, 2):
                    accepted(session, raw(session, commands(slot)[0], bytes(58)))
                began = True
                populated = (2,) if occupancy == "empty-full" else (1, 2) if occupancy == "full-full" else ()
                for slot in populated:
                    accepted(session, raw(session, commands(slot)[0], config(keys[slot]) + bytes(6)))
                    check_hmac(session, slot, keys[slot], f"slot {slot} before swap")
                accepted(session, raw(session, 6))
                trigger = session.evidence()
                for previous in populated:
                    check_hmac(session, 3 - previous, keys[previous], "key moved to other slot")
                for previous in set((1, 2)) - set(populated):
                    missing = raw(session, commands(3 - previous)[1], bytes(64), 20)
                    session.check("empty slot moved to other slot", missing.protocol != "success")
                if populated:
                    session.transition("otp.slot_pair", occupancy, "swapped", trigger, [trigger, session.evidence()])
                else:
                    session.observe("empty_swap", "both challenge operations refused after acknowledged swap")
            finally:
                if began and not session.broken:
                    session.trace.phase = "cleanup"
                    for slot in (1, 2):
                        accepted(session, raw(session, commands(slot)[0], bytes(58)))


def extras(session):
    for slot in (3, 4):
        with session.case(f"otp.transition.extra-slot.{slot}", ("Y02", "Y04", "Y07", "Y14"), effects=("otp_extra_slots",)):
            session.require(session.profile == "rsk", "extra slots are RS-Key-specific", "excluded_by_profile")
            session.require(session.card is not None and session.otp_hid is None, "extra slots require the explicit card path", "excluded_by_mode")
            before = session.select("otp")
            session.check("legacy OTP status length", len(before), 6)
            write, _, offset = commands(slot)
            key = session.fixture(f"otp.extra.{slot}", 20)
            created = False
            try:
                accepted(session, raw(session, write, config(key) + bytes(6), offset=offset))
                created = True
                check_hmac(session, slot, key, "extra-slot HMAC")
                after = session.select("otp")
                session.check("extra slot leaves legacy slot bits unchanged", after[4] & 15, before[4] & 15)
                extended = accepted(session, raw(session, 0x14))
                session.check("extra slot listed in extended status", 0xB0 + slot - 1 in dict(codec.parse_tlv(extended)))
            finally:
                if created and not session.broken:
                    session.trace.phase = "cleanup"
                    accepted(session, raw(session, write, bytes(58), offset=offset))


def run(session):
    mutations(session)
    swaps(session)
    extras(session)
