# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Disabling OTP preserves slots while identify/config routes remain reachable."""
from contextlib import ExitStack

from . import codec, keyboard
from .keyboard_counters import configuration, ready, ticket
from .management_cases import read, write
from .otp_commands import Mode, Route, configure, extended, fixture, status, witness
from .runner import AIDS

FUNCTIONS = (1, 3, 4, 5, 6, 8, 9, 0x12, 0x20, 0x28, 0x30, 0x38)


def require(session):
    session.require(session.profile == "rsk", "disabled OTP routing/caching requires RS-Key", "excluded_by_profile")
    session.require(session.card is not None and session.otp_hid is not None and session.hid is not None,
        "disabled-routing matrix requires explicitly selected card, OTP and FIDO interfaces", "excluded_by_mode")
    from .binding import require_pair
    require_pair(session)


def writer(session):
    return "fido" if "strict-config" in session.options.features else "hid"


def consistency(session, configurations):
    device = read(session, "card")
    session.select("otp")
    session.check("OTP serial agrees with the bound management identity", session.otp_call(0x10, expected_len=4).data, device[2])
    card_status, hid_status = status(session, Route.CARD), status(session, Route.HID)
    session.check("refreshed OTP feature status agrees with the live card record", hid_status, card_status)
    session.check("both OTP routes expose the same extended slot/mode records", extended(session, Route.HID), extended(session, Route.CARD))
    for route in Route:
        for slot, config in configurations.items():
            if route == Route.CARD or slot <= 2:
                witness(session, route, slot, config)
    return device


def routing(session):
    for restorer in ("card", "hid", "otp", "fido"):
        with session.case("otp.disabled.functions-and-identify.restore-" + restorer,
                ("Y01", "Y02", "Y03", "Y04", "Y05", "Y07", "Y08", "Y13", "Y14", "M03", "M05", "X08", "G10", "G14"),
                effects=("config_change", "otp_both_slots", "otp_extra_slots"), touch=True):
            require(session)
            session.require("strict-config" not in session.options.features or restorer in ("card", "fido"), "strict build disables this configuration writer", "excluded_by_profile")
            original = read(session, "card")
            session.require(original.get(10) == b"\x00" and int.from_bytes(original[3], "big") & 1, "unlocked and enabled OTP fixture required")
            configs = {slot: configure(session.fixture(f"OTP.disabled.key.{slot}", 20), Mode.HMAC) for slot in range(1, 5)}
            with ExitStack() as stack:
                for slot, config in configs.items():
                    stack.enter_context(fixture(session, Route.CARD, slot, config))
                consistency(session, configs)
                disabled = (int.from_bytes(original[3], "big") & ~1).to_bytes(2, "big")
                try:
                    before = status(session, Route.HID)
                    write(session, writer(session), codec.tlv(3, disabled))
                    for command in (3, 1):
                        session.check("disabling an already-selected OTP applet immediately blocks card dispatch", session.apdu(codec.apdu(command, 0x10)).status, 0x6d00)
                    session.check("disabled OTP AID cannot be reselected", session.apdu(codec.apdu(0xa4, 4, data=AIDS["otp"])).status, 0x6a82)
                    for command in FUNCTIONS:
                        data = configs[1] + bytes(6) if command in (1, 3, 4, 5) else bytes(64)
                        reply = session.otp_call(command, data, expected_len=20 if command in (0x30, 0x38) else 16 if command in (0x20, 0x28) else 0)
                        session.check("disabled OTP feature functions are inert rather than leaking a challenge", (reply.protocol, reply.status), ("applet_error", "CommandRejectedError"))
                        session.check("disabled OTP function cannot change sequence, occupancy or touch flags", status(session, Route.HID), before)
                    session.check("identify serial remains available while OTP is disabled", session.otp_call(0x10, expected_len=4).data, original[2])
                    session.check("extended identify still reports the retained slots", extended(session, Route.HID), {0xaf + slot: codec.tlv(0xa0, config[46:48]) for slot, config in configs.items()})
                    for route in ("card", "hid", "otp", "fido"):
                        current = read(session, route)
                        session.check("every identify route agrees on the disabled application mask", current[3], disabled)
                        session.check("disabling OTP preserves protocol identity", current[2], original[2])
                    write(session, restorer, codec.tlv(3, original[3]))
                    session.check("reachable selected writer can re-enable the actual OTP applet", read(session, "card")[3], original[3])
                    consistency(session, configs)
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        write(session, writer(session), codec.tlv(3, original[3]))
                        session.select("otp")


def cache(session):
    with session.case("otp.status.CCID-write-feature-cache-refresh", ("Y01", "Y02", "Y14", "T15", "X08", "G11", "G14"), effects=("replace_otp_slot_1",)):
        require(session)
        session.select("otp")
        session.otp_call(0x10, expected_len=4)
        before = status(session, Route.HID)
        session.require(not before[4] & 1, "owned cache-control slot must initially be empty")
        config = configure(session.fixture("OTP.cache.key", 20), Mode.HMAC)
        with fixture(session, Route.CARD, 1, config):
            live = status(session, Route.CARD)
            session.check("card mutation changes the actual status", live != before)
            session.check("unsolicited feature status is a cache and does not invent a live refresh", status(session, Route.HID), before)
            session.otp_call(0x10, expected_len=4)
            session.check("a completed feature command refreshes the cached status", status(session, Route.HID), live)
            consistency(session, {1: config})


def typing(session):
    for slot in range(1, 5):
        with session.case(f"otp.disabled.keyboard.slot-{slot}", ("Y01", "Y09", "Y10", "Y12", "Y14", "M03", "X08", "G14"), effects=("config_change", "otp_extra_slots", "keyboard_output"), touch=True):
            require(session)
            ready(session, Mode.HOTP6)
            original = read(session, "card")
            session.require(original.get(10) == b"\x00" and int.from_bytes(original[3], "big") & 1, "unlocked enabled OTP required")
            config = configuration(session, slot, Mode.HOTP6)
            with fixture(session, Route.CARD, slot, config):
                ticket(session, slot, config, 0)
                try:
                    write(session, writer(session), codec.tlv(3, (int.from_bytes(original[3], "big") & ~1).to_bytes(2, "big")))
                    frames, _, _ = keyboard.listen(session, keyboard.gesture(session, slot), allow_empty=True)
                    session.check("disabled OTP gestures emit no keyboard report in the observed window", frames, [])
                    write(session, writer(session), codec.tlv(3, original[3]))
                    session.select("otp")
                    ticket(session, slot, config, 1)
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        write(session, writer(session), codec.tlv(3, original[3]))
                        session.select("otp")


def run(session):
    routing(session)
    cache(session)
    typing(session)
