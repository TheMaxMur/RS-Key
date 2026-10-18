# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Every swap layout checks both source identities and independent access codes."""
from contextlib import ExitStack
from itertools import product

from .otp_commands import Mode, Route, checksum, configure, fixture, mutate, vacant, witness


def layouts(first, second):
    offsets = bytes([first - 1, second - 2])
    yield "offsets-no-code", offsets, False
    yield "offsets-code", offsets + b"code-A", True
    yield "offsets-wrong-code", offsets + b"wrong!", True
    if (first, second) == (1, 2):
        yield "empty-default-pair", b"", False
        yield "standard-six-byte-code", b"code-A", True
        yield "standard-wrong-code", b"wrong!", True
    for size in (1, 3, 5, 7, 9, 64, 255):
        yield f"body-length-{size}", bytes(size), False
    for body in (b"\x04\x00", b"\x00\x03", b"\xff\xff", b"\x04\x00code-A", b"\x00\x03code-A"):
        yield "out-of-range-" + body.hex(), body, len(body) == 8


def run(session):
    codes = ((bytes(6), bytes(6)), (b"code-A", b"code-A"), (b"code-A", b"code-B"), (bytes(6), b"code-A"), (b"code-A", bytes(6)))
    for route, first, second, occupied, access in product(Route, range(1, 5), range(2, 5), ("none", "first", "second", "both"), codes):
        if first == second and (occupied in ("first", "second") or access[0] != access[1]):
            continue
        for label, body, code_supplied in layouts(first, second):
            with session.case(f"otp.SWAP.{route.value}.pair-{first}-{second}.{occupied}.codes-{access[0].hex()}-{access[1].hex()}.{label}", ("Y01", "Y02", "Y04", "Y05", "Y06", "Y07", "Y14", "G01", "G03", "G04", "G09", "G10", "G13", "G14"), effects=("otp_both_slots", "otp_extra_slots") if max(first, second) > 2 else ("otp_both_slots",)):
                session.require(route == Route.CARD or (first, second) == (1, 2) and len(body) <= 64, "OTP HID has no offset and a fixed 64-byte body", "excluded_by_mode")
                configs = {first: configure(session.fixture(f"OTP.swap.slot-{first}", 20), Mode.HMAC, access[0]),
                           second: configure(session.fixture(f"OTP.swap.slot-{second}", 20), Mode.HMAC, access[1])}
                if first != second:
                    varied = bytearray(configs[second])
                    varied[45] = 0x80
                    varied[47] |= 4
                    configs[second] = checksum(varied)
                present = set((first, second)) if occupied == "both" else {first} if occupied == "first" else {second} if occupied == "second" else set()
                with ExitStack() as stack:
                    states = {slot: stack.enter_context(fixture(session, route, slot, configs[slot] if slot in present else None)) for slot in dict.fromkeys((first, second))}
                    for slot, state in states.items():
                        witness(session, route, slot, state["config"]) if state["config"] is not None else vacant(session, route, slot)
                    valid_length = len(body) in (0, 2, 6, 8) and route == Route.CARD
                    target_a, target_b = (body[0] + 1, body[1] + 2) if len(body) in (2, 8) else (1, 2)
                    if not valid_length:
                        expected = 0x6700
                    elif target_a > 4 or target_b > 4:
                        expected = 0x6a86
                    else:
                        supplied = body[-6:] if code_supplied else bytes(6)
                        expected = 0x9000 if all(states[slot]["config"] is None or states[slot]["config"][38:44] == supplied for slot in (first, second)) else 0x6982
                    def committed():
                        a, b = states[first]["config"], states[second]["config"]
                        states[first]["config"], states[second]["config"] = b, a
                    mutate(session, route, 6, body, expected=expected, changes=expected == 0x9000,
                        committed=committed if target_a <= 4 and target_b <= 4 else None)
                    if route == Route.HID:
                        session.observe("profile_swap_limit", "fixed 64-byte process_hid body is rejected before access checks; card layouts remain independently covered")
                    for slot, state in states.items():
                        witness(session, route, slot, state["config"]) if state["config"] is not None else vacant(session, route, slot)
