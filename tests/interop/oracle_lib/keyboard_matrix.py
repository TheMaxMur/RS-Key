# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Raw static material, flags and lengths are witnessed as exact HID press edges."""
from itertools import product

from . import keyboard
from .otp_commands import Route, checksum, fixture

SCANCODES = ((0x04, "a"), (0x84, "A"), (0x1e, "1"), (0x9e, "!"), (0x2b, "\t"), (0x28, "\r"),
             (0x2f, "["), (0xaf, "{"), (0xb0, "}"), (0xb1, "|"), (0xb3, ":"), (0xb4, '"'),
             (0xb5, "~"), (0xb6, "<"), (0xb7, ">"), (0xb8, "?"), (0x00, ""), (0x80, ""))


def vectors():
    for flags, ticket, pacing in product((2, 0x20, 0x22), (0, 1, 2, 4, 8, 16, 32, 63), (0, 4, 8, 12)):
        yield f"flags-{flags}.ticket-{ticket}.pacing-{pacing}", 38, 6, flags | pacing, ticket
    for flags, size, append in product((2, 0x20), (0, 1, 15, 16, 17, 37, 38), (False, True)):
        yield f"length-{size}.mode-{flags}.CR-{append}", size, size, flags, 32 if append else 0
    for flags, size in product((2, 0x20), (0, 1, 6, 15, 16, 17, 38, 39, 255)):
        yield f"fixed-size-field-{size}.mode-{flags}", 38, size, flags, 0


def static(session):
    for slot in range(1, 5):
        for label, length, fixed_length, flags, ticket in vectors():
            with session.case(f"otp.keyboard.static.slot-{slot}.{label}", ("Y01", "Y02", "Y03", "Y06", "Y11", "Y12", "Y14", "G03", "G04", "G14"), effects=("otp_extra_slots", "keyboard_output") if slot > 2 else (f"replace_otp_slot_{slot}", "keyboard_output"), parameters={"slot": slot, "layout": "US", "length": length, "fixed_size": fixed_length, "cfg_flags": flags, "ticket_flags": ticket}):
                session.require(session.profile == "rsk", "raw static and flag semantics require RS-Key", "excluded_by_profile")
                session.require(session.keyboard is not None and session.options.operator, "static output needs the selected keyboard interface and operator")
                pairs = [SCANCODES[index % len(SCANCODES)] for index in range(length)]
                body = bytearray(52)
                body[:length] = bytes(value for value, _ in pairs)
                body[38:44], body[44], body[46], body[47] = bytes(range(4, 10)), fixed_length, ticket, flags
                body = checksum(body)
                with fixture(session, Route.CARD, slot, body):
                    expected = "".join(text for _, text in pairs) + ("\r" if ticket & 32 else "")
                    expected_presses = [(2 if value & 128 else 0, value & 127) for value, _ in pairs if value & 127]
                    if ticket & 32:
                        expected_presses.append((0, 0x28))
                    frames, timestamps, started = keyboard.listen(session, keyboard.gesture(session, slot), allow_empty=not expected_presses)
                    text, pressed = keyboard.decode(frames)
                    session.check("static output is exact raw material without access-code leakage or invented TAB prefixes", text, expected)
                    session.check("static report modifiers and press ordering are exact", pressed, expected_presses)
                    session.observe("static_keyboard_timing", {"listen_started_ns": started, "first_report_ns": timestamps[0] if timestamps else None,
                        "final_report_ns": timestamps[-1] if timestamps else None, "report_count": len(frames),
                        "report_intervals_ns": [b - a for a, b in zip(timestamps, timestamps[1:])], "gesture_started_ns": None,
                        "pacing_profile": "stored pacing/TAB flags do not change the current RS-Key raw ticket builder; host report times remain observations"}, "presence")


def run(session):
    static(session)
