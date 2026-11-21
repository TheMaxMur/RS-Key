# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Admin acknowledgments, sequence effects and scan-map output are distinct evidence."""
from contextlib import ExitStack
from itertools import product

from . import keyboard
from .keyboard_counters import configuration, expected_hotp, ready
from .lifecycle import Action, change
from .otp_admin import CHARSET
from .otp_commands import Mode, Route, configure, fixture, request, result, status, witness

SCAN_BYTES, NDEF_BYTES, LEGACY_BYTES = 45, 64, 4
ACCESS = b"code-A"


def default_map():
    return bytes(next(code for code, text in keyboard.US.items() if text == char.lower()) | (0x80 if char.isupper() else 0) if char != "!" else 0x9e for char in CHARSET)


def configurations(session, codes):
    return {slot: configure(session.fixture(f"OTP.admin.key.{slot}", 20), Mode.HMAC, code) for slot, code in enumerate(codes, 1)}


def accepted(command, body, codes, strict):
    if strict:
        return 0x9000, False
    if command == 0x11:
        return 0x9000, bool(body)
    width = SCAN_BYTES if command == 0x12 else NDEF_BYTES
    if command == 0x12 and len(body) < width or not body:
        return 0x9000, False
    presented = body[width:width + 6] if len(body) >= width + 6 else bytes(6)
    allowed = all(code == presented for code in codes)
    return (0x9000, True) if allowed else (0x6982, False)


def grammar(session):
    for route, command, policy in product(Route, (8, 9, 0x11, 0x12), ("unprotected", "same-code", "mixed-code")):
        codes = (bytes(6),) * 4 if policy == "unprotected" else (ACCESS,) * 4 if policy == "same-code" else (bytes(6), ACCESS, ACCESS, ACCESS)
        width = SCAN_BYTES if command == 0x12 else LEGACY_BYTES if command == 0x11 else NDEF_BYTES
        for size, presented in product(sorted({0, 1, width - 1, width, width + 1, width + 5, width + 6, width + 7, 127, 128, 255}), (bytes(6), ACCESS, b"wrong!")):
            with session.case(f"otp.admin.grammar.{route.value}.{command:02x}.{policy}.length-{size}.code-{presented.hex()}",
                    ("Y01", "Y06", "Y13", "Y14", "G01", "G03", "G05", "G10", "G13", "G14"), effects=("config_change", "otp_both_slots", "otp_extra_slots")):
                session.require(session.profile == "rsk", "admin truncation/strict rules require RS-Key", "excluded_by_profile")
                session.require(route != Route.HID or size <= 64, "HID always carries 64 bytes; a longer card body has no feature equivalent", "excluded_by_mode")
                configs = configurations(session, codes)
                with ExitStack() as stack:
                    for slot, config in configs.items():
                        stack.enter_context(fixture(session, Route.CARD, slot, config))
                    body = (bytes([4]) * width + presented + b"tail")[:size].ljust(size, b"x")
                    delivered = body.ljust(64, b"\x00") if route == Route.HID else body
                    expected, changed = accepted(command, delivered, codes, "strict-config" in session.options.features)
                    if route == Route.HID:
                        session.otp_call(0x10, expected_len=4)
                    before = status(session, route)
                    reply = request(session, route, command, body)
                    result(session, route, reply, expected, changed)
                    session.check("admin sequence advances only for an enabled accepted record write", status(session, route)[3], (before[3] + changed) & 255)
                    for slot, config in configs.items():
                        witness(session, Route.CARD, slot, config)
                    session.observe("admin_storage_visibility", "NDEF and legacy mode have no export or active USB effect; acknowledgment/sequence do not prove their opaque stored bytes")
                if not session.broken and "strict-config" not in session.options.features and command == 0x12:
                    session.trace.phase = "cleanup"
                    session.select("otp")
                    request(session, Route.CARD, 0x12, default_map())
                    session.observe("cleanup_limit", "known default US map restored after all owned slots were deleted; previous write-only map cannot be exported")


def scan_persistence(session):
    for slot, action in product(range(1, 5), Action):
        with session.case(f"otp.admin.scan-map.persistence.slot-{slot}.{action.value}",
                ("Y09", "Y10", "Y11", "Y12", "Y13", "Y14", "X11", "G10", "G14"), effects=("config_change", "otp_both_slots", "otp_extra_slots", "keyboard_output", "reboot")):
            ready(session, Mode.HOTP6)
            # All slots are owned so no unknown slot code can silently veto a global map.
            configs = {number: configuration(session, number, Mode.HOTP6, access=ACCESS) for number in range(1, 5)}
            with ExitStack() as stack:
                for number, config in configs.items():
                    stack.enter_context(fixture(session, Route.CARD, number, config))
                try:
                    before = status(session, Route.CARD)
                    reply = request(session, Route.CARD, 0x12, bytes([4]) * SCAN_BYTES + ACCESS)
                    result(session, Route.CARD, reply)
                    strict = "strict-config" in session.options.features
                    session.check("strict build swallows scan-map writes without a sequence change", status(session, Route.CARD)[3], (before[3] + (not strict)) & 255)
                    change(session, action)
                    session.select("otp")
                    for position in (0, 1):
                        text = keyboard.receive(session, keyboard.gesture(session, slot))
                        session.check("scan map remains effective after the connection transition", text,
                            expected_hotp(configs[slot], position) if strict else "aaaaaa")
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        session.select("otp")
                        request(session, Route.CARD, 0x12, default_map() + ACCESS)
                        session.observe("cleanup_limit", "default US scan map requested; prior custom map is write-only")


def run(session):
    grammar(session)
    scan_persistence(session)
